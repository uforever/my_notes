## Intel PIN

```cpp
#include <stdio.h>
#include <string>
#include "pin.H"
#include "inverse.h"

// 参考：https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-dynamic-binary-instrumentation-tool.html

// 构造处理命令行参数的KNOB类模板
// 第一个参数：KNOB_MODE // KNOB_MODE_WRITEONCE表示只写一次 KNOB_MODE_APPEND表示追加
// 第二个参数：表示所属的“家族”或分类
// 第三个参数：表示命令行参数的名称
// 第四个参数：表示默认值
// 第五个参数：表示参数的描述
KNOB<std::string> pwfile_name(KNOB_MODE_WRITEONCE, "pintool", "o", "password.txt", "File to save password in");
// KNOB<TYPE>对象具有如下常用方法：
// .Type() // 获取参数类型 -> const std::string
// .Value() // 获取参数值 -> const TYPE &
// .Value(const UINT32 index) // 获取参数值 -> const TYPE &
// .NumberOfValues() // 获取参数个数 -> UINT32

FILE *pwfile;

// syscall指令调用前执行的函数
// 第一个参数 syscall指令所在的地址
// 第二个参数 eax寄存器的值
// 第三个参数 上下文指针
VOID syscall_before(ADDRINT rip, ADDRINT call_num, CONTEXT* ctxt)
{
    if (call_num == 0)  // eax=0 即 sys_read
    {
        // 在指定上下文中设置整数寄存器或fp状态/控制寄存器的给定值
        // VOID PIN_SetContextReg(CONTEXT *	ctxt, REG reg, ADDRINT val)
        PIN_SetContextReg(ctxt, REG_GAX, 16);           // REG_GAX 表示 eax或rax 这里也就是设置函数返回值
        PIN_SetContextReg(ctxt, REG_INST_PTR, rip + 2); // 设置IP寄存器 加2 表示跳过当前syscall指令的2字节
        // VOID PIN_ExecuteAt(const CONTEXT * ctxt)	
        PIN_ExecuteAt(ctxt);                            // 回到guest程序 以指定的上下文环境继续运行
    }
}

// aesenc/aesdec指令调用前执行的函数
VOID aes_before(ADDRINT eip, VOID* rsp, UINT8* xmm0, UINT8* xmm1, UINT8* xmm2, CONTEXT* ctxt, bool enc)
{
    // size_t PIN_SafeCopy(VOID * dst, const VOID *	src, size_t size)
    // 将指定数目的字节从源内存区域复制到目标内存区域
    // 返回实际成功复制的字节数
    if (PIN_SafeCopy((VOID*)xmm2, (VOID*)xmm0, 16) != 16)
    {
        printf("[%lx] Error copying xmm0 to xmm2!", eip);
        // NORETURN VOID PIN_ExitApplication(INT32 status)
        // 在退出回调执行后终止当前进程 参数为退出状态码
        PIN_ExitApplication(-1);
    }

    // aesenc或aesdec执行逆运算
    if (enc)
        inv_aesenc(xmm2, xmm1);
    else
        inv_aesdec(xmm2, xmm1);
    
    // xmm2的运算结果复制到栈上
    if (PIN_SafeCopy(rsp, xmm2, 16) != 16)
    {
        printf("[%lx] Error copying calculated input to [rsp]!", eip);
        PIN_ExitApplication(-1);
    }

    // VOID PIN_LockClient() 锁定客户端	
	PIN_LockClient();
    printf("[%lx] \"", eip);

    for (size_t i = 0; i < 16; i++)
        printf("\\x%.2x", xmm2[i] & 0xff);

    puts("\"");
    // VOID PIN_UnlockClient() 解锁客户端
	PIN_UnlockClient();
	
	// size_t fwrite(const void *ptr, size_t size, size_t count, FILE *stream);
	fwrite(xmm2, 16, 1, pwfile);
}

// INS_INSTRUMENT_CALLBACK 实现
// 指令级别插桩回调函数
// 第一个参数是指令 第二个参数是自定义数据
VOID insInstrumentation(INS ins, VOID* v)
{
    // OPCODE INS_Opcode(INS ins)
    // 参数是指令
    switch (INS_Opcode(ins))
    // 返回值是XED_ICLASS_name形式的常量
    // 枚举定义在/extras/xed-??/include/xed/xed-iclass-enum.h头文件中
    // 如果需要字符串 使用INS_Mnemonic函数
    {
    case XED_ICLASS_SYSCALL: // syscall 指令
        // 相对指令粒度 插入回调函数
        // VOID INS_InsertCall(INS ins, IPOINT action, AFUNPTR funptr, ...)
        // 第一个参数：指令
        // 第二个参数：插入位置
        // - IPOINT_BEFORE 指令执行前
        // - IPOINT_AFTER 指令执行后(注意如果有跳转的话回调会失效)
        // - IPOINT_TAKEN_BRANCH 控制流指令边缘插入 仅当INS_IsValidForIpointTakenBranch()为true时有效
        // 第三个参数：回调函数
        // 其余参数：作为回调函数的参数
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)syscall_before,
            // VOID syscall_before(ADDRINT rip, ADDRINT call_num, CONTEXT* ctxt)
            IARG_INST_PTR, // Type: ADDRINT 被插桩指令的地址 是IARG_ADDRINT, INS_Address(ins)的简写
            IARG_REG_VALUE, REG_EAX, // IARG_REG_VALUE, <REG> 整数寄存器的ADDRINT值
            IARG_CONTEXT, // Type: Context manipulation API * 上下文指针 传递当前guest程序的上下文
            IARG_END); // 所有参数列表必须以IARG_END结尾
        break;

    case XED_ICLASS_AESENC: // aesenc 指令
		// REG INS_OperandReg(INS ins, UINT32 n)
        // 第一个参数：指令
        // 第二个参数：操作数索引
        if (INS_OperandReg(ins, 0) == REG_XMM2) // 第一个操作数(0)是XMM2寄存器
        {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)aes_before,
                IARG_INST_PTR, // 被插桩指令地址
                IARG_REG_VALUE, REG_STACK_PTR, // SP寄存器的值
                IARG_REG_REFERENCE, REG_XMM0, // Type: UINT8* 指向保存所请求寄存器内容的缓冲区的指针
                // 如果是读取值 不修改 请改用 IARG_REG_CONST_REFERENCE
                IARG_REG_REFERENCE, REG_XMM1,
                IARG_REG_REFERENCE, REG_XMM2,
                IARG_CONTEXT, // 上下文指针
                IARG_BOOL, true, // Type: BOOL.
                IARG_END);
        }
        break;

    case XED_ICLASS_AESDEC: // aesdec 指令
        if (INS_OperandReg(ins, 0) == REG_XMM2) // 第一个操作数(0)是XMM2寄存器
        {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)aes_before,
                IARG_INST_PTR, // 被插桩指令地址
                IARG_REG_VALUE, REG_STACK_PTR, // SP寄存器的值
                IARG_REG_REFERENCE, REG_XMM0, // Type: UINT8* 指向保存所请求寄存器内容的缓冲区的指针
                IARG_REG_REFERENCE, REG_XMM1,
                IARG_REG_REFERENCE, REG_XMM2,
                IARG_CONTEXT, // 上下文指针
                IARG_BOOL, false, // Type: BOOL.
                IARG_END);
        }
        break;
    }
}

// FINI_CALLBACK 实现
// 退出回调 第一个参数是OS退出码 第二个参数可以传递自定义数据
VOID finished(INT32 code, VOID* v)
{
    fclose(pwfile);
    printf("Finished");
}

int main(int argc, char* argv[])
{
    // 初始化符号表 允许操作PE格式中存在的符号
    // 必须在PIN_StartProgram之前调用
    PIN_InitSymbols();

    // 初始化Pin系统 必须在PIN_StartProgram之前调用
    if (PIN_Init(argc, argv))
        return -1;

    // 尝试打开参数中的输出文件
    if ( !(pwfile = fopen(pwfile_name.Value().c_str(), "wb")) )
    {
        printf("Unable to open file to write password: %s\n", pwfile_name.Value().c_str());
        return -1;
    }

    // 增加指令级别的插桩函数 PIN_CALLBACK INS_AddInstrumentFunction (INS_INSTRUMENT_CALLBACK fun, VOID * val)
    // 第一个参数是插桩函数 typedef VOID(* INS_INSTRUMENT_CALLBACK) (INS ins, VOID *v) // 其返回值是void 第一个参数是指令 第二个参数可以传递自定义数据
    // 第二个参数 作为第二个参数传递给插桩函数
    INS_AddInstrumentFunction(insInstrumentation, 0);
    // 返回PIN_CALLBACK 是此回调的句柄 可用于进一步修改此回调的属性
    
    // 为PIN增加退出函数 在应用程序退出之前立即调用该函数
    // 不是检测函数不能插桩 可以有多个Fini函数
    // PIN_CALLBACK PIN_AddFiniFunction	(FINI_CALLBACK fun, VOID * val)
    // 第一个参数是函数指针 typedef VOID(* FINI_CALLBACK) (INT32 code, VOID *v) // 返回值是void 第一个参数是OS退出码 第二个参数可以传递自定义数据
    // 第二个参数 要传递给退出函数的数据
    PIN_AddFiniFunction(finished, 0);
    // 返回PIN_CALLBACK 是此回调的句柄 可用于进一步修改此回调的属性

    // 当Pin处于JIT模式(默认模式)时 开始执行应用程序
    // 必须在PIN_StartProgram()之前调用PIN_Init()
    PIN_StartProgram();

    return 0;
}
```

## QBDI

```JavaScript
// QBDI
import { VM, InstPosition, VMAction } from "./frida-qbdi.js";

// 初始化 QBDI 虚拟机对象
const vm = new VM();
// - 选项
// VM.getOptions() // 获取当前虚拟机选项
// VM.setOptions(options) // 设置虚拟机选项
// - 状态管理
// VM.getGPRState() // 获取当前通用寄存器状态
// VM.getFPRState() // 获取当前浮点寄存器状态
// VM.setGPRState(state) // 设置通用寄存器状态
// VM.setGPRState(state) // 设置浮点寄存器状态
// - 插桩范围
// VM.addInstrumentedRange(start, end) // 将指定的地址范围添加到插桩范围
// VM.addInstrumentedModule(name) // 将模块的可执行地址范围添加到插桩范围
// VM.addInstrumentedModuleFromAddr(addr) // 通过模块中的地址将模块的可执行地址范围添加到插桩范围
// VM.instrumentAllExecutableMaps() // 将所有可执行内存映射添加到插桩范围
// VM.removeInstrumentedRange(start, end) // 从插桩范围中删除指定地址范围
// VM.removeInstrumentedModule(name) // 从插桩范围中删除模块的可执行地址范围
// VM.removeInstrumentedModuleFromAddr(addr) // 通过模块中的地址从插桩范围中删除模块的可执行地址范围
// VM.removeAllInstrumentedRanges() // 删除所有插桩范围
// - 回调管理
// VM.newInstCallback(cbk) // 创建一个指令回调
// VM.newInstrRuleCallback(cbk) // 创建一个指令规则回调/条件指令回调?
// VM.newVMCallback(cbk) // 创建一个虚拟机回调
// VM.addCodeCB(pos, cbk, data, priority) // 为指令注册回调(插桩函数)
// VM.addCodeAddrCB(addr, pos, cbk, data, priority) // 注册一个回调函数 在特定地址被执行时触发
// VM.addCodeRangeCB(start, end, pos, cbk, data, priority) // 注册一个回调函数 在特定地址范围内执行
// VM.addMnemonicCB(mnem, pos, cbk, data, priority) // 注册一个回调函数 在特定指令被执行时触发
// VM.addVMEventCB(mask, cbk, data) // 注册一个回调函数 在特定虚拟机事件发生时触发
// VM.addMemAccessCB(type, cbk, data, priority) // 注册一个回调函数 在特定方式的内存访问时触发
// VM.addMemAddrCB(addr, type, cbk, data) // 注册一个回调函数 在指定内存被特定的方式访问时触发
// VM.addMemRangeCB(start, end, type, cbk, data) // 注册一个回调函数 在指定内存范围被特定的方式访问时触发
// VM.addInstrRule(cbk, type, data) // 添加自定义插桩规则
// VM.addInstrRuleRange(start, end, cbk, type, data) // 为指定的地址范围添加自定义插桩规则
// VM.deleteInstrumentation(id) // 删除指定ID的插桩
// VM.deleteAllInstrumentations() // 删除所有插桩
// - 内存管理
// VM.alignedAlloc(size, align) // 分配一个指定大小的内存块 并使用给定的对齐基址
// VM.allocateVirtualStack(state, stackSize) // 分配新堆栈 并设置通用寄存器状态GPRState
// VM.alignedFree(ptr) // 释放内存
// - 检索
// VM.getModuleNames() // 获取所有已加载模块的名称
// - 运行
// VM.run(start, stop) // DBI从给定的地址执行到另一个给定的地址
// VM.call(address, args) // 通过地址主动调用函数 并传递参数
// VM.switchStackAndCall(address, args, stackSize) // 通过地址主动调用函数 使用栈传递参数
// VM.simulateCall(state, retAddr, args) // 通过修改相应的堆栈和寄存器来模拟调用
// - 指令分析
// VM.getInstAnalysis(type) // 获取当前指令的分析 类型可以是反汇编、操作数、符号等
// VM.getCachedInstAnalysis(addr, type) // 从缓存中获取指定地址的指令分析
// - 内存访问
// VM.getInstMemoryAccess() // 获取最后执行的指令所进行的内存访问 如果没有进行内存访问 则返回NULL和大小0
// VM.getBBMemoryAccess() // 获取最后执行的基本快所进行的内存访问 如果没有进行内存访问 则返回NULL和大小0
// VM.recordMemoryAccess(type) // 获取最后执行的指令所进行的指定类型的内存访问 读/写/读写
// - 缓存管理
// VM.precacheBasicBlock(pc) // 预缓存已知的基本块
// VM.clearCache(start, end) // 从缓存中清除特定地址范围
// VM.clearAllCache() // 清除所有缓存

console.log("QBDI version is " + vm.version.string);

// 在初始化虚拟堆栈之前 我们需要获取当前通用寄存器状态 // assert(state != NULL);
const state = vm.getGPRState();
// 返回 GPRState 包含通用寄存器状态的对象
// GPRState.dump(color) // color(bool) 打印上下文 是否使用颜色
// GPRState.getRegister(rid) // rid(String|Number) 获取寄存器值 可以使用寄存器名称或ID
// GPRState.getRegisters() // 获取所有寄存器值
// GPRState.pp(color) // color(bool) 美观打印(Pretty print)上下文 是否使用颜色
// GPRState.setRegister(rid, value) // rid(String|Number) value(String|Number) 设置寄存器值
// GPRState.setRegisters(gprs) // gprs(Array) 设置所有寄存器值
// GPRState.synchronizeContext(FridaCtx, direction) // 此函数用于单向同步Frida和QBDI之间的上下文
// GPRState.synchronizeRegister(FridaCtx, rid, direction) // 此函数用于单向同步Frida和QBDI之间的特定寄存器


// 虚拟机不使用的常规堆栈 请求一个虚拟堆栈 并设置通用寄存器状态
// const stack = vm.allocateVirtualStack(state, 0x100000);
vm.allocateVirtualStack(state, 0x100000);

console.log(Process.mainModule.name);
console.log(Process.mainModule.base);
console.log(Process.mainModule.size);

const offset__start = 0x10E0;
const offset_main = 0x12E8;
const offset_Hello = 0x12CE;

// 添加插桩范围
vm.addInstrumentedModuleFromAddr(Process.mainModule.base);

// 插桩回调函数
const preinst_ckb = vm.newInstCallback(function (vm, gpr, fpr, data) {
    // 分析指令
    const inst = vm.getInstAnalysis();
    // InstAnalysis.address // 指令地址
    // InstAnalysis.affectControlFlow // 指令是否影响控制流
    // InstAnalysis.disassembly // 反汇编
    // InstAnalysis.instSize // 指令大小 共多少个字节
    // InstAnalysis.isBranch // 指令是否是分支/跳转
    // InstAnalysis.isCall // 指令是否是调用
    // InstAnalysis.isCompare // 指令是否是比较
    // InstAnalysis.isPredicable // 指令是否包含谓词 涉及到类似于比较或选择的操作
    // InstAnalysis.isMoveImm // 指令是否立即移动
    // InstAnalysis.isReturn // 指令是否是返回
    // InstAnalysis.condition // 与指令关联的条件
    // InstAnalysis.mnemonic // 指令LLVM助记符
    // InstAnalysis.operands // 指令操作数
    // InstAnalysis.moduleName // 模块名称
    // InstAnalysis.symbolName // 符号名称
    // InstAnalysis.symbolOffset // 符号偏移量
    console.log("0x" + inst.address.toString(16) + " " + inst.disassembly); // 打印指令返反汇编
    return VMAction.CONTINUE;
});

// VM.addCodeCB(pos, cbk, data, priority) // 为指令注册回调
// 第一个参数：回调的相对位置 PreInst / PostInst 指令执行之前/之后
// 第二个参数：(插桩)回调函数
// 第三个参数：用户定义的函数 作为参数传递给插桩回调函数
// 第四个参数：回调优先级
const iid = vm.addCodeCB(InstPosition.PREINST, preinst_ckb);
// 返回插桩/回调的ID

// 主动运行程序
// vm.run(Process.mainModule.base, Process.mainModule.base + Process.mainModule.size);
// vm.call(Process.mainModule.findExportByName("start"), []);
// vm.call(Process.mainModule.base.add(offset__start), []);
vm.call(Process.mainModule.base.add(offset_main), []); // 暂时只能这样运行了
// vm.call(Process.mainModule.base.add(offset_Hello), []);
```