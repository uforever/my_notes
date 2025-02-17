## 基础知识

###  通用模块

- **idautils** 这个模块提取了最有用和最方便的函数，允许您立即跳转并与反汇编交互，而无需从一开始就仔细检查整个IDAPython API。您可以在这里找到要遍历整个段的函数、函数（由IDA创建，也可以是用户定义的）、命名位置等。
- **ida_idaapi** 当您想要创建自定义插件或处理事件时，`ida_idaapi`模块非常方便，因为它允许您访问更高级的功能，并允许与整个系统进行交互
- **idc** 此模块提供了原本是本机IDAIDC脚本语言一部分的函数，这些函数被包装以在IDAPython API中使用。如果您已经熟悉IDC脚本，这是一个很好的起点。
- **ida_funcs** 这个模块提供了在IDA中创建和操作函数的工具。
- **ida_kernwin** 这个模块提供了与IDA UI交互的功能，因此您可以创建自定义对话框等。

### 常用变量和常量

最常传递的变量之一是`ea`，它引用有效内存地址（有效地址）。另一方面，`BADADDR`是指示无效地址的常量。它用于指示操作（如查询函数）失败或返回无效结果，或表示特定内存位置不可用。当您使用返回内存地址的函数时，最佳做法是检查结果是否等于BADADDR，以确保操作成功。

### 常用代码片段

#### 地址

- 获取当前地址
```python
ea = idc.here()
print(f"Current address: {hex(ea)}")
```
- 设置当前地址
```python
idc.jumpto(0x401000)
```
- 获取最小地址
```python
idc.get_inf_attr(INF_MIN_EA)
```
- 获取最大地址
```python
idc.get_inf_attr(INF_MAX_EA)
```
- 列出所有指令地址
```python
import idautils
for ea in idautils.Heads():
  print(hex(ea))
```
- 获取与给定地址关联的名称
```python
ida_name.get_name(0x100000da0)
```
- 获取与给定名称关联的地址
```python
ida_name.get_name_ea(0, "main")
```

#### 数据

- 读取数据
```python
byte_value = idc.get_wide_byte(0x14001E5D8) # Read a byte at address 0x14001E5D8

word_value = idc.get_wide_word(0x14001E5D8) # Read a word (2 bytes) at address 0x14001E5D8

dword_value = idc.get_wide_dword(0x14001E5D8) # Read a double word (4 bytes) at address 0x14001E5D8

print(f"Byte: {hex(byte_value)}, Word: {hex(word_value)}, Dword: {hex(dword_value)}")
```
- 写入数据
```python
idc.patch_byte(0x401000, 0x90)  # Write a byte (0x90) at address 0x401000
idc.patch_word(0x401002, 0x9090)  # Write a word (0x9090) at address 0x401002
idc.patch_dword(0x401004, 0x90909090)  # Write a double word (0x90909090) at address 0x401004
```

#### 注释

- 添加注释
```python
idc.set_cmt(0x401000, "This is a comment", 0)  # Add a regular comment at address 0x401000
idc.set_cmt(0x401000, "This is a repeatable comment", 1)  # Add a repeatable comment at address 0x401000
```
- 获取注释
```python
comment = idc.get_cmt(0x401000, 0)  # Get a regular comment at address 0x401000
print(f"Comment: {comment}")
```

#### 段

- 获取指定地址的段名称
```python
idc.get_segm_name(ea)
idc.get_segm_name(0x14001B004)
```
- 获取第一个段地址
```python
idc.get_first_seg()
```
- 遍历所有段并返回段名称
```python
for seg in idautils.Segments(): print (idc.get_segm_name(seg))
```

#### 函数

- 创建函数
```python
idc.add_func(0x401000, 0x401050)  # Create a function starting at 0x401000 and ending at 0x401050
```
- 删除函数
```python
idc.del_func(0x401000)  # Delete the function at 0x401000
```
- 获取指定地址的函数名
```python
get_func_name(ea)
get_func_name(0x1400023BB)
```
- 遍历所有函数并打印它们的有效地址和名称
```python
for func_ea in idautils.Functions(): func_name = idc.get_func_name(func_ea); print(hex(func_ea), func_name)
```
#### 交叉引用

- 列出地址的交叉引用
```python
for xref in idautils.XrefsTo(0x1400023A0):
    print(f"Xref to 0x1400023A0 from {hex(xref.frm)}")
```
- 列出地址的主动引用
```python
for xref in idautils.XrefsFrom(0x1400023A0):
    print(f"Xref from 0x1400023A0 to {hex(xref.to)}")
```
- 遍历所有对特定地址的交叉引用，并打印引用的来源地址
```python
for ref in idautils.XrefsTo(ea):
  print(hex(ref.frm))
```

#### UI

- 设置背景颜色
```python
set_color(0x1400023A0, idc.CIC_ITEM, 0x007fff)  # Set background color for the function starting at address 0x1400023A0
```
- 弹出对话框
```python
ida_kernwin.info("This is a custom message dialog. Good luck with learning IDAPython API!")
```

## 常用API

```python
# 获取屏幕光标处的地址
ida_kernwin.get_screen_ea()
# addr = ida_kernwin.get_screen_ea()
```

## 案例

### IDA Trace 指令

```python
import idc
import re
import ida_dbg
import ida_idd
from idaapi import *
import os

debughook = None

# 初始化完成后 手动调用一次 starthook()
# 根据实际情况 手动或自动调用 suspend_other_thread() 绕过反调试/干扰

# 将程序运行到断点位置

# 设置 Tracing
# Debugger -> Tracing -> Tracing options
# 设置 Trace text file 路径
# 去掉 "Trace over debugger segments" 选项
# 选中 "Log internal instructions" 选项

# 开始 Tracing
# Debugger -> Tracing -> Instruction tracing

# 放行程序
# 运行完毕后 手动调用一次 unhook()
# 得到了 trace.log


def xx_hex(ea):  # 去除地址多余字符
    return hex(ea).rstrip("L").lstrip("0x")


def set_breakpoint(ea, isthumb=0):  # 根据地址设置断点
    # 设置寄存器T的值为1，通常用于ARM指令集的Thumb模式
    if isthumb:
        idc.SetReg(ea, "T", 1)
    # 将地址ea处的数据转换为代码，确保该地址被解释为代码段
    # idc.MakeCode(ea)
    idc.add_bpt(ea)


def my_get_reg_value(register):  # 获取寄存器的值
    # 创建一个regval_t类型的对象rv，用于存储寄存器的值
    rv = ida_idd.regval_t()
    # 调用ida_dbg模块的get_reg_val函数，获取指定寄存器的值，并存储到rv对象中
    ida_dbg.get_reg_val(register, rv)
    # 从rv对象中提取ival属性，即寄存器的整数值，赋值给current_addr变量
    current_addr = rv.ival
    # 返回寄存器的当前值
    return current_addr


def suspend_other_thread():  # 暂停其它线程
    # 获取当前线程的ID
    current_thread = idc.get_current_thread()
    # 获取系统中线程的总数量
    thread_count = idc.get_thread_qty()
    # 遍历所有线程
    for i in range(0, thread_count):
        # 获取第i个线程的ID
        other_thread = idc.getn_thread(i)
        # 如果该线程不是当前线程
        if other_thread != current_thread:
            # 挂起该线程
            idc.suspend_thread(other_thread)


def resume_process():  # 恢复整个进程和每个线程
    # 获取当前线程的ID
    current_thread = idc.get_current_thread()
    # 获取系统中线程的总数量
    thread_count = idc.get_thread_qty()
    # 遍历所有线程
    for i in range(0, thread_count):
        # 获取第i个线程的ID
        other_thread = idc.getn_thread(i)
        # 如果该线程不是当前线程
        if other_thread != current_thread:
            # 恢复该线程的执行
            idc.resume_thread(other_thread)
    # 恢复当前线程的执行
    idc.resume_thread(current_thread)
    # 恢复整个进程的执行
    idc.resume_process()


class MyDbgHook(DBG_Hooks):
    """ Own debug hook class that implementd the callback functions """

    def __init__(self, modules_info, skip_functions, end_ea):
        # 调用父类的构造函数，确保父类的初始化逻辑也被执行
        super(MyDbgHook, self).__init__()
        # 初始化模块信息，用于存储模块相关的数据
        self.modules_info = modules_info
        # 初始化跳过函数列表，用于存储需要跳过的函数地址
        self.skip_functions = skip_functions
        # 初始化步进计数器，用于记录步进操作的次数
        self.trace_step_into_count = 0
        # 初始化步进大小，默认为1，表示每次步进一条指令
        self.trace_step_into_size = 1
        # 初始化总跟踪大小，默认为300000，表示跟踪的最大指令数
        self.trace_total_size = 300000
        # 初始化当前跟踪大小，用于记录已经跟踪的指令数
        self.trace_size = 0
        # 初始化跟踪链接寄存器，用于记录当前指令的链接地址
        self.trace_lr = 0
        # 初始化结束地址，用于标记调试结束的位置
        self.end_ea = end_ea
        # 初始化断点跟踪标志，默认为0，表示未启用断点跟踪
        self.bpt_trace = 0
        # 初始化日志记录器，默认为None，需要在后续代码中设置具体的日志记录器实例
        self.Logger = None
        # 初始化行跟踪标志，默认为0，表示未启用行跟踪
        self.line_trace = 0
        # 打印初始化信息，用于调试和确认初始化过程
        print("__init__")

    def start_line_trace(self):
        # 将断点跟踪标志设置为0，表示不进行断点跟踪
        self.bpt_trace = 0
        # 将行跟踪标志设置为1，表示开始进行行跟踪
        self.line_trace = 1
        # 调用start_hook方法，开始设置钩子，用于实现行跟踪功能
        self.start_hook()

    def start_hook(self):
        # 调用对象的 hook 方法
        self.hook()
        # 打印字符串 "start_hook" 到控制台
        print("start_hook")

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        print("Process started, pid=%d tid=%d name=%s" % (pid, tid, name))

    def dbg_process_exit(self, pid, tid, ea, code):
        # 调用unhook方法，可能是用于解除之前设置的钩子（hook）
        self.unhook()
        # 检查Logger属性是否存在，如果存在则调用log_close方法，可能是用于关闭日志记录
        if self.Logger:
            self.Logger.log_close()
        # 打印进程退出的信息，包括进程ID(pid)、线程ID(tid)、退出地址(ea)和退出代码(code)
        print("Process exited pid=%d tid=%d ea=0x%x code=%d" %
              (pid, tid, ea, code))

    def dbg_process_detach(self, pid, tid, ea):
        # 调用unhook方法，可能是用于解除之前设置的钩子（hook）
        self.unhook()
        # 调用Logger对象的log_close方法，可能是用于关闭日志文件或清理日志相关资源
        self.Logger.log_close()
        # 返回0，表示函数执行成功，通常在函数末尾返回一个整数值作为状态码
        return 0

    def dbg_bpt(self, tid, ea):
        # 打印断点信息，包括断点地址和线程ID
        print("Break point at 0x%x tid=%d" % (ea, tid))
        # 检查当前断点地址是否在结束地址列表中
        if ea in self.end_ea:
            # 如果是结束地址，则禁用指令跟踪和单步跟踪
            ida_dbg.enable_insn_trace(False)
            ida_dbg.enable_step_trace(False)
            # 暂停进程
            ida_dbg.suspend_process()
            # 返回0，表示处理完成
            return 0
        # 如果不是结束地址，也返回0，表示处理完成
        return 0

    def dbg_trace(self, tid, ea):
        # 打印调试信息，显示当前线程ID和地址（已注释）
        # print("Trace tid=%d ea=0x%x" % (tid, ea))
        # return values:
        #   1  - do not log this trace event;
        #   0  - log it
        if self.line_trace:
            in_mine_so = False
            for module_info in self.modules_info:
                # print (module_info)
                so_base = module_info["base"]
                so_size = module_info["size"]
                if so_base <= ea <= (so_base + so_size):
                    in_mine_so = True
                    break

            self.trace_size += 1
            if (not in_mine_so) or (ea in self.skip_functions):
                if (self.trace_lr != 0) and (self.trace_step_into_count < self.trace_step_into_size):
                    self.trace_step_into_count += 1
                    return 0

                if (self.trace_lr != 0) and (self.trace_step_into_count == self.trace_step_into_size):
                    ida_dbg.enable_insn_trace(False)
                    ida_dbg.enable_step_trace(False)
                    ida_dbg.suspend_process()
                    if self.trace_size > self.trace_total_size:
                        self.trace_size = 0
                        ida_dbg.request_clear_trace()
                        ida_dbg.run_requests()

                    ida_dbg.request_run_to(self.trace_lr & 0xFFFFFFFE)
                    ida_dbg.run_requests()
                    self.trace_lr = 0
                    self.trace_step_into_count = 0
                    return 0

                if self.trace_lr == 0:
                    self.trace_lr = my_get_reg_value("LR")
            return 0

    def dbg_run_to(self, pid, tid=0, ea=0):
        # 打印调试信息，显示函数被调用时的pid和ea值
        # print("dbg_run_to 0x%x pid=%d" % (ea, pid))
        # 检查是否启用了行级跟踪
        if self.line_trace:
            # 启用指令级跟踪
            ida_dbg.enable_insn_trace(True)
            # 启用步进跟踪
            ida_dbg.enable_step_trace(True)
            # 请求继续执行进程
            ida_dbg.request_continue_process()
            # 运行所有挂起的调试请求
            ida_dbg.run_requests()


def unhook():
    global debughook
    # Remove an existing debug hook
    try:
        if debughook:
            print("Removing previous hook ...")
            debughook.unhook()
            debughook.Logger.log_close()
    except:
        pass


def starthook():
    # 声明全局变量 debughook，以便在函数内部访问和修改它
    global debughook
    # 检查 debughook 是否为真（即是否已经初始化或启用）
    if debughook:
        # 如果 debughook 为真，则调用其 start_line_trace 方法开始行跟踪
        debughook.start_line_trace()


def main():
    # 声明全局变量 debughook
    global debughook
    # 调用 unhook 函数，可能是为了取消之前的调试钩子
    unhook()
    # 初始化一个空列表，用于存储需要跳过的函数地址
    skip_functions = []
    # 初始化一个空列表，用于存储模块信息
    modules_info = []
    # 初始化起始地址为 0
    start_ea = 0
    # 初始化结束地址列表为空
    end_ea = []
    # 定义一个列表，包含需要处理的模块名称
    so_modules = ["libhello-jni.so"]        # module name
    # 遍历所有模块
    for module in idc._get_modules():
        # 获取模块的文件名
        module_name = os.path.basename(module.name)
        # 遍历需要处理的模块名称
        for so_module in so_modules:
            # 使用正则表达式忽略大小写搜索模块名称
            if re.search(so_module, module_name, re.IGNORECASE):
                # 打印模块信息
                print("modules_info append %08X %s %08X" %
                      (module.base, module.name, module.size))
                # 如果模块名称匹配 "libhello-jni.so"
                if module_name == "libhello-jni.so":
                    # 将模块信息添加到 modules_info 列表
                    modules_info.append(
                        {"base": module.base, "size": module.size, "name": module.name})
                    # 设置起始地址
                    start_ea = (module.base + 0x1CFF0)      # start address
                    # 设置结束地址列表
                    end_ea = [((module.base + 0x1D6D4))]    # end address
                    # 跳出内层循环
                    break

    # 为起始地址和结束地址设置断点
    if start_ea:
        set_breakpoint(start_ea)
    if end_ea:
        for ea in end_ea:
            set_breakpoint(ea)

    if skip_functions:
        print("skip_functions")
        for skip_function in skip_functions:
            print("%08X" % skip_function)

    debughook = MyDbgHook(modules_info, skip_functions, end_ea)

    pass


if __name__ == "__main__":
    main()
    pass
```