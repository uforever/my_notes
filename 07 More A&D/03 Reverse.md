### 反汇编
#### 编译过程

一个经典C程序：`hello.c`

```c
#include <stdio.h>

int main()
{
    printf("Hello, World!\n");
    return 0;
}
```

执行过程

```shell
gcc hello.c
./a.out
# 编译过程可以通过添加-v参数查看
```

其实可以分解为：预处理、编译、汇编、链接

预编译：展开宏、删除注释、添加文件名和行号等操作

```shell
gcc -E hello.c -o hello.i
```

编译：生成对应汇编代码

```shell
gcc -S hello.i -o hello.s
```

汇编：将汇编代码转变为机器指令，输出目标文件 Object File

```shell
as hello.s -o hello.o
# 或
gcc -c hello.s -o hello.o
```

链接：输出可执行文件

```shell
ld -static crt1.o crti.o crtbegin.o hello.o --start-group -lgcc -lgcc_eh -lc --end-groud crtend.o crtn.o
```

目标文件主要包括：`.obj` 和 `.o`
PE文件、ELF文件、链接库都按照可执行文件格式存储
动态链接库包括：`.dll` 和 `.so`
静态链接库包括：`.lib` 和 `.a`



#### 基础知识

- 一个字节8bit，可以用2位十六进制表示。一个十六进制数也被称为半字节。
- 两个字节称为一个字，两个字称为双字(dword，4字节，32位，8位十六进制表示）
- 64bit称为一个四字，用qword表示
- `xmm`寄存器是128bit宽的，16字节
- `ymm`寄存器是256bit宽的，32字节

#### 通用寄存器

通用寄存器是一种计算机硬件组件，用于存储和操作CPU中的数据。它们被称为"通用"寄存器，因为它们可以用于执行各种不同的任务，例如存储内存地址、整数值、指针等。 在x86架构的CPU中，有8个通用寄存器，分别命名为AX、BX、CX、DX、SI、DI、BP、SP。其中，AX、BX、CX、DX被称为"数据寄存器"，而SI、DI、BP、SP则被称为"指针寄存器"。

| 缩写 | 寄存器 | 作用 |
| --- | --- | --- |
| AX | **累加**器 | 存储二进制数字、ASCII码字符和字符串等 |
| BX | **基址**寄存器 | 存储访问内存中的数据时的基地址 |
| CX | **计数**器 | 循环和移位操作 |
| DX | **数据**寄存器 | I/O端口操作和乘法/除法运算，有时扩展AX |
| SI | **源索引**寄存器 | 存储源数据的偏移地址 |
| DI | **目标索引**寄存器 | 存储目标数据的偏移地址 |
| BP | **基址指针**寄存器 | 存储堆栈框架的基地址 |
| SP | **堆栈指针**寄存器 | 存储堆栈顶部的地址 |

EAX（32位，4字节，1个双字）：31-0
AX（16位，2字节，1个单字）：15-0
AH（8位，1字节）：15-8
AL（8位，1字节）：7-0

BH、CH 和 DH（高字节）和 BL、CL 和 DL同理

ESI（32位，4字节，1个双字）：31-0
SI（16位，2字节，1个单字）：15-0
DI、BP、SP同理

![[registers.png]]

#### 段寄存器

在x86架构CPU中，除了8个通用寄存器之外，还有4个段寄存器，分别命名为CS、DS、ES、SS。这些寄存器用于存储内存地址和数据段的相关信息，例如代码段、数据段、堆栈段等。

| 缩写 | 寄存器 | 作用 |
| ---- | ---- | ---- |
| CS | **代码段**寄存器 | 存储执行CPU指令时的程序代码所在的段地址（.text 部分） |
| DS | **数据**段寄存器 | 存储数据操作时的数据所在的段地址（.data 部分） |
| ES | **附加段**（**额外段**）寄存器 | 提供一个额外的段地址，用于特殊操作或字符串处理 |
| SS | **堆栈段**寄存器 | 存储堆栈操作时的堆栈段地址 |

处理器根据 CS 寄存器值和指令指针 （EIP） 寄存器中包含的偏移值从内存中检索指令代码。任何程序都不能显式加载或更改 CS 寄存器，处理器在为程序分配内存空间时分配其值。
DS、ES、**FS 和 GS**（额外段寄存器） 都用于指向数据段。四个独立的数据段中的每一个都有助于程序分离数据元素，以确保它们不重叠。程序使用适当的指针值加载数据段寄存器，然后使用偏移值引用各个内存位置。
堆栈段寄存器 （SS） 用于指向堆栈段。堆栈包含传递给程序中的函数和过程的数据值。
段寄存器被视为操作系统的一部分，在几乎所有情况下都不能直接读取或更改。

#### 控制寄存器

| 缩写 | 寄存器 | 作用 |
| ---- | ---- | ---- |
| CR0 | 控制寄存器0 | 控制保护模式内核的运行方式，例如启用或禁用内存分页、写保护等 |
| CR2 | 控制寄存器2 | 存储最近一次访问发生缺页异常时的线性地址 |
| CR3 | 控制寄存器3 | 存储页目录表的物理基地址，用于虚拟内存管理 |
| CR4 | 控制寄存器4 | 控制一些特殊的系统级功能，例如调试寄存器和扩展保护模式 |

除了以上四个控制寄存器，还有一些其他的控制寄存器可供使用，例如调试寄存器DR0-DR7、高速缓存控制寄存器CR8等。这些寄存器通常由操作系统内核或驱动程序使用，而不是普通的用户应用程序。

控制寄存器在计算机系统中扮演着重要的角色，它们允许CPU控制某些关键性能和安全特性，并支持各种不同类型的应用程序。了解它们的功能和用途对于系统编程和优化非常有帮助。

#### Flags寄存器

标志有助于控制、检查和验证程序的执行，是确定处理器执行的每个操作是否成功的机制。

32 位汇编中存在一个包含一组状态、控制和系统标志的 32 位寄存器。该寄存器称为 EFLAGS 寄存器，因为它包含 32 位信息，这些信息被映射以表示特定的信息标志。

| 缩写 | 寄存器 | 作用 |
| ---- | ---- | ---- |
| CF | 进位标志（Carry Flag） | 存储最高有效位（MSB）进位或借位的状态 |
| PF | 奇偶标志（Parity Flag） | 存储结果中1的个数是否为偶数 |
| AF | 辅助进位标志（Auxiliary Carry Flag） | 存储低四位进位或借位的状态，用于二进制编码十进制数学运算 |
| ZF | 零标志（Zero Flag） | 存储结果是否为0 |
| SF | 符号标志（Sign Flag） | 存储结果的符号，1代表负数，0代表正数或零 |
| TF | 跟踪标志（Trap Flag） | 调试器使用的单步跟踪标志 |
| IF | 中断标志（Interrupt Flag） | 控制CPU响应外部中断的开关 |
| DF | 方向标志（Direction Flag） | 控制字符串操作的方向，0表示从左往右，1表示从右往左 |
| OF | 溢出标志（Overflow Flag） | 存储有符号整数运算是否溢出的状态 |

在实际编程中，可以使用特殊汇编指令（例如`add eax, ebx; setc al`）来读取或写入Flags寄存器中的特定标志位，以及根据其值进行条件判断等操作。对于不同的指令集和编程语言，可能会提供不同的方式和工具来操作和管理Flags寄存器。

Flags寄存器是计算机硬件中非常重要的组件之一，它们记录着CPU运算过程中的状态和结果，是控制程序流程和处理异常情况的关键所在。了解Flags寄存器的含义和用途对于系统编程和优化非常有帮助。

#### 栈

栈指针是一个包含堆栈顶部的寄存器。堆栈指针包含最小的地址，例如 0x00001000，小于 0x00001000 的地址被视为垃圾地址，大于 0x00001000 的地址被视为有效地址。

栈在内存中是向下增长的，栈底是堆栈中最大的有效地址，栈极限是堆栈的最小有效地址。如果堆栈指针小于此值，就会出现堆栈溢出，从而破坏程序。

在堆栈上有两种操作，即push和pop。通过将堆栈指针设置为一个较小的值，可以push一个或多个寄存器。通常的做法是减去要push到堆栈的寄存器数的四倍，然后将寄存器复制到堆栈。

pop一个或多个寄存器的方法是将数据从堆栈复制到寄存器，然后向堆栈指针添加一个值。通常的做法是将要pop的寄存器数目的四倍加到堆栈上。

#### 堆

堆栈向下增长，堆向上增长。

内存泄露：要在堆上分配内存，必须使用 malloc（） 或 calloc（），它们是内置的 C 函数。在堆上分配内存后，一旦不再需要内存，就要使用 free（） 取消分配内存来释放内存。如果不执行此步骤，程序将出现所谓的内存泄漏。也就是说，堆上的内存仍将被搁置，并且不会被需要它的其他进程使用。

与堆栈不同，在堆上创建的变量可由程序中任何位置的任何函数访问。堆变量本质上是全局范围的。

#### 常见指令

##### 浮点数指令

| 指令 | 用法 | 含义 | 功能 |
| ---- | ---- | ---- | ---- |
| FLD | `FLD <in>` | Floating-Point Load | 浮点数值从指定的内存位置复制到浮点寄存器堆栈的顶部 |
| FILD | `FILD <in>` | Floating-Point Integer Load | 将带符号整数转换为浮点数并加载到浮点寄存器中 |
| FLDZ | `FLDZ` | Floating-Point Load Zero | 将浮点常量0.0从内存中加载到浮点寄存器堆栈的顶部，这个指令可以用来初始化浮点变量或者清空浮点数值 |
| FLD1 | `FLD1` | Floating-Point Load One | 将浮点常量1.0从内存中加载到浮点寄存器堆栈的顶部 |
| FST | `FST <out>` | Floating-Point Store | 将浮点寄存器堆栈的顶部的数值存储到内存地址中 |
| FSTP | `FSTP <out>` | Floating-Point Store with Pop | 将浮点寄存器堆栈的顶部的数值弹出到指定的内存位置 |
| FIST | `FIST <out>` | Floating-Point Integer Store | 将浮点寄存器堆栈的顶部的数值转换为带符号整数，然后存储到指定的内存位置 |
| FISTP | `FISTP <out>` | Floating-Point Integer Store with Pop | 将浮点寄存器堆栈的顶部的数值弹出后转换为带符号整数，然后存储到指定的内存位置 |
| FCOM | `FCOM [in]` | Floating-Point Compare | 将IN地址数据与栈顶ST(0)进行实数比较，影响对应标记位（CF和ZF），如果不传IN，则默认比较浮点寄存器堆栈的顶部两个数值 |
| FTST | `FTST` | Floating-Point Test for Zero | 比较栈顶ST(0)是否为0.0，影响对应标记位（ZF） |
| FADD | `FADD [in]` | Floating-Point ADDition | 将IN地址内的数据与ST(0)做加法运算，结果放入ST(0)中，即替换ST(0) |
| FADDP | `FADDP [n] [st]` | Floating-Point ADDition with Pop | 将ST(N)中的数据与ST(0)中的数据做加法运算，N为0~7中的任意一个数，先执行一次出栈操作，然后将相加结果放入ST(0)中保存 |

##### CMOV指令

| 指令 | 功能 | 条件码 |
| ---- | ---- | ---- |
| CMOVZ | 如果ZF标志位为1，则复制源操作数 | ZF（等于/零） |
| CMOVNZ | 如果ZF标志位为0，则复制源操作数 | ZF（不等于/非零） |
| CMOVS | 如果SF标志位为1，则复制源操作数 | SF（带符号/小于） |
| CMOVNS | 如果SF标志位为0，则复制源操作数 | SF（无符号/大于等于） |
| CMOVG | 如果ZF、SF均未设置，则复制源操作数 | ZF=0且SF=OF（大于） |
| CMOVGE | 如果SF=OF，则复制源操作数 | SF=OF（大于等于） |
| CMOVL | 如果SF≠OF，则复制源操作数 | SF≠OF（小于） |
| CMOVLE | 如果ZF或者SF≠OF，则复制源操作数 | ZF=1或者SF≠OF（小于等于） |
| CMOVA | 如果CF和ZF均未设置，则复制源操作数 | CF=0且ZF=0（无符号/大于） |
| CMOVNBE | 如果CF和ZF均未设置，则复制源操作数 | CF=0且ZF=0（无符号/大于） |
| CMOVAE | 如果CF未设置，则复制源操作数 | CF=0（无符号/大于等于） |
| CMOVNB | 如果CF未设置，则复制源操作数 | CF=0（无符号/大于等于） |
| CMOVBE | 如果CF或ZF被设置，则复制源操作数 | CF=1或ZF=1（无符号/小于等于） |
| CMOVNA | 如果ZF或CF被设置，则复制源操作数 | ZF=1或CF=1（无符号/不大于） |

无符号指令使用 CF、ZF 和 PF 来确定两个操作数之间的差异，其中有符号指令使用 SF 和 OF 来指示操作数之间比较的条件。


##### 其它指令

| 指令 | 功能 | 用法示例 |
| ---- | ---- | ---- |
| `mov` | 将数据从一个位置复制到另一个位置 | `mov eax, ebx` - 将 EBX 寄存器中的值复制到 EAX 寄存器中 |
| `add` | 将两个数相加 | `add eax, 10` - 将 EAX 寄存器中的值加上 10 |
| `sub` | 将两个数相减 | `sub edx, ecx` - 将 ECX 寄存器中的值从 EDX 寄存器中的值中减去 |
| `inc` | 将一个数加一 | `inc ebx` - 将 EBX 寄存器中的值加 1 |
| `dec` | 将一个数减一 | `dec ecx` - 将 ECX 寄存器中的值减 1 |
| `cmp` | 比较两个数的大小 | `cmp eax, ebx` - 比较 EAX 寄存器中的值和 EBX 寄存器中的值的大小 |
| `jmp` | 无条件跳转至指定地址 | `jmp label` - 跳转至标号为 "label" 的代码行 |
| `je` | 当前结果等于零时跳转 | `je label` - 如果最近一次比较操作结果为 0，则跳转至标号为 "label" 的代码行 |
| `jne` | 当前结果不等于零时跳转 | `jne label` - 如果最近一次比较操作结果不为 0，则跳转至标号为 "label" 的代码行 |
| `lea` | 将内存地址加载到寄存器中 | `lea ebx, [my_var]` - 将名为 "my_var" 变量的地址加载到 EBX 寄存器中 |
| `shl` | 将一个数左移若干位 | `shl eax, 3` - 将 EAX 寄存器中的值左移 3 位 |
| `shr` | 将一个数右移若干位 | `shr ecx, 2` - 将 ECX 寄存器中的值右移 2 位 |
| `rol` | 将一个数向左循环移位（包括进位） | `rol edx, 4` - 将 EDX 寄存器中的值循环左移 4 位 |
| `ror` | 将一个数向右循环移位（包括进位） | `ror ebx, 5` - 将 EBX 寄存器中的值循环右移 5 位 |
| `times` | 重复执行某个代码片段多次 | `times 5 db 0` - 定义5个字节并将其初始化为0 |

|指令|含义|所定义的数据大小|
|---|---|---|
|`db`|定义一个或多个8位字节（即一个或多个字节）|8位（1字节）|
|`dw`|定义一个或多个16位的字（即一个或多个双字节）|16位（2字节）|
|`dd`|定义一个或多个32位的字（即4个字节）|32位（4字节）|
|`dq`|定义一个或多个64位的字（即8个字节）|64位（8字节）|
|`dt`|定义一个或多个10字节的十进制实数|80位（10字节）|


#### 汇编程序
一个典型的汇编程序由三个主要部分组成：数据段（data segment）、BSS段（block started by symbol segment）和代码段（text segment）。：

1. 数据段（data segment）：数据段是定义程序中使用的全局变量的地方。在这个段中，程序员可以定义各种类型的数据，例如整数、字符串、数组等等。在程序执行期间，这个段的内容是只读的，它的作用主要是为了存储程序需要的静态数据，以及初始化全局变量。
    
2. BSS段（block started by symbol segment）：BSS段是用于存储未初始化的全局变量的地方。如果程序中有未经初始化的全局变量，在编译时，它们会被分配到BSS段中。在程序执行期间，BSS段的初始值全部为0，这个段也是只读的。
    
3. 代码段（text segment）：代码段是存储程序的指令的地方。在这个段中，程序员可以定义各种操作码和寻址方式，完成特定的任务。在程序执行期间，这个段的内容是只可执行的，不能被修改。代码段通常是机器语言指令（即二进制代码）的集合，一个指令对应着一条汇编语句。它以全局_start开头，告诉内核执行开始的位置。
    

除了上述三个主要部分之外，汇编程序还可能包括其他的部分，例如符号表（symbol table）、重定位表（relocation table）等等。这些部分的作用是辅助链接器将不同的二进制文件组合成单个可执行文件。

汇编语句的每一行结构：【标签】【助记符】【操作数】【注释】

使用`objdump -d`命令将二进制文件以汇编代码的形式展示出来
```shell
objdump -d -M intel <ELF file name>
# ...
# b8 00 00 00 00          mov    eax,0x0
# ...

# 不加 -M intel 将会输出 AT&T 语法
# ...
# b8 00 00 00 00          mov    $0x0,%eax
# ...
```
如 `b8 00 00 00 00` 表示指令 `mov eax,0x0`
则 `mov eax,0x1` 的二进制应为 `b8 01 00 00 00`
`01 00 00 00` 表示一个双字的立即数

**编译可调试程序**
```shell
gcc -m32 -ggdb -o {test} {test.c}
```
**转换为 AT&T 语法汇编**
```shell
gcc -S -m32 -O0 {exit.c}
```
-O0 将告诉编译器在编译二进制文件时要使用多少优化，数字 0 表示没有优化，这意味着它是人类最可读的指令集。如果要代入 1、2 或 3，则优化量会随着值的增加而增加。
**编译成二进制对象文件**
```shell
gcc -m32 -c {exit.s} -o {exit.o}
```
**使用链接器从二进制对象文件创建实际的二进制可执行文件**
```shell
gcc -m32 {exit.o} -o {exit}
```

**AT&T 汇编代码程序**
```
.section .data

.section .bss
    .lcomm buffer 1

.section .text
    .global _start

_start:
    nop

mov_immediate_data_to_register:
    movl $100, %eax
    movl $0x50, buffer

exit:
    movl $1, %eax
    movl $0, %ebx
    int $0x80
```
编译
```shell
as --32 -gstabs -o {moving_immediate_data.o} {moving_immediate_data.s}
ld -m elf_i386 -o {moving_immediate_data} {moving_immediate_data.o}
```

**intel 汇编代码程序**
```nasm
section .data

section .bss
    buffer resb 1

section .text
    global _start

_start:
    nop

mov_immediate_data_to_register:
    mov eax, 100
    mov byte[buffer], 0x50

exit:
    mov eax, 1
    mov ebx, 0
    int 0x80
```
编译
```shell
nasm -f elf32 {moving_immediate_data.asm}
ld -m elf_i386 -o {moving_immediate_data} {moving_immediate_data.o}

# 64位
nasm -f elf64 [-o test.o] test.asm
```

**gdb使用**
```shell
# 启动
gdb -q {./moving_immediate_data}
# 设置断点
# break, brea, bre, br, b -- Set breakpoint at specified location.
(gdb) > b _start
(gdb) > b *0x0804900c
# 运行程序
# run, r -- Start debugged program.
(gdb) > r
# 反编译
# disassemble -- Disassemble a specified section of memory.
(gdb) > disassemble
# 设置语法
# set disassembly-flavor -- Set the disassembly flavor.
(gdb) > set disassembly-flavor intel
(gdb) > set disassembly-flavor att
# 单步步入
# stepi, si -- Step one instruction exactly.
(gdb) > si
# 寄存器信息
# info registers, info r -- List of integer registers and their contents, for selected stack frame.
(gdb) > info r
# 变量信息
# info variables -- All global and static variable names or those matching REGEXPs.
(gdb) > info variables
# 函数信息
# info functions -- All function names or those matching REGEXPs.
(gdb) > info functions
# 打印
# print, inspect, p -- Print value of expression EXP.
# /d - 以10进制格式打印整数
# /x - 以16进制格式打印整数
# /o - 以8进制格式打印整数
# /t - 以2进制格式打印整数
# /f - 以浮点数格式打印实数
# /a - 以地址格式打印指针
(gdb) > print $ebx
(gdb) > print /t $rax
(gdb) > print (int) constant
(gdb) > print (int [11]) constants
(gdb) > print *0x804a000
# 查找变量、函数或标签的地址
# info address -- Describe where symbol SYM is stored.
(gdb) > info address constant
# 检查内存内容
# x -- Examine memory: x/FMT ADDRESS.
# /xb表示以十六进制字节的形式显示内存内容
# /11d表示打印11个十进制数
# /c表示以字符形式打印
(gdb) > x/xb 0x804a000
(gdb) > x/11d &constants
(gdb) > x /1c &answer
# 设置值
# set -- Evaluate expression EXP and assign result to variable VAR.
(gdb) > set $eax = 0x66
(gdb) > set $eip = 0x0804901e
(gdb) > set {int}0x804a000 = 333
(gdb) > set (int) (*&constant) = 444
(gdb) > set *0x804a000 = 33
```

#### BIOS引导扇区

##### 关键地址

1) 0x0 = 中断向量表 - 我们的中断表就存在于内存的最底层。我们所有的中断调用都存在于此。  
  
2) 0x400 = BIOS 数据区 - 这里存储有关可启动设备状态的变量。  
  
3) 0x7c00 = 已加载引导扇区 - 这里有我们的机器代码，这些代码将被引导加载器固件加载到 RAM 中（注：固件只是在操作系统运行之前运行的代码，就像我们正在做的那样）。  
  
4) 0x7e00 = 空闲区 - 这是您可以开发的堆栈区。  
  
5) 0x9fc00 = 扩展 BIOS 数据区 - 保存磁盘轨道缓冲区和其他连接设备的数据，因为目前还没有文件系统。  
  
6) 0xa0000 = 视频内存 - BIOS 在启动时将视频内存映射到这里。  
  
7) 0xc0000 = BIOS - BIOS 正式所在区域。  
  
8) 0x100000 = 可用 - 可以开发的额外空间。


##### 示例代码

```nasm
loop:
    jmp loop

db 0x10 ; 定义一个byte
db 'Welcome To The Machine' ; 定义多个byte

times 0x1fe-($-$$) db 0 ; 重复多次
; $ 表示当前地址, $$ 表示当前section起始地址
; 这里表示(512-2) - 已使用地址 都用0填充
dw 0xaa55 ; 定义一个字 写入后为 55 AA
```

```asm
[org 0x7c00] ; 指定程序的起始地址为0x7C00

mov bp, 0xffff ; 将bp寄存器设置为0xFFFF，即栈的底部
mov sp, bp ; 将sp寄存器设置为bp寄存器的值，即栈的顶部等于栈底，从而创建了一个空的栈。

call set_video_mode ; 调用set_video_mode函数

call get_char_input ; 调用get_char_input函数

jmp $ ; 无条件跳转到当前位置，也就是一个死循环，程序将一直停留在此处。

set_video_mode:
    mov al, 0x03 ; 设置ax低8位
    mov ah, 0x00 ; 设置ax高8位
    int 0x10 ; 调用BIOS中断向量0x10，设置显卡的图形模式
    ret

get_char_input:
    xor ah, ah ; 将ah寄存器（ax高8位）清零，以准备调用BIOS中断0x16（键盘输入）
    int 0x16 ; 调用BIOS中断0x16，等待用户按下键盘上的任意键，并将其保存在al寄存器中

    cmp al, 0x30 ; 比较用户输入的字符是否小于ASCII码值0x30（即数字0）
    jl get_char_input ; 如果小于则跳转到get_char_input
    cmp al, 0x39 ; 比较用户输入的字符是否小于ASCII码值0x39（即数字9）
    jg get_char_input ; 如果大于则跳转到get_char_input

    mov ah, 0x0e ; 将ah寄存器设置为0x0E，以准备调用BIOS中断0x10（视频输出）
    int 0x10 ; 调用BIOS中断0x10，将用户输入的字符输出到屏幕上

    jmp get_char_input ; 无条件跳转回get_char_input函数开头，等待用户输入下一个字符

times 0x1fe-($-$$) db 0 ; 用0填充512字节内没有使用到的位置
dw 0xaa55 ; 以 55 AA 作为结尾
```

编译
```shell
nasm bootsector.asm -f bin -o boots
ector.bin
```

### JS逆向

#### 去混淆

常见：webpack、eval、aa、jj、jsfuck、ollvm、sojson

在线工具：
[de4js](https://lelinhtinh.github.io/de4js/)
[JavaScript Deobfuscator](https://deobfuscate.io/)

webpack 分析：
1. 加载器有一个自执行函数入口，和模块不一定在同一个文件。可以先在外部定义若干变量，接收其内部加载器。
2. 如果遇到未定义，可以尝试补环境。如果需要补的内容太多，可以尝试删除多余的模块：找到导出的数组 `]` ，扩大选取，删除其中内容，只留下 `[]` 即可。如果因此引发了错误，可以酌情去除报错的部分代码。然后将需要用到的模块，写入 `[]` 中。改为 `{ index: value }` 格式。
3. 使用工具自动扣取：[webpack_ast](https://gitcode.net/zjq592767809/webpack_ast)
```shell
node webpack_mixer.js -l loader.js -m module0.js -m module1.js -o output/result.js
```

#### 加密参数定位方法

1. 全局搜索
2. 堆栈调试
3. XHR断点
4. 事件监听
5. 添加代码片
6. JS注入

注入的方式有很多，可以通过抓包工具、浏览器插件、代码片等，最简单的方式就是现在第一行下断点，然后在控制台手动执行代码，但这样不能够持久化，最好根据实际情况酌情选择hook方式。

Hook Cookie

```javascript
(function () {
    'use strict';
    let $cookie = document.cookie;
    Object.defineProperty(document, 'cookie', {
        get: function () {
            console.log(`[GET COOIKE]: \`${$cookie}\``);
            return $cookie;
        },
        set: function (val) {
            console.log(`[SET COOIKE]: \`${val}\``);
            debugger; const cookie = val.split(';')[0];
            const pair = cookie.split('=');
            let key = ""
                , value = "";
            if (pair.length === 1) {
                value = pair[0].trim();
            } else {
                key = pair[0].trim();
                value = pair[1].trim();
            }
            let flag = false;
            if ($cookie === '') {
                $cookie = cookie;
                return $cookie;
            } else {
                let cache = $cookie.split('; ');
                cache = cache.map((item) => {
                    const itemPair = item.split('=');
                    let itemKey = "";
                    if (itemPair.length !== 1) {
                        itemKey = itemPair[0];
                    }
                    if (itemKey === key) {
                        flag = true;
                        return cookie;
                    } else {
                        return item;
                    }
                }
                );
                if (!flag) {
                    cache.push(cookie);
                }
                $cookie = cache.join('; ');
                return $cookie;
            }
        },
    });
})();
```

过无限debugger

```JavaScript
(function () {
    const $toString = Function.prototype.toString;
    const symbol = Symbol();
    const fakeToString = function () {
        return typeof this === 'function' && this[symbol] || $toString.call(this);
    }
    function addAttr(func, key, value) {
        Object.defineProperty(func, key, {
            writable: true,
            configurable: true,
            enumerable: false,
            value: value,
        })
    }
    delete Function.prototype.toString;
    addAttr(Function.prototype, "toString", fakeToString);
    addAttr(Function.prototype.toString, symbol, "function toString() { [native code] }");
    globalThis.setNativeCode = function (func, funcName) {
        addAttr(func, symbol, `function ${funcName || func.name || ''}() { [native code] }`);
    }
})();

Function.prototype.$constructor = Function.prototype.constructor;
Function.prototype.constructor = function () {
    var args = arguments;
    for (var i = 0; i < arguments.length; i++) {
        if (arguments[i].indexOf("debugger") != -1) {
            // debugger;
            args[i] = arguments[i].replaceAll("debugger", "        ");
        }
    }
    return Function.prototype.$constructor.apply(this, args);
};

$eval = eval;
eval = function (arg) {
    if (arg.indexOf("debugger") != -1) {
        // debugger;
        arg = arg.replaceAll("debugger", "        ");
        // return function(){return false};
    }
    return $eval(arg);
};

setNativeCode(eval, "eval");
```

7. 内存漫游

[ast-hook-for-js-RE](https://github.com/JSREI/ast-hook-for-js-RE)
[Trace](https://github.com/L018/Trace)

#### AST

##### 混淆示例

```js
const fs = require('fs');
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const generator = require('@babel/generator').default;
const t = require('@babel/types');

const jscode = fs.readFileSync('./input.js', {
    encoding: 'utf-8'
});

const ast = parser.parse(jscode);

const usedHex = new Set();
const generateRandomHex = function () {
    let num;
    do {
        num = Math.floor(Math.random() * 0xffff);
        hex = num.toString(16).padStart(4, '0');
    } while (usedHex.has(hex));
    usedHex.add(hex);
    return hex;
};
let bigArr = [];
const bigArrName = '$_' + generateRandomHex();
const toHex = function (str) {
    const buffer = Buffer.from(str, 'utf8');
    let hexStr = '';
    for (let i = 0; i < buffer.length; i++) {
        // hexStr += '\\x' + ('00' + buffer[i].toString(16)).slice(-2);
        hexStr += '\xB1\xD7\xF7' + ('00' + buffer[i].toString(16)).slice(-2);
    }
    return hexStr;
};

const visitor = {
    MemberExpression(path) {
        if (t.isIdentifier(path.node.property)) {
            const name = path.node.property.name;
            path.node.property = t.stringLiteral(name);
        }
        path.node.computed = true;
    },
    Identifier(path) {
        const name = path.node.name;
        const globalIdentifiers = [
            "Object", "Function", "Array", "Number",
            "parseFloat", "parseInt", "Infinity", "NaN",
            "undefined", "Boolean", "String", "Symbol",
            "Date", "Promise", "RegExp", "Error",
            "AggregateError", "EvalError", "RangeError", "ReferenceError",
            "SyntaxError", "TypeError", "URIError", "JSON",
            "Math", "Intl", "ArrayBuffer", "Atomics",
            "Uint8Array", "Int8Array", "Uint16Array", "Int16Array",
            "Uint32Array", "Int32Array", "Float32Array", "Float64Array",
            "Uint8ClampedArray", "BigUint64Array", "BigInt64Array", "DataView",
            "Map", "BigInt", "Set", "WeakMap",
            "WeakSet", "Proxy", "Reflect", "FinalizationRegistry",
            "WeakRef", "decodeURI", "decodeURIComponent", "encodeURI",
            "encodeURIComponent", "escape", "unescape", "eval",
            "isFinite", "isNaN", "console", "Option",
            "Image", "Audio"
        ];
        if (globalIdentifiers.indexOf(name) != -1) {
            path.replaceWith(t.memberExpression(t.identifier('window'), t.stringLiteral(name), true));
        }
    },
    NumericLiteral(path) {
        const value = path.node.value;
        const key = parseInt(Math.random() * 899999 + 100000, 10);
        const cipherNum = value ^ key;
        path.replaceWith(t.binaryExpression('^', t.numericLiteral(cipherNum), t.numericLiteral(key)));
        path.skip();
    },
    StringLiteral(path) {
        const cipherText = btoa(path.node.value);
        const bigArrIndex = bigArr.indexOf(cipherText);
        let index = bigArrIndex;
        if (bigArrIndex == -1) {
            const length = bigArr.push(cipherText);
            index = length - 1;
        }
        const encStr = t.callExpression(
            t.identifier('atob'),
            [t.memberExpression(t.identifier(bigArrName), t.numericLiteral(index), true)]
        );
        path.replaceWith(encStr);
        path.skip();
    },
    BinaryExpression(path) {
        const operator = path.node.operator;
        const left = path.node.left;
        const right = path.node.right;
        const a = t.identifier('a');
        const b = t.identifier('b');
        const funcNameIdentifier = path.scope.generateUidIdentifier('xxx');
        const func = t.functionDeclaration(
            funcNameIdentifier,
            [a, b],
            t.blockStatement([
                t.returnStatement(t.binaryExpression(operator, a, b)),
            ])
        );
        const blockStatement = path.findParent(p => p.isBlockStatement());
        blockStatement.node.body.unshift(func);
        path.replaceWith(t.callExpression(funcNameIdentifier, [left, right]));
    },
};
traverse(ast, visitor);

const offset = Math.floor(Math.random() * bigArr.length);

(function (arr, num) {
    const disrupt = function (number) {
        while (--number) {
            arr.unshift(arr.pop());
        }
    };
    disrupt(++num);
})(bigArr, offset);

const restoreCode = `(function(arr, num) {
    const disrupt = function(number) {
        while (--number) {
            arr.push(arr.shift());
        }
    };
    disrupt(++num);
})(${bigArrName}, ${offset});`;
const astRestore = parser.parse(restoreCode);
const visitorRestore = {
    MemberExpression(path) {
        if (t.isIdentifier(path.node.property)) {
            const name = path.node.property.name;
            path.node.property = t.stringLiteral(toHex(name));
        }
        path.node.computed = true;
    },
};
traverse(astRestore, visitorRestore);
ast.program.body.unshift(astRestore.program.body[0]);

const renameOwnBinding = function (path) {
    let ownBinding = {};
    let globalBinding = {};
    path.traverse({
        Identifier(p) {
            const name = p.node.name;
            const binding = p.scope.getOwnBinding(name);
            binding && generator(binding.scope.block).code == path + '' ?
                (ownBinding[name] = binding) : (globalBinding[name] = 1)
        }
    });
    for (let originName in ownBinding) {
        let newName;
        do {
            newName = '_$' + generateRandomHex();
        } while (globalBinding[newName]);
        ownBinding[originName].scope.rename(originName, newName);
    }
};
// traverse(ast, {
//     FunctionExpression(path) {
//         const blockStatement = path.node.body;
//         const Statements = blockStatement.body.map(function (v) {
//             if (t.isReturnStatement(v)) return v;
//             const code = generator(v).code;
//             const cipherText = btoa(code);
//             const decryptFunc = t.callExpression(t.identifier('atob'), [t.stringLiteral(cipherText)]);
//             return t.expressionStatement(t.callExpression(t.identifier('eval'), [decryptFunc]));
//         });
//         path.get('body').replaceWith(t.blockStatement(Statements));
//     },
// });
// traverse(ast, {
//     FunctionExpression(path) {
//         const blockStatement = path.node.body;
//         const Statements = blockStatement.body.map(function (v) {
//             if (t.isReturnStatement(v)) return v;
//             // if (!(v.trailingComments && v.trailingComments[0].value == 'ASCIIEncrypt')) return v;
//             // delete v.trailingComments;
//             const code = generator(v).code;
//             const asciiCode = [].map.call(code, function (v) {
//                 return t.numericLiteral(v.charCodeAt(0));
//             });
//             const decryptFuncName = t.memberExpression(t.identifier('String'), t.identifier('fromCharCode'));
//             const decryptFunc = t.callExpression(decryptFuncName, asciiCode);
//             return t.expressionStatement(t.callExpression(t.identifier('eval'), [decryptFunc]));
//         });
//         path.get('body').replaceWith(t.blockStatement(Statements));
//     },
// });
traverse(ast, {
    'Program|FunctionDeclaration|FunctionExpression'(path) {
        renameOwnBinding(path);
    },
});

bigArr = bigArr.map(function (v) {
    return t.stringLiteral(v);
});
bigArr = t.variableDeclarator(t.identifier(bigArrName), t.arrayExpression(bigArr));
bigArr = t.variableDeclaration('var', [bigArr]);
ast.program.body.unshift(bigArr);

let code = generator(ast).code;
// const hexRegex = /\\\\x([0-9A-Fa-f]{2})/g;
// code = code.replace(hexRegex, (_match, pattern) => {
//     return "\\x" + pattern.toUpperCase();
// });
code = code.replace(/\\xB1\\xD7\\xF7/g, '\\x');
fs.writeFileSync('./output.js', code);
```

#### 补环境框架

JS 在线文档：[JavaScript](https://developer.mozilla.org/zh-CN/docs/Web/JavaScript)

##### 创建JS Object对象的方法

```JS
// 1. 字面量
let a = {};

// 2. 通过 new
let b = new Object();

// 3. 通过 Object.create(Object.prototype)
// 这里表示 以Object的原型 为 原型
// 创建出的对象就是 Object 本身
let c = Object.create(Object.prototype);

console.log(a);
console.log(b);
console.log(c);
```

##### 原型链

```JS
// JS中 所有对象都有一个内置属性 称为它的 prototype 原型
// 原型本身是一个对象 故原型对象也有它自己的原型 从而构成了原型链
// 实际上大部分浏览器都使用 __proto__ 而不是 prototype 指向原型
// 当一个属性被访问时 如果在本身找不到 就会逐级到原型中找
// dir(document);
// 颜色深的是自有属性，颜色浅的是继承来的属性
// document -> HTMLDocument -> Document -> Node -> EventTarget -> Object

const greet = {
    hello(name) {
        console.log(`Hello, ${name}!`);
    },
    hi() {
        console.log(`Hello, ${this.name}!`);
    },
};

// 以指定对象为原型 创建对象
// 原型 -> 对象
const hw = Object.create(greet);
console.log(hw);
// hw.hello("World");

// JS中 所有函数都有一个 prototype 属性
// 调用一个函数作为构造函数时 这个属性将作为新对象的原型
// 构造函数
function User(name) {
    this.name = name;
};
// User.prototype.hi = greet.hi;
// 或 复制可枚举的自有属性
Object.assign(User.prototype, greet);

// 原型 -> 构造函数
const userPrototype = User.prototype;
console.log(userPrototype.constructor);

// 构造函数 -> 对象
const hh = new User("Hh");
console.log(hh);
// hh.hi();

// 构造函数 -> 原型
console.log(User.prototype);

// 对象 -> 原型
console.log(hh.__proto__);
// console.log(Object.getPrototypeOf(hh));

// 对象 -> 构造函数
console.log(hh.__proto__.constructor);
```

##### 函数的调用方式

```JS
function add(a, b) {
    console.log(a + b);
}
// 直接调用
add(1, 1);
// apply 方法
add.apply(null, [1, 2]);
// call 方法
add.call(null, 1, 3);

// this 指向当前作用域
function info() {
    console.log(`${this.username}:${this.age}`);
}
username = "alice";
age = 18;
// 直接调用 作用域为整个文件
info();
let bob = {
    username: "bob",
    age: 20,
}
// bind() 可以理解为绑定作用域
const bobInfo = info.bind(bob);
bobInfo();
// 等价于
info.apply(bob);
info.call(bob);

// arguments
function test() {
    console.log(arguments);
}
test(1);
test(1, 2);
test(1, 2, 3);
```

##### Object 常用内置方法

```JS
const person = {
    age: 10,
    email: "",
};
// Object.create
// 以现有对象为原型创建一个新对象
const alice = Object.create(person);

// Object.is
// 判断两个值是否为相同值
// 区别于 == 判断两个值是否相等
console.log(Object.is('1', 1));
// false
console.log('1' == 1);
// true

console.log(Object.is(NaN, NaN));
// true
console.log(NaN == NaN);
// false

console.log(Object.is(-0, 0));
// false
console.log(-0 == 0);
// true

// Object.hasOwn
// 判断对象是否有指定的自有属性
console.log(Object.hasOwn(person, 'age'));
console.log(Object.hasOwn(person, 'username'));

// Object.getOwnPropertyDescriptor
// 返回对象指定自有属性的属性描述（配置）
const ageConfig = Object.getOwnPropertyDescriptor(person, 'age');
console.log(ageConfig.configurable);
console.log(ageConfig.value);

// Object.getOwnPropertyDescriptors
// 返回指定对象的所有自有属性描述符
const personConfig = Object.getOwnPropertyDescriptors(person);
console.log(personConfig.age.writable);

// Object.getOwnPropertyNames
// 返回指定对象的所有自有属性
console.log(Object.getOwnPropertyNames(person));

// Object.getPrototypeOf
// 获取指定对象的原型
console.log(Object.getPrototypeOf(alice));
// 等价于
console.log(alice.__proto__);

// Object.setPrototypeOf
// 为指定对象设置原型
const bob = {};
Object.setPrototypeOf(bob, person);
console.log(bob.age);

// Object.defineProperty
// 为对象定义新属性
const female = {
    email: "",
};
Object.defineProperty(female, 'gender', {
    value: 0,
    writable: false,
})
female.gender = 1; // strict 模式下会报错
console.log(female);
Object.defineProperties(female, {
    height: {
        value: 160,
        writable: true,
    },
    weight: {
        value: 50,
        writable: true,
    }
})
console.log(female)
```

##### toString 和 valueOf

```JS
// toString 和 valueOf
// 这两个函数会自动调用
let a = {
    toString: function () {
        console.log("toString is executing...");
        return "aaa";
    },
    valueOf: function () {
        console.log("valueOf is executing...");
        return 111;
    },
};

console.log(0 + a); // valueOf > toString
console.log('0' + a); // valueOf > toString
console.log(`${a}`); // toString > valueOf
console.log`${a}`;
// 这个结果比较特殊
// 是 ['', ''] {...}
// 表示 字面量字符串数组 + 插值
```

##### 判断对象的类型

```JS
// typeof
console.log(typeof 42); // number
console.log(typeof 'blubber'); // string
console.log(typeof true); // boolean
console.log(typeof NaN); // number
console.log(typeof {}); // object
console.log(typeof []); // object
console.log(typeof null); // object
console.log(typeof undefined); // undefined
console.log(typeof (() => { })); // function

// Object.prototype.toString.call()
console.log(Object.prototype.toString.call(42)); // [object Number]
console.log(Object.prototype.toString.call('blubber')); // [object String]
console.log(Object.prototype.toString.call(true)); // [object Boolean]
console.log(Object.prototype.toString.call(NaN)); // [object Number]
console.log(Object.prototype.toString.call({})); // [object Object]
console.log(Object.prototype.toString.call([])); // [object Array]
console.log(Object.prototype.toString.call(null)); // [object Null]
console.log(Object.prototype.toString.call(undefined)); // [object Undefined]
console.log(Object.prototype.toString.call(() => { })); // [object Function]
```

##### 函数hook

```JS
function add(a, b) {
    return a + b;
}

addTemp = add;
add = function (a, b) {
	// 加一句打印参数
    console.log(`${a} + ${b}`);
    // return addTemp.apply(this, arguments);
    return addTemp(a, b);
}

console.log(add(1, 2));
```

##### 对象属性hook

```JS
// 主要为 赋值 和 取值 两种操作
let person = {
    "age": 10,
}

// hook的时机 对象已经定义或者加载后
ageTemp = person.age;
Object.defineProperty(person, "age", {
    get() {
        console.log("Getting value...");
        return ageTemp;
    },
    set(value) {
        console.log("Setting value...");
        ageTemp = value;
    },
})

console.log(person.age);
person.age = 18;
console.log(person.age);
```

##### 浏览器环境hook

```JS
// 以base64编解码函数为例
atobTemp = atob;
btoaTemp = btoa;
// console.log(atob);

atob = function(input) {
    const output = atobTemp(input);
    console.log(`Func: \`atob()\`; Input: \`${input}\`; Output: \`${output}\`;`);
    return output;
}

btoa = function(input) {
    const output = btoaTemp(input);
    console.log("---- btoa() ----");
    console.log("Input:", input);
    console.log("Output:", output);
    console.log("---- ---- ----");
    return output;
}
// console.log(atob);

btoa("admin");
atob("YWRtaW4=");
```

##### 简易Cookie hook

```JS
// ==UserScript==
// @name         Cookie Hook
// @namespace    http://test.demo/
// @version      1.0
// @description  Hook document.cookie
// @author       v9ng
// @match        *://*/*
// @grant        none
// ==/UserScript==

(function () {
    'use strict';
    let $cookie = document.cookie;
    Object.defineProperty(document, 'cookie', {
        get: function () {
            console.log(`[GET COOIKE]: \`${$cookie}\``);
            return $cookie;
        },
        set: function (val) {
            console.log(`[SET COOIKE]: \`${val}\``);
            debugger; const cookie = val.split(';')[0];
            const pair = cookie.split('=');
            let key = ""
                , value = "";
            if (pair.length === 1) {
                value = pair[0].trim();
            } else {
                key = pair[0].trim();
                value = pair[1].trim();
            }
            let flag = false;
            if ($cookie === '') {
                $cookie = cookie;
                return $cookie;
            } else {
                let cache = $cookie.split('; ');
                cache = cache.map((item) => {
                    const itemPair = item.split('=');
                    let itemKey = "";
                    if (itemPair.length !== 1) {
                        itemKey = itemPair[0];
                    }
                    if (itemKey === key) {
                        flag = true;
                        return cookie;
                    } else {
                        return item;
                    }
                }
                );
                if (!flag) {
                    cache.push(cookie);
                }
                $cookie = cache.join('; ');
                return $cookie;
            }
        },
    });
})();
```

##### hook检测与保护

```JS
atobTemp = atob;
console.log(atob.toString());
// 浏览器下输出为
// function atob() { [native code] }

atob = function(input) {
    const output = atobTemp(input);
    console.log(`Func: \`atob()\`; Input: \`${input}\`; Output: \`${output}\`;`);
    return output;
}
console.log(atob.toString());
// function(input) { ... }

// 检测方式
// .toString()
console.log(atob.toString() === 'function atob() { [native code] }');
// Function.prototype.toString.call
console.log(Function.prototype.toString.call(atob) === 'function atob() { [native code] }');

// 保护
/* 不够好的写法
atob.toString = function() {
    return 'function atob() { [native code] }';
}
*/
// 最好从原型链上改写
Function.prototype.toString = function() {
    // 更通用的写法
    // return `function ${this.name}() { [native code] }`;
    if (this.name == "atob") {
        return 'function atob() { [native code] }';
    }
}
```

##### 立即执行函数

```JS
// 立即执行函数 需要加括号
(function () {
    console.log(1);
})();
(function () {
    console.log(2);
}());
// 以下类似写法可以不用加括号
!function () {
    console.log(3);
}();
~function () {
    console.log(4);
}();
```

##### 函数native化

```JS
(function () {
    // 保留原始toString方法
    const $toString = Function.prototype.toString;
    // symbol值是唯一的
    // symbol值能作为对象属性的标识符 这是该数据类型唯一的用途
    const symbol = Symbol();
    const fakeToString = function () {
        // 类型是函数 且设置过符号属性 即被手动Native化过的 返回符号属性的值
        // 否则调用原始的toString方法
        return typeof this === 'function' && this[symbol] || $toString.call(this);
    }
    // 为对象添加 可写、可配置、不可枚举的属性 的函数
    function addAttr(func, key, value) {
        Object.defineProperty(func, key, {
            writable: true,
            configurable: true,
            enumerable: false,
            value: value,
        })
    }
    // 删除Function的 toString 属性
    delete Function.prototype.toString;
    // 添加一个新的 toString 属性
    addAttr(Function.prototype, "toString", fakeToString);
    // 为新的toString 设置符号属性
    addAttr(Function.prototype.toString, symbol, "function toString() { [native code] }");
    // globalThis
    // 可以理解为兼容浏览器和node等不同环境的 window/self/global
    globalThis.setNativeCode = function (func, funcName) {
        // 输出内容 按照手动传参、本身名称、空 优先级选择
        // 为函数添加一个符号属性 值为native code
        addAttr(func, symbol, `function ${funcName || func.name || ''}() { [native code] }`);
    }
})();

add = function (a, b) {
    return a + b;
}
console.log(add.toString());
// 调用setNativeCode
setNativeCode(add, "add");
console.log(add.toString());
console.log(Function.prototype.toString.toString());
console.log(Function.prototype.toString.call(Function.prototype.toString));
```

##### 函数重命名

```JS
/* 浏览器执行如下代码
Object.getOwnPropertyDescriptor(Document.prototype, "cookie")
// {enumerable: true, configurable: true, get: ƒ, set: ƒ}
Object.getOwnPropertyDescriptor(Document.prototype, "cookie").get
// ƒ cookie() { [native code] }
Object.getOwnPropertyDescriptor(Document.prototype, "cookie").get.name
// get cookie
Object.getOwnPropertyDescriptor(Document.prototype, "cookie").get.toString()
// function get cookie() { [native code] }
*/

funcRename = function (func, name) {
    Object.defineProperty(func, "name", {
        writable: false,
        configurable: true,
        enumerable: false,
        value: name,
    });
}

add = function something(a, b) {
    return a + b;
}

console.log(add.name);
funcRename(add, "add");
console.log(add.name);
funcRename(add, "Some Thing");
console.log(add.name);
```
##### Hook 函数

```JS
funcHook = function (func, funcInfo, isDebug, onEnter, onLeave, isExec) {
    // 原函数 函数属性 是否调试 执行前回调 执行后回调 是否执行原函数
    if (typeof func !== 'function') {
        return func;
    }
    if (funcInfo === undefined) {
        funcInfo = {};
        funcInfo.objName = "globalThis";
        funcInfo.funcName = func.name || '';
    }
    if (isDebug === undefined) {
        isDebug = false;
    }
    if (!onEnter) {
        onEnter = function (obj) {
            console.log(`FUNC: \`${funcInfo.objName}[${funcInfo.funcName}]\` START
ARGS: \`${JSON.stringify(obj.args)}\``);
        }
    }
    if (!onLeave) {
        onLeave = function (obj) {
            console.log(`FUNC: \`${funcInfo.objName}[${funcInfo.funcName}]\` END
RETURN: \`${JSON.stringify(obj.result)}\``);
        }
    }
    if (isExec === undefined) {
        isExec = true;
    }

    hookedFunc = function () {
        if (isDebug) {
            debugger;
        }
        let obj = {};
        obj.args = [];
        for (let i = 0; i < arguments.length; i++) {
            obj.args[i] = arguments[i];
        }
        onEnter.call(this, obj);
        let result;
        if (isExec) {
            result = func.apply(this, obj.args);
        }
        obj.result = result;
        onLeave.call(this, obj);
        return obj.result;
    }

    return hookedFunc;
}

function add(a, b) {
    result = a + b;
    console.log(`${a} + ${b} = ${result}`);
    return result;
}

add(1, 2);
hookedAdd = funcHook(add);
hookedAdd(1, 2);
```

##### 模块化/插件化

```JS
frmwk = {};

(function () {
    const $toString = Function.prototype.toString;
    const symbol = Symbol();
    const fakeToString = function () {
        return typeof this === 'function' && this[symbol] || $toString.call(this);
    }
    function addAttr(func, key, value) {
        Object.defineProperty(func, key, {
            writable: true,
            configurable: true,
            enumerable: false,
            value: value,
        })
    }
    delete Function.prototype.toString;
    addAttr(Function.prototype, "toString", fakeToString);
    addAttr(Function.prototype.toString, symbol, "function toString() { [native code] }");
    frmwk.setNativeCode = function (func, funcName) {
        addAttr(func, symbol, `function ${funcName || func.name || ''}() { [native code] }`);
    }
})();

frmwk.funcRename = function (func, name) {
    Object.defineProperty(func, "name", {
        writable: false,
        configurable: true,
        enumerable: false,
        value: name,
    });
}

frmwk.funcHook = function (func, funcInfo, isDebug, onEnter, onLeave, isExec) {
    if (typeof func !== 'function') {
        return func;
    }
    if (funcInfo === undefined) {
        funcInfo = {};
        funcInfo.objName = "globalThis";
        funcInfo.funcName = func.name || '';
    }
    if (isDebug === undefined) {
        isDebug = false;
    }
    if (!onEnter) {
        onEnter = function (obj) {
            console.log('\x1b[31m%s\x1b[0m', `[FUNC]: \`${funcInfo.objName}[${funcInfo.funcName}]\` START
ARGS: \`${JSON.stringify(obj.args)}\``);
        }
    }
    if (!onLeave) {
        onLeave = function (obj) {
            console.log('\x1b[31m%s\x1b[0m', `[FUNC]: \`${funcInfo.objName}[${funcInfo.funcName}]\` END
RETURN: \`${JSON.stringify(obj.result)}\``);
        }
    }
    if (isExec === undefined) {
        isExec = true;
    }

    hookedFunc = function () {
        if (isDebug) {
            debugger;
        }
        let obj = {};
        obj.args = [];
        for (let i = 0; i < arguments.length; i++) {
            obj.args[i] = arguments[i];
        }
        onEnter.call(this, obj);
        let result;
        if (isExec) {
            result = func.apply(this, obj.args);
        }
        obj.result = result;
        onLeave.call(this, obj);
        return obj.result;
    }
    frmwk.setNativeCode(hookedFunc, funcInfo.funcName);
    frmwk.funcRename(hookedFunc, funcInfo.funcName)
    return hookedFunc;
}

function add(a, b) {
    result = a + b;
    console.log(`${a} + ${b} = ${result}`);
    return result;
}

add(1, 2);
hookedAdd = frmwk.funcHook(add);
hookedAdd(1, 2);
console.log(hookedAdd.toString());
console.log(hookedAdd.name);
```

##### Hook Object

```JS
// hook的本质是替换属性描述符
// 不可配置的属性 无法修改其属性描述符 无法hook
frmwk.objHook = function (obj, objName, propName, isDebug) {
    let originDescriptor = Object.getOwnPropertyDescriptor(obj, propName);
    let targetDescriptor = {};
    if (!originDescriptor.configurable) {
        return;
    }
    targetDescriptor.configurable = true;
    targetDescriptor.enumerable = originDescriptor.enumerable;
    if (Object.hasOwn(originDescriptor, 'writable')) {
        targetDescriptor.writable = originDescriptor.writable;
    }
    if (Object.hasOwn(originDescriptor, 'value')) {
        let value = originDescriptor.value;
        if (typeof value !== 'function') {
            return;
        }
        let funcInfo = {
            "objName": objName,
            "funcName": propName,
        };
        targetDescriptor.value = frmwk.funcHook(value, funcInfo, isDebug);
    }
    if (Object.hasOwn(originDescriptor, 'get')) {
        let getFunc = originDescriptor.get;
        let funcInfo = {
            "objName": objName,
            "funcName": `get ${propName}`,
        };
        targetDescriptor.get = frmwk.funcHook(getFunc, funcInfo, isDebug);
    }
    if (Object.hasOwn(originDescriptor, 'set')) {
        let setFunc = originDescriptor.set;
        let funcInfo = {
            "objName": objName,
            "funcName": `set ${propName}`,
        };
        targetDescriptor.set = frmwk.funcHook(setFunc, funcInfo, isDebug);
    }
    Object.defineProperty(obj, propName, targetDescriptor);
}
```

##### hook 全局

```JS
v9ng.globalHook = function (isDebug) {
    for (const propName in Object.getOwnPropertyDescriptors(globalThis)) {
        const globalProp = globalThis[propName];
        if (typeof globalProp === 'function') {
            const propProtoType = typeof globalProp.prototype;
            if (propProtoType === 'object') {
                v9ng.protoHook(globalProp, isDebug);
            } else if (propProtoType === 'undefined') {
                let funcInfo = {
                    "objName": "globalThis",
                    "funcName": propName,
                }
                v9ng.funcHook(globalProp, funcInfo, isDebug);
            }
        }
    }
}
```

##### 封装Hook

```JS
v9ng = {};

(function () {
    const originToString = Function.prototype.toString;
    const symbol = Symbol();
    const targetToString = function () {
        return typeof this === 'function' && this[symbol] || originToString.call(this);
    }
    function setProp(func, key, value) {
        Object.defineProperty(func, key, {
            writable: true,
            configurable: true,
            enumerable: false,
            value: value,
        })
    }
    delete Function.prototype.toString;
    setProp(Function.prototype, "toString", targetToString);
    setProp(Function.prototype.toString, symbol, "function toString() { [native code] }");
    v9ng.funcNaturalize = function (func, funcName) {
        setProp(func, symbol, `function ${funcName || func.name || ''}() { [native code] }`);
    }
})();

v9ng.funcRename = function (func, funcName) {
    Object.defineProperty(func, "name", {
        writable: false,
        configurable: true,
        enumerable: false,
        value: funcName,
    });
}

v9ng.funcHook = function (originFunc, funcInfo, isDebug, onEnter, onLeave, isExec) {
    if (typeof originFunc !== 'function') {
        return originFunc;
    }
    if (funcInfo === undefined) {
        funcInfo = {};
        funcInfo.objName = "globalThis";
        funcInfo.funcName = originFunc.name || '';
    }
    if (isDebug === undefined) {
        isDebug = false;
    }
    if (!onEnter) {
        onEnter = function (obj) {
            console.log('\x1b[33m%s\x1b[0m', `[FUNC START]: \`${funcInfo.objName}\`->\`${funcInfo.funcName}\`
[ARGS]: \`${JSON.stringify(obj.args)}\``);
        }
    }
    if (!onLeave) {
        onLeave = function (obj) {
            console.log('\x1b[33m%s\x1b[0m', `[FUNC END]: \`${funcInfo.objName}\`->\`${funcInfo.funcName}\`
[RETURN]: \`${JSON.stringify(obj.result)}\``);
        }
    }
    if (isExec === undefined) {
        isExec = true;
    }

    targetFunc = function () {
        if (isDebug) {
            debugger;
        }
        let obj = {};
        obj.args = [];
        for (let i = 0; i < arguments.length; i++) {
            obj.args[i] = arguments[i];
        }
        onEnter.call(this, obj);
        let result;
        if (isExec) {
            result = originFunc.apply(this, obj.args);
        }
        obj.result = result;
        onLeave.call(this, obj);
        return obj.result;
    }
    v9ng.funcNaturalize(targetFunc, funcInfo.funcName);
    v9ng.funcRename(targetFunc, funcInfo.funcName)
    return targetFunc;
}

v9ng.propHook = function (obj, objName, propName, isDebug) {
    let originDescriptor = Object.getOwnPropertyDescriptor(obj, propName);
    let targetDescriptor = {};
    if (!originDescriptor.configurable) {
        return;
    }
    targetDescriptor.configurable = true;
    targetDescriptor.enumerable = originDescriptor.enumerable;
    if (Object.hasOwn(originDescriptor, 'writable')) {
        targetDescriptor.writable = originDescriptor.writable;
    }
    if (Object.hasOwn(originDescriptor, 'value')) {
        let propValue = originDescriptor.value;
        if (typeof propValue !== 'function') {
            return;
        }
        let funcInfo = {
            "objName": objName,
            "funcName": propName,
        };
        targetDescriptor.value = v9ng.funcHook(propValue, funcInfo, isDebug);
    }
    if (Object.hasOwn(originDescriptor, 'get')) {
        let getFunc = originDescriptor.get;
        let funcInfo = {
            "objName": objName,
            "funcName": `get ${propName}`,
        };
        targetDescriptor.get = v9ng.funcHook(getFunc, funcInfo, isDebug);
    }
    if (Object.hasOwn(originDescriptor, 'set')) {
        let setFunc = originDescriptor.set;
        let funcInfo = {
            "objName": objName,
            "funcName": `set ${propName}`,
        };
        targetDescriptor.set = v9ng.funcHook(setFunc, funcInfo, isDebug);
    }
    Object.defineProperty(obj, propName, targetDescriptor);
}

v9ng.protoHook = function (obj, isDebug) {
    let objProto = obj.prototype;
    let objName = obj.name;
    for (const prop in Object.getOwnPropertyDescriptors(objProto)) {
        v9ng.propHook(objProto, `${objName}.prototype`, prop, isDebug);
    }
}

v9ng.globalHook = function (isDebug) {
    for (const propName in Object.getOwnPropertyDescriptors(globalThis)) {
        const globalProp = globalThis[propName];
        if (typeof globalProp === 'function') {
            const propProtoType = typeof globalProp.prototype;
            if (propProtoType === 'object') {
                v9ng.protoHook(globalProp, isDebug);
            } else if (propProtoType === 'undefined') {
                let funcInfo = {
                    "objName": "globalThis",
                    "funcName": propName,
                }
                v9ng.funcHook(globalProp, funcInfo, isDebug);
            }
        }
    }
}
```

##### Proxy

```JS
let symbol = Symbol(123);

let person = {
    "username": "tom",
    1: 2,
    [symbol]: "symbol123",
}

person = new Proxy(person, {
    get: function (target, prop, reciver) {
        console.log(`[GET]: \`${prop.toString()}\``);
        let result = Reflect.get(target, prop, reciver);
        console.log(`[VALUE]: \`${result}\``);
        return result;
    }
})

for (const key in Object.getOwnPropertyDescriptors(person)) {
    console.log(person[key]);
}
console.log(person[symbol]);
```

##### 简单封装Proxy

```JS
v9ng = {};
v9ng.config = {};
v9ng.config.proxy = true;

v9ng.objProxy = function (obj, objName) {
    if (!v9ng.config.proxy) {
        return obj;
    }

    let handler = {
        get: function (target, prop, reciver) {
            console.log(`[GET]: \`${objName}[${prop.toString()}]\``);
            let result = Reflect.get(target, prop, reciver);
            console.log(`[VALUE]: \`${result}\``);
            return result;
        },
    };

    return new Proxy(obj, handler);
}

let symbol = Symbol(123);

let person = {
    "username": "tom",
    1: 2,
    [symbol]: "symbol123",
}

person = v9ng.objProxy(person, "person");

for (const key in Object.getOwnPropertyDescriptors(person)) {
    console.log(person[key]);
}
console.log(person[symbol]);
```

##### 封装Proxy

```JS
v9ng = {};
v9ng.config = {};
v9ng.config.enableProxy = true;

v9ng.objProxy = function (obj, objName) {
    if (!v9ng.config.enableProxy) {
        return obj;
    }

    let handler = {
        get: function (target, prop, reciver) {
            let result = Reflect.get(target, prop, reciver);
            try {
                if (result instanceof Object) {
                    console.log('\x1b[32m%s\x1b[0m', `[GET PROP]: \`${objName}[${prop.toString()}]\`
[TYPE]: ${Object.prototype.toString.call(result)}`);
                    result = v9ng.objProxy(result, `${objName}.${prop.toString()}`);
                } else {
                    console.log('\x1b[32m%s\x1b[0m', `[GET PROP]: \`${objName}[${prop.toString()}]\`
[VALUE]: \`${result}\``);
                }
            } catch (e) {
                console.log('\x1b[31m%s\x1b[0m', `[GET PROP]: \`${objName}[${prop.toString()}]\`
[ERROR]: ${e.message}`);
            }
            return result;
        },
        set: function (target, prop, value, reciver) {
            try {
                if (value instanceof Object) {
                    console.log('\x1b[32m%s\x1b[0m', `[SET PROP]: \`${objName}[${prop.toString()}]\`
[TYPE]: ${Object.prototype.toString.call(value)}`);
                    // TODO: detailed value
                } else {
                    console.log('\x1b[32m%s\x1b[0m', `[SET PROP]: \`${objName}[${prop.toString()}]\`
[VALUE]: \`${value}\``);
                }
            } catch (e) {
                console.log('\x1b[31m%s\x1b[0m', `[SET PROP]: \`${objName}[${prop.toString()}]\`
[ERROR]: ${e.message}`);
            }
            return Reflect.set(target, prop, value, reciver);
        },
        getOwnPropertyDescriptor: function (target, prop) {
            let result = Reflect.getOwnPropertyDescriptor(target, prop);
            try {
                console.log('\x1b[35m%s\x1b[0m', `[GET DESCRIPTOR]: \`${objName}[${prop.toString()}]\`
[TYPE]: ${Object.prototype.toString.call(result)}`);
                // optional
                // if (typeof result !== "undefined") {
                //     result = v9ng.objProxy(result, `${objName}.${prop.toString()}.PropertyDescriptor`);
                // }
            } catch (e) {
                console.log('\x1b[31m%s\x1b[0m', `[GET DESCRIPTOR]: \`${objName}[${prop.toString()}]\`
[ERROR]: ${e.message}`);
            }
            return result;
        },
        defineProperty: function (target, prop, descriptor) {
            try {
                console.log('\x1b[35m%s\x1b[0m', `[SET DESCRIPTOR]: \`${objName}[${prop.toString()}]\`
[VALUE]: \`${descriptor.value}\``);
            } catch (e) {
                console.log('\x1b[31m%s\x1b[0m', `[SET DESCRIPTOR]: \`${objName}[${prop.toString()}]\`
[ERROR]: ${e.message}`);
            }
            return Reflect.defineProperty(target, prop, descriptor);
        },
        apply: function (target, thisArg, args) {
            let result = Reflect.apply(target, thisArg, args);
            try {
                // TODO: add args log
                if (result instanceof Object) {
                    console.log('\x1b[34m%s\x1b[0m', `[FUNC APPLY]: \`${objName}\`
[RESULT TYPE]: ${Object.prototype.toString.call(result)}`);
                } else if (typeof result === 'symbol') {
                    console.log('\x1b[34m%s\x1b[0m', `[FUNC APPLY]: \`${objName}\`
[RESULT]: ${result.toString()}`);
                } else {
                    console.log('\x1b[34m%s\x1b[0m', `[FUNC APPLY]: \`${objName}\`
[RESULT]: ${result}`);
                }
            } catch (e) {
                console.log('\x1b[31m%s\x1b[0m', `[FUNC APPLY]: \`${objName}\`
[ERROR]: ${e.message}`);
            }
            return result;
        },
        construct: function (target, args, newTarget) {
            let result = Reflect.construct(target, args, newTarget);
            console.log(`[CONSTRUCTOR EXEC]: \`${objName}\`
[PROTO TYPE]: ${Object.prototype.toString.call(result)}`);
            return result;
        },
        deleteProperty: function (target, prop) {
            let result = Reflect.deleteProperty(target, prop);
            console.log(`[DELETE PROP]: \`${objName}[${prop.toString()}]\`
[RESULT]: \`${result}\``);
            return result;
        },
        has: function (target, prop) {
            let result = Reflect.has(target, prop);
            console.log(`[PROP EXIST]: \`${objName}[${prop.toString()}]\`
[RESULT]: \`${result}\``);
            return result;
        },
        ownKeys: function (target) {
            let result = Reflect.ownKeys(target);
            const keys = [];
            result.forEach(key => {
                keys.push(key.toString());
            });
            console.log(`[GET KEYS]: \`${objName}\`
[RESULT]: \`[${keys}]\``);
            return result;
        },
        getPrototypeOf: function (target) {
            let result = Reflect.getPrototypeOf(target);
            console.log(`[GET PROTO]: \`${objName}\`
[RESULT]: \`${result}\``);
            return result;
        },
        setPrototypeOf: function (target, proto) {
            let result = Reflect.setPrototypeOf(target, proto);
            console.log(`[SET PROTO]: \`${objName}\`
[TYPE]: ${Object.prototype.toString.call(proto)}`);
            return result;
        },
        preventExtensions: function (target) {
            let result = Reflect.preventExtensions(target);
            console.log(`[PREVENT EXTENSIONS]: \`${objName}\`
[RESULT]: \`${result}\``);
            return result;
        },
        isExtensible: function (target) {
            let result = Reflect.isExtensible(target);
            console.log(`[GET EXTENSIBLE]: \`${objName}\`
[RESULT]: \`${result}\``);
            return result;
        },
    };
    return new Proxy(obj, handler);
};


// let symbol = Symbol(123);
// let person = {
//     "username": "tom",
//     1: 2,
//     [symbol]: "symbol123",
//     "info": {
//         "age": 12,
//         "email": "tom@abc.com",
//     }
// };
// Object.defineProperty(person, "weight", {
//     configurable: false,
//     enumerable: true,
//     value: 60,
// })
// person = v9ng.objProxy(person, "person");
// delete person.weight;
// delete person.username;
// console.log("info" in person);
// console.log("height" in person);
// console.log(Object.keys(person));
// console.log(person.__proto__);
// let testObj = {};
// person.__proto__ = testObj;
// console.log(person[1], person[symbol], person.info.email, person.info.age);
// person.info = {
//     "age": 15,
//     "email": "abc@abc.com",
//     "notfound": "not found",
// }
// console.log(person.info.notfound);
// console.log(Object.getOwnPropertyDescriptors(person));
// person.height = 180;
// function add(a, b) {
//     return a + b;
// }
// add = v9ng.objProxy(add, "add");
// add(1, 2);
// function Address() {
// }
// Object.defineProperty(Address.prototype, Symbol.toStringTag, {
//     value: "AddressTest"
// })
// Address = v9ng.objProxy(Address, "Address");
// let addr = new Address();
```

##### 代理环境检测案例

```JS
// window is not defined
window = globalThis;
// Cannot read properties of undefined (reading 'getItem')
window = v9ng.objProxy(window, "window");
// [GET PROP]: `window[localStorage]`
// [VALUE]: `undefined`
window.localStorage = {};
// [GET PROP]: `window.localStorage[getItem]`
// [VALUE]: `undefined`
window.localStorage.getItem = function () {
    return null;
};
// document is not defined
document = {};
document = v9ng.objProxy(document, "document");
// [GET PROP]: `document[cookie]`
// [VALUE]: `undefined`
document.cookie = '';
// [GET PROP]: `window[navigator]`
// [VALUE]: `undefined`
window.navigator = {};

// [GET PROP]: `window.navigator[userAgent]`
// [VALUE]: `undefined`
// window.navigator.userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36";
// [GET DESCRIPTOR]: `window.navigator[userAgent]`
// [TYPE]: [object Object] // should be undefined
window.navigator.__proto__.userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36";

// [GET PROP]: `window.navigator[webdriver]`
// [VALUE]: `undefined`
// window.navigator.webdriver = false;
// [GET DESCRIPTOR]: `window.navigator[webdriver]`
// [TYPE]: [object Object] // should be undefined
window.navigator.__proto__.webdriver = false;

// [GET PROP]: `window[name]`
// [VALUE]: `undefined`
window.name = '';
// [GET PROP]: `window[Buffer]`
// [TYPE]: [object Function] // should be undefined
// node env
delete Buffer;
console.log('---- START ----');
```

##### vm2

```JS
// 调试断点：node_modules/vm2/lib/vm.js : 288
```

##### 通用转字符串

```JS
const commToString = function(data) {
    if (data === null) {
        return "null";
    }

    const dataType = typeof data;
    if (dataType === 'object' && data instanceof Object) {
        if (Array.isArray(data)) {
            let result = [];
            for (const element of data) {
                result.push(commToString(element));
            }
            return '[' + result.join(',') + ']';
        } else if (Object.prototype.toString.call(data) === '[object Arguments]') {
            let result = [];
            for (let i = 0; i < data.length; i++) {
                result.push(commToString(data[i]));
            }
            return result.join(' ');
        } else {
            const propKeys = Reflect.ownKeys(data);
            let result = [];
            for (const prop of propKeys) {
                result.push(`${commToString(prop)}:${commToString(data[prop])}`);
            }
            return '{' + result.join(',') + '}';
        }
    }

    switch (dataType) {
    case 'string':
        return `"${data}"`;

    case 'function':
        return `\`${data.toString()}\``;

    case 'undefined':
        return "undefined";

    default:
        try {
            return data.toString();
        } catch (e) {
            return "***UNKNOWN***";
        }
    }
};
```
##### 脱环境脚本

```JS
getDescriptorCode = function (obj, propKey, objName, instance) {
    const descriptor = Object.getOwnPropertyDescriptor(obj, propKey);
    let code = `{
        configurable: ${descriptor.configurable},
        enumerable: ${descriptor.enumerable},`;
    if (Object.hasOwn(descriptor, "writable")) {
        code += `
        writable: ${descriptor.writable},`;
    }
    if (Object.hasOwn(descriptor, "value")) {
        const value = descriptor.value;
        const valueType = typeof value;
        if (value instanceof Object) {
            if (valueType === 'function') {
                code += `
        value: function () {
            return v9ng.toolsFunc.funcDispatch(this, "${objName}", "${propKey}", arguments);
        },`;
            } else {
                console.log('\x1b[31m%s\x1b[0m', `[SPECIAL PROP]: \`${objName}[${propKey.toString()}]\`
[VALUE]: ${value}`);
                code += `
        value: {},`;
            }
        } else if (valueType === 'symbol') {
            code += `
        value: ${value.toString()},`;
        } else if (valueType === 'string') {
            code += `
        value: "${value}",`;
        } else {
            code += `
        value: ${value},`;
        }
    }
    if (Object.hasOwn(descriptor, "get")) {
        const get = descriptor.get;
        if (typeof get === 'function') {
            let defaultRet;
            try {
                defaultRet = get.call(instance);
            } catch (e) { }
            if (defaultRet === undefined || defaultRet instanceof Object) {
                code += `
        get: function () {
            return v9ng.toolsFunc.funcDispatch(this, "${objName}", "${propKey}_get", arguments);
        },`;
            } else {
                if (typeof defaultRet === 'string') {
                    code += `
        get: function () {
            return v9ng.toolsFunc.funcDispatch(this, "${objName}", "${propKey}_get", arguments, "${defaultRet}");
        },`;
                } else if (typeof value === 'symbol') {
                    code += `
        get: function () {
            return v9ng.toolsFunc.funcDispatch(this, "${objName}", "${propKey}_get", arguments, ${defaultRet.toString()});
        },`;
                } else {
                    code += `
        get: function () {
            return v9ng.toolsFunc.funcDispatch(this, "${objName}", "${propKey}_get", arguments, ${defaultRet});
        },`;
                }
            }
        } else {
            code += `
        get: undefined,`;
        }
    }
    if (Object.hasOwn(descriptor, "set")) {
        const set = descriptor.set;
        if (typeof set === 'function') {
            code += `
        set: function () {
            return v9ng.toolsFunc.funcDispatch(this, "${objName}", "${propKey}_set", arguments);
        },`;
        } else {
            code += `
        set: undefined,`;
        }
    }
    code += `
    }`;
    return code;
};

genCtorCode = function (ctor, instance) {
    // 构造函数
    const ctorName = ctor.name;
    let code = `(function () { // ${ctorName}
    ${ctorName} = function () {`;
    try {
        new ctor;
    } catch (e) {
        code += `
        return v9ng.toolsFunc.throwError('${e.name}', "${e.message}");`
    }
    code += `
    };
    v9ng.toolsFunc.ctorGuard(${ctorName}, "${ctorName}");`;
    // 原型链
    const proto = ctor.prototype;
    const protoProto = Object.getPrototypeOf(proto);
    const protoProtoName = protoProto[Symbol.toStringTag];
    if (protoProtoName !== undefined) {
        code += `
    Object.setPrototypeOf(${ctorName}.prototype, ${protoProtoName}.prototype);`;
    }
    // 属性
    const metaProperties = [
        "arguments",
        "caller",
        "length",
        "name",
        "prototype",
    ];
    for (const propKey in Object.getOwnPropertyDescriptors(ctor)) {
        if (metaProperties.indexOf(propKey) !== -1) {
            continue;
        }
        const descriptorCode = getDescriptorCode(ctor, propKey, ctorName, instance);
        code += `
    v9ng.toolsFunc.defineProperty(${ctorName}, "${propKey}", ${descriptorCode});`;
    }
    // 原型属性
    for (const propKey in Object.getOwnPropertyDescriptors(ctor.prototype)) {
        if (propKey === "constructor") {
            continue;
        }
        const descriptorCode = getDescriptorCode(ctor.prototype, propKey, `${ctorName}.prototype`, instance);
        code += `
    v9ng.toolsFunc.defineProperty(${ctorName}.prototype, "${propKey}", ${descriptorCode});`;
    }
    code += `
})();`;

    console.log(code);
    copy(code);
};

genObjCode = function (obj, objName, instance) {
    let code = `(function () { // ${objName}
    ${objName} = {};`;
    const protoName = Object.getPrototypeOf(obj)[Symbol.toStringTag];
    if (protoName !== undefined) {
        code += `
    Object.setPrototypeOf(${objName}, ${protoName}.prototype);`;
    }
    for (const propKey in Object.getOwnPropertyDescriptors(obj)) {
        const descriptorCode = getDescriptorCode(obj, propKey, objName, instance);
        code += `
    v9ng.toolsFunc.defineProperty(${objName}, "${propKey}", ${descriptorCode});`;
    }
    code += `
})();`;

    console.log(code);
    copy(code);
};
```

##### 收集鼠标移动轨迹

```JS
console.log('*** start ***');
let list = [];
let encodeFunc = function encodeFunc(resultList) {
    let result = [];
    for (let i = 0; i < 10; i++) {
        result.push(resultList[i].clientX);
        result.push(resultList[i].clientY);
        result.push(resultList[i].timeStamp);
    }
    let str = btoa(result.toString());
    console.log(str);
}
let mousemoveFunc = function mousemoveFunc(event) {
    const obj = {
        clientX: event.clientX,
        clientY: event.clientY,
        timeStamp: event.timeStamp,
        type: event.type,
    };
    list.push(obj);
}
let mousedownFunc = function mousedownFunc(event) {
    const obj = {
        clientX: event.clientX,
        clientY: event.clientY,
        timeStamp: event.timeStamp,
        type: event.type,
    };
    list.push(obj);
}
let mouseupFunc = function mouseupFunc(event) {
    const obj = {
        clientX: event.clientX,
        clientY: event.clientY,
        timeStamp: event.timeStamp,
        type: event.type,
    };
    list.push(obj);
    let len = list.length;
    let resultList = [];
    for (let i = len - 10; i < len; i++) {
        resultList.push(list[i]);
    }
    encodeFunc(resultList);
}
let setTimeoutcallBack = function setTimeoutcallBack() {
    console.log("*** timeout call ***");
    document.addEventListener("mousemove", mousemoveFunc);
    document.addEventListener("mousedown", mousedownFunc);
    document.addEventListener("mouseup", mouseupFunc);
}
let unloadFunc = function unloadFunc() {
    console.log("*** page unload ***");
    debugger ;
}
let loadFunc = function loadFunc() {
    console.log("*** page load ***");
}
setTimeout(setTimeoutcallBack, 0);
window.addEventListener("load", loadFunc);
window.addEventListener("unload", unloadFunc);
console.log('*** end ***');

// copy(commToString(mouseList.slice(0, 500)));
```

##### 补环境步骤

1. 补缺少的环境
2. 实现环境方法：mdn查参数、返回值、作用。好实现的实现：只对当前对象产生影响直接给this赋值或者取值即可，对全局有影响的最复杂需要观察使用情况按需补；不好实现的：没有返回值的方法有些有时不用补，有返回值且较为固定或易于模拟的有些有时不用完全实现，只给出输出即可。



