### CPU寄存器

16位CPU通常会有以下几种类型的寄存器：

1. **通用寄存器**：这些寄存器用于存储数据、地址、和临时计算结果。常见的有：

    - **AX** (Accumulator Register)：用于算术运算和数据处理。
    - **BX** (Base Register)：常用于存储数据段的基地址。
    - **CX** (Count Register)：用于计数操作，如循环计数。
    - **DX** (Data Register)：通常与输入输出操作有关。

```
64 bits :   rax     rbx    rcx    rdx 
32 bits :   eax     ebx    ecx    edx
16 bits :    ax      bx     cx     dx
 8 bits : ah al   bh bl  ch cl  dh dl
# 8 位寄存器上的“h”和“l”后缀代表高字节和低字节
```
    
2. **段寄存器**：用于存储内存段的基地址。常见的有：

    - **CS** (Code Segment)：存储代码段的起始地址。
    - **DS** (Data Segment)：存储数据段的起始地址。
    - **SS** (Stack Segment)：存储栈段的起始地址。
    - **ES** (Extra Segment)、**FS**、**GS**：可用于额外的数据存储。

3. **索引和指针寄存器**：用于存储内存地址。

    - **DI** (Destination Index Register)：用于存储目的地址，常用于字符串操作。
    - **SI** (Source Index Register)：用于字符串操作（例如，内存拷贝）中存储源地址。
    - **SP** (Stack Pointer Register)：指向栈顶。
    - **BP** (Stack Base Pointer Register)：指向当前栈帧的基地址。
    - **IP** (Index Pointer)：存储下一条指令的地址。

```
ES:EDI EDI DI : Destination index register
                Used for string, memory array copying and setting and
                for far pointer addressing with ES

DS:ESI EDI SI : Source index register
                Used for string and memory array copying

SS:EBP EBP BP : Stack Base pointer register
                Holds the base address of the stack
                
SS:ESP ESP SP : Stack pointer register
                Holds the top address of the stack

CS:EIP EIP IP : Index Pointer
                Holds the offset of the next instruction
                It can only be read
# CS:IP 的形式 表示 段基址+段内偏移
```

4. **标志寄存器**：用于存储处理器的状态标志。

    - **FLAGS** (Flag Register)：包含如零标志（**ZF**）、进位标志（**CF**）、符号标志（**SF**）等状态位，指示计算和控制状态。

```
Bit   Label    Desciption
---------------------------
0      CF      Carry flag
2      PF      Parity flag
4      AF      Auxiliary carry flag
6      ZF      Zero flag
7      SF      Sign flag
8      TF      Trap flag
9      IF      Interrupt enable flag
10     DF      Direction flag
11     OF      Overflow flag
12-13  IOPL    I/O Priviledge level
14     NT      Nested task flag
16     RF      Resume flag
17     VM      Virtual 8086 mode flag
18     AC      Alignment check flag (486+)
19     VIF     Virutal interrupt flag
20     VIP     Virtual interrupt pending flag
21     ID      ID flag
```

### 寻址方式

#### 实模式

实模式的"实"更多地体现在其地址是真实的物理地址，物理地址 = 段基址<<4 + 段内偏移。
实模式不支持内存保护（memory protection），多任务处理（multitasking）或 代码权限级别（code privilege levels）。寻址能力最大为2 ^ 20 = 1MB。

#### 保护模式

##### 分段式

**GDT** (全局描述符表)：全局描述表位于内存中。全局描述表的条目描述及规定了不同内存分区的各种特征，包括*段基地址*、*段大小*和*访问权限*等特权如可执行和可写等。 在 Intel 的术语中，这些内存区域被称为 **段** 。全局描述表用于内存地址的转换。所有程序的内存访问都需要用到GDT中的有关内存区域即x86内存分段的信息。访问GDT需要使用**segment selector**和**segment offset**。处理器使用segment selector为索引查找GDT的条目。当适当的条目找到后，处理器将会做一系列的检查，包括*检查segment offset尝试访问区间是否在此内存分段内*，*代码是否有权限访问此内存分段(检查分级保护域权限*等。为了加速全局描述表的访问，往segment寄存器里载入segment的值会使得GDT的特定条目被读入处理器内部的缓存中。之后的内存访问将会通过缓存进行处理。

**LDT** (本地描述符表)：每个任务/线程都可以有自己的 LDT，并且操作系统可以在每次任务切换时更改 LDT 寄存器（**LDTR**）。这意味着每个程序都可以有自己的内存段描述符列表，并使它们对其他程序保持私有。

**GDTR** 和 **LDTR**：分别指向 **GDT** 和 **LDT** 地址的寄存器。

![[DescriptorTable.png]]

![[DescriptorTable2.png]]

其中**DPL**为Descriptor Privilege level，表示描述符权限等级。分别为Ring 0到Ring 3，实际中一般只用到内核和应用。

段寄存器结构图：

2bit的权限+1bit的描述符表索引+剩下的索引号

![[SegmentSelector.png]]

##### 分页式

分段的办法很好，解决了程序本身不需要关心具体的物理内存地址的问题，但它也有一些不足之处：第一个就是内存碎片的问题。第二个就是内存交换的效率低的问题。

这里的内存碎片的问题共有两处地方：
外部内存碎片，也就是产生了多个不连续的小物理内存，导致新的程序无法被装载；
内部内存碎片，程序所有的内存都被装载到了物理内存，但是这个程序有部分的内存可能并不是很常使用，这也会导致内存的浪费。

分段式内存交换的时候，交换的是一个占内存空间很大的程序，这样整个机器都会显得卡顿。

分页是把整个虚拟和物理内存空间切成一段段固定尺寸的大小。这样一个连续并且尺寸固定的内存空间，我们叫页（Page）。在 Linux 下，每一页的大小为 *4KB*。虚拟地址与物理地址之间通过**分页表/页表**来映射。相对于分段，分页允许存储器存储于不连续的区块以维持文件系统的整齐。分页是磁盘和内存间传输数据块的最小单位。

**多级分页表**
倒排分页表为所有物理内存中的帧，建立一个映射列表。但是这个可能会比较浪费。相反，我们通过保持一些覆盖当前虚拟内存区块的分页表，建立一个包含虚拟页映射的分页表数据结构。比如，我们创建1024个小于4K的页，覆盖4M的虚拟内存。

这非常有用，因为通常虚拟内存的顶部和底部用于正在运行的进程，顶部通常用于文本和数据段，底部用于堆栈，空闲内存居中。多级分页表会保持少量较小分页表，仅覆盖内存顶部和底部，只有确实需要时候才创建新的。每种较小分页表被一个主分页表链接再一起，有效的创建一个树型数据结构。需要不只2级，可能有多级。

这种模式下，一个虚拟地址可以分成三部分：*根分页表/页目录的索引*，*子分页表的索引*，*子分页表偏移量/页内偏移*。多级分页表也叫做**分级分页表**。

**TLB** (Translation Lookaside Buffer)：**转译后备缓冲区**，或*页表缓存*、*转址旁路缓存*，用于改进虚拟地址到物理地址的转译速度。如果请求的虚拟地址在TLB中存在，CAM 将给出一个非常快速的匹配结果，之后就可以使用得到的物理地址访问存储器。如果请求的虚拟地址不在 TLB 中，就会使用标签页表进行虚实地址转换，而标签页表的访问速度比TLB慢很多。

### x86汇编

指令格式分为intel格式和AT&T格式，一般使用intel格式，比较简洁

```asm
jmp 0x1234
jmp dword ptr [ebx]
```

#### 比较指令

```asm
test eax, eax
cmp eax, eax
# 区别在于 cmp 进行的是减法操作 而 test 进行的是与运算
```

#### 跳转指令

1. 无条件跳转 `jmp`
2. Jump if Equal `je` 或 `jz` ZF=1
3. Jump if Not Equal `jne` 或 `jnz` ZF=0
4. Jump if Greater `jg` SF = OF and ZF = 0
5. Jump if Greater or Equal `jge` SF = OF or ZF = 1
6. Jump if Above `ja` CF = 0 and ZF = 0 (和`jg`基本相同，除了它执行无符号比较)
7. Jump if Above or Equal `jae` CF = 0 or ZF = 1
8. Jump if Lesser `jl` SF != OF
9. Jump if Less or Equal `jle` SF != OF or ZF = 1
10. Jump if Below `jb` CF = 1
11. Jump if Below or Equal `jbe` CF = 1 or ZF = 1
12. Jump if Zero `jz` ZF = 1
13. Jump if Not Zero `jnz` ZF = 0
14. Jump if Signed `js` SF = 1
15. Jump if Not Signed `jns` SF = 0
16. Jump if Carry `jc` CF = 1
17. Jump if Not Carry `jnc` CF = 0
18. Jump if Overflow `jo` OF = 1
19. Jump if Not Overflow `jno` OF = 0
20. Jump if counter register is zero
    `jcxz` CX = 0
    `jecxz` ECX = 0
    `jrcxz` RCX = 0

#### 函数调用指令

```asm
call proc
# 将跟在调用后面的指令的地址（通常是源代码中的下一行）推到堆栈顶部，然后跳转到指定位置

ret [val]
# 从栈中弹出返回地址 跳转到返回地址
# 如果函数有返回值，通常在返回之前，栈上会保存额外的局部变量或调用参数。ret 会调整栈指针，将栈恢复到调用函数之前的状态。此时，返回值通常已经放置在相应的寄存器中，调用者可以通过该寄存器获取结果。

# 32位 sysenter sysexit
# 64位 syscall  sysret
# 中断 iret
```
### 栈

x86中栈的增长方向由高地址向低地址。

### 分支/循环

#### if else 语句

变成一个比较和一条跳转指令

```asm
cmp     DWORD PTR _a$[ebp], 1
jne     SHORT $LN2@if_test
```

#### switch case 语句

变成一系列比较和条件跳转指令（称为跳转表）
break指令会变成代码块结尾的无条件跳转

```asm
        mov     DWORD PTR _msg$[ebp], 0
        mov     eax, DWORD PTR _status$[ebp]
        mov     DWORD PTR tv64[ebp], eax
        cmp     DWORD PTR tv64[ebp], 404      ; 00000194H
        jg      SHORT $LN9@switch_cas
        cmp     DWORD PTR tv64[ebp], 404      ; 00000194H
        je      SHORT $LN6@switch_cas
        cmp     DWORD PTR tv64[ebp], 200      ; 000000c8H
        je      SHORT $LN4@switch_cas
        cmp     DWORD PTR tv64[ebp], 301      ; 0000012dH
        je      SHORT $LN5@switch_cas
        jmp     SHORT $LN2@switch_cas
$LN9@switch_cas:
        cmp     DWORD PTR tv64[ebp], 502      ; 000001f6H
        je      SHORT $LN7@switch_cas
        jmp     SHORT $LN2@switch_cas
$LN4@switch_cas:
        mov     DWORD PTR _msg$[ebp], OFFSET $SG9731
        jmp     SHORT $LN2@switch_cas
$LN5@switch_cas:
        mov     DWORD PTR _msg$[ebp], OFFSET $SG9733
        jmp     SHORT $LN2@switch_cas
$LN6@switch_cas:
        mov     DWORD PTR _msg$[ebp], OFFSET $SG9735
        jmp     SHORT $LN2@switch_cas
$LN7@switch_cas:
        mov     DWORD PTR _msg$[ebp], OFFSET $SG9737
$LN2@switch_cas:
        mov     eax, DWORD PTR _msg$[ebp]
```

#### while 循环

无条件往回跳转

```asm
$LN2@while_test:
        cmp     DWORD PTR _n$[ebp], 0
        jle     SHORT $LN3@while_test
        mov     eax, DWORD PTR _n$[ebp]
        mov     DWORD PTR tv67[ebp], eax
        mov     ecx, DWORD PTR tv67[ebp]
        push    ecx
        push    OFFSET $SG9728
        call    _printf
        add     esp, 8
        mov     edx, DWORD PTR _n$[ebp]
        sub     edx, 1
        mov     DWORD PTR _n$[ebp], edx
        jmp     SHORT $LN2@while_test
$LN3@while_test:
```

#### for 循环

```asm
        mov     DWORD PTR _sum$[ebp], 0
        mov     DWORD PTR _i$1[ebp], 0
        jmp     SHORT $LN4@for_test
        ; 表达式1; int i = 0;
$LN2@for_test:
        mov     eax, DWORD PTR _i$1[ebp]
        add     eax, 1
        mov     DWORD PTR _i$1[ebp], eax
        ; 表达式3; i++
$LN4@for_test:
        cmp     DWORD PTR _i$1[ebp], 100      ; 00000064H
        jge     SHORT $LN3@for_test
        ; 表达式2; i < 100;
        mov     ecx, DWORD PTR _sum$[ebp]
        add     ecx, DWORD PTR _i$1[ebp]
        mov     DWORD PTR _sum$[ebp], ecx
        jmp     SHORT $LN2@for_test
$LN3@for_test:
```

### 函数调用约定

主要涉及两方面问题：
- 参数如何传递给被调用函数？
- 返回值如何传递给调用函数？

**调用约定**是一种定义子例程或函数如何从其调用者接收参数以及如何返回结果实现级别（低级）的方案。

不同调用约定的区别在于：

- 参数和返回值放置的位置（寄存器中；栈中；两者混合；其他内存结构 ）
- 参数传递的顺序或者单个参数不同部分的顺序（左到右；右到左；更复杂的顺序）
- 返回值如何从被调用方传递回调用方（栈上；寄存器中；堆上分配内容的引用）
- 调用前设置和调用后清理的工作，在调用者和被调用者之间如何分配。特别是栈帧的还原。
- 如何处理可变参数
- 是否以及如何传递描述参数的元数据
- 哪些寄存器保证在被调用方返回时具有与被调用方被调用时相同的值（preserved；volatile）
- 对于面向对象的语言，如何引用函数的对象
#### Windows函数调用约定

在 32 位 Windows 上，操作系统调用具有 stdcall 调用约定，而在大部分 C 程序使用 cdecl 调用约定。为了适应调用约定中的这些差异，编译器通常允许指定给定函数的调用约定的关键字。 函数声明将包括额外的平台特定的关键字，这些关键字指示要使用的调用约定。如果处理正确，编译器将生成代码，以适当的方式调用函数。

| 类型       | 含义            | 参数                                        | 返回值                      | 环境相关工作分配         |
| -------- | ------------- | ----------------------------------------- | ------------------------ | ---------------- |
| cdecl    | C declaration | 栈上传递；从右到左依次压入栈中                           | 寄存器中；整型或指针放在eax中，浮点型在st0 | 调用方在函数调用返回后清理堆栈  |
| stdcall  |               | 栈上传递；从右到左依次压入栈中                           | 寄存器中；整型或指针放在eax中，浮点型在st0 | 被调用方在函数调用返回前清理堆栈 |
| fastcall | 同__msfastcall | 将前两个参数（从左到右计算）传递到 ecx 和 edx，剩余的参数从右向左压入栈中 | 寄存器中；整型或指针放在eax中，浮点型在st0 | 被调用方在函数调用返回前清理堆栈 |
##### cdecl

```c
#include <stdio.h>

int __cdecl callee(int a, int b, int c) {
  return a*b+c;
}

int caller(void)
{
  return callee(1, 2, 3) + 5;
}

int main(){
  caller();
  return 0;
}
```

```asm
callee:
    ; 初始化栈帧
    push    ebp
    mov     ebp, esp
    ; 这时
    ; [ebp]   调用者栈帧
    ; [ebp+4] 函数返回地址
    mov     eax, DWORD PTR [ebp+8]  ; 参数a
    imul    eax, DWORD PTR [ebp+12] ; 参数b
    add     eax, DWORD PTR [ebp+16] ; 参数c
    pop     ebp
    ; 这里不清理栈 弹出函数返回地址 直接跳转
    ret     0

caller:
    ; 初始化栈帧
    ; (有的编译器会产出一个 'enter' 指令)
    push    ebp       ; 保存旧的栈帧
    mov     ebp, esp  ; 初始化新栈帧
    ; 逐个压入参数，从右到左
    ; 有的编译器可能会从堆栈指针中减去所需的空间，然后直接写入每个参数
    ; sub esp, 12      : 'enter' instruction could do this for us
    ; mov [ebp-4], 3   : or mov [esp+8], 3
    ; mov [ebp-8], 2   : or mov [esp+4], 2
    ; mov [ebp-12], 1  : or mov [esp], 1
    ; 'enter' 会做类似的操作
    push    3
    push    2
    push    1
    call    callee    ; 调用被调用函数 'callee'
    add     esp, 12   ; 从栈帧中移除调用参数
    add     eax, 5    ; eax中保存着返回值 这里直接用它进行下一步运算了
    ; 回复旧栈帧 即调用者的栈帧
    ; (有的编译器使用 'leave' 指令代替)
    ; 大多数调用约定都规定ebp由被调用者保存，即在调用被调用者后，ebp会被保留。因此，它仍然指向我们堆栈帧的起始位置。不过，我们确实需要确保被调用者不会修改（或恢复）ebp，因此我们需要确保它使用的调用约定会执行恢复旧调用帧的操作
    pop     ebp       ; restore old call frame
    ret               ; return
```

##### stdcall

```c
#include <stdio.h>

int __stdcall callee(int a, int b, int c) {
  return a*b+c;
}

int caller(void)
{
  return callee(1, 2, 3) + 5;
}

int main(){
  caller();
  return 0;
}
```

```asm
callee:
    ; 初始化栈帧
    push    ebp
    mov     ebp, esp
    ; 这时
    ; [ebp]   调用者栈帧
    ; [ebp+4] 函数返回地址
    mov     eax, DWORD PTR [ebp+8]  ; 参数a
    imul    eax, DWORD PTR [ebp+12] ; 参数b
    add     eax, DWORD PTR [ebp+16] ; 参数c
    pop     ebp
    ; 与cdecl不同的是 这里函数返回时 自行清理了参数占用的12字节的栈空间
    ret     12

caller:
    ; 初始化栈帧
    push    ebp
    mov     ebp, esp
    ; 传参并调用 callee
    push    3
    push    2
    push    1
    call    callee
    ; 栈已经由被调用函数清理完了 直接使用返回值即可
    add     eax, 5
    pop     ebp
    ret     0
```
##### fastcall

```c
#include <stdio.h>

int __fastcall callee(int a, int b, int c) {
  return a*b+c;
}

int caller(void)
{
  return callee(1, 2, 3) + 5;
}

int main(){
  caller();
  return 0;
}
```

```asm
callee:
    ; 初始化栈帧
    push    ebp
    mov     ebp, esp
    ; 相当于
    ; push eax; 第一个参数压入栈中
    ; push edx; 第二个参数压入栈中
    sub     esp, 8
    mov     DWORD PTR [ebp-8], edx
    mov     DWORD PTR [ebp-4], ecx
    ; 此时
    ; [ebp-8] 第二个参数
    ; [ebp-4] 第一个参数
    ; [ebp]   调用者栈帧
    ; [ebp+4] 函数返回地址
    ; [ebp+8] 第三个参数
    mov     eax, DWORD PTR [ebp-4] ; eax = a;
    imul    eax, DWORD PTR [ebp-8] ; eax *= b;
    add     eax, DWORD PTR [ebp+8] ; eax += c;
    mov     esp, ebp ; 这里相当于清理了栈上的前两个参数
    pop     ebp      ; 弹出原始栈帧
    ret     4        ; 弹出返回地址 清理剩余参数(这里只有1个)占用的栈空间

caller:
    ; 初始化栈帧
    push    ebp
    mov     ebp, esp
    push    3          ; (剩余的参数从右向左压入栈中，这里只有三个，第三个参数直接压入栈中)
    mov     edx, 2     ; 第二个参数通过 edx 寄存器传递
    mov     ecx, 1     ; 第一个参数通过 ecx 寄存器传递
    call    callee
    ; 调用后不需要清理堆栈 由被调用函数自行清理
    add     eax, 5
    pop     ebp
    ret     0


printnums:
	; 初始化栈帧
	push ebp
	mov ebp, esp
	sub esp, 0x08
	mov [ebp-0x04], ecx    ; x86下 ecx 传递第一个参数
	mov [ebp-0x08], edx    ; x86下 edx 传递第一个参数
	push [ebp+0x08]        ; arg3 is pushed to stack.
	push [ebp-0x08]        ; arg2 is pushed
	push [ebp-0x04]        ; arg1 is pushed
	push 0x8065d67         ; "The numbers you sent are %d %d %d"
	call printf            ; printf 函数默认是 cdecl 调用约定，因此它将以默认方式调用。
	; 自行清理栈
	add esp, 0x10
	nop
	leave
	retn 0x04
```

#### 栈帧布局

以32位为例

| 栈中位置                   | 保存数据                       |
| ---------------------- | -------------------------- |
| `[ebp]`                | 调用者栈帧                      |
| `[ebp+4]`              | 函数返回地址（即下一条指令的地址）          |
| `[epb+8]`              | 第1个参数（`__fastcall`对应第3个参数） |
| `[epb+12]`即`[epb+0Ch]` | 第2个参数（`__fastcall`对应第4个参数） |
| `[epb+16]`即`[ebp+10h]` | 第3个参数（`__fastcall`对应第5个参数） |
| `[epb+...]`            | 第...个参数                    |

函数常见开头结尾

```asm
push ebp
mov ebp, esp

...

mov     esp, ebp
pop     ebp
ret
```


### C++内存布局

#### 对齐

- 数据的起始地址必须是其自身大小的整数倍
- 结构体和对象的对齐值是其成员中占用内存最大的数据类型的大小

有虚函数的话，会包含一个虚表指针。

`#pragma pack(1)`它指示编译器在1字节边界上打包结构或联合成员，这意味着在成员之间不插入填充字节以满足自然对齐要求。

#### 栈帧填充

填充字节用 `0xCC` 主要是因为其在调试和内存管理中的方便性和传统。不同的编译器和环境可能会使用不同的填充字节，但 `0xCC` 已经成为一个广泛使用的标准。比起 `0x00`（空白），`0xCC` 具有更强的显眼性，便于定位问题。

#### 构造函数

函数名与类名相同
没有返回类型 （不是void）
创建对象时自动调用
用于对象初始化成员变量
可以被重载（多个参数类型不同的构造函数）
若没有写，编译器会提供一个默认构造函数

创建对象的两种方式

```cpp
User user(20, 1, "Tom"); // 栈上

User *ptrUser = new User(20, 1, "Tom"); // 堆上，栈上仅有指针
```

在成员函数中，可以通过this指针访问当前对象

```cpp
#include <stdio.h>

class User {
public:
  User(int a, char g, char *n) {
    this->age = a;
    this->gender = g;
    this->name = n;
    printf("User %s created.\n", name);
  }

public:
  int age;
  char gender;
  char *name;
};

int main() {
  User user1(30, 'M', "Bob");
  User *user2 = new User(25, 'F', "Alice");

  return 0;
}
```

汇编

```asm
_this$ = -4                                   ; size = 4
_a$ = 8                                       ; size = 4
_g$ = 12                                                ; size = 1
_n$ = 16                                                ; size = 4
User::User(int,char,char *) PROC                         ; User::User, COMDAT
        push    ebp
        mov     ebp, esp
        push    ecx
        mov     DWORD PTR _this$[ebp], ecx
        ; this->age = a;
        mov     eax, DWORD PTR _this$[ebp]
        mov     ecx, DWORD PTR _a$[ebp]
        mov     DWORD PTR [eax], ecx
        ; this->gender = g;
        mov     edx, DWORD PTR _this$[ebp]
        movzx   eax, BYTE PTR _g$[ebp]
        mov     BYTE PTR [edx+4], al
        ; this->name = n;
        mov     ecx, DWORD PTR _this$[ebp]
        mov     edx, DWORD PTR _n$[ebp]
        mov     DWORD PTR [ecx+8], edx
        ; printf("User %s created.\n", name);
        mov     eax, DWORD PTR _this$[ebp]
        mov     ecx, DWORD PTR [eax+8]
        push    ecx
        push    OFFSET `string'
        call    _printf
        add     esp, 8
        mov     eax, DWORD PTR _this$[ebp]
        mov     esp, ebp
        pop     ebp
        ret     12                                        ; 0000000cH
User::User(int,char,char *) ENDP                         ; User::User

$SG5675 DB        'Bob', 00H
$SG5677 DB        'Alice', 00H
_user1$ = -40                                     ; size = 12
_user2$ = -28                                     ; size = 4
; User user1(30, 'M', "Bob");
        push    OFFSET $SG5675                      ; 'Bob'
        push    77                                  ; 'M'
        push    30                                  ; 30
        lea     ecx, DWORD PTR _user1$[ebp]         ; this指针加载到ecx寄存器中
        call    User::User(int,char,char *)         ; User::User
        npad    1

; User *user2 = new User(25, 'F', "Alice");
        ; 先分配内存12字节=0x0C
        push    12                                  ; 0000000cH
        call    void * operator new(unsigned int)                            ; operator new
        add     esp, 4
        mov     DWORD PTR $T3[ebp], eax
        mov     DWORD PTR __$EHRec$[ebp+8], 0
        cmp     DWORD PTR $T3[ebp], 0
        je      SHORT $LN3@main
        push    OFFSET $SG5677                      ; 'Alice'
        push    70                                  ; 'F'
        push    25                                  ; 25
        mov     ecx, DWORD PTR $T3[ebp]             ; this指针加载到ecx寄存器中
        call    User::User(int,char,char *)                    ; User::User
        mov     DWORD PTR tv82[ebp], eax
        jmp     SHORT $LN4@main
$LN3@main:
        mov     DWORD PTR tv82[ebp], 0
$LN4@main:
        mov     eax, DWORD PTR tv82[ebp]
        mov     DWORD PTR $T2[ebp], eax
        mov     DWORD PTR __$EHRec$[ebp+8], -1
        mov     ecx, DWORD PTR $T2[ebp]
        mov     DWORD PTR _user2$[ebp], ecx
```

#### 析构函数

函数名与类名相同，前面多了一个`~`符号
用于对象清理工作
自动调用
若没有写，编译器会提供一个默认构造函数

#### 虚函数

有些类似接口的概念。
不同的类有各自虚函数的实现。可以通过同一个父类调用。

### PE文件格式

PE格式和ELF格式都源自Unix中的通用对象文件格式 (COFF) 格式

peHeader
    dosHeader（定长0x40=64）
        signature 以'MZ'开头 微软编译器早期作者姓名首字母
        结尾4字节是coffHeaderPointer 指向coff头
    dosStub（不定长）调⽤21号中断的9号功能：向屏幕输出⼀个字符串 "This program cannot be run in DOS mode."
coffHeader
    signature 50 45 00 00 即"PE\x00\x00"
    architecture 2字节枚举值 运行平台
    numberOfSections 2字节 section数目
    timeDateStamp 4字节 文件创建时间
    pointerToSymbolTable（弃用了）4字节
    numberOfSymbols（弃用了）4字节
    sizeOfOptionalHeader 2字节 可选头大小
    characteristics 2字节 属性 每bit有其含义
    OptionalHeader 可选头 其大小由sizeOfOptionalHeader定义 名为可选头实际中几乎必用
        magic 2字节枚举值 指示PE文件的类型 常见值为0x10B（32位）和0x20B（64位）
        majorLinkerVersion 1字节 链接器主版本
        minorLinkerVersion 1字节 链接器次版本
        sizeOfCode 代码段（.text）的大小
        sizeOfInitializedData 已初始化的数据段（如静态变量）的大小
        sizeOfUninitializedData 未初始化数据段的大小。通常为.bss段
        **addressOfEntryPoint** 程序的入口点地址 相对于**imageBase**的偏移
        baseOfCode 代码段的起始地址，在加载到内存时使用
        **imageBase**（64位）/baseOfData+imageBase 程序在内存中加载的基地址，实际未必
        **virtualSectionAlignment** 内存中各个节区的对齐方式（两个对齐值不同）
        **rawSectionAlignment** PE文件在磁盘上的节区对齐方式（两个对齐值不同）
        majorOperatingSystemVersion
        minorOperatingSystemVersion
        majorImageVersion
        minorImageVersion
        majorSubsystemVersion
        minorSubsystemVersion
        win32VersionValue
        sizeOfImage
        sizeOfHeaders
        checksum 文件的校验和，用于文件完整性验证。
        subsystem
        **dllCharacteristics** pe文件属性
        ... stack and heap sth. ...
        loaderFlags
        **numberOfRVAsAndSizes** 指定数据目录中条目的数量 一般值为16=0x10
        **directories** 数据目录指针（存放导入表、导出表、资源表、调试信息等）。一般是16项，每项包括RVA和size两个字段，都是4字节。最后一项暂时没有使用，通常8字节全为0。
sectionsTable 每一项40字节 结构固定
    sectionName 8字节 节区名
    virtualSize 4字节 节区在内存中所占的实际大小，可能与节区在文件中的大小不同
    **rva** 4字节 节区在内存中的相对起始地址
    sizeOfRawData 4字节 节区在PE文件中的实际数据大小
    **ptrRawData** 4字节 节区数据在PE文件中的偏移地址
    ptrRelocations 4字节 节区重定位表的偏移地址
    ptrLineNumbers 4字节 该字段用于调试信息，指示源代码行号的映射关系
    numberOfRelocations 2字节 节区中重定位条目的数量
    numberOfLineNumbers 2字节 节区中行号条目的数量
    characteristics 4字节 节区的属性标志
sections


RVA（相对虚拟地址）是PE文件中各个部分（如代码段、数据段、资源表等）在内存中加载后的地址，通常是相对于程序加载基地址（Image Base）的偏移量。通过RVA，操作系统可以在运行时定位文件的各个部分。
IAT（导入地址表）

手动查看导入表的示例：
1、可选头中最后的数据目录里，第二项的rva 0x003BA1A4
2、节表中查看第一步得到的rva，在哪个节区的rva范围里。比如这里查到在 `.rdata` 中，其rva为0x00282000，其ptrRawData为 0x00280C00
3、计算磁盘和内存地址的偏差，(节区rva - 节区ptrRawData) = *0x1400*
4、导入表在文件中的地址= rva - *0x1400* = 0x003B8DA4
之后想要通过rva找其在文件中的地址，都要进行类似的减偏差操作（磁盘和内存对齐值不同导致的）。

导入表结构：每项40字节
    lookupTableRVA 0x003BA420 减偏差后 3B9020 指向结构
    timeDateStamp
    forwarderChain
    dllNameRVA 0x003BA6FE 减偏差后 3B92FE 字符串指针指向DLL名
    addressTableRVA 0x00282160 减偏差后 280D60 指向结构

lookupTableRVA **数组** 8字节全为空隔开
    4字节nameTableRVA *0x003BA6F0*
    3个空子节+1字节ordinalFlag
    

addressTableRVA **数组** 8字节全为空隔开
    4字节nameTableRVA *0x003BA6F0* 目前是一样的 执行时会变成**IAT** 导入到内存的实际地址
    3个空子节+1字节ordinalFlag

*0x003BA6F0* 减偏差后 3B92F0 **不是数组** 00结尾
    两字节hint通过序号指定要导入的函数
    字符串以00结尾

导出表结构
exportFlags 4字节 属性
exportTimeDateStamp 4字节 时间戳
majorVersion 2字节 主版本
minorVersion 2字节 次版本
imageNameRVA 导出库名rva 要减偏差
ordinalBase 导出函数编号的base基数
addressesAmount 函数（也就是函数的地址）总数
namePointersAmount 函数名（即以函数名导出而不是编号的函数）总数
addressTableRVA 地址表rva 要减偏差
namePointerTableRVA 函数名列表的rva 要减偏差
ordinalTableRVA 序号表rva 包含了每个导出符号的序号
![[peFormat.png]]