## ARM 可执行文件生成过程

```shell
# 预编译
aarch64-linux-android30-clang++ -E hello.c -o hello.i
# 编译
aarch64-linux-android30-clang++ -S hello.i -o hello.s
# 汇编
aarch64-linux-android30-clang++ -c hello.s -o hello.o
# 链接
aarch64-linux-android30-clang++ hello.o -o hello
```

```
adb push hello /data/local/tmp/

# cd /data/local/tmp
# chmod +x hello
# ./hello
```

## GDB调试ARM汇编

先安装 `gdb-multiarch` 和 `gef`

```
/data/local/tmp # ./gdbserver 0.0.0.0:24486 ./hello
```

```shell
adb forward tcp:24486 tcp:24486

gdb-multiarch
# 连接远程端口
gef➤  gef-remote 127.0.0.1 24486

# 给指定函数下断点
gef➤  b main
# 通过地址下断点
gef➤  b *0x55555566E4

# 继续运行
gef➤  c

# 汇编单步
gef➤  ni

# 退出
gef➤  q
```

zr 是一个特殊寄存器，它的值总是 0
w8 寄存器实际上是 x8 寄存器的低 32 位

x29 通常用作帧指针（Frame Pointer, FP），用于指向当前栈帧的开始位置。
x30 通常用作链接寄存器（Link Register, LR），用于保存返回地址，在函数调用时保存函数返回的位置。
stp 指令用于 存储寄存器的值到内存。它的全称是 "Store Pair"
stur 指令用于 将寄存器的值存储到内存 中，它是 "Store Register" 的缩写
b 跳转
bx 切换状态 跳转
bl 外部跳转
blx 从thumb调用arm（或arm调thumb） 用x来切换状态


```assembly
	.text
	.file	"hello.c"
	.globl	main                            // -- Begin function main
	.p2align	2
	.type	main,@function
main:                                   // @main
	.cfi_startproc
// %bb.0:
	sub	sp, sp, #32  // sp(0x0000007ffffff0b0) 减 0x20 -> 0x0000007ffffff090
	stp	x29, x30, [sp, #16]             // 将 x29 存储到 [sp + 0x10] 位置，将 x30 存储到 [sp + 0x18] 位置

// x29 : 0x0000007ffffff0b0
// x30 : 0x0000007fbe046e5c

	add	x29, sp, #16 // x29 = sp + 0x10 -> 0x0000007ffffff0a0
	.cfi_def_cfa w29, 16
	.cfi_offset w30, -8
	.cfi_offset w29, -16
	mov	w8, wzr // w8 = 0
	str	w8, [sp, #8]                    // 将 w8 寄存器的值(0)存储到 栈指针 sp 指向的地址偏移 8 字节的位置
	stur	wzr, [x29, #-4] // 将x29寄存器地址偏移-4处的4字节清零
	adrp	x0, .L.str // 将 0x5555555000 地址所在页面的基地址加载到 x0 寄存器中，低 12 位被清除为 0。
	add	x0, x0, :lo12:.L.str // x0 = x0 + 0x560
	bl	printf
	ldr	w0, [sp, #8]                    // 4-byte Folded Reload
	ldp	x29, x30, [sp, #16]             // 16-byte Folded Reload
	add	sp, sp, #32
	ret
.Lfunc_end0:
	.size	main, .Lfunc_end0-main
	.cfi_endproc
                                        // -- End function
	.type	.L.str,@object                  // @.str
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
	.asciz	"Hello, world!\n"
	.size	.L.str, 15

	.ident	"Android (9352603, based on r450784d1) clang version 14.0.7 (https://android.googlesource.com/toolchain/llvm-project 4c603efb0cca074e9238af8b4106c30add4418f6)"
	.section	".note.GNU-stack","",@progbits
```

## 常用指令

`mla x0, x1, x2, x3` 表示 `x0 = (x1 * x2) + x3`
`eor x0, x1, x2` 表示 `x0 = x1 ^ x2`
`bic x0, x1, x2` 表示 `x0 = x1 & (~x2)`
`orr x0, x1, x2` 表示 `x0 = x1 | x2`
`str x0, [x1]` 表示 `*x1 = x0`
`strb x0, [x1]` 表示 `*x1 = (u8)x0`
`strh x0, [x1]` 表示 `*x1 = (u16)x0`
`ldr x0, [x1]` 表示 `x0 = *x1`
`ldrb x0, [x1]` 表示 `x0 = *(u8*)x1`
`ldrh x0, [x1]` 表示 `x0 = *(u16*)x1`
`push {r0, r1, r2}` 表示 把寄存器 r0、r1 和 r2 的值压入堆栈中 是 `stmfd` 的别名
`stm sp!, {r0, r1, r2}` 将寄存器 r0、r1 和 r2 的值存储到堆栈中（sp 指向的内存位置），并且 sp 会自动递减
`pop {r0, r1, r2}` 从堆栈中恢复寄存器 r0、r1 和 r2 的值 是 `ldmfd` 的别名
`ldm sp!, {r0, r1, r2}` 从堆栈（sp）加载数据到寄存器 r0、r1 和 r2，并且 sp 会自动增加

IT 指令通常用于执行多条条件指令，只有在满足特定条件时才会执行。这是 ARM 中的一种优化方式，避免了频繁的分支跳转。
## 寻址方式

### 立即数寻址（Immediate Addressing）

直接在指令中指定一个常数值（立即数）

```
add r0, r1, #0x10  ; r0 = r1 + 16
```

### 寄存器寻址（Register Addressing）

操作数直接来自寄存器

```
add r0, r1, r2  ; r0 = r1 + r2
```

### 基址寻址（Base Register Addressing）

通过寄存器的值加上一个偏移量 来访问内存

```
ldr r0, [r1, #4]  ; r0 = *(r1 + 4)
```

### 偏移寻址（Offset Addressing）

类似于基址寻址，但偏移量可以是一个常量或者由另一个寄存器提供

```
ldr r0, [r1, r2]  ; r0 = *(r1 + r2)
```

### 预加/预减寻址（Pre-indexed/Pre-decremented Addressing）

在进行内存访问之前，首先对基址寄存器进行加法或减法操作。

```
ldr r0, [r1, #4]!  ; r1 += 4; r0 = *r1;
```

### 后加/后减寻址（Post-indexed/ Post-decremented Addressing）

在内存访问后，基址寄存器的值才进行加法或减法操作。

```
ldr r0, [r1], #4  ; r0 = *r1; r1 += 4;
```

### 堆栈寻址（Stack Addressing）

```
push {r0, r1}
pop {r0, r1}
```

### 相对寻址（PC-relative Addressing）

基于程序计数器（pc）的值，偏移量是相对于当前指令位置的。通常用于跳转和分支指令。

```
b 0x1000   ; 跳转到 0x1000 地址
```

### 嵌套寻址（Register Indirect Addressing）

使用寄存器的值来作为内存地址

```
ldr r0, [r1]  ; r0 = *r1
```

### 位移寻址（Shift Addressing）

通过对寄存器中的值进行位移来计算地址。位移寻址常常用于数组元素的计算，尤其是在数组元素的大小为 4 字节时。

```
ldr r0, [r1, r2, lsl #2]  ; r0 = *(r1 + (r2 << 2))
```

## 指令编码

参考手册

## 调用约定

前 8 个参数通过寄存器 x0 到 x7 传递。
超过 8 个参数通过栈传递。
返回值存储在寄存器 x0 中。
浮点数参数通过 s0 到 s7 或 d0 到 d7 寄存器传递。
栈对齐要求为 16 字节。
对于函数调用中的 "callee-saved" 寄存器（x19 到 x28），需要被调用者保存和恢复。