### 编译过程

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