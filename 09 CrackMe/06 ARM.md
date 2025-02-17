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

## GDB调试ARM汇编

先安装 `gdb`