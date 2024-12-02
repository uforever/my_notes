```
需要学会：
1、确定偏移量
  导致程序崩溃的（那个函数的）retn指令执行前（可以通过下硬件断点）
  r/esp寄存器指向的值（堆栈地址上的值）
  也就是 程序崩溃时r/eip寄存器的值
  可以通过gdb或者脚本time.sleep()期间使用IDA调试attach上去

  msf-pattern_create -l 200
  msf-pattern_offset -l 200 -q 6341356341346341

2、知道函数调用是传参的方式
  寄存器作为参数 和 栈传递参数 的不同以及利用上的区别
  寄存器上的参数要在调用前设置 需要查找是否有合适的gadget 通常是pop|ret
  栈上的值作为参数 位于调用后面 但不是第一个位置 第一个位置是返回地址 从第二个开始设置
  需要注意的是 system() 在x86和x64上的传参方式并不相同
  x86上通常使用栈传递参数 而x64上通常使用寄存器传参
  具体使用的寄存器顺序可以参考
  https://en.wikipedia.org/wiki/X86_calling_conventions#System_V_AMD64_ABI

3、理解.text .plt .got.plt段的区别
  一定要能够区分 system_plt system_got_plt 和 实际system_addr 的区别
  实际system_addr 就是libc实际加载后 system_got_plt 地址上的值（其本身也是一个地址/偏移）

杂项：
查看动态符号表 是否使用了libc中的函数
  objdump -R rop
  IDA手动分析也行

搜索gadgets
ROPgadget --binary rop --only 'pop|ret'
ROPgadget --binary rop --only 'pop|ret' | grep eax

搜索字符串
ROPgadget --binary ret2libc2 --string '/bin/sh'

libc数据库网站查找匹配的版本和关键的偏移量
https://libc.rip/
一般来说只用后5、6位就可以了

动态获取libc地址
需要一个输出函数(plt段上)
其后一定跟着main/_start函数(text段上的) 这样可以保证程序正常运行 能够二次溢出
可以的话尽量用_start 返回到main的话还要考虑栈平衡的问题
再根据需要为输出函数设置参数 看具体是通过栈传递还是通过寄存器传递
寄存器提前设置 需要对应的gadget支撑 不一定每个寄存器都要设置 有时现有的值就能用
栈上的值在函数地址(plt)、返回地址(text)后设置
要输出位于.got.plt段上的地址 作为指针
需要注意的是这个值有时候需要加1 因为实际地址可能以00结尾 读不出内容
```