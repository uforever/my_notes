### 抓包

1. 证书（安装到系统CA目录）

```Shell
# 查看证书信息
# PEM
openssl x509 -in ca.crt -text -noout
# DER
openssl x509 -inform DER -in ca.crt -text -noout

# DER格式需要先进行转换
# PEM格式不需要
openssl x509 -inform DER -in cacert.der -out cacert.pem

# 提取公钥
openssl x509 -in ca.crt -pubkey -noout -out ca.pub

# 反向转换
openssl x509 -outform der -in yak.pem -out yak.der

# 计算哈希
openssl x509 -subject_hash_old -in cacert.pem | head -1

# 重命名
mv cacert.pem 9a5ba575.0

# 复制到系统目录
adb root
adb remount
adb push 9a5ba575.0 /sdcard/
adb shell
z2_plus:/ # mv /sdcard/9a5ba575.0 /system/etc/security/cacerts/
z2_plus:/ # chmod 644 /system/etc/security/cacerts/9a5ba575.0
z2_plus:/ # reboot
```

### Root检测

[Shamiko](https://github.com/LSPosed/LSPosed.github.io)

```Shell
# 推荐白名单模式运行 如需分配root权限 需关闭后重启
adb shell
touch /data/adb/shamiko/whitelist
ls -l /data/adb/shamiko/whitelist
# -rw-r--r-- 0B
# 如果不是就改
chmod 644 /data/adb/shamiko/whitelist
```

[Hide-My-Applist](https://github.com/Dr-TSNG/Hide-My-Applist) ：推荐黑名单模式运行 先创建模板再选择应用

[ApplistDetector](https://github.com/Dr-TSNG/ApplistDetector) ：检测隐藏效果的APP


### 禁止网络检查

```Shell
adb shell 'settings put global captive_portal_detection_enabled 0'
adb shell 'settings put global captive_portal_server localhost'
adb shell 'settings put global captive_portal_mode 0'
```

### 设置代理

```Shell
adb shell 'settings put global http_proxy 10.26.14.222:7890'
adb shell 'settings put global http_proxy :0'

adb shell 'settings put global all_proxy 10.26.14.222:8444'
adb shell 'settings put global all_proxy :0'
```

### 启动程序

```Shell
adb shell 'am start org.lsposed.manager/.ui.activity.MainActivity'
```

### 反编译

```Shell
apktool d app-release.apk -o outdir
```

### 破解思路

1. 错误提示信息是关键，通常属于字符串资源，可能硬编码，也可能引用自 `res/values/strings.xml` 文件，其中的内容在打包时会进入 `resources.arsc` 文件。如果反编译成功，就能被解密出来。以 `abc_` 开头的字符串是系统默认生成的，其它都是程序中使用的字符串。搜索错误提示，可以看到其对应的 `name`  ，再搜索 `name` 可以在 `public.xml` 中找到其对应的 `id` ，再搜索其 `id` ，看看是否出现在 `smali` 代码中。


### 回编译

```Shell
apktool b outdir
```

### 签名

```Shell
signapk outdir/dist/app-release.apk
```

### 杂项

#### class2dex

```Shell
dx --dex --output=Hello.dex Hello.class
```

#### dex2smali

```Shell
baksmali -o outdir hello.dex
```

#### 查看Java字节码

```Shell
javap -c -classpath . Hello
```

#### 查看Dalvik字节码

```Shell
dexdump -d Hello.dex
```

#### smali类型描述符

| 类型 | 含义 |
| -- | -- |
| v | void |
| Z | boolean |
| B | Byte |
| S | Short |
| C | Char |
| I | Int |
| J | Long |
| F | Float |
| D | Double |
| L | 类 |
| \[ | 数组 |

例子：
1. `[Ljava/lang/String;` 表示Java中的字符串数组
2. `Lpackage/name/ObjectName;->MethodName(III)Z` 表示对象的某个方法，参数是三个整型，返回一个布尔值
3. `method(I[[IILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;` 对应的 `Java` 源码应为：`String method(int, int[][], int, String, Object[])`
4. `Lpackage/name/ObjectName;->FieldName:Ljava/lang/String;` 表示类型、字段名和字段类型

#### Dalvik指令集

后缀表示操作数的类型，如

```
-boolean
-byte
-char
-short
-int
-long
-float
-double
-object
-string
-class
-void
```

| 指令 | 含义 |
| -- | -- |
| `nop` | 空指令 |
| `move d, s` | 将s(source)的值赋给d(destination) |
| `move-result d` | 将上一个invoke类型指令的结果赋给d |
| `move-exception e` | 将运行时发生的异常赋给e |
| `return-void` | 返回 |
| `return r` | 返回r(result)的值 |
| `const c, v` | 将v(value)的值赋给c(const) |
| `monitor-enter m` | 给m(mutex)上锁 |
| `monitor-exit m` | 释放m |
| `check-cast o c` | 将o(object)的类型转换为c(class) |
| `instance-of z o c` | o是否可以转换为c?1:0 值赋给z |
| `new-instance o c` | 创建一个c类的o |
| `array-length l a` | 计算a(array)的长度赋给l(length) |
| `new-array a l t` | 创造指定t(type)和l(length)的数组 |
| `filled-new-array {i1, i2, i3}, t` | 填充数组 |
| `filled-new-array/range {i1 ... in}, t` | 填充数组 |
| `fill-array-data a, d` | 填充数组 |
| `arrayop v, a, i` | 设置数组a的i位置的值为v |
| `throw e` | 抛出异常 |
| `goto o` | 无条件跳转偏移量o(offset) |
| `packed-switch v, l` | 分支跳转比较v(value)和分支表l(list) |
| `if-eq v1, v2, offset` | 等于 |
| `if-ne v1, v2, offset` | 不等于 |
| `if-lt v1, v2, offset` | 小于 |
| `if-gt v1, v2, offset` | 大于 |
| `if-le v1, v2, offset` | 小于等于 |
| `if-ge v1, v2, offset` | 大于等于 |
| `if-eqz v, offset` | 等于0 |
| `if-nez v, offset` | 不等于0 |
| `if-ltz v, offset` | 小于0 |
| `if-gtz v, offset` | 大于0 |
| `if-lez v, offset` | 小于等于0 |
| `if-gez v, offset` | 大于等于0 |
| `cmp r, v1, v2` | 比较v1v2结果放到r >1 =0 <-1 |
| `cmpl r, v1, v2` | >-1 =0 <1 |
| `cmpg r, v1, v2` | >1 =0 <-1 |
| `iop/sop` | 字段操作 |
| `invoke {p1, p2, p3}, m` | 方法调用 |
| `a-to-b r, v` | 将值v的格式从b转换到a结果保存到r |
| `neg r v` | 求补 |
| `not r v` | 求反 |
| `add r, v1, v2` | 加 |
| `sub r, v1, v2` | 减 |
| `mul r, v1, v2` | 乘 |
| `div r, v1, v2` | 除 |
| `rem r, v1, v2` | 模 |
| `and r, v1, v2` | 与 |
| `or r, v1, v2` | 或 |
| `xor r, v1, v2` | 异或 |
| `shl r, v1, v2` | 左移 |
| `shr r, v1, v2` | 右移 |
| `ushr r, v1, v2` | 无符号右移 |


### 日志插桩

```
invoke-static {vXX}, Lcom/mtools/LogUtils;->v(Ljava/lang/Object;)V
```
### Frida逆向

```shell
# 进程列表
frida-ps -U
# 应用列表
frida-ps -Uai
# 运行中的应用
frida-ps -Ua
# 列出所有设备
frida-ls-devices
# 跟踪本机API
frida-trace -U Twitter -i "*URL*"
# attach模式注入
frida -U -l hook.js com.example.demo
```

objection

```shell
# 连接应用
objection -g "APP名" explore
# 列出类名 结果很长 一般不用 用搜索
android hooking list classes
# 搜索类名
android hooking search classes emulator
# 列出类的方法
android hooking list class_methods android.hardware.display.DisplayManager
# Hook 方法 监听参数、调用堆栈、返回值
android hooking watch class_method com.bonc.moveportal.util.CheckEmulatorUtil.a --dump-args --dump-backtrace --dump-return
# 列出 Hook
jobs list
# 结束 Hook
jobs kill 124069
# Hook 整个类
android hooking watch class java.io.File
# 堆上搜索实例
android heap search instances com.android.settings.DisplaySettings
# 调用无参实例方法
android heap execute 0x2526 getPreferenceScreenResId
# 调用有参实例方法
android heap execute 0x2526
# demo.instanceFunc(x,y) 调用

# Spawn方式Hook
objection -g "com.bonc.moveportal" explore --startup-command 'android hooking watch class java.io.File'
# 搜索内存中的方法
android hooking search methods CheckIsNotRealPhone
# 列出Activity
android hooking list activities
# 列出Service
android hooking list services

# 查看命令帮助
help env
```

demo

```python
import frida, sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

jscode = """
Java.perform(() => {
  // 开始定义Hook
  console.log("1. Start Hooking");

  // 指定类
  const MainActivity = Java.use('com.example.seccon2015.rock_paper_scissors.MainActivity');
  console.log("2. Class Found");

  // 指定函数
  const onClick = MainActivity.onClick;
  console.log("3. Function Found");
  
  onClick.implementation = function (v) {
    // 显示函数被调用的信息
    send('onClick');

    // 调用原始函数
    onClick.call(this, v);

    // Set our values after running the original onClick handler
    // 注意这里使用.value来设置值 而不是直接赋值
    this.m.value = 0;
    this.n.value = 1;
    this.cnt.value = 999;

    // Log to the console that it's done, and we should have the flag!
    console.log('Done:' + JSON.stringify(this.cnt));
  };
});
"""

# 通过USB连接到设备 指定进程
process = frida.get_usb_device().attach('com.example.seccon2015.rock_paper_scissors')
# 加载js脚本
script = process.create_script(jscode)
# 也可以从JS文件中加载
# script = process.create_script(open('hook.js', 'r').read())
script.on('message', on_message)
print('[*] Running CTF')
script.load()
sys.stdin.read()
```