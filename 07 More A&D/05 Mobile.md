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
openssl x509 -inform DER -in public_key -pubkey -noout -out pubkey.pem

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

#### 通过反射获取ClassLoader中加载的全部类名

```Java
	public static void getClassNameListInClassLoader(ClassLoader classLoader) {
        try {
            Class BaseDexClassLoaderClass = Class.forName("dalvik.system.BaseDexClassLoader");
            Field pathListField = BaseDexClassLoaderClass.getDeclaredField("pathList");
            pathListField.setAccessible(true);
            Object pathListObj = pathListField.get(classLoader);

            Class DexPathListClass = Class.forName("dalvik.system.DexPathList");
            Field dexElementsField = DexPathListClass.getDeclaredField("dexElements");
            dexElementsField.setAccessible(true);
            Object dexElementsObj = dexElementsField.get(pathListObj);

            Object[] elementObjs = (Object[]) dexElementsObj;

            Class elementClass = Class.forName("dalvik.system.DexPathList$Element");
            Field dexFileField = elementClass.getDeclaredField("dexFile");
            dexFileField.setAccessible(true);

            Class DexFileClass = Class.forName("dalvik.system.DexFile");
            // private static native String[] getClassNameList(Object cookie);
            Method getClassNameListMethod = DexFileClass.getDeclaredMethod("getClassNameList", Object.class);
            getClassNameListMethod.setAccessible(true);
            Field mCookieField = DexFileClass.getDeclaredField("mCookie");
            mCookieField.setAccessible(true);
            Field mFileNameField = DexFileClass.getDeclaredField("mFileName");
            mFileNameField.setAccessible(true);

            for (Object elementObj : elementObjs) {
                Object dexFileObj = dexFileField.get(elementObj);
                Object mCookieObj = mCookieField.get(dexFileObj);

                Object classNameListObj = getClassNameListMethod.invoke(dexFileObj, mCookieObj);
                String[] classesName = (String[]) classNameListObj;

                Log.e("inClassLoader", classLoader.toString());
                for (String className : classesName) {
                    Log.e("inClassLoader", "- " + className);
                }
            }
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        }
    }
```

#### 从内存中加载dex文件的调用过程

- Android 8

```
InMemoryDexClassLoader -> BaseDexClassLoader -> DexPathList (makeInMemoryDexElements) -> DexFile (openInMemoryDexFile) -> art/runtime/native/dalvik_system_DexFile.cc { DexFile_createCookieWithDirectBuffer, DexFile_createCookieWithArray } -> CreateSingleDexFileCookie -> CreateDexFile -> art/runtime/dex_file.cc (Open) -> art/runtime/dex_file.cc (OpenCommon) -> DexFile::DexFile
```

#### 从文件加载dex的调用过程

```
DexClassLoader -> BaseDexClassLoader -> DexPathList (makeDexElements) -> loadDexFile -> DexFile (openDexFile) -> art/runtime/native/dalvik_system_DexFile.cc (DexFile_openDexFileNative) -> art/runtime/oat_file_manager.cc (OpenDexFilesFromOat) -> DexFile::Open -> DexFile::OpenFile -> art/runtime/dex_file.cc (OpenCommon) -> DexFile::DexFile
```

#### 动态加载dex文件demo

```Java
	protected void onCreate(Bundle savedInstanceState) {
		// ... ...
        Context appContext = this.getApplicationContext();
        dynamicLoad(appContext, "/sdcard/demo2.dex");
    }

    public void dynamicLoad(Context context, String dexPath) {
        File optFile = context.getDir("opt_dex", 0);
        File libFile = context.getDir("lib_path", 0);
        ClassLoader parentCL = MainActivity.class.getClassLoader();
        ClassLoader tmpCL = context.getClassLoader();
        DexClassLoader dexCL = new DexClassLoader(dexPath, optFile.getAbsolutePath(), libFile.getAbsolutePath(), parentCL);
        try {
            Class clazz = dexCL.loadClass("com.example.demo2.TestJava");
            Method testFuncMethod = clazz.getDeclaredMethod("testFunc");
            Object demo2Obj = clazz.newInstance();
            testFuncMethod.invoke(demo2Obj);
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (InstantiationException e) {
            e.printStackTrace();
        }
    }
```

#### dex文件checksum计算

抽取dex文件指令后需要重新计算并修改dex文件头中的checksum

```python
#! /usr/bin/python2
# -*- coding: utf8 -*-
import binascii  #删除缩进(Tab)

def CalculationVar(srcByte,vara,varb):#删除缩进(Tab)
    varA = vara
    varB = varb
    icount = 0
    listAB = []

    while icount < len(srcByte):
        varA = (varA + srcByte[icount]) % 65521
        varB = (varB + varA) % 65521
        icount += 1

    listAB.append(varA)
    listAB.append(varB)

    return listAB

def getCheckSum(varA,varB): #删除缩进(Tab)
    Output = (varB << 16) + varA
    return Output

if __name__ == '__main__':
    filename = 'demo3.dex'
    f = open(filename, 'rb', True)
    f.seek(0x0c)
    VarA = 1
    VarB = 0
    flag = 0
    CheckSum = 0
    while True:
        srcBytes = []
        for i in range(1024):               #一次只读1024个字节，防止内存占用过大
            ch = f.read(1)
            if not ch:                      #如果读取到末尾，设置标识符，然后退出读取循环
                flag = 1
                break
            else:
                ch = binascii.b2a_hex(ch)              #将字节转为int类型，然后添加到数组中
                ch = str(ch)
                ch = int(ch,16)
                srcBytes.append(ch)
        varList = CalculationVar(srcBytes,VarA,VarB)
        VarA = varList[0]
        VarB = varList[1]
        if flag == 1:
            CheckSum = getCheckSum(VarA,VarB)
            break
    print('[*] DEX FILENAME: '+filename)
    print('[+] CheckSum = '+hex(CheckSum))
```

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

### objection

```shell
# 连接应用
objection -g "<APP_NAME>" explore

# 列出Activity
android hooking list activities
# 启动Activity
android intent launch_activity "<ACTIVITY_NAME>"

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

spawn

```python
import frida, sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

# 通过USB连接到设备 指定进程
device = frida.get_usb_device()
process = device.spawn(["com.example.application"])
session = device.attach(process)
# 加载JS脚本 hook.js
with open('hook.js', 'r', encoding='utf-8') as f:
    jscode = f.read()
    script = session.create_script(jscode)

script.on('message', on_message)
print('[*] Hooking')
script.load()
device.resume(process)
sys.stdin.read()
```

```javascript
Java.perform(() => {
    // 开始定义Hook
    console.log("\n1. Start Hooking");
    var application = Java.use("android.app.Application");
    application.attach.overload("android.content.Context").implementation = function(context) {
        console.log("2. Hooking attach");
        // 执行原来的方法
        this.attach(context);
        var classLoader = context.getClassLoader();
        var classFactory = Java.ClassFactory.get(classLoader);
        var targetClass = classFactory.use("com.example.application.TargetClass");

        targetClass.target.overload().implementation = function() {
            console.log("3. Hooking target function");
            this.$super.SomeSuperFunc();
        }
    }
});
```

Java层自吐算法

```javascript
function bin2hex(array) {
    var result = [];
    var len = array.length;
    for (var i = 0; i < len; i++) {
        result.push(('0' + (array[i] & 0xFF).toString(16)).slice(-2));
    }
    return result.join('');
}

function bin2utf8(array) {
    var result = [];
    for (var i = 0; i < array.length; i++) {
        result.push('%' + ('0' + (array[i] & 0xFF).toString(16)).slice(-2));
    }
    return decodeURIComponent(result.join(''));
}

function bin2base64(array) {
    var base64chars = [];
    var alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    var len = array.length;

    for (var i = 0; i < len; i += 3) {
        var byte1 = array[i] & 0xFF;
        var byte2 = array[i + 1] & 0xFF;
        var byte3 = array[i + 2] & 0xFF;

        var triplet = (byte1 << 16) | (byte2 << 8) | byte3;

        for (var j = 0; (j < 4) && (i + j * 0.75 < len); j++) {
            base64chars.push(alphabet.charAt((triplet >> (6 * (3 - j))) & 0x3F));
        }
    }

    var padding = alphabet.charAt(64);
    if (padding) {
        while (base64chars.length % 4) {
            base64chars.push(padding);
        }
    }

    return base64chars.join('');
}

Java.perform(function () {
    console.log("\n---- Start hooking ----");

    Java.use('javax.crypto.spec.SecretKeySpec').$init.overload('[B', 'java.lang.String').implementation = function (key, spec) {
        console.log("密钥: " + bin2base64(key));
        return this.$init(key, spec);
    };

    Java.use('javax.crypto.Cipher')['getInstance'].overload('java.lang.String').implementation = function (spec) {
        console.log("加密类型: " + spec);
        return this.getInstance(spec);
    };

    Java.use('javax.crypto.Cipher')['doFinal'].overload('[B').implementation = function (data) {
        console.log("---- crypto ----");
        console.log("输入数据: ");
        console.log(bin2base64(data));
        var result = this.doFinal(data);
        console.log("输出数据: ");
        console.log(bin2base64(result));
        return result;
    };

    Java.use('javax.crypto.Cipher').init.overload('int', 'java.security.Key').implementation = function (opmode, key) {
        var keyWords = key.getEncoded();
        console.log("密钥: " + bin2base64(keyWords));
        return this.init(opmode, key);
    }

    Java.use('javax.crypto.Cipher').init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (opmode, key, params) {
        var keyWords = key.getEncoded();
        console.log("密钥: " + bin2base64(keyWords));
        var iv = Java.cast(params, Java.use('javax.crypto.spec.IvParameterSpec')).getIV();
        console.log("IV: " + bin2base64(iv));
        return this.init(opmode, key, params);
    }
});
```

```javascript
Java.perform(function () {
    console.log("\n*** Start hooking ***");

    function showStacks() {
        console.log(
            "调用堆栈：" +
            Java.use("android.util.Log")
                .getStackTraceString(
                    Java.use("java.lang.Throwable").$new()
                )
        );
    }

    var ByteString = Java.use("com.android.okhttp.okio.ByteString");

    function toBase64(tag, data) {
        console.log(tag + " Base64: ", ByteString.of(data).base64());
    }

    function toHex(tag, data) {
        console.log(tag + " Hex: ", ByteString.of(data).hex());
    }

    function toUTF8(tag, data) {
        console.log(tag + " UTF8: ", ByteString.of(data).utf8());
    }

    var cipher = Java.use("javax.crypto.Cipher");

    cipher.init.overload('int', 'java.security.Key').implementation = function () {
        console.log("---- ---- 方法调用 ---- ----");
        console.log("Cipher.init('int', 'java.security.Key')");
        var algorithm = this.getAlgorithm();
        var tag = algorithm + " 密钥";
        var className = JSON.stringify(arguments[1]);
        if (className.indexOf("OpenSSLRSAPrivateKey") === -1) {
            var keyBytes = arguments[1].getEncoded();
            toUTF8(tag, keyBytes);
            // toHex(tag, keyBytes);
            toBase64(tag, keyBytes);
        }
        showStacks();
        console.log("---- ---- ---- ---- ----\n");
        return this.init.apply(this, arguments);
    }
    cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function () {
        console.log("---- ---- 方法调用 ---- ----");
        console.log("Cipher.init('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec')");
        var algorithm = this.getAlgorithm();
        var keyTag = algorithm + " 密钥";
        var keyBytes = arguments[1].getEncoded();
        toUTF8(keyTag, keyBytes);
        // toHex(keyTag, keyBytes);
        // toBase64(keyTag, keyBytes);
        var ivTag = algorithm + " 初始向量";
        var iv = Java.cast(arguments[2], Java.use("javax.crypto.spec.IvParameterSpec"));
        var ivBytes = iv.getIV();
        toUTF8(ivTag, ivBytes);
        // toHex(ivTag, ivBytes);
        // toBase64(ivTag, ivBytes);
        showStacks();
        console.log("---- ---- ---- ---- ----\n");
        return this.init.apply(this, arguments);
    }

    cipher.doFinal.overload('[B').implementation = function () {
        console.log("---- ---- 方法调用 ---- ----");
        console.log("Cipher.doFinal('[B')");
        var algorithm = this.getAlgorithm();
        var inputTag = algorithm + " 输入";
        var data = arguments[0];
        toUTF8(inputTag, data);
        // toHex(inputTag, data);
        toBase64(inputTag, data);
        var result = this.doFinal.apply(this, arguments);
        console.log();
        var outputTag = algorithm + " 输出";
        toUTF8(outputTag, result);
        // toHex(outputTag, result);
        toBase64(outputTag, result);
        showStacks();
        console.log("---- ---- ---- ---- ----\n");
        return result;
    }
    cipher.doFinal.overload('[B', 'int', 'int').implementation = function () {
        console.log("---- ---- 方法调用 ---- ----");
        console.log("Cipher.doFinal('[B', 'int', 'int')");
        var algorithm = this.getAlgorithm();
        var inputTag = algorithm + " 输入";
        var data = arguments[0];
        toUTF8(inputTag, data);
        // toHex(inputTag, data);
        toBase64(inputTag, data);
        var result = this.doFinal.apply(this, arguments);
        console.log();
        var outputTag = algorithm + " 输出";
        toUTF8(outputTag, result);
        // toHex(outputTag, result);
        toBase64(outputTag, result);
        console.log("arguments[1]:", arguments[1],);
        console.log("arguments[2]:", arguments[2]);
        showStacks();
        console.log("---- ---- ---- ---- ----\n");
        return result;
    }
});
```

### 脱壳

#### frida-dexdump

- 安装

```shell
python -m venv env
# activate
pip install frida-dexdump
```

- 破解前台应用

```shell
frida-dexdump -FU
```

- 破解指定应用

```shell
frida-dexdump -U -f <APP_NAME>
```

- 检索输出结果

```Shell
grep -ril "MainActivity" *

grep -ril "MainActivity" * | xargs du -h
```

#### frida-fart

- 拷贝fart.so和fart64.so到/data/app目录下，并使用chmod 777 设置好权限

- 以反射方式破解前台应用

```shell
frida -FU -l frida_fart_reflection.js
fart()
```

- hook方式破解指定应用

```shell
frida -U -f <APP_NAME> -l frida_fart_hook.js --no-pause
```

### 强制开启 root adb

- `adb_root.sh`

```shell
#!/system/bin/sh
resetprop ro.debuggable 1
resetprop service.adb.root 1
magiskpolicy --live 'allow adbd adbd process setcurrent'
magiskpolicy --live 'allow adbd su process dyntransition'
magiskpolicy --live 'permissive { su }'
kill -9 `ps -A | grep adbd | awk '{print $2}'`
```

- 重启adbd

```shell
adb push adb_root.sh /sdcard/Download/

adb shell "su -c 'sh /sdcard/Download/adb_root.sh'"

# adb remount
# adb shell
```

- frida-server

```shell
adb push frida-server* /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server*"

adb shell "su -c '/data/local/tmp/frida-server-16.1.8-android-arm64 &'"
```

### 安卓8.0.0沙箱源码分析

- `frameworks/base/core/java/android/app/ActivityThread.java`

ActivityThread负责管理应用程序中所有Activity的生命周期。当Application启动后（`attachBaseContext()`和`onCreate()`是app中最先执行的方法，壳通常都是通过实现这两个函数，达到dex解密、加载，hook执行流程，替换ClassLoader、Application的目标。因此，我们可以选择任意一个在onCreate()之后执行的函数中进行dump），ActivityThread会负责创建应用程序的主Activity。可以选择在ActivityThread中的performLaunchActivity函数作为时机。

```Java
// ... after import
import android.app.Application;
import android.os.Build;
import android.util.ArrayMap;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.ref.WeakReference;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import dalvik.system.BaseDexClassLoader;

public final class ActivityThread {
	// ... after vars declare
	public static HashMap<String, String> dumpClassm_hashmap = new HashMap<>();
	// ... ...

	private Activity performLaunchActivity(ActivityClientRecord r, Intent customIntent) {
		// return 前创建一个fart线程
		fartthread();
		// ... return
	}

	// add 9 public static methods
	public static Field getClassField(ClassLoader classloader, String class_name,
                                      String filedName) {

        try {
            Class obj_class = classloader.loadClass(class_name);//Class.forName(class_name);
            Field field = obj_class.getDeclaredField(filedName);
            field.setAccessible(true);
            return field;
        } catch (SecurityException e) {
            e.printStackTrace();
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static Object getClassFieldObject(ClassLoader classloader, String class_name, Object obj,
                                             String filedName) {

        try {
            Class obj_class = classloader.loadClass(class_name);//Class.forName(class_name);
            Field field = obj_class.getDeclaredField(filedName);
            field.setAccessible(true);
            Object result = null;
            result = field.get(obj);
            return result;
            //field.setAccessible(true);
            //return field;
        } catch (SecurityException e) {
            e.printStackTrace();
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static Object invokeStaticMethod(String class_name,
                                            String method_name, Class[] pareTyple, Object[] pareVaules) {

        try {
            Class obj_class = Class.forName(class_name);
            Method method = obj_class.getMethod(method_name, pareTyple);
            return method.invoke(null, pareVaules);
        } catch (SecurityException e) {
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static Object getFieldOjbect(String class_name, Object obj,
                                        String filedName) {
        try {
            Class obj_class = Class.forName(class_name);
            Field field = obj_class.getDeclaredField(filedName);
            field.setAccessible(true);
            return field.get(obj);
        } catch (SecurityException e) {
            e.printStackTrace();
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (NullPointerException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static ClassLoader getClassloader() {
        ClassLoader resultClassloader = null;
        Object currentActivityThread = invokeStaticMethod(
                "android.app.ActivityThread", "currentActivityThread",
                new Class[]{}, new Object[]{});// 获取主线程对象
        Object mBoundApplication = getFieldOjbect(
                "android.app.ActivityThread", currentActivityThread,
                "mBoundApplication");
        Application mInitialApplication = (Application) getFieldOjbect("android.app.ActivityThread",
                currentActivityThread, "mInitialApplication");
        Object loadedApkInfo = getFieldOjbect(
                "android.app.ActivityThread$AppBindData",
                mBoundApplication, "info");
        Application mApplication = (Application) getFieldOjbect("android.app.LoadedApk", loadedApkInfo, "mApplication");
        resultClassloader = mApplication.getClassLoader();
        return resultClassloader;
    }
   
    public static void loadClassAndInvoke(ClassLoader appClassloader, String eachclassname, Method dumpMethodCode_method) {
        Log.i("ActivityThread", "go into loadClassAndInvoke->" + "classname:" + eachclassname);
        Class resultclass = null;
        try {
            Log.v("ActivityThread","fart->try load class:" + eachclassname + "\n");
            resultclass = appClassloader.loadClass(eachclassname);
        } catch (Exception e) {
            e.printStackTrace();
            return;
        } catch (Error e) {
            e.printStackTrace();
            return;
        }
        if (resultclass != null) {
            try {
                Constructor<?> cons[] = resultclass.getDeclaredConstructors();//获取构造函数
                for (Constructor<?> constructor : cons) {
                    if (dumpMethodCode_method != null) {
                        try {
                            dumpMethodCode_method.invoke(null, constructor);
                        } catch (Exception e) {
                            e.printStackTrace();
                            continue;
                        } catch (Error e) {
                            e.printStackTrace();
                            continue;
                        }
                    } else {
                        Log.e("ActivityThread", "dumpMethodCode_method is null ");
                    }

                }
            } catch (Exception e) {
                e.printStackTrace();
            } catch (Error e) {
                e.printStackTrace();
            }
            try {
                Method[] methods = resultclass.getDeclaredMethods();
                if (methods != null) {
                    Log.e("ActivityThread", eachclassname + "--" + methods.length);
                    for (Method m : methods) {
                        if (dumpMethodCode_method != null) {
                            try {
                                dumpMethodCode_method.invoke(null, m);
                            } catch (Exception e) {
                                e.printStackTrace();
                                continue;
                            } catch (Error e) {
                                e.printStackTrace();
                                continue;
                            }
                        } else {
                            Log.e("ActivityThread", "dumpMethodCode_method is null ");
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            } catch (Error e) {
                e.printStackTrace();
            }
        }
    }
    
    public static void fart() {
        ClassLoader appClassloader = getClassloader();
        if (appClassloader == null) {
            return;
        }
        ClassLoader parentClassloader=appClassloader.getParent();
        if(!appClassloader.toString().contains("java.lang.BootClassLoader"))
        {
            fartwithClassloader(appClassloader);
        }
        while(parentClassloader!=null){
            if(!parentClassloader.toString().contains("java.lang.BootClassLoader"))
            {
                fartwithClassloader(parentClassloader);
            }
            parentClassloader=parentClassloader.getParent();
        }
    }
    
    public static void fartwithClassloader(ClassLoader appClassloader) {
        Object pathList_object = getFieldOjbect("dalvik.system.BaseDexClassLoader", appClassloader, "pathList");
        Object[] ElementsArray = (Object[]) getFieldOjbect("dalvik.system.DexPathList", pathList_object, "dexElements");
        if(ElementsArray==null){return;}
        Field dexFile_fileField = null;
        try {
            dexFile_fileField = (Field) getClassField(appClassloader, "dalvik.system.DexPathList$Element", "dexFile");
        } catch (Exception e) {
            e.printStackTrace();
        } catch (Error e) {
            e.printStackTrace();
        }
        Class DexFileClazz = null;
        try {
            DexFileClazz = appClassloader.loadClass("dalvik.system.DexFile");
        } catch (Exception e) {
            e.printStackTrace();
        } catch (Error e) {
            e.printStackTrace();
        }
        Method getClassNameList_method = null;

        Method dumpMethodCode_method = null;

        for (Method field : DexFileClazz.getDeclaredMethods()) {
            if (field.getName().equals("getClassNameList")) {
                getClassNameList_method = field;
                getClassNameList_method.setAccessible(true);
            }
            if (field.getName().equals("dumpMethodCode")) {
                dumpMethodCode_method = field;
                dumpMethodCode_method.setAccessible(true);
            }
        }
        Field mCookiefield = getClassField(appClassloader, "dalvik.system.DexFile", "mCookie");

        if (dumpMethodCode_method == null) {
            Log.e("error", "dumpMethodCode is null!!!");
            return;
        }
        if (ElementsArray == null) {
            Log.e("error", "ElementsArray is null!!!");
            return;
        }



        Log.v("ActivityThread->methods", "dalvik.system.DexPathList.ElementsArray.length:" + ElementsArray.length);
        for (int j = 0; j < ElementsArray.length; j++) {
            Object element = ElementsArray[j];
            Object dexfile = null;
            try {
                dexfile = (Object) dexFile_fileField.get(element);
            } catch (Exception e) {
                e.printStackTrace();
            } catch (Error e) {
                e.printStackTrace();
            }
            if (dexfile == null) {
                Log.e("ActivityThread", "dexfile is null");
                continue;
            }
            if (dexfile != null) {
                Object mcookie = getClassFieldObject(appClassloader, "dalvik.system.DexFile", dexfile, "mCookie");
                if (mcookie == null) {
                    Log.v("ActivityThread->err", "get resultmcookie is null");
                    Object mInternalCookie = getClassFieldObject(appClassloader, "dalvik.system.DexFile", dexfile, "mInternalCookie");
                    if(mInternalCookie!=null)
                    {
                        mcookie=mInternalCookie;
                    }else{
                        Log.v("ActivityThread->err", "get mInternalCookie is null");
                        continue;
                    }

                }
                String[] classnames = null;
                try {
                    classnames = (String[]) getClassNameList_method.invoke(dexfile, mcookie);
                } catch (Exception e) {
                    e.printStackTrace();
                    continue;
                } catch (Error e) {
                    e.printStackTrace();
                    continue;
                }
                if (classnames != null) {
                    for (String eachclassname : classnames) {
                        loadClassAndInvoke(appClassloader, eachclassname, dumpMethodCode_method);
                    }
                }

            }
        }
        return;
    }

	// 创建一个线程 休眠一分钟后调用 fart方法
    public static void fartthread() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                // TODO Auto-generated method stub
                try {
                    Log.e("ActivityThread", "start sleep......");
                    Thread.sleep(1 * 60 * 1000);
                } catch (InterruptedException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
                Log.e("ActivityThread", "sleep over and start fart");
                fart();
                Log.e("ActivityThread", "fart run over");

            }
        }).start();
    }
}
```

- `art/runtime/art_method.cc`

实现5个函数供调用
在函数调用时对其进行dump

```C
// ... after includes
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "runtime.h"
#include <android/log.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define gettidv1() syscall(__NR_gettid)
#define LOG_TAG "ActivityThread"
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// add 5 methods
uint8_t* codeitem_end(const uint8_t **pData)
{
    uint32_t num_of_list = DecodeUnsignedLeb128(pData);
    for (;num_of_list>0;num_of_list--) {
        int32_t num_of_handlers=DecodeSignedLeb128(pData);
        int num=num_of_handlers;
        if (num_of_handlers<=0) {
            num=-num_of_handlers;
        }
        for (; num > 0; num--) {
            DecodeUnsignedLeb128(pData);
            DecodeUnsignedLeb128(pData);
        }
        if (num_of_handlers<=0) {
            DecodeUnsignedLeb128(pData);
        }
    }
    return (uint8_t*)(*pData);
}

extern "C" char *base64_encode(char *str,long str_len,long* outlen){
	long len;   
    char *res;  
    int i,j;  
    const char *base64_table="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";  
    if(str_len % 3 == 0)  
        len=str_len/3*4;  
    else  
        len=(str_len/3+1)*4;  
  
    res=(char*)malloc(sizeof(char)*(len+1)); 
    if(res==nullptr)
    {
		LOG(ERROR) << "base64_encode malloc failed!!size:"<<len;
		return nullptr;
		} 
    res[len]='\0';  
    *outlen=len;
    for(i=0,j=0;i<len-2;j+=3,i+=4)  
    {  
        res[i]=base64_table[str[j]>>2];  
        res[i+1]=base64_table[(str[j]&0x3)<<4 | (str[j+1]>>4)]; 
        res[i+2]=base64_table[(str[j+1]&0xf)<<2 | (str[j+2]>>6)]; 
        res[i+3]=base64_table[str[j+2]&0x3f]; 
    }  
  
    switch(str_len % 3)  
    {  
        case 1:  
            res[i-2]='=';  
            res[i-1]='=';  
            break;  
        case 2:  
            res[i-1]='=';  
            break;  
    }  
  
    return res;  
}

extern "C" void dumpdexfilebyArtMethod(ArtMethod* artmethod)  REQUIRES_SHARED(Locks::mutator_lock_) {
			char *dexfilepath=(char*)malloc(sizeof(char)*1000);	
			if(dexfilepath==nullptr)
			{
				LOG(INFO) << "ArtMethod::dumpdexfilebyArtMethod,methodname:"<<artmethod->PrettyMethod().c_str()<<"malloc 1000 byte failed";
				return;
			}
			int result=0;
			int fcmdline =-1;
			char szCmdline[64]= {0};
			char szProcName[256] = {0};
			int procid = getpid();
			sprintf(szCmdline,"/proc/%d/cmdline", procid);
			fcmdline = open(szCmdline, O_RDONLY,0644);
			if(fcmdline >0)
			{
				result=read(fcmdline, szProcName,256);
				if(result<0)
				{
					LOG(ERROR) << "ArtMethod::dumpdexfilebyArtMethod,open cmdline file error";
					return;
					}
				close(fcmdline);
				
			}
			
			if(szProcName[0])
			{
				
					  
					  const DexFile* dex_file = artmethod->GetDexFile();
					  const uint8_t* begin_=dex_file->Begin();  // Start of data.
					  size_t size_=dex_file->Size();  // Length of data.
					  
					  memset(dexfilepath,0,1000);
					  int size_int_=(int)size_;
							  	  
					  memset(dexfilepath,0,1000);
					  sprintf(dexfilepath,"/data/data/%s/%d_dexfile_execute.dex",szProcName,size_int_);
					  int dexfilefp=open(dexfilepath,O_RDONLY,0666);
					  if(dexfilefp>0){
						  close(dexfilefp);
						  dexfilefp=0;
						  
						  }else{
									  int fp=open(dexfilepath,O_CREAT|O_APPEND|O_RDWR,0666);
									  if(fp>0)
									  {
										  result=write(fp,(void*)begin_,size_);
										  if(result<0)
										  {
											  LOG(ERROR) << "ArtMethod::dumpdexfilebyArtMethod,open dexfilepath error";
											  }
										  fsync(fp); 
										  close(fp);  
										  memset(dexfilepath,0,1000);
										  sprintf(dexfilepath,"/data/data/%s/%d_classlist_execute.txt",szProcName,size_int_);
										  int classlistfile=open(dexfilepath,O_CREAT|O_APPEND|O_RDWR,0666);
											if(classlistfile>0)
											{
												for (size_t ii= 0; ii< dex_file->NumClassDefs(); ++ii) 
												{
													const DexFile::ClassDef& class_def = dex_file->GetClassDef(ii);
													const char* descriptor = dex_file->GetClassDescriptor(class_def);
													result=write(classlistfile,(void*)descriptor,strlen(descriptor));
													if(result<0)
													{
														}
													const char* temp="\n";
													result=write(classlistfile,(void*)temp,1);
													if(result<0)
													{
														}
													}
												  fsync(classlistfile); 
												  close(classlistfile); 
												
												}
										  }


									  }

					
			}
			
			if(dexfilepath!=nullptr)
			{
				free(dexfilepath);
				dexfilepath=nullptr;
			}
}

extern "C" void dumpArtMethod(ArtMethod* artmethod)  REQUIRES_SHARED(Locks::mutator_lock_) {
			char *dexfilepath=(char*)malloc(sizeof(char)*1000);	
			if(dexfilepath==nullptr)
			{
				LOG(INFO) << "ArtMethod::dumpArtMethod,methodname:"<<artmethod->PrettyMethod().c_str()<<"malloc 1000 byte failed";
				return;
			}
			int result=0;
			int fcmdline =-1;
			char szCmdline[64]= {0};
			char szProcName[256] = {0};
			int procid = getpid();
			sprintf(szCmdline,"/proc/%d/cmdline", procid);
			fcmdline = open(szCmdline, O_RDONLY,0644);
			if(fcmdline >0)
			{
				result=read(fcmdline, szProcName,256);
				if(result<0)
				{
					LOG(ERROR) << "ArtMethod::dumpArtMethod,open cmdline file file error";	
					return;									
				}
				close(fcmdline);
			}
			
			if(szProcName[0])
			{
				
					  const DexFile* dex_file = artmethod->GetDexFile();
					  const uint8_t* begin_=dex_file->Begin();  // Start of data.
					  size_t size_=dex_file->Size();  // Length of data.
					  
					  memset(dexfilepath,0,1000);
					  int size_int_=(int)size_;
					 	  
					  memset(dexfilepath,0,1000);
					  sprintf(dexfilepath,"/data/data/%s/%d_dexfile.dex",szProcName,size_int_);
					  int dexfilefp=open(dexfilepath,O_RDONLY,0666);
					  if(dexfilefp>0){
						  close(dexfilefp);
						  dexfilefp=0;
						  
						  }else{
									  int fp=open(dexfilepath,O_CREAT|O_APPEND|O_RDWR,0666);
									  if(fp>0)
									  {
										  result=write(fp,(void*)begin_,size_);
										  if(result<0)
										  {
											  }
										  fsync(fp); 
										  close(fp);  
										  memset(dexfilepath,0,1000);
										  sprintf(dexfilepath,"/data/data/%s/%d_classlist.txt",szProcName,size_int_);
										  int classlistfile=open(dexfilepath,O_CREAT|O_APPEND|O_RDWR,0666);
											if(classlistfile>0)
											{
												for (size_t ii= 0; ii< dex_file->NumClassDefs(); ++ii) 
												{
													const DexFile::ClassDef& class_def = dex_file->GetClassDef(ii);
													const char* descriptor = dex_file->GetClassDescriptor(class_def);
													result=write(classlistfile,(void*)descriptor,strlen(descriptor));
													if(result<0)
													{
														}
													const char* temp="\n";
													result=write(classlistfile,(void*)temp,1);
													if(result<0)
													{
														}
													}
												  fsync(classlistfile); 
												  close(classlistfile); 
												
												}
										  }


									  }
						  const DexFile::CodeItem* code_item = artmethod->GetCodeItem();
						  if (LIKELY(code_item != nullptr)) 
						  {
							  
					  
								  int code_item_len = 0;
								  uint8_t *item=(uint8_t *) code_item;
								  if (code_item->tries_size_>0) {
									  const uint8_t *handler_data = (const uint8_t *)(DexFile::GetTryItems(*code_item, code_item->tries_size_));
									  uint8_t * tail = codeitem_end(&handler_data);
									  code_item_len = (int)(tail - item);
								  }else{
									  code_item_len = 16+code_item->insns_size_in_code_units_*2;
								  }  
									  memset(dexfilepath,0,1000);
									  int size_int=(int)dex_file->Size();  // Length of data
									  uint32_t method_idx=artmethod->GetDexMethodIndexUnchecked();
									  sprintf(dexfilepath,"/data/data/%s/%d_ins_%d.bin",szProcName,size_int,(int)gettidv1());
								      int fp2=open(dexfilepath,O_CREAT|O_APPEND|O_RDWR,0666);
									  if(fp2>0){
										  lseek(fp2,0,SEEK_END);
										  memset(dexfilepath,0,1000);
										  int offset=(int)(item - begin_);
										 
										  result = write(fp2, "{name:", 6);
											if (result < 0) {

											}
											const char* methodname=artmethod->PrettyMethod().c_str();
											result = write(fp2, methodname, strlen(methodname));
											if (result < 0) {

											}
											memset(dexfilepath, 0, 1000);
											sprintf(dexfilepath, ",method_idx:%d,offset:%d,code_item_len:%d,ins:",method_idx, offset, code_item_len);
											int contentlength = strlen(dexfilepath);
											result = write(fp2, (void *) dexfilepath, contentlength);
											if (result < 0) {

											}
											
										  long outlen=0;
										  char* base64result=base64_encode((char*)item,(long)code_item_len,&outlen);
										  if(base64result!=nullptr)
										  {
											  result=write(fp2,base64result,outlen);
											  if(result<0)
													{
														}
											  }else{
													    const char* errorinfo="base64encode codeitem error";
														result=write(fp2,errorinfo,strlen(errorinfo));
														if(result<0)
														{
															}
												  
												  }
										  if(base64result!=nullptr){
											  free(base64result);
											  base64result=nullptr;
											  }
										  result=write(fp2,"};",2);
										  if(result<0)
										  {
										  }
										  fsync(fp2); 
										  close(fp2);
										   }
					
							}

					
			}
			
			if(dexfilepath!=nullptr)
			{
				free(dexfilepath);
				dexfilepath=nullptr;
			}
}

extern "C" void myfartInvoke(ArtMethod* artmethod)  REQUIRES_SHARED(Locks::mutator_lock_) {
	JValue *result=nullptr;
	Thread *self=nullptr;
	uint32_t temp=6;
	uint32_t* args=&temp;
	uint32_t args_size=6;
	artmethod->Invoke(self, args, args_size, result, "fart");
}

void ArtMethod::Invoke(Thread* self, uint32_t* args, uint32_t args_size, JValue* result,
                       const char* shorty) {
	// start
	if (self== nullptr) {
		dumpArtMethod(this);
		return;
	}
	// ...
}
```

- `art/runtime/native/dalvik_system_DexFile.cc`

实现2个native方法

```C
// ... after includes
#include "scoped_fast_native_object_access.h"
namespace art {
// ... start
// load method from art_method.cc
extern "C" void myfartInvoke(ArtMethod* artmethod);
// load method from java_lang_reflect_Method.cc`
extern "C" ArtMethod* jobject2ArtMethod(JNIEnv* env, jobject javaMethod);
// ...

// add 2 native function
static void DexFile_dumpDexFile(JNIEnv* env, jclass, jstring filepath,jobject cookie) {
	  const OatFile* oat_file = nullptr;
  std::vector<const DexFile*> dex_files;
  if (!ConvertJavaArrayToDexFiles(env, cookie, /*out */ dex_files, /* out */ oat_file)) {
    DCHECK(env->ExceptionCheck());
    return;
  }
  int dexnum=0;
  char dexfilepath[1000];
  int result=0;
  for (auto& dex_file : dex_files) {
    for (size_t i = 0; i < dex_file->NumClassDefs(); ++i) {
      const uint8_t* begin_=dex_file->Begin();  // Start of data.
	  size_t size_=dex_file->Size();  // Length of data.
	  int dexfilesize=(int)size_;
	  const char *filepathcstr = env->GetStringUTFChars(filepath, nullptr);
	  memset(dexfilepath,0,1000);
	  sprintf(dexfilepath,"%s_%d_%d",filepathcstr,dexfilesize,dexnum);
	  dexnum++;
	  //LOG(INFO) << "DexFile_dumpDexFile'" <<"dexfile name:"<<dex_file->kClassesDex<<"filepath:"<<filepathcstr<<"finaldumppath111:"<<dexfilepath;
	  int dexfilefp=open(dexfilepath,O_RDONLY,0666);
					  if(dexfilefp>0){
						  close(dexfilefp);
						  dexfilefp=0;
						  
						  }else{
									int fp=open(dexfilepath,O_CREAT|O_APPEND|O_RDWR,0666);
									result=write(fp,(void*)begin_,size_);
									if(result<0)
													{
														LOG(ERROR) << "ArtMethod::DexFile_dumpDexFile,write  file error";
														
														}
									fsync(fp); 
									close(fp);
							  }
	LOG(INFO)  << "DexFile_dumpDexFile'" <<"dexfile name:"<<dex_file->kClassesDex<<"filepath:"<<filepathcstr<<"finaldumppath222:"<<dexfilepath;
    }
  }
  return;
}

static void DexFile_dumpMethodCode(JNIEnv* env, jclass,jobject method) {
  if(method!=nullptr)
  {
		  ArtMethod* proxy_method = jobject2ArtMethod(env, method);
		  myfartInvoke(proxy_method);
	  }	 

  return;
}

// ... 注册这两个方法
static JNINativeMethod gMethods[] = {
	// ... + ,
	NATIVE_METHOD(DexFile, dumpDexFile,
                "(Ljava/lang/String;Ljava/lang/Object;)V"),
	NATIVE_METHOD(DexFile, dumpMethodCode,
                "(Ljava/lang/Object;)V")
}
// ...
} // namespace art
```

- `libcore/dalvik/src/main/java/dalvik/system/DexFile.java`

引入2个native方法

```Java
	// load 2 native function
    private static native void dumpDexFile(String dexfilepath,Object cookie);
    private static native void dumpMethodCode(Object m);
```

- `art/runtime/interpreter/interpreter.cc`

```C
namespace art {
// ... start
// load 1 method from art_method.cc
extern "C" void dumpdexfilebyArtMethod(ArtMethod* artmethod);
namespace interpreter {
// ...
static inline JValue Execute(
    Thread* self,
    const DexFile::CodeItem* code_item,
    ShadowFrame& shadow_frame,
    JValue result_register,
    bool stay_in_interpreter = false) REQUIRES_SHARED(Locks::mutator_lock_) {
	// ..start
	if(strstr(shadow_frame.GetMethod()->PrettyMethod().c_str(),"<clinit>")){
	    	dumpdexfilebyArtMethod(shadow_frame.GetMethod());
	}	
}
// ...
} // namespace interpreter
} // namespace art
```

- `art/runtime/native/java_lang_reflect_Method.cc`

```C
namespace art {
// ... start
// add a method
extern "C" ArtMethod* jobject2ArtMethod(JNIEnv* env, jobject javaMethod) {
  ScopedFastNativeObjectAccess soa(env);
  ArtMethod* method = ArtMethod::FromReflectedMethod(soa, javaMethod);
  return method;
}

}
```