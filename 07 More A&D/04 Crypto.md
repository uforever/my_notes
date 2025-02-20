### Base64
Base64 编码
梯度示例：
```
56m65bGx5paw6Zuo5ZCOYWJjZGVm
56m65bGx5paw6Zuo5ZCOYWJjZGU=
56m65bGx5paw6Zuo5ZCOYWJjZA==
56m65bGx5paw6Zuo5ZCOYWJj
56m65bGx5paw6Zuo5ZCOYWI=
```

### Caesar
凯撒密码，ROT13
给所有字母一个偏移量

### Morce
莫尔斯电码
特征：由大量 `-` 和 `.` 或 0和1 以及某个分隔符组成

### Rail Fence
栅栏密码
特征：字母不变，打乱排序

### Bacon
培根密码
特征：由大量重复，如字母A和B，或0和1组成

### RSA

#### 密钥生成
1. 准备两个大质数 `p` 和 `q`
2. 计算乘积 `n = p * q`
3. 计算 `m = (p-1)(q-1)`
4. 找一个数 `e` 与 `m` 互质（实际应用中，常常选择65537）
5. 计算 `e` 在模 `m` 域上的逆元 `d`（即满足 `e*d mod m = 1` ）
6. 公钥为 `(n,e)` ，私钥为 `(n,d)`

#### 加密和解密
加密：计算出 `c = m^e mod n`
解密：计算出 `m = c^d mod n`

#### 短公钥破解

暴力破解RSA公钥的私钥是一个非常困难的问题，因为它涉及到对一个大整数进行质因数分解，这是一个没有有效算法的数学难题。一般来说，RSA公钥的模数n是两个大素数p和q的乘积，而私钥的指数d是公钥指数e的逆元，满足de = 1 mod (p-1)(q-1)。因此，如果能够找到p和q，就可以计算出d，从而得到私钥。

但是，如果n很大（通常至少为1024位），则没有已知的有效方法可以在合理的时间内分解n。目前最好的算法是基于数域筛选（NFS）的方法，但它仍然需要巨大的计算资源和时间。因此，暴力破解RSA公钥的私钥是不可行的。

然而，如果n很小（比如小于100位），或者有一些特殊的性质（比如p和q很接近，或者e或d很小），则可能存在一些攻击方法可以分解n或者直接求出d。这些方法包括：

•  费马分解法：如果p和q很接近，则可以尝试找到n的平方根附近的两个平方数，使得n = x^2 - y^2 = (x+y)*(x-y)。

•  维纳攻击：如果d很小，则可以利用连分数展开来求出d。

•  哈斯塔德攻击：如果e很小，并且有多个相同明文加密后的密文，则可以利用中国剩余定理和低指数广播攻击来求出明文。

•  骨-杜菲攻击：如果d < n^0.292，则可以利用格基约化来求出d。

•  共模攻击：如果有两个不同的公钥指数e1和e2，但是相同的模数n，并且有相同明文加密后的密文c1和c2，则可以利用扩展欧几里得算法来求出明文。

•  共质因子攻击：如果有多个公钥模数n1,n2,...,nk，并且其中至少两个有共同的质因子p，则可以利用最大公约数算法来求出p。

•  小q攻击：如果n = p*q，并且q很小（比如小于10万），则可以利用试除法来求出q。

```shell
# 通过n和e生成公钥
python3 RsaCtfTool.py --createpub -n 25162507052339714421839688873734596177751124036723831003300959761137811490715205742941738406548150240861779301784133652165908227917415483137585388986274803 -e 10 > output/hastads01.pub

# 哈斯塔德攻击
python3 RsaCtfTool.py --publickey "examples/hastads01.pub,examples/hastads02.pub,examples/hastads03.pub" --uncipher "261345950255088824199206969589297492768083568554363001807292202086148198540785875067889853750126065910869378059825972054500409296763768604135988881188967875126819737816598484392562403375391722914907856816865871091726511596620751615512183772327351299941365151995536802718357319233050365556244882929796558270337,147535246350781145803699087910221608128508531245679654307942476916759248311896958780799558399204686458919290159543753966699893006016413718139713809296129796521671806205375133127498854375392596658549807278970596547851946732056260825231169253750741639904613590541946015782167836188510987545893121474698400398826,633230627388596886579908367739501184580838393691617645602928172655297372145912724695988151441728614868603479196153916968285656992175356066846340327304330216410957123875304589208458268694616526607064173015876523386638026821701609498528415875970074497028482884675279736968611005756588082906398954547838170886958" --attack hastads

# 共模攻击
python3 RsaCtfTool.py -e "17,65537" -n "111381961169589927896512557754289420474877632607334685306667977794938824018345795836303161492076539375959731633270626091498843936401996648820451019811592594528673182109109991384472979198906744569181673282663323892346854520052840694924830064546269187849702880332522636682366270177489467478933966884097824069977" --uncipher "54995751387258798791895413216172284653407054079765769704170763023830130981480272943338445245689293729308200574217959018462512790523622252479258419498858307898118907076773470253533344877959508766285730509067829684427375759345623701605997067135659404296663877453758701010726561824951602615501078818914410959610,91290935267458356541959327381220067466104890455391103989639822855753797805354139741959957951983943146108552762756444475545250343766798220348240377590112854890482375744876016191773471853704014735936608436210153669829454288199838827646402742554134017280213707222338496271289894681312606239512924842845268366950" --attack same_n_huge_e

python3 RsaCtfTool.py -e "117,65537" -n "13060424286033164731705267935214411273739909173486948413518022752305313862238166593214772698793487761875251030423516993519714215306808677724104692474199215119387725741906071553437840256786220484582884693286140537492541093086953005486704542435188521724013251087887351409946184501295224744819621937322469140771245380081663560150133162692174498642474588168444167533621259824640599530052827878558481036155222733986179487577693360697390152370901746112653758338456083440878726007229307830037808681050302990411238666727608253452573696904083133866093791985565118032742893247076947480766837941319251901579605233916076425572961" --uncipherfile "input/cipher1.txt,input/cipher2.txt" --attack same_n_huge_e

# 直接因式分解破解密钥
python3 RsaCtfTool.py -n 87924348264132406875276140514499937145050893665602592992418171647042491658461 -e 65537 --private
```

手动攻击：
通过python脚本读取 n 和 e
```python
import base64
from Crypto.PublicKey import RSA

pubkey = b"""-----BEGIN PUBLIC KEY-----
MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAMJjauXD2OQ/+5erCQKPGqxsC/bNPXDr
yigb/+l/vjDdAgMBAAE=
-----END PUBLIC KEY-----"""

key = RSA.importKey(pubkey)
n = key.n
e = key.e
print("n =", n)
print("e =", e)
```
使用工具破解出私钥
```shell
# n = 87924348264132406875276140514499937145050893665602592992418171647042491658461
# e = 65537
python3 RsaCtfTool.py -n 87924348264132406875276140514499937145050893665602592992418171647042491658461 -e 65537 --private
```
或
```powershell
.\yafu-x64.exe "factor(87924348264132406875276140514499937145050893665602592992418171647042491658461)"
```
或使用在线破解：[RSA Cipher Calculator](https://www.dcode.fr/rsa-cipher) ，最大公因数在线计算 [GCD Calculator](https://www.dcode.fr/gcd)
暴力破解脚本（可行性较差，需要运行很久）
```python
import base64
import math
from Crypto.PublicKey import RSA

pubkey = b"""-----BEGIN PUBLIC KEY-----
MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAMJjauXD2OQ/+5erCQKPGqxsC/bNPXDr
yigb/+l/vjDdAgMBAAE=
-----END PUBLIC KEY-----"""

key = RSA.importKey(pubkey)
n = key.n
e = key.e
print("n =", n)
print("e =", e)

# ---------------------------------------------------------- #

def trial_division(n):
    factors = []
    while n % 2 == 0:
        factors.append(2)
        n //= 2
    limit = int(math.sqrt(n)) + 1
    for i in range(3, limit, 2):
        if n % i == 0:
            factors.append(i)
            n //= i
            return factors + trial_division(n)
    if n > 1:
        factors.append(n)
    return factors

# n = 172501195984241284410913211758112446677
factors = trial_division(n)
print("factors =", factors)

# ---------------------------------------------------------- #

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('No modular inverse')
    else:
        return x % m

# p = 149512557939643
p = factors[0]
# q = 1154381666990073
p = factors[1]
# e = 65537

phi = (p-1)*(q-1)
d = modinv(e, phi)
print("d =", d)

# ---------------------------------------------------------- #

# p = 149512557939643
# q = 1154381666990073
# e = 65537
# d = 109648609218485189397995983529192787969

key_params = (int(p*q), int(e), int(d), int(p), int(q))
key = RSA.construct(key_params)
privkey = key.exportKey()
print(privkey.decode())
```
### MD5

在线破解网站：[SOMD5](https://www.somd5.com/)、[CrackStation](https://crackstation.net/)

### AES

非标准长度密钥直接加解密
```js
var CryptoJS = require("crypto-js");

const input = "U2FsdGVkX18OvTUlZubDnmvk2lSAkb8Jt4Zv6UWpE7Xb43f8uzeFRUKGMo6QaaNFHZriDDV0EQ/qt38Tw73tbQ==";
const key = "ISCC";

const result = CryptoJS.AES.decrypt(input, key);
console.log(CryptoJS.enc.Utf8.stringify(result));
```

### 差分故障分析（DFA）

以AES128为例，其扩散性主要由每一轮的列混合操作提供。
DFA攻击常见的目标是轮密钥（round key）而非加密过程中的明文或密文。最后一轮密钥足以恢复原始AES-128主密钥，因为AES密钥调度是完全可逆的。
在最后两次列混合操作之间，产生一个字节的差异，会对最终的输出结果产生四个字节的影响。至少需要8次故障（每4字节列2个）。如下
[SideChannelMarvels/JeanGrey: Tools to perform differential fault analysis attacks (DFA).](https://github.com/SideChannelMarvels/JeanGrey)

```python
#!/usr/bin/env python3
import phoenixAES

with open('tracefile', 'wb') as t:
# 加法一定会让值发生改变 针对列所以是4*i
# vec[4 * i] = vec[4 * i].wrapping_add(0x99);
# vec[4 * i] = vec[4 * i].wrapping_add(0x66);
    t.write("""
d2ca4c3d81aa97144304ac414b1b6153
c3ca4c3d81aa976e430441414bc66153
d25a4c3d16aa97144304ac224b1b7453
d2ca613d815097140504ac414b1b616a
d2ca4ca481aa5b144336ac416e1b6153
dfca4c3d81aa97ad43046c414b4e6153
d2fa4c3dc3aa97144304ac444b1b5553
d2ca8a3d814397140a04ac414b1b61d6
d2ca4c8b81aa28144364ac41231b6153
""".encode('utf8'))

phoenixAES.crack_file('tracefile')
```

```python
import phoenixAES

data = """875fe01c35e3399c9e9c8a0a4f3e8a68
8c5fe01c35e339179e9c2d0a4f0e8a68
6a5fe01c35e339ed9e9c2c0a4f268a68
2b5fe01c35e339559e9cf60a4fa68a68
835fe01c35e339259e9cc60a4fd88a68
885fe01c35e3393d9e9c450a4f548a68
ec5fe01c35e339ac9e9c740a4f038a68
fd5fe01c35e339da9e9c7c0a4fb08a68
715fe01c35e339c79e9ce50a4f108a68
b35fe01c35e339779e9c950a4f9b8a68
075fe01c35e339e49e9c9c0a4f498a68
625fe01c35e3396c9e9c810a4f238a68
a45fe01c35e339d89e9cc50a4fe28a68
1a5fe01c35e339759e9c850a4fb88a68
f05fe01c35e339639e9cad0a4f658a68
fb5fe01c35e339cc9e9cf00a4f7f8a68
485fe01c35e339e69e9cb10a4f318a68
"""

idx = [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15]

def transpose(data):
    return bytes([data[idx[i]] for i in range(16)])


with open("./crackfile",'w') as f:
    for line in data.splitlines():
        if line:
            line = transpose(bytes.fromhex(line)).hex()
            f.write(line + '\n')

phoenixAES.crack_file("crackfile",[],True,False,verbose=2)
```

通过最终轮密钥和任意一个中间轮密钥（128bit只用最终轮就够了）打印所有轮密钥
[SideChannelMarvels/Stark: Repository of small utilities related to key recovery](https://github.com/SideChannelMarvels/Stark)
```bash
.\aes_keyschedule 957ceed29ab914260ca5ef870c059557 10
# 输出中K00即为主密钥
```

unidbg 进行DFA攻击案例
```java
package com.luckin;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.ReadHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.BreakPointCallback;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.pointer.UnidbgPointer;
import unicorn.ArmConst;

import java.io.File;
import java.util.Random;

public class LKAES extends AbstractJni {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;
    public int times = 0;

    public LKAES() {
        emulator = AndroidEmulatorBuilder.for32Bit().build();
        final Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        // 通过安装包运行 可以规避一部分检查
        vm = emulator.createDalvikVM(new File("unidbg-android/src/test/resources/apks/lucky.apk"));
        vm.setVerbose(true);
        // 加载共享库
        DalvikModule dm = vm.loadLibrary("cryptoDD", true);
        module = dm.getModule();
        // 设置JNI
        vm.setJni(this);
        dm.callJNI_OnLoad(emulator);
    }

    public static String toHexString(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            // 将每个字节转换为两位的16进制数，不足两位前面补零
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString().toUpperCase();  // 可选：将字母转换为大写
    }

    public void call_wbaes() {
        times = 0;
        MemoryBlock inblock = emulator.getMemory().malloc(16, true);
        UnidbgPointer inPtr = inblock.getPointer();
        MemoryBlock outblock = emulator.getMemory().malloc(16, true);
        UnidbgPointer outPtr = outblock.getPointer();
        byte[] stub = new String("0123456789abcdef").getBytes();
        inPtr.write(0, stub, 0, stub.length);

        // 目标函数 wbaes_encrypt_ecb 地址 通过地址主动调用
        module.callFunction(emulator, 0x17bd5, inPtr, 16, outPtr, 0);

        String ret = toHexString(outPtr.getByteArray(0, 0x10));
        System.out.println(ret);
        inblock.free();
        outblock.free();
    }

    public static int randInt(int min, int max) {
        Random rand = new Random();
        return rand.nextInt((max - min) + 1) + min;
    }

    public void dfaAttack() {
        // 列混合函数 wbShiftRows 入口
        emulator.attach().addBreakPoint(module.base + 0x14F98 + 1, new BreakPointCallback() {
            UnidbgPointer pointer;

            @Override
            public boolean onHit(Emulator<?> emulator, long address) {
                times++;
                RegisterContext registerContext = emulator.getContext();
                pointer = registerContext.getPointerArg(0);
                emulator.attach().addBreakPoint(registerContext.getLRPointer().peer, new BreakPointCallback() {
                    @Override
                    public boolean onHit(Emulator<?> emulator, long address) {
                        if (times == 9) {
                            pointer.setByte(randInt(0, 15), (byte) randInt(0, 0xff));
                        }
                        return true;
                    }
                });

                return true;
            }
        });
    }

    public void traceAESRead() {
        emulator.getBackend().hook_add_new(new ReadHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                long now = emulator.getBackend().reg_read(ArmConst.UC_ARM_REG_PC).intValue();
                if ((now > module.base) & (now < (module.base + module.size))) {
                    System.out.println(now - module.base); // 原作者这里通过绘制内存访问的曲线图快速找到了列混合函数的地址
                }
            }

            @Override
            public void onAttach(UnHook unHook) {

            }

            @Override
            public void detach() {

            }
        }, module.base, module.base + module.size, null);
    }


    public static void main(String[] args) {
        LKAES lkaes = new LKAES();
        // 原作者这里通过绘制内存访问的曲线图快速找到了列混合函数的地址
        // lkaes.traceAESRead();
        lkaes.dfaAttack();
        System.out.println("---- ----");
        for (int i = 0; i < 32; i++) {
            lkaes.call_wbaes();
        }
        System.out.println("---- ----");

        // lkaes.call_wbaes();

        // 0123456789abcdef -> b0f59c0d48c145915fc8f6a842c4d5eb

        // 输出只有四个字节改变 说明hook的位置对了
        // b02f9c0d08c145915fc8f6a342c405eb
    }
}
```

### 其它

二进制幂数加密（Binary idempotent encryption）、车轮密码（Wheel Cipher [Jefferson Wheel Cipher](https://www.dcode.fr/jefferson-wheel-cipher)）、键盘密码（环绕、坐标、顺序等）、椭圆曲线加密算法（ECC）、替换密码（cryptoquip [quipqiup](https://quipqiup.com/)）、黑客语（leet/1337 [Leet Speak Translator - 1337](https://www.dcode.fr/leet-speak-1337)）、诗歌密码（Poem Code）、维吉尼亚密码（Vigenère Cipher，使用一系列凯撒密码组成密码字母表）、Brainfuck（[brainfuck](http://pablojorge.github.io/brainfuck/)）