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
注意：加密的时候要求明文 m 要小于 n。如果 m > n，而在计算过程中用到了 mod 运算，则不能通过解密算法正确求得明文 m，只能得到比 n 小且与 m(mod n) 同余的整数

加密：计算出 `c = m^e mod n`
解密：计算出 `m = c^d mod n`

#### 正确性证明

##### 欧拉定理

如果 a 和 n 是互质的正整数，即 $\text{gcd}(a, n) = 1$ ，那么有：

$$
a^{\phi(n)} \equiv 1 \mod n
$$
其中，$\phi(n)$ 是欧拉函数，它表示小于或等于 ( n ) 的正整数中，与 ( n ) 互质的整数的数量
$$
\phi(n) = \text{count} { k \in \mathbb{Z}^+ | 1 \leq k \leq n, \text{gcd}(k, n) = 1 }
$$
如果 ( n ) 是质数，那么它和任意一个比他小的数都互质，则：
$$
\phi(p) = p - 1
$$
如果 ( n ) 是质数 ( p ) 的 ( k ) 次幂（用总数减去不互质的数 即包含因子p的数），则：
$$
\phi(p^k) = p^k - p^{k-1} = p^k \left( 1 - \frac{1}{p} \right)
$$
如果 ( n ) 是不同质数的乘积，即 $n = p_1^{k_1} p_2^{k_2} \cdots p_m^{k_m}$，则：
$$
\phi(n) = n \left( 1 - \frac{1}{p_1} \right) \left( 1 - \frac{1}{p_2} \right) \cdots \left( 1 - \frac{1}{p_m} \right)
$$

证明：
定义集合 ( S ) 为所有小于 ( n ) 的与 ( n ) 互质的正整数
$$
S = { k \in \mathbb{Z}^+ | 1 \leq k < n \text{ and } \text{gcd}(k, n) = 1 }
$$
考虑将集合 ( S ) 中的每个元素 ( k ) 乘以 ( a )，得到新的集合：
$$
S' = { ak \mod n | k \in S }
$$
由于 ( a ) 和 ( n ) 互质，因此乘法操作不会改变元素的互质性。即 ( S' ) 中的元素仍然与 ( n ) 互质。
集合 ( S' ) 的元素也是小于 ( n ) 的正整数，因此 ( S' ) 有 $\phi(n)$ 个元素。
我们可以证明 ( S' ) 与 ( S ) 之间存在一一对应关系。因此，这两个集合实际上是相同的，只是排列顺序可能不同。即：$S' = S$，称为*整数模 n 乘法群*，也称为*模 n 既约剩余类*
两个集合具备单射性和满射性
单射性如果 $f(k_1) = f(k_2)$，那么必有 $k_1 = k_2$
假设
$$
ak_1 \mod n = ak_2 \mod n
$$
也就是
$$
ak_1 \equiv ak_2 \mod n
$$
因为 ( a ) 和 ( n ) 互质，根据同余的性质，如果存在上述情况，则可以得出：
$$
k_1 \equiv k_2 \mod n
$$
而集合S中的元素都小于n，所以
$$
k_1 = k_2
$$
单射性表明，每个S'集合中的元素唯一对应一个集合S中的元素
再来看满射性
需要证明对于任意 $y \in S'$，存在一个 $x \in S$，使得 $f(x) = y$
取任意元素：存在某个k使得
$$
y = ak \mod n
$$
我们希望找到一个 ( k ) 使得
$$
f(k) = y
$$
即
$$
ak \equiv y \mod n
$$

考察集合 ( S ) 中所有元素的乘积：
$$
P = \prod_{k \in S} k
$$
然后，考虑乘积 ( P' )：
$$
P' = \prod_{k \in S} (ak \mod n) = a^{\phi(n)} \cdot P \mod n
$$
因为 ( S' ) 和 ( S ) 是相同的集合，因此我们有：
$$
P \equiv a^{\phi(n)} \cdot P \mod n
$$

由于 ( P ) 中的所有元素都与 ( n ) 互质，因此可以对两边同时除以 ( P )（在模 ( n ) 下），得到
$$
a^{\phi(n)} \equiv 1 \mod n
$$
这就是*欧拉定理*的结论

##### RSA算法示例

RSA中用到了欧拉定理的一种特殊情况
当$n=pq$，其中p和q都为质数时，根据上述公式计算可得
$$
\phi(n) = n \left( 1 - \frac{1}{p} \right) \left( 1 - \frac{1}{q} \right) = (p-1)(q-1)
$$
选取两个不同的大素数p和q
Choose $p = 3$ and $q = 11$
计算$N=p \cdot q$
$$
n = p * q = 3 * 11 = 33
$$

计算欧拉函数值
$$
\phi(33) = (3-1)\times(11-1) = 20
$$

选择一个小于欧拉值的整数e 要求互质
$e=7$
$(7,20) = 1$ 互质

求d 使
$$
d \cdot e \equiv 1 \mod \phi(n)
$$
这里取d = 3
$(3 \times 7) \mod 20 = 1$
称3和7互为模20意义下的乘法逆元

销毁p、q
公钥为 (e, n) => (7, 33)
私钥为 (d, n) => (3, 33)

这里e和d是等价的 可以互换
c 和 m^e或m^d 同模33
m和 c^d或m^e 同模33

密文 m = 2 is $c = 2^7 \mod 33 = 29$
明文 c = 29 is $m = 29^3 \mod 33 = 2$

Q：假如两数同模于某数，那么这两数的平方是否同模，立方是否同模，为什么？
A：也同模。证明如下
假设a、b同模于n
则 $a-b = kn$ 其中k为整数
而$a^2 - b^2 = (a-b)(a+b) = kn(a+b)$ 必然也同模
同理
$a^3 - b^3$或更高次幂 都能因式分解出 $a-b = kn$ 必然同模
##### 证明

假设 $c \equiv m^e \mod n$ ，$m \equiv c^d \mod n$
则 需要证明
$$
m \equiv c^d \equiv m^{(de)} \mod n
$$

而
$$
de \equiv 1 \mod \phi(n)
$$
所以进一步只需证明
$$
m^{(de)} \equiv m^{1 + k \cdot \phi(n)} \equiv m \cdot m^{k \cdot \phi(n)} \mod n
$$
第一种情况m、n互质，根据欧拉公式$m^{k \cdot \phi(n)} \equiv 1 \mod n$ ，等式成立。
第二种情况m、n不互质，由于算法性质 m < n（否则只能恢复同余数，会丢失信息）
p 和 q 又都是素数，意味着 m 要么是 p 的倍数，要么是 q 的倍数，不能同时是 p 和 q 的倍数（如果同时是 p 和 q 的倍数，那么不满足 m < n）
不妨设m 是 p 的倍数，即 m = xp。这时m和q互质，根据欧拉定理有
$$
m^{\phi(q)} \equiv 1 \mod q
$$
两边同时$k\phi(p)$次幂
$$
(m^{\phi(q)})^{k\phi(p)} \equiv 1^{k\phi(p)} \mod q
$$
而由于p q都是质数，其欧拉函数值都为-1，两者相乘即$\phi(n)$
于是

$$
m^{k\phi(n)} \equiv 1 \mod q
$$
所以 存在一个整数y 使得 $m^{k\phi(n)} = 1+yq$
两边同时乘以 $m = xp$
即
$$
m \cdot m^{k \cdot \phi(n)} \equiv m(1+yq) \equiv m + xp \cdot yq \equiv m + x \cdot y \cdot n \equiv m \mod n
$$
证毕
#### 短公钥破解

暴力破解RSA公钥的私钥是一个非常困难的问题，因为它涉及到对一个大整数进行质因数分解，这是一个没有有效算法的数学难题。一般来说，RSA公钥的模数n是两个大素数p和q的乘积，而私钥的指数d是公钥指数e的逆元，满足de = 1 mod (p-1)(q-1)。因此，如果能够找到p和q，就可以计算出d，从而得到私钥。

但是，如果n很大（通常至少为1024位），则没有已知的有效方法可以在合理的时间内分解n。目前最好的算法是基于数域筛选（NFS）的方法，但它仍然需要巨大的计算资源和时间。因此，暴力破解RSA公钥的私钥是不可行的。

然而，如果n很小（比如小于100位），或者有一些特殊的性质（比如p和q很接近，或者e或d很小），则可能存在一些攻击方法可以分解n或者直接求出d。这些方法包括：

##### 费马分解

•  费马分解法：对于一个奇模数，可以写成一个平方差
$$
n = p \cdot q = (\frac{p+q}{2})^2-(\frac{p-q}{2})^2
$$
费马因数分解法就是不断循环，找到两个平方数，使得$n = a^2 - b^2$。
这时p、q分别等于$a+b$和$a-b$。
我们让$a$ 从 $\lceil \sqrt{n} \rceil$ 开始，不断自增，直到$a^2-n$也是一个平方数时，就成功找到了因子。

•  维纳攻击：如果d很小，则可以利用连分数展开来求出d。

##### 低加密指数广播攻击

•  Hastad's attack：如果*加密指数e相同且很小*，并且*有多个相同明文加密后的密文*，则可以利用中国剩余定理和低指数广播攻击来求出明文。

**中国剩余定理**：有物不知其数，三三数之剩二，五五数之剩三，七七数之剩二。问物几何？
这个被叫做“物不知数”的问题本质上是解下面的同余方程组
$$
\begin{gather}
x \equiv a_1 \mod m_1 \\
x \equiv a_2 \mod m_2 \\
\ldots \\
x \equiv a_k \mod m_k
\end{gather}
$$
并且$m_1$ $m_2$ …… $m_k$两两互质，则该同余方程组有唯一解：
$$
x \equiv t_1M_1a_1 + t_2M_2a_2 + \ldots + t_kM_ka_k \mod m
$$
其中
$$
\begin{gather}
m = m_1 m_2 \ldots m_k \\
M_i = \frac{m}{m_i} \\
t_iM_i \equiv 1 \mod m_i
\end{gather}
$$
证明
对于任意$i$，模$m_i$能够有余数的只有本身这项，因为其它项中有$M_j$均包含$m_i$这个因子。于是可以证明$x$是同余方程组的解。
$$
\begin{gather}
t_iM_ia_i \equiv a_i \cdot 1 \equiv a_i \mod m_i \\
t_jM_ja_j \equiv 0 \mod m_i (i \ne j) \\
\end{gather}
$$
下面证明唯一性
对于任意两个解$x_1$和$x_2$，满足$x_1 - x_2 \equiv 0 \mod m_i$
所以$x_1 \equiv x_2 \mod m$必然成立。即$x$一定在解集中。

在Hastad攻击中，利用中国剩余定理求同余方程组的解，即可得到*加密原文的加密指数次方*，再计算根即可得到明文。

•  骨-杜菲攻击：如果d < n^0.292，则可以利用格基约化来求出d。

##### 共模攻击

•  共模攻击：如果*有两个不同的公钥指数$e_1$和$e_2$和相同的模数n*，并且*有相同明文加密后的密文$c_1$和$c_2$*，其中*两个加密指数互质*，则可以利用扩展欧几里得算法来求出明文。

**欧几里得算法**
$$
\gcd(a,b) = \gcd(b, a \mod b)
$$
两个整数的最大公约数等于其中较小的那个数和两数相除余数的最大公约数。
证明：
1. 如果a被b整除，且b被a整除，则a等于b（自然数范围）。
2. 如果a被d整除，且b被d整除，则a和b的线性组合都被d整除。
3. $a \mod n = a - n \lfloor \frac{a}{n} \rfloor$
4. 如果a被d整除，且b被d整除，则a和b的最大公因数被d整除。（因为既能整除a又能整除b，根据定义d是a和b的一个公因数，一定是最大公因数的因数）
设 $d = \gcd(a,b)$ ，$c = \gcd(b, a \mod b)$
根据1，证明欧几里得算法，只需证明 $c$ 整除 $d$，并且 $d$ 整除 $c$
- 先证明 $c$ 被 $d$ 整除
$$
a \mod b = a - kb , k = \lfloor \frac{a}{b} \rfloor
$$
是 $a$ 和 $b$ 的线性组合，所以 $a \mod b$ 被 $d$ 整除。同时 $b$ 也被 $d$ 整除。
根据4，$c$ 被 $d$ 整除
- 再证明 $d$ 被 $c$ 整除
$b$ 被 $c$ 整除 ，$a \mod b$ 被 $c$ 整除 ，设
$$
a = (a \mod b) + kb , k = \lfloor \frac{a}{b} \rfloor
$$
$a$ 是 $a \mod b$ 和 $b$ 的线性组合 ，根据2，$a$ 被 $c$ 整除
同时 $b$ 被 $c$ 整除 ，根据4，$d$ 被 $c$ 整除。算法得证。

**贝祖定理**
对于任意两个整数 $a$ 和 $b$ ，存在整数 $x$ 和 $y$ ，使得：
$$
ax + by = \gcd(a,b)
$$
也就是说，整数 $a$ 和 $b$ 的最大公约数 $d$ 可以表示为 $a$ 和 $b$ 的整数线性组合

证明
根据欧几里得算法
用 $a$ 除以 $b$ ，得到商 $q_1$ 和余数 $r_1$ ，即：
$$
a = bq_1 + r_1
$$
接下来用 $b$ 除以 $r_1$ ，得到商 $q_2$ 和余数 $r_2$ ，即：
$$
b = r_1q_2 + r_2
$$
$$
r_2 = b - r_1q_2 = b - q_2(a - bq_1) = b - q_2 \cdot a + q_1q_2 \cdot b
$$
继续这样展开，直到余数为零时，最后一个除数就是最大公约数。
也就是说，最终可以展开成包含 $\gcd(a,b)$ 的式子，它是a和b的线性组合。

由于*在共模攻击中两个加密指数互质*，根据贝祖定理，存在
$$
xe_1+ye_2 = \gcd(e_1,e_2) = 1
$$
于是
$$
m = m^1 = m^{xe_1+ye_2} = (m^{e_1})^x(m^{e_2})^y
$$
而在RSA中
$$
\begin{gather}
c_1 = m^{e_1} \mod n \\
c_2 = m^{e_2} \mod n \\
\therefore m = c_1^xc_2^y
\end{gather}
$$
而 x 和 y 必然一正一负，需要对负数的底数先取逆元
$$
c_2^y \equiv (c_2^{-1})^{-y} \mod n
$$

•  共质因子攻击：如果有多个公钥模数n1,n2,...,nk，并且其中至少两个有共同的质因子p，则可以利用最大公约数算法来求出p。

•  小q攻击：如果q很小（比如小于10万），则可以利用试除法来求出q。

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
搜索[factordb](https://factordb.com/)
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

#### 差分故障分析（DFA）

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