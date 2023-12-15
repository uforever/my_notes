### 花里胡哨的混淆/加密

与佛论禅（[与佛论禅密码](https://ctf.bugku.com/tool/todousharp)）
aa加密
日历连线，数字间联系较明显

### 隐写术

直接用文本编辑器打开，搜索flag、ctf、jpg、png、http、test等关键词
搜索十六进制值`89504e47`等图片头
尝试提取子文件
PDF隐写：全选-可以复制可打印字符
图片分析工具：[Stegsolve](http://www.caesum.com/handbook/Stegsolve.jar)，可以查看各个图层，可以比较像素差，或者尝试提取数据
GIF分解：[sioe.cn](https://tu.sioe.cn/gj/fenjie/)
音频频谱：Audacity

### RAR修复文件头

子块：0x7A
文件头：0x74

### BMP内容破解

```Shell
zsteg xxx.bmp
```

### Base64隐写

```python
def to_decimal(c):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    return alphabet.index(c)


if __name__ == "__main__":
    with open("stego.txt", 'r') as f:
        lines = f.readlines()

    result = ""

    for line in lines:
        line = line.strip()
        line = line.strip('=')
        remainder = len(line) % 4
        if remainder == 0:
            continue

        key_char = line[-1]
        if remainder == 2:
            mask = 0b1111
            index = to_decimal(key_char)
            result += "{:04b}".format(index & mask)
        if remainder == 3:
            mask = 0b11
            index = to_decimal(key_char)
            result += "{:02b}".format(index & mask)

    print(result)
```

### 解压图片隐藏内容

```Shell
binwalk -e a_very_good_idea.jpg
```

### 两图比对

```python
from PIL import Image

exp = Image.open("a.png")
cipher = Image.open("b.png")
result = Image.new("RGBA", size=exp.size)

for i in range(640):
    for j in range(480):
        y_p = exp.getpixel((i, j))
        c_p = cipher.getpixel((i, j))
        if y_p == c_p:
            result.putpixel((i,j), (255,255,255))
        else:
            result.putpixel((i,j), (0,0,0))

result.save("c.png")
```

### 修改PNG图片宽高

Winhex 第二行前四个字节为宽度，4-7字节为高度，最后三个字节以及第三行第一字节为CRC校验值
一个PNG图片的头部数据为：
```
89504E47 0D0A1A0A 0000000D 49484452
0000039E 0000044C 08020000 0038165A
34
```
其中包含哪些信息？
- `89504E47`：PNG 文件的文件类型标识符（Magic Number），表示这是一个 PNG 文件。
- `0D0A1A0A`：文件结构标识符，由固定的四个字节组成，用于标识 PNG 文件的开头和结尾。
- `0000000D`：IHDR（Image Header）块的长度，表示该块占用13个字节。
- `49484452`：IHDR 块的类型标识符，表示该块为图像头块，即"IHDR"。
后面13字节都是IHDR，即`0000039E 0000044C 08020000 00`，其中
- `0000039E`：图像宽度，以像素为单位，该图像的宽度为 926 像素。
- `0000044C`：图像高度，以像素为单位，该图像的高度为 1100 像素。
- `08 02 00 00 00`：色深(8bit)，颜色类型(RGB)，压缩方法(DEFLATE压缩)，过滤方法(无)，隔行方式(无)
- `38165A34`：IHDR CRC校验，参与的字节为12-29，即包含`49484452`和后面13字节的IHDR
```
89504e47 0d0a1a0a 0000000d 49484452
00000ac2 0000087c 0802000000 6503ee80
```

### Git恢复暂存文件

```shell
git stash apply
```

### Base编码

除了常见的Base64，破解base编码
```shell
python basecrack.py
```

### BMP lsb隐写

用画图3D打开另存为PNG格式，再查看各个图层即可
python脚本
```python
import PIL.Image as Image

img = Image.open('x.bmp')
img_tmp = img.copy()
pix = img_tmp.load()
width, height = img_tmp.size
for w in range(width):
    for h in range(height):
        if pix[w, h] & 1 == 0:
            pix[w, h] = 0
        else:
            pix[w, h] = 255

img_tmp.save("result.png")
```

### GPS绘制

[GPS Visualizer](https://www.gpsvisualizer.com/map_input?form=leaflet)

### 压缩包伪加密

010Editor将ushort frFlags改为0