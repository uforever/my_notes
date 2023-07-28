### 编译过程

一个经典C程序：`hello.c`

```c
#include <stdio.h>

int main()
{
    printf("Hello, World!\n");
    return 0;
}
```

执行过程

```shell
gcc hello.c
./a.out
# 编译过程可以通过添加-v参数查看
```

其实可以分解为：预处理、编译、汇编、链接

预编译：展开宏、删除注释、添加文件名和行号等操作

```shell
gcc -E hello.c -o hello.i
```

编译：生成对应汇编代码

```shell
gcc -S hello.i -o hello.s
```

汇编：将汇编代码转变为机器指令，输出目标文件 Object File

```shell
as hello.s -o hello.o
# 或
gcc -c hello.s -o hello.o
```

链接：输出可执行文件

```shell
ld -static crt1.o crti.o crtbegin.o hello.o --start-group -lgcc -lgcc_eh -lc --end-groud crtend.o crtn.o
```

目标文件主要包括：`.obj` 和 `.o`
PE文件、ELF文件、链接库都按照可执行文件格式存储
动态链接库包括：`.dll` 和 `.so`
静态链接库包括：`.lib` 和 `.a`

### JS

#### 去混淆

常见：webpack、eval、aa、jj、jsfuck、ollvm、sojson

在线工具：
[de4js](https://lelinhtinh.github.io/de4js/)
[JavaScript Deobfuscator](https://deobfuscate.io/)

webpack 分析：
1. 加载器有一个自执行函数入口，和模块不一定在同一个文件。可以先在外部定义若干变量，接收其内部加载器。
2. 如果遇到未定义，可以尝试补环境。如果需要补的内容太多，可以尝试删除多余的模块：找到导出的数组 `]` ，扩大选取，删除其中内容，只留下 `[]` 即可。如果因此引发了错误，可以酌情去除报错的部分代码。然后将需要用到的模块，写入 `[]` 中。改为 `{ index: value }` 格式。
3. 使用工具自动扣取：[webpack_ast](https://gitcode.net/zjq592767809/webpack_ast)
```shell
node webpack_mixer.js -l loader.js -m module0.js -m module1.js -o output/result.js
```

#### 加密参数定位方法

1. 全局搜索
2. 堆栈调试
3. XHR断点
4. 事件监听
5. 添加代码片
6. JS注入

注入的方式有很多，可以通过抓包工具、浏览器插件、代码片等，最简单的方式就是现在第一行下断点，然后在控制台手动执行代码，但这样不能够持久化，最好根据实际情况酌情选择hook方式。

```javascript
(function () {
    'use strict';
    var cookieTemp = "";
    Object.defineProperty(document, 'cookie', {
        set: function (val) {
            console.log('Hook cookie ->', val);
            debugger;
            cookieTemp = val;
            return val;
        },
        get: function () {
            return cookieTemp;
        }
    });
})();
```

7. 内存漫游

[ast-hook-for-js-RE](https://github.com/JSREI/ast-hook-for-js-RE)
[Trace](https://github.com/L018/Trace)



