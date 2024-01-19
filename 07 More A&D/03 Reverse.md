### 反汇编
#### 编译过程

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



#### 基础知识

- 一个字节8bit，可以用2位十六进制表示。一个十六进制数也被称为半字节。
- 两个字节称为一个字，两个字称为双字(dword，4字节，32位，8位十六进制表示）

#### 常见指令

##### 浮点数指令

| 指令 | 用法 | 含义 | 功能 |
| ---- | ---- | ---- | ---- |
| FLD | `FLD <in>` | Floating-Point Load | 浮点数值从指定的内存位置复制到浮点寄存器堆栈的顶部 |
| FILD | `FILD <in>` | Floating-Point Integer Load | 将带符号整数转换为浮点数并加载到浮点寄存器中 |
| FLDZ | `FLDZ` | Floating-Point Load Zero | 将浮点常量0.0从内存中加载到浮点寄存器堆栈的顶部，这个指令可以用来初始化浮点变量或者清空浮点数值 |
| FLD1 | `FLD1` | Floating-Point Load One | 将浮点常量1.0从内存中加载到浮点寄存器堆栈的顶部 |
| FST | `FST <out>` | Floating-Point Store | 将浮点寄存器堆栈的顶部的数值存储到内存地址中 |
| FSTP | `FSTP <out>` | Floating-Point Store with Pop | 将浮点寄存器堆栈的顶部的数值弹出到指定的内存位置 |
| FIST | `FIST <out>` | Floating-Point Integer Store | 将浮点寄存器堆栈的顶部的数值转换为带符号整数，然后存储到指定的内存位置 |
| FISTP | `FISTP <out>` | Floating-Point Integer Store with Pop | 将浮点寄存器堆栈的顶部的数值弹出后转换为带符号整数，然后存储到指定的内存位置 |
| FCOM | `FCOM [in]` | Floating-Point Compare | 将IN地址数据与栈顶ST(0)进行实数比较，影响对应标记位（CF和ZF），如果不传IN，则默认比较浮点寄存器堆栈的顶部两个数值 |
| FTST | `FTST` | Floating-Point Test for Zero | 比较栈顶ST(0)是否为0.0，影响对应标记位（ZF） |
| FADD | `FADD [in]` | Floating-Point ADDition | 将IN地址内的数据与ST(0)做加法运算，结果放入ST(0)中，即替换ST(0) |
| FADDP | `FADDP [n] [st]` | Floating-Point ADDition with Pop | 将ST(N)中的数据与ST(0)中的数据做加法运算，N为0~7中的任意一个数，先执行一次出栈操作，然后将相加结果放入ST(0)中保存 |

### JS逆向

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

Hook Cookie

```javascript
(function () {
    'use strict';
    let $cookie = document.cookie;
    Object.defineProperty(document, 'cookie', {
        get: function () {
            console.log(`[GET COOIKE]: \`${$cookie}\``);
            return $cookie;
        },
        set: function (val) {
            console.log(`[SET COOIKE]: \`${val}\``);
            debugger; const cookie = val.split(';')[0];
            const pair = cookie.split('=');
            let key = ""
                , value = "";
            if (pair.length === 1) {
                value = pair[0].trim();
            } else {
                key = pair[0].trim();
                value = pair[1].trim();
            }
            let flag = false;
            if ($cookie === '') {
                $cookie = cookie;
                return $cookie;
            } else {
                let cache = $cookie.split('; ');
                cache = cache.map((item) => {
                    const itemPair = item.split('=');
                    let itemKey = "";
                    if (itemPair.length !== 1) {
                        itemKey = itemPair[0];
                    }
                    if (itemKey === key) {
                        flag = true;
                        return cookie;
                    } else {
                        return item;
                    }
                }
                );
                if (!flag) {
                    cache.push(cookie);
                }
                $cookie = cache.join('; ');
                return $cookie;
            }
        },
    });
})();
```

过无限debugger

```JavaScript
(function () {
    const $toString = Function.prototype.toString;
    const symbol = Symbol();
    const fakeToString = function () {
        return typeof this === 'function' && this[symbol] || $toString.call(this);
    }
    function addAttr(func, key, value) {
        Object.defineProperty(func, key, {
            writable: true,
            configurable: true,
            enumerable: false,
            value: value,
        })
    }
    delete Function.prototype.toString;
    addAttr(Function.prototype, "toString", fakeToString);
    addAttr(Function.prototype.toString, symbol, "function toString() { [native code] }");
    globalThis.setNativeCode = function (func, funcName) {
        addAttr(func, symbol, `function ${funcName || func.name || ''}() { [native code] }`);
    }
})();

Function.prototype.$constructor = Function.prototype.constructor;
Function.prototype.constructor = function () {
    var args = arguments;
    for (var i = 0; i < arguments.length; i++) {
        if (arguments[i].indexOf("debugger") != -1) {
            // debugger;
            args[i] = arguments[i].replaceAll("debugger", "        ");
        }
    }
    return Function.prototype.$constructor.apply(this, args);
};

$eval = eval;
eval = function (arg) {
    if (arg.indexOf("debugger") != -1) {
        // debugger;
        arg = arg.replaceAll("debugger", "        ");
        // return function(){return false};
    }
    return $eval(arg);
};

setNativeCode(eval, "eval");
```

7. 内存漫游

[ast-hook-for-js-RE](https://github.com/JSREI/ast-hook-for-js-RE)
[Trace](https://github.com/L018/Trace)

#### AST

##### 混淆示例

```js
const fs = require('fs');
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const generator = require('@babel/generator').default;
const t = require('@babel/types');

const jscode = fs.readFileSync('./input.js', {
    encoding: 'utf-8'
});

const ast = parser.parse(jscode);

const usedHex = new Set();
const generateRandomHex = function () {
    let num;
    do {
        num = Math.floor(Math.random() * 0xffff);
        hex = num.toString(16).padStart(4, '0');
    } while (usedHex.has(hex));
    usedHex.add(hex);
    return hex;
};
let bigArr = [];
const bigArrName = '$_' + generateRandomHex();
const toHex = function (str) {
    const buffer = Buffer.from(str, 'utf8');
    let hexStr = '';
    for (let i = 0; i < buffer.length; i++) {
        // hexStr += '\\x' + ('00' + buffer[i].toString(16)).slice(-2);
        hexStr += '\xB1\xD7\xF7' + ('00' + buffer[i].toString(16)).slice(-2);
    }
    return hexStr;
};

const visitor = {
    MemberExpression(path) {
        if (t.isIdentifier(path.node.property)) {
            const name = path.node.property.name;
            path.node.property = t.stringLiteral(name);
        }
        path.node.computed = true;
    },
    Identifier(path) {
        const name = path.node.name;
        const globalIdentifiers = [
            "Object", "Function", "Array", "Number",
            "parseFloat", "parseInt", "Infinity", "NaN",
            "undefined", "Boolean", "String", "Symbol",
            "Date", "Promise", "RegExp", "Error",
            "AggregateError", "EvalError", "RangeError", "ReferenceError",
            "SyntaxError", "TypeError", "URIError", "JSON",
            "Math", "Intl", "ArrayBuffer", "Atomics",
            "Uint8Array", "Int8Array", "Uint16Array", "Int16Array",
            "Uint32Array", "Int32Array", "Float32Array", "Float64Array",
            "Uint8ClampedArray", "BigUint64Array", "BigInt64Array", "DataView",
            "Map", "BigInt", "Set", "WeakMap",
            "WeakSet", "Proxy", "Reflect", "FinalizationRegistry",
            "WeakRef", "decodeURI", "decodeURIComponent", "encodeURI",
            "encodeURIComponent", "escape", "unescape", "eval",
            "isFinite", "isNaN", "console", "Option",
            "Image", "Audio"
        ];
        if (globalIdentifiers.indexOf(name) != -1) {
            path.replaceWith(t.memberExpression(t.identifier('window'), t.stringLiteral(name), true));
        }
    },
    NumericLiteral(path) {
        const value = path.node.value;
        const key = parseInt(Math.random() * 899999 + 100000, 10);
        const cipherNum = value ^ key;
        path.replaceWith(t.binaryExpression('^', t.numericLiteral(cipherNum), t.numericLiteral(key)));
        path.skip();
    },
    StringLiteral(path) {
        const cipherText = btoa(path.node.value);
        const bigArrIndex = bigArr.indexOf(cipherText);
        let index = bigArrIndex;
        if (bigArrIndex == -1) {
            const length = bigArr.push(cipherText);
            index = length - 1;
        }
        const encStr = t.callExpression(
            t.identifier('atob'),
            [t.memberExpression(t.identifier(bigArrName), t.numericLiteral(index), true)]
        );
        path.replaceWith(encStr);
        path.skip();
    },
    BinaryExpression(path) {
        const operator = path.node.operator;
        const left = path.node.left;
        const right = path.node.right;
        const a = t.identifier('a');
        const b = t.identifier('b');
        const funcNameIdentifier = path.scope.generateUidIdentifier('xxx');
        const func = t.functionDeclaration(
            funcNameIdentifier,
            [a, b],
            t.blockStatement([
                t.returnStatement(t.binaryExpression(operator, a, b)),
            ])
        );
        const blockStatement = path.findParent(p => p.isBlockStatement());
        blockStatement.node.body.unshift(func);
        path.replaceWith(t.callExpression(funcNameIdentifier, [left, right]));
    },
};
traverse(ast, visitor);

const offset = Math.floor(Math.random() * bigArr.length);

(function (arr, num) {
    const disrupt = function (number) {
        while (--number) {
            arr.unshift(arr.pop());
        }
    };
    disrupt(++num);
})(bigArr, offset);

const restoreCode = `(function(arr, num) {
    const disrupt = function(number) {
        while (--number) {
            arr.push(arr.shift());
        }
    };
    disrupt(++num);
})(${bigArrName}, ${offset});`;
const astRestore = parser.parse(restoreCode);
const visitorRestore = {
    MemberExpression(path) {
        if (t.isIdentifier(path.node.property)) {
            const name = path.node.property.name;
            path.node.property = t.stringLiteral(toHex(name));
        }
        path.node.computed = true;
    },
};
traverse(astRestore, visitorRestore);
ast.program.body.unshift(astRestore.program.body[0]);

const renameOwnBinding = function (path) {
    let ownBinding = {};
    let globalBinding = {};
    path.traverse({
        Identifier(p) {
            const name = p.node.name;
            const binding = p.scope.getOwnBinding(name);
            binding && generator(binding.scope.block).code == path + '' ?
                (ownBinding[name] = binding) : (globalBinding[name] = 1)
        }
    });
    for (let originName in ownBinding) {
        let newName;
        do {
            newName = '_$' + generateRandomHex();
        } while (globalBinding[newName]);
        ownBinding[originName].scope.rename(originName, newName);
    }
};
// traverse(ast, {
//     FunctionExpression(path) {
//         const blockStatement = path.node.body;
//         const Statements = blockStatement.body.map(function (v) {
//             if (t.isReturnStatement(v)) return v;
//             const code = generator(v).code;
//             const cipherText = btoa(code);
//             const decryptFunc = t.callExpression(t.identifier('atob'), [t.stringLiteral(cipherText)]);
//             return t.expressionStatement(t.callExpression(t.identifier('eval'), [decryptFunc]));
//         });
//         path.get('body').replaceWith(t.blockStatement(Statements));
//     },
// });
// traverse(ast, {
//     FunctionExpression(path) {
//         const blockStatement = path.node.body;
//         const Statements = blockStatement.body.map(function (v) {
//             if (t.isReturnStatement(v)) return v;
//             // if (!(v.trailingComments && v.trailingComments[0].value == 'ASCIIEncrypt')) return v;
//             // delete v.trailingComments;
//             const code = generator(v).code;
//             const asciiCode = [].map.call(code, function (v) {
//                 return t.numericLiteral(v.charCodeAt(0));
//             });
//             const decryptFuncName = t.memberExpression(t.identifier('String'), t.identifier('fromCharCode'));
//             const decryptFunc = t.callExpression(decryptFuncName, asciiCode);
//             return t.expressionStatement(t.callExpression(t.identifier('eval'), [decryptFunc]));
//         });
//         path.get('body').replaceWith(t.blockStatement(Statements));
//     },
// });
traverse(ast, {
    'Program|FunctionDeclaration|FunctionExpression'(path) {
        renameOwnBinding(path);
    },
});

bigArr = bigArr.map(function (v) {
    return t.stringLiteral(v);
});
bigArr = t.variableDeclarator(t.identifier(bigArrName), t.arrayExpression(bigArr));
bigArr = t.variableDeclaration('var', [bigArr]);
ast.program.body.unshift(bigArr);

let code = generator(ast).code;
// const hexRegex = /\\\\x([0-9A-Fa-f]{2})/g;
// code = code.replace(hexRegex, (_match, pattern) => {
//     return "\\x" + pattern.toUpperCase();
// });
code = code.replace(/\\xB1\\xD7\\xF7/g, '\\x');
fs.writeFileSync('./output.js', code);
```

#### 补环境框架

JS 在线文档：[JavaScript](https://developer.mozilla.org/zh-CN/docs/Web/JavaScript)

##### 创建JS Object对象的方法

```JS
// 1. 字面量
let a = {};

// 2. 通过 new
let b = new Object();

// 3. 通过 Object.create(Object.prototype)
// 这里表示 以Object的原型 为 原型
// 创建出的对象就是 Object 本身
let c = Object.create(Object.prototype);

console.log(a);
console.log(b);
console.log(c);
```

##### 原型链

```JS
// JS中 所有对象都有一个内置属性 称为它的 prototype 原型
// 原型本身是一个对象 故原型对象也有它自己的原型 从而构成了原型链
// 实际上大部分浏览器都使用 __proto__ 而不是 prototype 指向原型
// 当一个属性被访问时 如果在本身找不到 就会逐级到原型中找
// dir(document);
// 颜色深的是自有属性，颜色浅的是继承来的属性
// document -> HTMLDocument -> Document -> Node -> EventTarget -> Object

const greet = {
    hello(name) {
        console.log(`Hello, ${name}!`);
    },
    hi() {
        console.log(`Hello, ${this.name}!`);
    },
};

// 以指定对象为原型 创建对象
// 原型 -> 对象
const hw = Object.create(greet);
console.log(hw);
// hw.hello("World");

// JS中 所有函数都有一个 prototype 属性
// 调用一个函数作为构造函数时 这个属性将作为新对象的原型
// 构造函数
function User(name) {
    this.name = name;
};
// User.prototype.hi = greet.hi;
// 或 复制可枚举的自有属性
Object.assign(User.prototype, greet);

// 原型 -> 构造函数
const userPrototype = User.prototype;
console.log(userPrototype.constructor);

// 构造函数 -> 对象
const hh = new User("Hh");
console.log(hh);
// hh.hi();

// 构造函数 -> 原型
console.log(User.prototype);

// 对象 -> 原型
console.log(hh.__proto__);
// console.log(Object.getPrototypeOf(hh));

// 对象 -> 构造函数
console.log(hh.__proto__.constructor);
```

##### 函数的调用方式

```JS
function add(a, b) {
    console.log(a + b);
}
// 直接调用
add(1, 1);
// apply 方法
add.apply(null, [1, 2]);
// call 方法
add.call(null, 1, 3);

// this 指向当前作用域
function info() {
    console.log(`${this.username}:${this.age}`);
}
username = "alice";
age = 18;
// 直接调用 作用域为整个文件
info();
let bob = {
    username: "bob",
    age: 20,
}
// bind() 可以理解为绑定作用域
const bobInfo = info.bind(bob);
bobInfo();
// 等价于
info.apply(bob);
info.call(bob);

// arguments
function test() {
    console.log(arguments);
}
test(1);
test(1, 2);
test(1, 2, 3);
```

##### Object 常用内置方法

```JS
const person = {
    age: 10,
    email: "",
};
// Object.create
// 以现有对象为原型创建一个新对象
const alice = Object.create(person);

// Object.is
// 判断两个值是否为相同值
// 区别于 == 判断两个值是否相等
console.log(Object.is('1', 1));
// false
console.log('1' == 1);
// true

console.log(Object.is(NaN, NaN));
// true
console.log(NaN == NaN);
// false

console.log(Object.is(-0, 0));
// false
console.log(-0 == 0);
// true

// Object.hasOwn
// 判断对象是否有指定的自有属性
console.log(Object.hasOwn(person, 'age'));
console.log(Object.hasOwn(person, 'username'));

// Object.getOwnPropertyDescriptor
// 返回对象指定自有属性的属性描述（配置）
const ageConfig = Object.getOwnPropertyDescriptor(person, 'age');
console.log(ageConfig.configurable);
console.log(ageConfig.value);

// Object.getOwnPropertyDescriptors
// 返回指定对象的所有自有属性描述符
const personConfig = Object.getOwnPropertyDescriptors(person);
console.log(personConfig.age.writable);

// Object.getOwnPropertyNames
// 返回指定对象的所有自有属性
console.log(Object.getOwnPropertyNames(person));

// Object.getPrototypeOf
// 获取指定对象的原型
console.log(Object.getPrototypeOf(alice));
// 等价于
console.log(alice.__proto__);

// Object.setPrototypeOf
// 为指定对象设置原型
const bob = {};
Object.setPrototypeOf(bob, person);
console.log(bob.age);

// Object.defineProperty
// 为对象定义新属性
const female = {
    email: "",
};
Object.defineProperty(female, 'gender', {
    value: 0,
    writable: false,
})
female.gender = 1; // strict 模式下会报错
console.log(female);
Object.defineProperties(female, {
    height: {
        value: 160,
        writable: true,
    },
    weight: {
        value: 50,
        writable: true,
    }
})
console.log(female)
```

##### toString 和 valueOf

```JS
// toString 和 valueOf
// 这两个函数会自动调用
let a = {
    toString: function () {
        console.log("toString is executing...");
        return "aaa";
    },
    valueOf: function () {
        console.log("valueOf is executing...");
        return 111;
    },
};

console.log(0 + a); // valueOf > toString
console.log('0' + a); // valueOf > toString
console.log(`${a}`); // toString > valueOf
console.log`${a}`;
// 这个结果比较特殊
// 是 ['', ''] {...}
// 表示 字面量字符串数组 + 插值
```

##### 判断对象的类型

```JS
// typeof
console.log(typeof 42); // number
console.log(typeof 'blubber'); // string
console.log(typeof true); // boolean
console.log(typeof NaN); // number
console.log(typeof {}); // object
console.log(typeof []); // object
console.log(typeof null); // object
console.log(typeof undefined); // undefined
console.log(typeof (() => { })); // function

// Object.prototype.toString.call()
console.log(Object.prototype.toString.call(42)); // [object Number]
console.log(Object.prototype.toString.call('blubber')); // [object String]
console.log(Object.prototype.toString.call(true)); // [object Boolean]
console.log(Object.prototype.toString.call(NaN)); // [object Number]
console.log(Object.prototype.toString.call({})); // [object Object]
console.log(Object.prototype.toString.call([])); // [object Array]
console.log(Object.prototype.toString.call(null)); // [object Null]
console.log(Object.prototype.toString.call(undefined)); // [object Undefined]
console.log(Object.prototype.toString.call(() => { })); // [object Function]
```

##### 函数hook

```JS
function add(a, b) {
    return a + b;
}

addTemp = add;
add = function (a, b) {
	// 加一句打印参数
    console.log(`${a} + ${b}`);
    // return addTemp.apply(this, arguments);
    return addTemp(a, b);
}

console.log(add(1, 2));
```

##### 对象属性hook

```JS
// 主要为 赋值 和 取值 两种操作
let person = {
    "age": 10,
}

// hook的时机 对象已经定义或者加载后
ageTemp = person.age;
Object.defineProperty(person, "age", {
    get() {
        console.log("Getting value...");
        return ageTemp;
    },
    set(value) {
        console.log("Setting value...");
        ageTemp = value;
    },
})

console.log(person.age);
person.age = 18;
console.log(person.age);
```

##### 浏览器环境hook

```JS
// 以base64编解码函数为例
atobTemp = atob;
btoaTemp = btoa;
// console.log(atob);

atob = function(input) {
    const output = atobTemp(input);
    console.log(`Func: \`atob()\`; Input: \`${input}\`; Output: \`${output}\`;`);
    return output;
}

btoa = function(input) {
    const output = btoaTemp(input);
    console.log("---- btoa() ----");
    console.log("Input:", input);
    console.log("Output:", output);
    console.log("---- ---- ----");
    return output;
}
// console.log(atob);

btoa("admin");
atob("YWRtaW4=");
```

##### 简易Cookie hook

```JS
// ==UserScript==
// @name         Cookie Hook
// @namespace    http://test.demo/
// @version      1.0
// @description  Hook document.cookie
// @author       v9ng
// @match        *://*/*
// @grant        none
// ==/UserScript==

(function () {
    'use strict';
    let $cookie = document.cookie;
    Object.defineProperty(document, 'cookie', {
        get: function () {
            console.log(`[GET COOIKE]: \`${$cookie}\``);
            return $cookie;
        },
        set: function (val) {
            console.log(`[SET COOIKE]: \`${val}\``);
            debugger; const cookie = val.split(';')[0];
            const pair = cookie.split('=');
            let key = ""
                , value = "";
            if (pair.length === 1) {
                value = pair[0].trim();
            } else {
                key = pair[0].trim();
                value = pair[1].trim();
            }
            let flag = false;
            if ($cookie === '') {
                $cookie = cookie;
                return $cookie;
            } else {
                let cache = $cookie.split('; ');
                cache = cache.map((item) => {
                    const itemPair = item.split('=');
                    let itemKey = "";
                    if (itemPair.length !== 1) {
                        itemKey = itemPair[0];
                    }
                    if (itemKey === key) {
                        flag = true;
                        return cookie;
                    } else {
                        return item;
                    }
                }
                );
                if (!flag) {
                    cache.push(cookie);
                }
                $cookie = cache.join('; ');
                return $cookie;
            }
        },
    });
})();
```

##### hook检测与保护

```JS
atobTemp = atob;
console.log(atob.toString());
// 浏览器下输出为
// function atob() { [native code] }

atob = function(input) {
    const output = atobTemp(input);
    console.log(`Func: \`atob()\`; Input: \`${input}\`; Output: \`${output}\`;`);
    return output;
}
console.log(atob.toString());
// function(input) { ... }

// 检测方式
// .toString()
console.log(atob.toString() === 'function atob() { [native code] }');
// Function.prototype.toString.call
console.log(Function.prototype.toString.call(atob) === 'function atob() { [native code] }');

// 保护
/* 不够好的写法
atob.toString = function() {
    return 'function atob() { [native code] }';
}
*/
// 最好从原型链上改写
Function.prototype.toString = function() {
    // 更通用的写法
    // return `function ${this.name}() { [native code] }`;
    if (this.name == "atob") {
        return 'function atob() { [native code] }';
    }
}
```

##### 立即执行函数

```JS
// 立即执行函数 需要加括号
(function () {
    console.log(1);
})();
(function () {
    console.log(2);
}());
// 以下类似写法可以不用加括号
!function () {
    console.log(3);
}();
~function () {
    console.log(4);
}();
```

##### 函数native化

```JS
(function () {
    // 保留原始toString方法
    const $toString = Function.prototype.toString;
    // symbol值是唯一的
    // symbol值能作为对象属性的标识符 这是该数据类型唯一的用途
    const symbol = Symbol();
    const fakeToString = function () {
        // 类型是函数 且设置过符号属性 即被手动Native化过的 返回符号属性的值
        // 否则调用原始的toString方法
        return typeof this === 'function' && this[symbol] || $toString.call(this);
    }
    // 为对象添加 可写、可配置、不可枚举的属性 的函数
    function addAttr(func, key, value) {
        Object.defineProperty(func, key, {
            writable: true,
            configurable: true,
            enumerable: false,
            value: value,
        })
    }
    // 删除Function的 toString 属性
    delete Function.prototype.toString;
    // 添加一个新的 toString 属性
    addAttr(Function.prototype, "toString", fakeToString);
    // 为新的toString 设置符号属性
    addAttr(Function.prototype.toString, symbol, "function toString() { [native code] }");
    // globalThis
    // 可以理解为兼容浏览器和node等不同环境的 window/self/global
    globalThis.setNativeCode = function (func, funcName) {
        // 输出内容 按照手动传参、本身名称、空 优先级选择
        // 为函数添加一个符号属性 值为native code
        addAttr(func, symbol, `function ${funcName || func.name || ''}() { [native code] }`);
    }
})();

add = function (a, b) {
    return a + b;
}
console.log(add.toString());
// 调用setNativeCode
setNativeCode(add, "add");
console.log(add.toString());
console.log(Function.prototype.toString.toString());
console.log(Function.prototype.toString.call(Function.prototype.toString));
```

##### 函数重命名

```JS
/* 浏览器执行如下代码
Object.getOwnPropertyDescriptor(Document.prototype, "cookie")
// {enumerable: true, configurable: true, get: ƒ, set: ƒ}
Object.getOwnPropertyDescriptor(Document.prototype, "cookie").get
// ƒ cookie() { [native code] }
Object.getOwnPropertyDescriptor(Document.prototype, "cookie").get.name
// get cookie
Object.getOwnPropertyDescriptor(Document.prototype, "cookie").get.toString()
// function get cookie() { [native code] }
*/

funcRename = function (func, name) {
    Object.defineProperty(func, "name", {
        writable: false,
        configurable: true,
        enumerable: false,
        value: name,
    });
}

add = function something(a, b) {
    return a + b;
}

console.log(add.name);
funcRename(add, "add");
console.log(add.name);
funcRename(add, "Some Thing");
console.log(add.name);
```
##### Hook 函数

```JS
funcHook = function (func, funcInfo, isDebug, onEnter, onLeave, isExec) {
    // 原函数 函数属性 是否调试 执行前回调 执行后回调 是否执行原函数
    if (typeof func !== 'function') {
        return func;
    }
    if (funcInfo === undefined) {
        funcInfo = {};
        funcInfo.objName = "globalThis";
        funcInfo.funcName = func.name || '';
    }
    if (isDebug === undefined) {
        isDebug = false;
    }
    if (!onEnter) {
        onEnter = function (obj) {
            console.log(`FUNC: \`${funcInfo.objName}[${funcInfo.funcName}]\` START
ARGS: \`${JSON.stringify(obj.args)}\``);
        }
    }
    if (!onLeave) {
        onLeave = function (obj) {
            console.log(`FUNC: \`${funcInfo.objName}[${funcInfo.funcName}]\` END
RETURN: \`${JSON.stringify(obj.result)}\``);
        }
    }
    if (isExec === undefined) {
        isExec = true;
    }

    hookedFunc = function () {
        if (isDebug) {
            debugger;
        }
        let obj = {};
        obj.args = [];
        for (let i = 0; i < arguments.length; i++) {
            obj.args[i] = arguments[i];
        }
        onEnter.call(this, obj);
        let result;
        if (isExec) {
            result = func.apply(this, obj.args);
        }
        obj.result = result;
        onLeave.call(this, obj);
        return obj.result;
    }

    return hookedFunc;
}

function add(a, b) {
    result = a + b;
    console.log(`${a} + ${b} = ${result}`);
    return result;
}

add(1, 2);
hookedAdd = funcHook(add);
hookedAdd(1, 2);
```

##### 模块化/插件化

```JS
frmwk = {};

(function () {
    const $toString = Function.prototype.toString;
    const symbol = Symbol();
    const fakeToString = function () {
        return typeof this === 'function' && this[symbol] || $toString.call(this);
    }
    function addAttr(func, key, value) {
        Object.defineProperty(func, key, {
            writable: true,
            configurable: true,
            enumerable: false,
            value: value,
        })
    }
    delete Function.prototype.toString;
    addAttr(Function.prototype, "toString", fakeToString);
    addAttr(Function.prototype.toString, symbol, "function toString() { [native code] }");
    frmwk.setNativeCode = function (func, funcName) {
        addAttr(func, symbol, `function ${funcName || func.name || ''}() { [native code] }`);
    }
})();

frmwk.funcRename = function (func, name) {
    Object.defineProperty(func, "name", {
        writable: false,
        configurable: true,
        enumerable: false,
        value: name,
    });
}

frmwk.funcHook = function (func, funcInfo, isDebug, onEnter, onLeave, isExec) {
    if (typeof func !== 'function') {
        return func;
    }
    if (funcInfo === undefined) {
        funcInfo = {};
        funcInfo.objName = "globalThis";
        funcInfo.funcName = func.name || '';
    }
    if (isDebug === undefined) {
        isDebug = false;
    }
    if (!onEnter) {
        onEnter = function (obj) {
            console.log('\x1b[31m%s\x1b[0m', `[FUNC]: \`${funcInfo.objName}[${funcInfo.funcName}]\` START
ARGS: \`${JSON.stringify(obj.args)}\``);
        }
    }
    if (!onLeave) {
        onLeave = function (obj) {
            console.log('\x1b[31m%s\x1b[0m', `[FUNC]: \`${funcInfo.objName}[${funcInfo.funcName}]\` END
RETURN: \`${JSON.stringify(obj.result)}\``);
        }
    }
    if (isExec === undefined) {
        isExec = true;
    }

    hookedFunc = function () {
        if (isDebug) {
            debugger;
        }
        let obj = {};
        obj.args = [];
        for (let i = 0; i < arguments.length; i++) {
            obj.args[i] = arguments[i];
        }
        onEnter.call(this, obj);
        let result;
        if (isExec) {
            result = func.apply(this, obj.args);
        }
        obj.result = result;
        onLeave.call(this, obj);
        return obj.result;
    }
    frmwk.setNativeCode(hookedFunc, funcInfo.funcName);
    frmwk.funcRename(hookedFunc, funcInfo.funcName)
    return hookedFunc;
}

function add(a, b) {
    result = a + b;
    console.log(`${a} + ${b} = ${result}`);
    return result;
}

add(1, 2);
hookedAdd = frmwk.funcHook(add);
hookedAdd(1, 2);
console.log(hookedAdd.toString());
console.log(hookedAdd.name);
```

##### Hook Object

```JS
// hook的本质是替换属性描述符
// 不可配置的属性 无法修改其属性描述符 无法hook
frmwk.objHook = function (obj, objName, propName, isDebug) {
    let originDescriptor = Object.getOwnPropertyDescriptor(obj, propName);
    let targetDescriptor = {};
    if (!originDescriptor.configurable) {
        return;
    }
    targetDescriptor.configurable = true;
    targetDescriptor.enumerable = originDescriptor.enumerable;
    if (Object.hasOwn(originDescriptor, 'writable')) {
        targetDescriptor.writable = originDescriptor.writable;
    }
    if (Object.hasOwn(originDescriptor, 'value')) {
        let value = originDescriptor.value;
        if (typeof value !== 'function') {
            return;
        }
        let funcInfo = {
            "objName": objName,
            "funcName": propName,
        };
        targetDescriptor.value = frmwk.funcHook(value, funcInfo, isDebug);
    }
    if (Object.hasOwn(originDescriptor, 'get')) {
        let getFunc = originDescriptor.get;
        let funcInfo = {
            "objName": objName,
            "funcName": `get ${propName}`,
        };
        targetDescriptor.get = frmwk.funcHook(getFunc, funcInfo, isDebug);
    }
    if (Object.hasOwn(originDescriptor, 'set')) {
        let setFunc = originDescriptor.set;
        let funcInfo = {
            "objName": objName,
            "funcName": `set ${propName}`,
        };
        targetDescriptor.set = frmwk.funcHook(setFunc, funcInfo, isDebug);
    }
    Object.defineProperty(obj, propName, targetDescriptor);
}
```

##### hook 全局

```JS
v9ng.globalHook = function (isDebug) {
    for (const propName in Object.getOwnPropertyDescriptors(globalThis)) {
        const globalProp = globalThis[propName];
        if (typeof globalProp === 'function') {
            const propProtoType = typeof globalProp.prototype;
            if (propProtoType === 'object') {
                v9ng.protoHook(globalProp, isDebug);
            } else if (propProtoType === 'undefined') {
                let funcInfo = {
                    "objName": "globalThis",
                    "funcName": propName,
                }
                v9ng.funcHook(globalProp, funcInfo, isDebug);
            }
        }
    }
}
```

##### 封装Hook

```JS
v9ng = {};

(function () {
    const originToString = Function.prototype.toString;
    const symbol = Symbol();
    const targetToString = function () {
        return typeof this === 'function' && this[symbol] || originToString.call(this);
    }
    function setProp(func, key, value) {
        Object.defineProperty(func, key, {
            writable: true,
            configurable: true,
            enumerable: false,
            value: value,
        })
    }
    delete Function.prototype.toString;
    setProp(Function.prototype, "toString", targetToString);
    setProp(Function.prototype.toString, symbol, "function toString() { [native code] }");
    v9ng.funcNaturalize = function (func, funcName) {
        setProp(func, symbol, `function ${funcName || func.name || ''}() { [native code] }`);
    }
})();

v9ng.funcRename = function (func, funcName) {
    Object.defineProperty(func, "name", {
        writable: false,
        configurable: true,
        enumerable: false,
        value: funcName,
    });
}

v9ng.funcHook = function (originFunc, funcInfo, isDebug, onEnter, onLeave, isExec) {
    if (typeof originFunc !== 'function') {
        return originFunc;
    }
    if (funcInfo === undefined) {
        funcInfo = {};
        funcInfo.objName = "globalThis";
        funcInfo.funcName = originFunc.name || '';
    }
    if (isDebug === undefined) {
        isDebug = false;
    }
    if (!onEnter) {
        onEnter = function (obj) {
            console.log('\x1b[33m%s\x1b[0m', `[FUNC START]: \`${funcInfo.objName}\`->\`${funcInfo.funcName}\`
[ARGS]: \`${JSON.stringify(obj.args)}\``);
        }
    }
    if (!onLeave) {
        onLeave = function (obj) {
            console.log('\x1b[33m%s\x1b[0m', `[FUNC END]: \`${funcInfo.objName}\`->\`${funcInfo.funcName}\`
[RETURN]: \`${JSON.stringify(obj.result)}\``);
        }
    }
    if (isExec === undefined) {
        isExec = true;
    }

    targetFunc = function () {
        if (isDebug) {
            debugger;
        }
        let obj = {};
        obj.args = [];
        for (let i = 0; i < arguments.length; i++) {
            obj.args[i] = arguments[i];
        }
        onEnter.call(this, obj);
        let result;
        if (isExec) {
            result = originFunc.apply(this, obj.args);
        }
        obj.result = result;
        onLeave.call(this, obj);
        return obj.result;
    }
    v9ng.funcNaturalize(targetFunc, funcInfo.funcName);
    v9ng.funcRename(targetFunc, funcInfo.funcName)
    return targetFunc;
}

v9ng.propHook = function (obj, objName, propName, isDebug) {
    let originDescriptor = Object.getOwnPropertyDescriptor(obj, propName);
    let targetDescriptor = {};
    if (!originDescriptor.configurable) {
        return;
    }
    targetDescriptor.configurable = true;
    targetDescriptor.enumerable = originDescriptor.enumerable;
    if (Object.hasOwn(originDescriptor, 'writable')) {
        targetDescriptor.writable = originDescriptor.writable;
    }
    if (Object.hasOwn(originDescriptor, 'value')) {
        let propValue = originDescriptor.value;
        if (typeof propValue !== 'function') {
            return;
        }
        let funcInfo = {
            "objName": objName,
            "funcName": propName,
        };
        targetDescriptor.value = v9ng.funcHook(propValue, funcInfo, isDebug);
    }
    if (Object.hasOwn(originDescriptor, 'get')) {
        let getFunc = originDescriptor.get;
        let funcInfo = {
            "objName": objName,
            "funcName": `get ${propName}`,
        };
        targetDescriptor.get = v9ng.funcHook(getFunc, funcInfo, isDebug);
    }
    if (Object.hasOwn(originDescriptor, 'set')) {
        let setFunc = originDescriptor.set;
        let funcInfo = {
            "objName": objName,
            "funcName": `set ${propName}`,
        };
        targetDescriptor.set = v9ng.funcHook(setFunc, funcInfo, isDebug);
    }
    Object.defineProperty(obj, propName, targetDescriptor);
}

v9ng.protoHook = function (obj, isDebug) {
    let objProto = obj.prototype;
    let objName = obj.name;
    for (const prop in Object.getOwnPropertyDescriptors(objProto)) {
        v9ng.propHook(objProto, `${objName}.prototype`, prop, isDebug);
    }
}

v9ng.globalHook = function (isDebug) {
    for (const propName in Object.getOwnPropertyDescriptors(globalThis)) {
        const globalProp = globalThis[propName];
        if (typeof globalProp === 'function') {
            const propProtoType = typeof globalProp.prototype;
            if (propProtoType === 'object') {
                v9ng.protoHook(globalProp, isDebug);
            } else if (propProtoType === 'undefined') {
                let funcInfo = {
                    "objName": "globalThis",
                    "funcName": propName,
                }
                v9ng.funcHook(globalProp, funcInfo, isDebug);
            }
        }
    }
}
```

##### Proxy

```JS
let symbol = Symbol(123);

let person = {
    "username": "tom",
    1: 2,
    [symbol]: "symbol123",
}

person = new Proxy(person, {
    get: function (target, prop, reciver) {
        console.log(`[GET]: \`${prop.toString()}\``);
        let result = Reflect.get(target, prop, reciver);
        console.log(`[VALUE]: \`${result}\``);
        return result;
    }
})

for (const key in Object.getOwnPropertyDescriptors(person)) {
    console.log(person[key]);
}
console.log(person[symbol]);
```

##### 简单封装Proxy

```JS
v9ng = {};
v9ng.config = {};
v9ng.config.proxy = true;

v9ng.objProxy = function (obj, objName) {
    if (!v9ng.config.proxy) {
        return obj;
    }

    let handler = {
        get: function (target, prop, reciver) {
            console.log(`[GET]: \`${objName}[${prop.toString()}]\``);
            let result = Reflect.get(target, prop, reciver);
            console.log(`[VALUE]: \`${result}\``);
            return result;
        },
    };

    return new Proxy(obj, handler);
}

let symbol = Symbol(123);

let person = {
    "username": "tom",
    1: 2,
    [symbol]: "symbol123",
}

person = v9ng.objProxy(person, "person");

for (const key in Object.getOwnPropertyDescriptors(person)) {
    console.log(person[key]);
}
console.log(person[symbol]);
```

##### 封装Proxy

```JS
v9ng = {};
v9ng.config = {};
v9ng.config.enableProxy = true;

v9ng.objProxy = function (obj, objName) {
    if (!v9ng.config.enableProxy) {
        return obj;
    }

    let handler = {
        get: function (target, prop, reciver) {
            let result = Reflect.get(target, prop, reciver);
            try {
                if (result instanceof Object) {
                    console.log('\x1b[32m%s\x1b[0m', `[GET PROP]: \`${objName}[${prop.toString()}]\`
[TYPE]: ${Object.prototype.toString.call(result)}`);
                    result = v9ng.objProxy(result, `${objName}.${prop.toString()}`);
                } else {
                    console.log('\x1b[32m%s\x1b[0m', `[GET PROP]: \`${objName}[${prop.toString()}]\`
[VALUE]: \`${result}\``);
                }
            } catch (e) {
                console.log('\x1b[31m%s\x1b[0m', `[GET PROP]: \`${objName}[${prop.toString()}]\`
[ERROR]: ${e.message}`);
            }
            return result;
        },
        set: function (target, prop, value, reciver) {
            try {
                if (value instanceof Object) {
                    console.log('\x1b[32m%s\x1b[0m', `[SET PROP]: \`${objName}[${prop.toString()}]\`
[TYPE]: ${Object.prototype.toString.call(value)}`);
                    // TODO: detailed value
                } else {
                    console.log('\x1b[32m%s\x1b[0m', `[SET PROP]: \`${objName}[${prop.toString()}]\`
[VALUE]: \`${value}\``);
                }
            } catch (e) {
                console.log('\x1b[31m%s\x1b[0m', `[SET PROP]: \`${objName}[${prop.toString()}]\`
[ERROR]: ${e.message}`);
            }
            return Reflect.set(target, prop, value, reciver);
        },
        getOwnPropertyDescriptor: function (target, prop) {
            let result = Reflect.getOwnPropertyDescriptor(target, prop);
            try {
                console.log('\x1b[35m%s\x1b[0m', `[GET DESCRIPTOR]: \`${objName}[${prop.toString()}]\`
[TYPE]: ${Object.prototype.toString.call(result)}`);
                // optional
                // if (typeof result !== "undefined") {
                //     result = v9ng.objProxy(result, `${objName}.${prop.toString()}.PropertyDescriptor`);
                // }
            } catch (e) {
                console.log('\x1b[31m%s\x1b[0m', `[GET DESCRIPTOR]: \`${objName}[${prop.toString()}]\`
[ERROR]: ${e.message}`);
            }
            return result;
        },
        defineProperty: function (target, prop, descriptor) {
            try {
                console.log('\x1b[35m%s\x1b[0m', `[SET DESCRIPTOR]: \`${objName}[${prop.toString()}]\`
[VALUE]: \`${descriptor.value}\``);
            } catch (e) {
                console.log('\x1b[31m%s\x1b[0m', `[SET DESCRIPTOR]: \`${objName}[${prop.toString()}]\`
[ERROR]: ${e.message}`);
            }
            return Reflect.defineProperty(target, prop, descriptor);
        },
        apply: function (target, thisArg, args) {
            let result = Reflect.apply(target, thisArg, args);
            try {
                // TODO: add args log
                if (result instanceof Object) {
                    console.log('\x1b[34m%s\x1b[0m', `[FUNC APPLY]: \`${objName}\`
[RESULT TYPE]: ${Object.prototype.toString.call(result)}`);
                } else if (typeof result === 'symbol') {
                    console.log('\x1b[34m%s\x1b[0m', `[FUNC APPLY]: \`${objName}\`
[RESULT]: ${result.toString()}`);
                } else {
                    console.log('\x1b[34m%s\x1b[0m', `[FUNC APPLY]: \`${objName}\`
[RESULT]: ${result}`);
                }
            } catch (e) {
                console.log('\x1b[31m%s\x1b[0m', `[FUNC APPLY]: \`${objName}\`
[ERROR]: ${e.message}`);
            }
            return result;
        },
        construct: function (target, args, newTarget) {
            let result = Reflect.construct(target, args, newTarget);
            console.log(`[CONSTRUCTOR EXEC]: \`${objName}\`
[PROTO TYPE]: ${Object.prototype.toString.call(result)}`);
            return result;
        },
        deleteProperty: function (target, prop) {
            let result = Reflect.deleteProperty(target, prop);
            console.log(`[DELETE PROP]: \`${objName}[${prop.toString()}]\`
[RESULT]: \`${result}\``);
            return result;
        },
        has: function (target, prop) {
            let result = Reflect.has(target, prop);
            console.log(`[PROP EXIST]: \`${objName}[${prop.toString()}]\`
[RESULT]: \`${result}\``);
            return result;
        },
        ownKeys: function (target) {
            let result = Reflect.ownKeys(target);
            const keys = [];
            result.forEach(key => {
                keys.push(key.toString());
            });
            console.log(`[GET KEYS]: \`${objName}\`
[RESULT]: \`[${keys}]\``);
            return result;
        },
        getPrototypeOf: function (target) {
            let result = Reflect.getPrototypeOf(target);
            console.log(`[GET PROTO]: \`${objName}\`
[RESULT]: \`${result}\``);
            return result;
        },
        setPrototypeOf: function (target, proto) {
            let result = Reflect.setPrototypeOf(target, proto);
            console.log(`[SET PROTO]: \`${objName}\`
[TYPE]: ${Object.prototype.toString.call(proto)}`);
            return result;
        },
        preventExtensions: function (target) {
            let result = Reflect.preventExtensions(target);
            console.log(`[PREVENT EXTENSIONS]: \`${objName}\`
[RESULT]: \`${result}\``);
            return result;
        },
        isExtensible: function (target) {
            let result = Reflect.isExtensible(target);
            console.log(`[GET EXTENSIBLE]: \`${objName}\`
[RESULT]: \`${result}\``);
            return result;
        },
    };
    return new Proxy(obj, handler);
};


// let symbol = Symbol(123);
// let person = {
//     "username": "tom",
//     1: 2,
//     [symbol]: "symbol123",
//     "info": {
//         "age": 12,
//         "email": "tom@abc.com",
//     }
// };
// Object.defineProperty(person, "weight", {
//     configurable: false,
//     enumerable: true,
//     value: 60,
// })
// person = v9ng.objProxy(person, "person");
// delete person.weight;
// delete person.username;
// console.log("info" in person);
// console.log("height" in person);
// console.log(Object.keys(person));
// console.log(person.__proto__);
// let testObj = {};
// person.__proto__ = testObj;
// console.log(person[1], person[symbol], person.info.email, person.info.age);
// person.info = {
//     "age": 15,
//     "email": "abc@abc.com",
//     "notfound": "not found",
// }
// console.log(person.info.notfound);
// console.log(Object.getOwnPropertyDescriptors(person));
// person.height = 180;
// function add(a, b) {
//     return a + b;
// }
// add = v9ng.objProxy(add, "add");
// add(1, 2);
// function Address() {
// }
// Object.defineProperty(Address.prototype, Symbol.toStringTag, {
//     value: "AddressTest"
// })
// Address = v9ng.objProxy(Address, "Address");
// let addr = new Address();
```

##### 代理环境检测案例

```JS
// window is not defined
window = globalThis;
// Cannot read properties of undefined (reading 'getItem')
window = v9ng.objProxy(window, "window");
// [GET PROP]: `window[localStorage]`
// [VALUE]: `undefined`
window.localStorage = {};
// [GET PROP]: `window.localStorage[getItem]`
// [VALUE]: `undefined`
window.localStorage.getItem = function () {
    return null;
};
// document is not defined
document = {};
document = v9ng.objProxy(document, "document");
// [GET PROP]: `document[cookie]`
// [VALUE]: `undefined`
document.cookie = '';
// [GET PROP]: `window[navigator]`
// [VALUE]: `undefined`
window.navigator = {};

// [GET PROP]: `window.navigator[userAgent]`
// [VALUE]: `undefined`
// window.navigator.userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36";
// [GET DESCRIPTOR]: `window.navigator[userAgent]`
// [TYPE]: [object Object] // should be undefined
window.navigator.__proto__.userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36";

// [GET PROP]: `window.navigator[webdriver]`
// [VALUE]: `undefined`
// window.navigator.webdriver = false;
// [GET DESCRIPTOR]: `window.navigator[webdriver]`
// [TYPE]: [object Object] // should be undefined
window.navigator.__proto__.webdriver = false;

// [GET PROP]: `window[name]`
// [VALUE]: `undefined`
window.name = '';
// [GET PROP]: `window[Buffer]`
// [TYPE]: [object Function] // should be undefined
// node env
delete Buffer;
console.log('---- START ----');
```

##### vm2

```JS
// 调试断点：node_modules/vm2/lib/vm.js : 288
```

##### 通用转字符串

```JS
const commToString = function(data) {
    if (data === null) {
        return "null";
    }

    const dataType = typeof data;
    if (dataType === 'object' && data instanceof Object) {
        if (Array.isArray(data)) {
            let result = [];
            for (const element of data) {
                result.push(commToString(element));
            }
            return '[' + result.join(',') + ']';
        } else if (Object.prototype.toString.call(data) === '[object Arguments]') {
            let result = [];
            for (let i = 0; i < data.length; i++) {
                result.push(commToString(data[i]));
            }
            return result.join(' ');
        } else {
            const propKeys = Reflect.ownKeys(data);
            let result = [];
            for (const prop of propKeys) {
                result.push(`${commToString(prop)}:${commToString(data[prop])}`);
            }
            return '{' + result.join(',') + '}';
        }
    }

    switch (dataType) {
    case 'string':
        return `"${data}"`;

    case 'function':
        return `\`${data.toString()}\``;

    case 'undefined':
        return "undefined";

    default:
        try {
            return data.toString();
        } catch (e) {
            return "***UNKNOWN***";
        }
    }
};
```
##### 脱环境脚本

```JS
getDescriptorCode = function (obj, propKey, objName, instance) {
    const descriptor = Object.getOwnPropertyDescriptor(obj, propKey);
    let code = `{
        configurable: ${descriptor.configurable},
        enumerable: ${descriptor.enumerable},`;
    if (Object.hasOwn(descriptor, "writable")) {
        code += `
        writable: ${descriptor.writable},`;
    }
    if (Object.hasOwn(descriptor, "value")) {
        const value = descriptor.value;
        const valueType = typeof value;
        if (value instanceof Object) {
            if (valueType === 'function') {
                code += `
        value: function () {
            return v9ng.toolsFunc.funcDispatch(this, "${objName}", "${propKey}", arguments);
        },`;
            } else {
                console.log('\x1b[31m%s\x1b[0m', `[SPECIAL PROP]: \`${objName}[${propKey.toString()}]\`
[VALUE]: ${value}`);
                code += `
        value: {},`;
            }
        } else if (valueType === 'symbol') {
            code += `
        value: ${value.toString()},`;
        } else if (valueType === 'string') {
            code += `
        value: "${value}",`;
        } else {
            code += `
        value: ${value},`;
        }
    }
    if (Object.hasOwn(descriptor, "get")) {
        const get = descriptor.get;
        if (typeof get === 'function') {
            let defaultRet;
            try {
                defaultRet = get.call(instance);
            } catch (e) { }
            if (defaultRet === undefined || defaultRet instanceof Object) {
                code += `
        get: function () {
            return v9ng.toolsFunc.funcDispatch(this, "${objName}", "${propKey}_get", arguments);
        },`;
            } else {
                if (typeof defaultRet === 'string') {
                    code += `
        get: function () {
            return v9ng.toolsFunc.funcDispatch(this, "${objName}", "${propKey}_get", arguments, "${defaultRet}");
        },`;
                } else if (typeof value === 'symbol') {
                    code += `
        get: function () {
            return v9ng.toolsFunc.funcDispatch(this, "${objName}", "${propKey}_get", arguments, ${defaultRet.toString()});
        },`;
                } else {
                    code += `
        get: function () {
            return v9ng.toolsFunc.funcDispatch(this, "${objName}", "${propKey}_get", arguments, ${defaultRet});
        },`;
                }
            }
        } else {
            code += `
        get: undefined,`;
        }
    }
    if (Object.hasOwn(descriptor, "set")) {
        const set = descriptor.set;
        if (typeof set === 'function') {
            code += `
        set: function () {
            return v9ng.toolsFunc.funcDispatch(this, "${objName}", "${propKey}_set", arguments);
        },`;
        } else {
            code += `
        set: undefined,`;
        }
    }
    code += `
    }`;
    return code;
};

genCtorCode = function (ctor, instance) {
    // 构造函数
    const ctorName = ctor.name;
    let code = `(function () { // ${ctorName}
    ${ctorName} = function () {`;
    try {
        new ctor;
    } catch (e) {
        code += `
        return v9ng.toolsFunc.throwError('${e.name}', "${e.message}");`
    }
    code += `
    };
    v9ng.toolsFunc.ctorGuard(${ctorName}, "${ctorName}");`;
    // 原型链
    const proto = ctor.prototype;
    const protoProto = Object.getPrototypeOf(proto);
    const protoProtoName = protoProto[Symbol.toStringTag];
    if (protoProtoName !== undefined) {
        code += `
    Object.setPrototypeOf(${ctorName}.prototype, ${protoProtoName}.prototype);`;
    }
    // 属性
    const metaProperties = [
        "arguments",
        "caller",
        "length",
        "name",
        "prototype",
    ];
    for (const propKey in Object.getOwnPropertyDescriptors(ctor)) {
        if (metaProperties.indexOf(propKey) !== -1) {
            continue;
        }
        const descriptorCode = getDescriptorCode(ctor, propKey, ctorName, instance);
        code += `
    v9ng.toolsFunc.defineProperty(${ctorName}, "${propKey}", ${descriptorCode});`;
    }
    // 原型属性
    for (const propKey in Object.getOwnPropertyDescriptors(ctor.prototype)) {
        if (propKey === "constructor") {
            continue;
        }
        const descriptorCode = getDescriptorCode(ctor.prototype, propKey, `${ctorName}.prototype`, instance);
        code += `
    v9ng.toolsFunc.defineProperty(${ctorName}.prototype, "${propKey}", ${descriptorCode});`;
    }
    code += `
})();`;

    console.log(code);
    copy(code);
};

genObjCode = function (obj, objName, instance) {
    let code = `(function () { // ${objName}
    ${objName} = {};`;
    const protoName = Object.getPrototypeOf(obj)[Symbol.toStringTag];
    if (protoName !== undefined) {
        code += `
    Object.setPrototypeOf(${objName}, ${protoName}.prototype);`;
    }
    for (const propKey in Object.getOwnPropertyDescriptors(obj)) {
        const descriptorCode = getDescriptorCode(obj, propKey, objName, instance);
        code += `
    v9ng.toolsFunc.defineProperty(${objName}, "${propKey}", ${descriptorCode});`;
    }
    code += `
})();`;

    console.log(code);
    copy(code);
};
```

##### 收集鼠标移动轨迹

```JS
console.log('*** start ***');
let list = [];
let encodeFunc = function encodeFunc(resultList) {
    let result = [];
    for (let i = 0; i < 10; i++) {
        result.push(resultList[i].clientX);
        result.push(resultList[i].clientY);
        result.push(resultList[i].timeStamp);
    }
    let str = btoa(result.toString());
    console.log(str);
}
let mousemoveFunc = function mousemoveFunc(event) {
    const obj = {
        clientX: event.clientX,
        clientY: event.clientY,
        timeStamp: event.timeStamp,
        type: event.type,
    };
    list.push(obj);
}
let mousedownFunc = function mousedownFunc(event) {
    const obj = {
        clientX: event.clientX,
        clientY: event.clientY,
        timeStamp: event.timeStamp,
        type: event.type,
    };
    list.push(obj);
}
let mouseupFunc = function mouseupFunc(event) {
    const obj = {
        clientX: event.clientX,
        clientY: event.clientY,
        timeStamp: event.timeStamp,
        type: event.type,
    };
    list.push(obj);
    let len = list.length;
    let resultList = [];
    for (let i = len - 10; i < len; i++) {
        resultList.push(list[i]);
    }
    encodeFunc(resultList);
}
let setTimeoutcallBack = function setTimeoutcallBack() {
    console.log("*** timeout call ***");
    document.addEventListener("mousemove", mousemoveFunc);
    document.addEventListener("mousedown", mousedownFunc);
    document.addEventListener("mouseup", mouseupFunc);
}
let unloadFunc = function unloadFunc() {
    console.log("*** page unload ***");
    debugger ;
}
let loadFunc = function loadFunc() {
    console.log("*** page load ***");
}
setTimeout(setTimeoutcallBack, 0);
window.addEventListener("load", loadFunc);
window.addEventListener("unload", unloadFunc);
console.log('*** end ***');

// copy(commToString(mouseList.slice(0, 500)));
```

##### 补环境步骤

1. 补缺少的环境
2. 实现环境方法：mdn查参数、返回值、作用。好实现的实现：只对当前对象产生影响直接给this赋值或者取值即可，对全局有影响的最复杂需要观察使用情况按需补；不好实现的：没有返回值的方法有些有时不用补，有返回值且较为固定或易于模拟的有些有时不用完全实现，只给出输出即可。



