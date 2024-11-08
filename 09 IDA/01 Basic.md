## UI

### 主菜单

#### File

##### Load file

- Reload the input file 重新加载输入文件
- Load additional file 加载额外文件
- Load IDS file IDS文件包含众所周知的函数（例如MS Windows API中的函数）
- Load DBG debug information file 加载DBG调试信息文件
- Load PDB debug information file 加载PDB调试信息文件
- Load TDS debug information file 加载TDS调试信息文件
- Load FLIRT signature file 加载FLIRT签名文件
- Load C header 加载C语言头文件

##### Script file

可以执行内置脚本引擎（[IDC](https://docs.hex-rays.com/developer-guide/idc/core-concepts)或Python）支持的任何脚本文件，或添加插件脚本语言。要使用的语言由脚本的文件扩展名选择。

##### Script command

可以编辑并执行一个用内置IDC语言或任何其他注册的extlang编写的小脚本。

##### Produce output files

- Create MAP File 创建MAP文件
- Create ASM File 创建ASM文件
- Create INC File 创建INC文件 包含所有类型（结构和枚举）的信息
- Create LST File 创建LST文件
- Create Executable File 创建可执行文件 通常在打补丁后使用
- Create Difference File 创建差异文件
- Create HTML File 创建HTML文件
- Create flow chart GDL file 生成流程图GDL文件
- Create call graph GDL file 生成调用图GDL文件
- Dump database to IDC file 将数据库转储到IDC文件
- Dump typeinfo to IDC file 将typeinfo转储到IDC文件
- Create C header file 创建C头文件

##### Take database snapshot

生成数据库快照

##### Save database

保存数据库

##### Save database as...

数据库另存为……

##### Exit

退出IDA

#### Edit

##### Export data

导出数据

##### Undo an action

撤销 快捷键 `<C-z>`

##### Redo an action

重做 快捷键 `<C-y>`

##### Convert to instruction

转换为指令 快捷键 `c`

##### Convert to data

转换为数据 快捷键 `d`

##### Convert to string literal

转换为字符串文字 快捷键 `a` 可以选择不同语言风格的字符串格式

##### Convert to array

转换为数组 需要先将第一个元素类型设置好 输入数组长度
已经被识别为字符串的内容 可以通过这个选项调整长度

##### Undefine a byte

取消定义 快捷键 `u`

##### Rename

重命名 快捷键 `n`

##### Operand types

这个选项可以将操作数类型改为偏移量、数字、字符等。使用它可以使反汇编后的文本更容易理解。

- Convert operand to offset 将操作数转换为偏移量
  - Convert operand to offset (data segment) 将操作数转换为数据段偏移
  - Convert operand to offset (code segment) 将操作数转换为代码段偏移
  - Convert operand to offset (any segment) 将操作数转换为任意段偏移
  - Convert operand to offset (user-defined base) 将操作数转换为偏移量（用户定义的基）
  - Convert operand to structure offset 将操作数转换为结构体偏移 需要先定义好结构体 快捷键 `t`
- Convert operand to number 将操作数转换为数字
  - Convert operand to number 默认数字 快捷键 `#`
  - Convert operand to hexadecimal number 将操作数转换为十六进制数 快捷键 `q`
  - Convert operand to decimal number 将操作数转换为十进制数 快捷键 `h` 这个快捷键比较常用 可以将数字在十六进制和十进制之间转换
  - Convert operand to octal number 将操作数转换为八进制数
  - Convert operand to binary number 将操作数转换为二进制数 快捷键 `b`
  - Toggle leading zeroes 前缀0显示开关 快捷键 `0`
- Convert operand to character 将操作数转换为字符 快捷键 `r`
- Convert operand to segment 将操作数转换为段
- Convert operand to enum 将操作数转换为符号常量（枚举）
- Convert operand to stack variable 将操作数转换为堆栈变量 需要先定义变量
- Change operand sign 更改操作数符号
- Bitwise negate operand 按位取反操作数
- User-defined operand 用户定义操作数
- Set operand type 设置操作数类型

##### Comments

- Create a regular comment 创建常规注释
- Create a repeatable comment 创建可重复的注释 一个可重复的注释将附加到当前项和引用它的所有其他项
- Create additional comment lines 创建其他注释行

##### Functions

- Create Function 定义一个新函数 快捷键 `p`
- Edit Function 编辑函数 修改函数的起始地址、名称 和 Function flags 函数标志
  - Does not return 不返回
  - Far function 远函数 在区分近和远功能的处理器（例如PC x86）上，将函数标记为“远”。这可能会影响为返回地址保留的特殊堆栈帧字段的大小，以及对此函数调用的分析。
  - Library func 库函数 将函数标记为编译器运行时库代码的一部分。此标志通常在应用FLIRT签名时设置
  - Static func 静态函数 目前，IDA不使用此标志
  - BP based frame BP框架 使用帧指针 [BP+xxx]形式的操作数将自动转换为堆栈变量
  - BP equal to SP BP等于SP 帧指针指向堆栈的底部，而不是典型的局部变量区域的开始处。
  - Fuzzy SP 模糊SP 函数通过未知值更改SP，例如：`and esp, 0FFFFFFF0h`
  - Outlined code 大纲代码 该函数不是一个真实的函数，而是由编译器代码优化时提取的多个函数的公共指令序列的片段。
- Append Function Tail 追加函数尾部
- Remove Function Tail 删除函数尾部
- Delete Function 删除函数
- Set Function End 设置函数结束地址
- Edit the argument location 编辑参数或返回值地址
- Stack Variables Window “堆栈变量”窗口 堆栈变量在内部表示为一个结构体。这个结构体由两部分组成：局部变量和函数参数。
- Change Stack Pointer 更改堆栈指针
- Rename register 重命名寄存器
- Set function/item type 设置类型

	***TODO: 复杂函数类型定义、自定义调用、分散的参数位置、结构体偏移指针等，参考：[Functions | Hex-Rays Docs](https://docs.hex-rays.com/user-guide/user-interface/menu-bar/edit/functions)***

##### Structures

- Define a new structure 定义新结构
- Duplicate a structure type 复制结构体
- Delete a structure 删除结构体
- Expand a structure 展开结构体
- Shrink a structure 缩小结构体
- Edit a structure 编辑结构体
- Declare a structure variable 声明指定结构类型的变量
- Force zero field offset
- Select union member 选择union成员
- Create a new structure from current data 从当前数据创建新结构 **建议使用**这种选择的方式来创建结构体 函数名的字段设置为标识符方便跳转
- Copy field info to pointers 将字段信息复制到指针
- Add/Edit an enum 添加/编辑枚举
- Delete an enum type 删除枚举类型
- Define an enum member 定义枚举成员
- Edit an enum member 编辑枚举成员
- Delete an enum member 删除枚举成员

查看所有快捷键：**Options -> Show command palette...**

### 工具栏

前进、后退
高亮固定
启动/停止分析
调试运行、暂停、终止

### 导航栏

显示了分析的二进制文件的图形表示，并简要概述了其内容以及可能需要注意的区域。黄色箭头（指示器）显示了光标当前在反汇编视图中的位置。

### 输出

输出窗口是显示各种消息和日志的地方，通常描述IDA当前正在做的事情，如分析数据或运行脚本。在CLI框中，您可以用[IDC语言](https://docs.hex-rays.com/developer-guide/idc/core-concepts)或[IDAPython](https://docs.hex-rays.com/developer-guide/idapython/idapython-getting-started)键入命令。

### 状态栏

分析状态：idle表示空闲
搜索方向
剩余可用磁盘空间

鼠标控制：
- 右键菜单 `reanalyze the program` 重新分析程序

### 子视图

#### IDA View

有三种模式：
##### 图形视图

默认的反汇编表示。通过`Space`键和线性文本模式互相切换。
图由 _节点_（块）和 _边_（块之间的箭头）组成。
每个 _节点_ 大致对应于一个基本块（**基本块**是直线代码序列，除了入口和出口没有分支）。
_边_ 表示节点之间的代码流，其颜色根据代码流的类型而变化。条件跳转/分支具有两个输出边：绿色表示采用的分支，红色表示未采用的分支。其他类型的边是蓝色的。指向后的边宽度较粗（通常意味着它们可能是循环的一部分）。

键盘控制（经测试，不建议使用）：
- `w` 自动缩放，使整个图形适合可见窗口区域。
- `1` 缩放回初始比例
- `<C-Up>` 移动到父节点
- `<C-Down>` 移动到子节点

鼠标控制：
- 双击一条边以跳转到另一头的节点
- 悬停在边上以预览另一头的节点
- 拖动背景以向任何方向平移整个图形
- 鼠标滚轮上下滚动
- Alt+滚轮 左右滚动
- Ctrl+滚轮 缩放
- 可以通过拖动节点的标题来移动单个节点
- 通过右键菜单中的 `Layout graph` 选项回归初始布局
- 可以通过 按住Ctrl的同时 拖出方形选择框来选择多个节点
- 也可以通过 按住Ctrl的同时 单击多个节点的标题选择多个节点
- 通过右键菜单中的 `Group nodes` 和 `Ungroup nodes` 可以对节点进行分组和取消分组操作
##### 线性文本模式

通过`Space`键和图形视图互相切换。

##### 邻近视图
#### Pseudocode 伪代码

伪代码由著名的`F5`快捷键生成，将汇编语言翻译成人类可读的、类似C的伪代码。单击`Tab`直接跳转到伪代码视图。
#### Hex Dump View

IDA视图、伪代码和十六进制视图可以同步，这意味着它们突出显示所分析程序的同一部分，并且在其中一个视图中所做的更改在其他视图中可见。

键盘控制：
- `1` 单字节分组。
- `2` 2字节分组。
- `4` 4字节分组。
- `8` 8字节分组。
- `f` 单精度浮点数表示32bit分组。
- `d` 双精度浮点数表示64bit分组。
- `l` 长双精度浮点数表示80bit分组。
- `h` 十六进制表示。
- `u` 无符号整数表示。
- `s` 有符号整数表示。
- `<F2>` 进入/退出编辑模式。

鼠标控制：
- 同步 右键菜单选择 `Synchronize with` ，主动选择IDA视图或伪代码视图同步。IDA视图或伪代码视图的右键菜单中也有类似的同步选项。特别的，调试状态下的HexView可以与寄存器中的地址进行同步。
- 右键菜单选择 `Data format` 设置布局和数据格式。
- 右键菜单选择 `Columns` 设置列数。
- 右键菜单选择 `Text` 设置文本选项。
- 右键菜单选择 `Edit...` 进入编辑模式。 
#### Local Types 本地类型

可以对结构体、枚举进行增删改查操作

键盘控制：
- `d` 更改数据类型 / 插入枚举值

#### Functions View

鼠标控制：
- 右键菜单 `Turn on synchronization` 开启与IDA视图或伪代码视图的同步


## 杂项

### IDA数据库文件

以 `.i64` （以前是 `.idb` ） 为后缀。在开始加载文件之后，IDA不需要访问二进制文件。所做的任何修改都将保存在数据库中，不会影响原始可执行文件。

### 跳转

- 双击地址或函数时，IDA会自动跳转到该位置并重新定位显示。
- 主菜单 **Jump -> Jump to address..** 或 快捷键 `g` 输入函数名或地址。
- 工具栏 向后跳转（快捷键`<Esc>`） 向前跳转（快捷键`<C-CR>`）  鼠标上如果有前进后退快捷键也可以使用

### 交叉引用

- 主菜单 **Jump -> Jump to xref to operand...** 或 快捷键 `x` 输入函数名或地址。
- 快捷键 `<C-A-x>` 全局引用

### 操纵反汇编结果

#### 重命名堆栈变量

- 右键菜单 `Rename` 或 快捷键 `n` 插入新名称。
- 想在任何时候回归IDA提供的原始虚拟名称，可以将该字段置空后点击确定。
#### 添加注释

- 快捷键 `/` 伪代码注释
- 快捷键 `;` `:` 反汇编注释

### 自定义布局

- 主菜单 **Windows -> Save desktop** 保存当前桌面布局

### 调试

- 主菜单 **Debugger -> Select debugger...** 选择调试器
- 主菜单 **Debugger -> Debugger options** 调试器选项
- 添加断点 快捷键 `<F2>` 或 右键菜单选择
- 启动调试 快捷键 `<F9>` 或 工具栏运行按钮

### 插件

- 将插件文件/文件夹复制到IDA安装目录中的 plugins 目录下
- 或 主菜单 **File -> Script file...** 单次加载插件