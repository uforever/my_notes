## 基础知识

###  通用模块

- **idautils** 这个模块提取了最有用和最方便的函数，允许您立即跳转并与反汇编交互，而无需从一开始就仔细检查整个IDAPython API。您可以在这里找到要遍历整个段的函数、函数（由IDA创建，也可以是用户定义的）、命名位置等。
- **ida_idaapi** 当您想要创建自定义插件或处理事件时，`ida_idaapi`模块非常方便，因为它允许您访问更高级的功能，并允许与整个系统进行交互
- **idc** 此模块提供了原本是本机IDAIDC脚本语言一部分的函数，这些函数被包装以在IDAPython API中使用。如果您已经熟悉IDC脚本，这是一个很好的起点。
- **ida_funcs** 这个模块提供了在IDA中创建和操作函数的工具。
- **ida_kernwin** 这个模块提供了与IDA UI交互的功能，因此您可以创建自定义对话框等。

### 常用变量和常量

最常传递的变量之一是`ea`，它引用有效内存地址（有效地址）。另一方面，`BADADDR`是指示无效地址的常量。它用于指示操作（如查询函数）失败或返回无效结果，或表示特定内存位置不可用。当您使用返回内存地址的函数时，最佳做法是检查结果是否等于BADADDR，以确保操作成功。

### 常用代码片段

#### 地址

- 获取当前地址
```python
ea = idc.here()
print(f"Current address: {hex(ea)}")
```
- 设置当前地址
```python
idc.jumpto(0x401000)
```
- 获取最小地址
```python
idc.get_inf_attr(INF_MIN_EA)
```
- 获取最大地址
```python
idc.get_inf_attr(INF_MAX_EA)
```
- 列出所有指令地址
```python
import idautils
for ea in idautils.Heads():
  print(hex(ea))
```
- 获取与给定地址关联的名称
```python
ida_name.get_name(0x100000da0)
```
- 获取与给定名称关联的地址
```python
ida_name.get_name_ea(0, "main")
```

#### 数据

- 读取数据
```python
byte_value = idc.get_wide_byte(0x14001E5D8) # Read a byte at address 0x14001E5D8

word_value = idc.get_wide_word(0x14001E5D8) # Read a word (2 bytes) at address 0x14001E5D8

dword_value = idc.get_wide_dword(0x14001E5D8) # Read a double word (4 bytes) at address 0x14001E5D8

print(f"Byte: {hex(byte_value)}, Word: {hex(word_value)}, Dword: {hex(dword_value)}")
```
- 写入数据
```python
idc.patch_byte(0x401000, 0x90)  # Write a byte (0x90) at address 0x401000
idc.patch_word(0x401002, 0x9090)  # Write a word (0x9090) at address 0x401002
idc.patch_dword(0x401004, 0x90909090)  # Write a double word (0x90909090) at address 0x401004
```

#### 注释

- 添加注释
```python
idc.set_cmt(0x401000, "This is a comment", 0)  # Add a regular comment at address 0x401000
idc.set_cmt(0x401000, "This is a repeatable comment", 1)  # Add a repeatable comment at address 0x401000
```
- 获取注释
```python
comment = idc.get_cmt(0x401000, 0)  # Get a regular comment at address 0x401000
print(f"Comment: {comment}")
```

#### 段

- 获取指定地址的段名称
```python
idc.get_segm_name(ea)
idc.get_segm_name(0x14001B004)
```
- 获取第一个段地址
```python
idc.get_first_seg()
```
- 遍历所有段并返回段名称
```python
for seg in idautils.Segments(): print (idc.get_segm_name(seg))
```

#### 函数

- 创建函数
```python
idc.add_func(0x401000, 0x401050)  # Create a function starting at 0x401000 and ending at 0x401050
```
- 删除函数
```python
idc.del_func(0x401000)  # Delete the function at 0x401000
```
- 获取指定地址的函数名
```python
get_func_name(ea)
get_func_name(0x1400023BB)
```
- 遍历所有函数并打印它们的有效地址和名称
```python
for func_ea in idautils.Functions(): func_name = idc.get_func_name(func_ea); print(hex(func_ea), func_name)
```
#### 交叉引用

- 列出地址的交叉引用
```python
for xref in idautils.XrefsTo(0x1400023A0):
    print(f"Xref to 0x1400023A0 from {hex(xref.frm)}")
```
- 列出地址的主动引用
```python
for xref in idautils.XrefsFrom(0x1400023A0):
    print(f"Xref from 0x1400023A0 to {hex(xref.to)}")
```
- 遍历所有对特定地址的交叉引用，并打印引用的来源地址
```python
for ref in idautils.XrefsTo(ea):
  print(hex(ref.frm))
```

#### UI

- 设置背景颜色
```python
set_color(0x1400023A0, idc.CIC_ITEM, 0x007fff)  # Set background color for the function starting at address 0x1400023A0
```
- 弹出对话框
```python
ida_kernwin.info("This is a custom message dialog. Good luck with learning IDAPython API!")
```

## 常用API

```python
# 获取屏幕光标处的地址
ida_kernwin.get_screen_ea()
# addr = ida_kernwin.get_screen_ea()

```