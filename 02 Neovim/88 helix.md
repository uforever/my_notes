# 按键映射


> 标记为 LSP 的映射需要该文件类型的语言服务器。

> 标记为 TS 的映射需要该文件类型的 tree-sitter 语法支持。

> Windows Terminal想要正确显示文本，可以启用 AtlasEngine。

## Normal mode

### 光标移动

> 注意：与 Vim 不同的是，`f`, `F`, `t` 和 `T` 并不局限于当前行。

| 按键                   | 描述                                        | 命令                     |
| -----                 | -----------                                        | -------                     |
| `h`, `Left`           | 左移                                          | `move_char_left`            |
| `j`, `Down`           | 下移                                          | `move_visual_line_down`     |
| `k`, `Up`             | 上移                                            | `move_visual_line_up`       |
| `l`, `Right`          | 右移                                         | `move_char_right`           |
| `w`                   | 移动到下一个 word 开头（前一位）                               | `move_next_word_start`      |
| `b`                   | 移动到上一个 word 开头                           | `move_prev_word_start`      |
| `e`                   | 移动到下一个 word 结尾                                 | `move_next_word_end`        |
| `W`                   | 移动到下一个 WORD 开头（前一位的空格或换行）                               | `move_next_long_word_start` |
| `B`                   | 移动到下一个 WORD 开头（空格或换行后）                           | `move_prev_long_word_start` |
| `E`                   | 移动到下一个 WORD 结头（空格或换行前）                                 | `move_next_long_word_end`   |
| `t`                   | 找到下个字符（前一位）                               | `find_till_char`            |
| `f`                   | 找到上个字符                                     | `find_next_char`            |
| `T`                   | 找到上个字符（后一位）                           | `till_prev_char`            |
| `F`                   | 找到上个字符                                 | `find_prev_char`            |
| `G`                   | `nG` 表示去第 `n` 行                            | `goto_line`                 |
| `Alt-.`               | 重复上次光标移动 (`f`, `t` or `m`)               | `repeat_last_motion`        |
| `Home`                | 移动到当前行开头                      | `goto_line_start`           |
| `End`                 | 移动到当前行结尾                        | `goto_line_end`             |
| `Ctrl-b`, `PageUp`    | 往上翻页                                       | `page_up`                   |
| `Ctrl-f`, `PageDown`  | 往下翻页                                     | `page_down`                 |
| `Ctrl-u`              | 往上翻半页                                  | `half_page_up`              |
| `Ctrl-d`              | 往下翻半页                                | `half_page_down`            |
| `Ctrl-i`              | 移动到跳转列表上的下一项（跳转记录）                       | `jump_forward`              |
| `Ctrl-o`              | 移动到跳转列表上的上一项（跳转记录）                      | `jump_backward`             |
| `Ctrl-s`              | 保存当前光标位置/选区到跳转列表         | `save_selection`            |

### 文本修改

| 按键 | 描述 | 命令 |
| ---- | ---- | ---- |
| `r` | 替换为一个字符 | `replace` |
| `R` | 替换为复制的文本（剪贴板中的文本） | `replace_with_yanked` |
| `~` | 切换所选文本的大小写 | `switch_case` |
| `` ` `` | 将所选文本设置为小写 | `switch_to_lowercase` |
| `` Alt-` `` | 将所选文本设置为大写 | `switch_to_uppercase` |
| `i` | 在所选内容之前插入 | `insert_mode` |
| `a` | 在所选内容之后插入（追加） | `append_mode` |
| `I` | 在当前行开头插入 | `insert_at_line_start` |
| `A` | 在当前行结尾插入 | `insert_at_line_end` |
| `o` | 在所选内容下方开始新的一行 | `open_below` |
| `O` | 在所选内容上方开始新的一行 | `open_above` |
| `.` | 重复上次插入 | N/A |
| `u` | 撤销修改 | `undo` |
| `U` | 恢复修改 | `redo` |
| `Alt-u` | 回到上一次历史 | `earlier` |
| `Alt-U` | 回到下一次历史 | `later` |
| `y` | 复制选择的内容 | `yank` |
| `p` | 在所选内容后方粘贴 | `paste_after` |
| `P` | 在所选内容前方粘贴 | `paste_before` |
| `"` `<reg>` | 选择一个寄存器把文本复制到那里或者从那粘贴，如 `"ay` 再 `"ap` | `select_register` |
| `>` | 缩进所选内容 | `indent` |
| `<` | 取消缩进所选内容 | `unindent` |
| `=` | 对所选内容格式化(**LSP**) | `format_selections` |
| `d` | 删除所选内容 | `delete_selection` |
| `Alt-d` | 删除所选内容，但不复制被删除的内容 | `delete_selection_noyank` |
| `c` | 修改所选内容（删除并进入插入模式） | `change_selection` |
| `Alt-c` | 修改所选内容（删除并进入插入模式），但不复制被删除的内容 | `change_selection_noyank` |
| `Ctrl-a` | 对光标下的数字自增 | `increment` |
| `Ctrl-x` | 对光标下的数字自减 | `decrement` |
| `Q` | 开始/结束录制到所选寄存器的宏，录制前后都需要执行一次，直接 `Q` 或者指定寄存器 `"bQ`  | `record_macro` |
| `q` | 从所选寄存器回放录制的宏，直接 `q` 或者 `"bq` | `replay_macro` |

#### Shell命令

| 按键 | 描述 | 命令 |
| ---- | ---- | ---- |
| <code>&#124;</code> | 把每个选定内容作为参数，如一个目录，传递给指定命令，如`ls`，并将结果替换选中的文本。 | `shell_pipe` |
| <code>Alt-&#124;</code> | 把每个选定内容放入管道，并忽略掉 shell 命令的输出。 | `shell_pipe_to` |
| `!` | 运行 shell 命令，将其结果插入（每个选区之前） | `shell_insert_output` |
| `Alt-!` | 运行 shell 命令，将其结果追加（每个选区之后） | `shell_append_output` |
| `$` | 将每个选区通过管道传输到 shell 命令中，保留命令返回为 0 的选区 | `shell_keep_pipe` |


### 选择文本
| 按键 | 描述 | 命令 |
| ---- | ---- | ---- |
| `s` | 在选区范围内的选择所有正则表达式匹配的内容（如匹配windows绝对路径 `[a-zA-Z]:\\(?:[^\\/:*?"<>\|\r\n]+\\)*[^\\/:*?"<>\|\r\n]*`） | `select_regex` |
| `S` | 在选区范围内的选择正则表达式匹配之外的内容 | `split_selection` |
| `Alt-s` | 在多行选区中对每个非空行结尾放置一个光标 | `split_selection_on_newline` |
| `Alt-minus` | 合并多选区 | `merge_selections` |
| `Alt-_` | 合并连续选区（不连续的仍然是多选区之一） | `merge_consecutive_selections` |
| `&` | 按列对齐各个选区 | `align_selections` |
| `_` | 从选区中移除首尾空格来缩小选取 | `trim_selections` |
| `;` | 收敛选区到光标 | `collapse_selection` |
| `Alt-;` | 反转选区光标和锚点 | `flip_selections` |
| `Alt-:` | 确保选区往正文本方向（即把所有选区光标放置于选区结尾） | `ensure_selections_forward` |
| `,` | 只保留主选区（多光标时收缩到主光标） | `keep_primary_selection` |
| `Alt-,` | 移除主选区（多光标时移除主光标） | `remove_primary_selection` |
| `C` | 对下一行复制选区（多光标时往下增加一个相同位置的光标） | `copy_selection_on_next_line` |
| `Alt-C` | 对上一行复制选区（多光标时往上增加一个相同位置的光标） | `copy_selection_on_prev_line` |
| `(` | 把上一个选区作为主选区（主选区后移） | `rotate_selections_backward` |
| `)` | 把下一个选区作为主选区（主选区前移） | `rotate_selections_forward` |
| `Alt-(` | 把每个选区内容换成其下一个选区的内容（选区内容后移） | `rotate_selection_contents_backward` |
| `Alt-)` | 把每个选区内容换成其上一个选区的内容（选区内容前移） | `rotate_selection_contents_forward` |
| `%` | 选择整个文件 | `select_all` |
| `x` | 选择当前行；如果已选择，延伸到下一行 | `extend_line_below` |
| `X` | 将选区扩展到行边界 | `extend_to_line_bounds` |
| `Alt-x` | 将选区收缩到行边界 | `shrink_to_line_bounds` |
| `J` | 在选取内用空格拼接行 | `join_selections` |
| `Alt-J` | 在选取内拼接行，但连接处使用多光标 | `join_selections_space` |
| `K` | 多选区内只保留匹配正则的选区 | `keep_selections` |
| `Alt-K` | 多选区内移除匹配正则的选区 | `remove_selections` |
| `Ctrl-c` | 注释/取消注释所选内容 | `toggle_comments` |
| `Alt-o`, `Alt-up` | 将所选内容拓展到上一级父语法节点 (**TS**) | `expand_selection` |
| `Alt-i`, `Alt-down` | 将所选内容收缩语法节点 (**TS**) | `shrink_selection` |
| `Alt-p`, `Alt-left` | 选择语法树中的上一个同级节点 (**TS**) | `select_prev_sibling` |
| `Alt-n`, `Alt-right` | 选择语法树中的下一个同级节点 (**TS**) | `select_next_sibling` |

### 搜索文本

默认情况下，搜索命令都在 `/` 寄存器上操作。使用 `"<char>` 来操作不同的寄存器。

| 按键 | 描述 | 命令 |
| ---- | ---- | ---- |
| `/` | 文本正方向正则搜索 | `search` |
| `?` | 文本反方向正则搜索 | `rsearch` |
| `n` | 选择下一个匹配到的搜索内容（选区会增加） | `search_next` |
| `N` | 选择上一个匹配到的搜索内容（选区会增加） | `search_prev` |
| `*` | 使用当前选中的文本作为搜索模式 | `search_selection` |

### 子模式

这些子模式可从正常模式访问，通常在命令结束后切换回正常模式。

| 按键 | 描述 | 命令 |
| ---- | ---- | ---- |
| `v` | select (extend) mode | `select_mode` |
| `g` | goto mode | N/A |
| `m` | match mode | N/A |
| `:` | command mode | `command_mode` |
| `z` | view mode | N/A |
| `Z` | sticky view mode | N/A |
| `Ctrl-w` | window mode | N/A |
| `Space` | space mode | N/A |

这些模式（命令模式除外）可以通过重新映射键来配置。

#### View mode

按 `z` 进入此模式，这种模式的 sticky （按 `Z`）方式是持久的：需使用 `Esc` 键返回到正常模式。当你只是浏览文本而不是主动编辑它时，这一方式很有用。

| 按键 | 描述 | 命令 |
| ---- | ---- | ---- |
| `z`, `c` | 垂直居中当前行 | `align_view_center` |
| `t` | 将当前行与屏幕顶部对齐 | `align_view_top` |
| `b` | 将当前行与屏幕底部对齐 | `align_view_bottom` |
| `m` | 将当前行与屏幕中间水平对齐（水平居中） | `align_view_middle` |
| `j`, `down` | 向下滚动视图 | `scroll_down` |
| `k`, `up` | 向上滚动视图 | `scroll_up` |
| `Ctrl-f`, `PageDown` | 向下翻页 | `page_down` |
| `Ctrl-b`, `PageUp` | 向上翻页 | `page_up` |
| `Ctrl-d` | 向下翻半页 | `half_page_down` |
| `Ctrl-u` | 向上翻半页 | `half_page_up` |

#### Goto mode

按 `g` 进入此模式，来跳跃到不同的位置。

| 按键 | 描述 | 命令 |
| ---- | ---- | ---- |
| `g` | 输入 `gng` 跳转到第 n 行；不输入数字跳转到第 1 行。 `gng` 等价于 `ngg` 和 `nG`，都用于跳转到第 n 行。 | `goto_file_start` |
| `e` | 到最后一行 | `goto_last_line` |
| `f` | `gf` 会将所选内容视为文件路径（可以是相对路径也可以是绝对路径）；当该路径不存在，打开那个路径的缓冲区，写入即创建该文件（不写入不创建）。 | `goto_file` |
| `h` | 到当前行开头 | `goto_line_start` |
| `l` | 到当前行结尾 | `goto_line_end` |
| `s` | 到当前行第一个非空格字符 | `goto_first_nonwhitespace` |
| `t` | 到屏幕顶部那行 | `goto_window_top` |
| `c` | 到屏幕中间那行 | `goto_window_center` |
| `b` | 到屏幕底部那行 | `goto_window_bottom` |
| `d` | 跳转到定义 (**LSP**) | `goto_definition` |
| `y` | 跳转到类型定义 (**LSP**) | `goto_type_definition` |
| `r` | 跳转到引用 (**LSP**) | `goto_reference` |
| `i` | 跳转到实现 (**LSP**) | `goto_implementation` |
| `a` | 到上次访问的/备选文件 | `goto_last_accessed_file` |
| `m` | 到上次修改的/备选文件 | `goto_last_modified_file` |
| `n` | 到下个缓冲区 | `goto_next_buffer` |
| `p` | 到上个缓冲区 | `goto_previous_buffer` |
| `.` | 到当前文件中的最后一次修改处 | `goto_last_modification` |
| `j` | 向下移动一行（而不是代码过长wrap时的可视行） | `move_line_down` |
| `k` | 向上移动一行（而不是代码过长wrap时的可视行） | `move_line_up` |

#### Match mode

在 normal 模式按 `m` 进入该模式。

| 按键 | 描述 | 命令 |
| ---- | ---- | ---- |
| `m` | 到匹配的括号 (**TS**) | `match_brackets` |
| `s` `<char>` | 用将当前选定内容用 `<char>` 包围起来 | `surround_add` |
| `r` `<from><to>` | 把环绕的 `<from>` 字符替换成 `<to>` | `surround_replace` |
| `d` `<char>` | 删除环绕的 `<char>` | `surround_delete` |
| `a` `<object>` | 选择语法树 textobject 文本 | `select_textobject_around` |
| `i` `<object>` | 选择语法树 textobject 内部的文本 | `select_textobject_inner` |

#### Window mode

按 `<space>w` 或者 `<Ctrl-w>` 进入此模式

| 按键 | 描述 | 命令 |
| ---- | ---- | ---- |
| `w`, `Ctrl-w` | 切换到下一个窗口 | `rotate_view` |
| `v`, `Ctrl-v` | 垂直向右拆分 | `vsplit` |
| `s`, `Ctrl-s` | 水平底部拆分 | `hsplit` |
| `f` | 以水平拆分方式转到所选内容中的文件 | `goto_file` |
| `F` | 以垂直拆分方式转到所选内容中的文件 | `goto_file` |
| `h`, `Ctrl-h`, `Left` | 移动光标到左侧拆分窗口 | `jump_view_left` |
| `j`, `Ctrl-j`, `Down` | 移动光标到下侧拆分窗口 | `jump_view_down` |
| `k`, `Ctrl-k`, `Up` | 移动光标到上侧拆分窗口 | `jump_view_up` |
| `l`, `Ctrl-l`, `Right` | 移动光标到右侧拆分窗口 | `jump_view_right` |
| `q`, `Ctrl-q` | 关闭当前窗口 | `wclose` |
| `o`, `Ctrl-o` | 仅保留当前窗口，关闭所有其他窗口 | `wonly` |
| `H` | 交换当前窗口到左侧 | `swap_view_left` |
| `J` | 交换当前窗口到下侧 | `swap_view_down` |
| `K` | 交换当前窗口到上侧 | `swap_view_up` |
| `L` | 交换当前窗口到右侧 | `swap_view_right` |

#### Space mode

按 `<space>` 进入此模式

| 按键 | 描述 | 命令 |
| ---- | ---- | ---- |
| `f` | 打开文件选取器 | `file_picker` |
| `F` | 打开当前项目目录的文件选取器 | `file_picker_in_current_directory` |
| `b` | 打开缓冲区选取器 | `buffer_picker` |
| `j` | 打开跳转列表选取器 | `jumplist_picker` |
| `g` | Debug (experimental) | N/A |
| `k` | 在 popup 框中显示光标下条目的文档 | `hover` |
| `s` | 打开当前文档符号选取器 (**LSP**) | `symbol_picker` |
| `S` | 打开工作区符号选取器 (**LSP**) | `workspace_symbol_picker` |
| `d` | 打开当前文档代码诊断选取器 (**LSP**) | `diagnostics_picker` |
| `D` | 打开工作区代码诊断选取器 (**LSP**) | `workspace_diagnostics_picker` |
| `r` | 重命名符号 (**LSP**) | `rename_symbol` |
| `a` | 执行代码操作 (**LSP**) | `code_action` |
| `h` | 选择符号引用-多选区 (**LSP**) | `select_references_to_symbol_under_cursor` |
| `'` | 打开上次的模糊选取器 | `last_picker` |
| `w` | 进入 window mode | N/A |
| `p` | 在选区后方粘贴系统剪贴板的内容 | `paste_clipboard_after` |
| `P` | 在选区前方粘贴系统剪贴板的内容 | `paste_clipboard_before` |
| `y` | 复制所选文本到粘贴板 | `yank_to_clipboard` |
| `Y` | （多选区时）复制主选区到粘贴板 | `yank_main_selection_to_clipboard` |
| `R` | 将所选文本替换成系统粘贴板的文本 | `replace_selections_with_clipboard` |
| `/` | 在工作区文件夹下全局搜索文件名 | `global_search` |
| `?` | 打开命令选项板 | `command_palette` |

> 全局搜索虽然使用命令行输入，但在模糊选取器中显示结果，所以你可以在打开文件后使用 `<space>'` 将上次搜索的结果其带回

##### Popup

显示光标下条目的文档。

| 按键 | 描述 |
| ---- | ---- |
| `Ctrl-u` | 向上滚动 |
| `Ctrl-d` | 向下滚动 |

#### Unimpaired

使用 [vim-unimpaired](https://github.com/tpope/vim-unimpaired) 风格的映射来代码导航。

| 按键 | 描述 | 命令 |
| ---- | ---- | ---- |
| `]d` | 到上一个诊断 (**LSP**) | `goto_next_diag` |
| `[d` | 到下一个诊断 (**LSP**) | `goto_prev_diag` |
| `]D` | 到本文件的第一个诊断 (**LSP**) | `goto_last_diag` |
| `[D` | 到本文件的最后一个诊断 (**LSP**) | `goto_first_diag` |
| `]f` | 到下一个函数 (**TS**) | `goto_next_function` |
| `[f` | 到上一个函数 (**TS**) | `goto_prev_function` |
| `]t` | 到下一个类型定义 (**TS**) | `goto_next_class` |
| `[t` | 到上一个类型定义 (**TS**) | `goto_prev_class` |
| `]a` | 到下一个参数 (**TS**) | `goto_next_parameter` |
| `[a` | 到上一个参数 (**TS**) | `goto_prev_parameter` |
| `]c` | 到下一个注释 (**TS**) | `goto_next_comment` |
| `[c` | 到上一个注释 (**TS**) | `goto_prev_comment` |
| `]T` | 到下一个测试 (**TS**) | `goto_next_test` |
| `[T` | 到上一个测试 (**TS**) | `goto_prev_test` |
| `]p` | 到下一个段落 | `goto_next_paragraph` |
| `[p` | 到上一个段落 | `goto_prev_paragraph` |
| `]g` | 到下一个变动位置 | `goto_next_change` |
| `[g` | 到上一个变动位置 | `goto_prev_change` |
| `]G` | 到最后一个变动位置 | `goto_last_change` |
| `[G` | 到第一个变动位置 | `goto_first_change` |
| `]Space` | 在下面添加新的一行 | `add_newline_below` |
| `[Space` | 在上面添加新的一行 | `add_newline_above` |

## Insert mode

| 按键 | 描述 | 命令 |
| ---- | ---- | ---- |
| `Escape` | 切换到normal模式 | `normal_mode` |
| `Ctrl-s` | 提交撤消检查点 | `commit_undo_checkpoint` |
| `Ctrl-x` | 自动补全 | `completion` |
| `Ctrl-r` | 插入寄存器的内容 **[useful]** | `insert_register` |
| `Ctrl-w`, `Alt-Backspace` | 删除上一个单词 | `delete_word_backward` |
| `Alt-d`, `Alt-Delete` | 删除下一个单词 | `delete_word_forward` |
| `Ctrl-u` | 删除到行首 | `kill_to_line_start` |
| `Ctrl-k` | 删除到行尾 | `kill_to_line_end` |
| `Ctrl-h`, `Backspace`, `Shift-Backspace` | 删除上一个字符 | `delete_char_backward` |
| `Ctrl-d`, `Delete` | 删除下一个字符 | `delete_char_forward` |
| `Ctrl-j`, `Enter` | 插入新行 | `insert_newline` |

## Select / extend mode

按 `v` 进入和退出此模式，此模式类似于 normal mode，但会更改任意移动以扩展选区，而不是替换这些选区。goto 移动也被更改为扩展，例如，`vgl` 将所选内容扩展到行尾。

搜索也受到了影响。默认情况下，`n` 和 `N` 会移除当前选区，并选择搜索词的下一个实例。在按 `n` 或 `N` 之前切换此模式可以保持当前选区。将搜索项添加到新选区中-多选区

## Picker

在选取器中使用的按键。当前不支持重新映射这些按键。

| 按键 | 描述 |
| ---- | ---- |
| `Shift-Tab`, `Up`, `Ctrl-p` | 前一条 |
| `Tab`, `Down`, `Ctrl-n` | 后一条 |
| `PageUp`, `Ctrl-u` | 往上翻页 |
| `PageDown`, `Ctrl-d` | 往下翻页 |
| `Home` | 到第一条 |
| `End` | 到最后一条 |
| `Enter` | 打开所选项 |
| `Alt-Enter` | 后台打开 |
| `Ctrl-s` | 垂直分屏打开 |
| `Ctrl-v` | 水平分屏打开 |
| `Ctrl-t` | Toggle 文件内容预览 |
| `Escape`, `Ctrl-c` | 关闭选取器 |

## Prompt

在提示框内使用的按键（比如按 `s` 在命令行弹出待输入的那个位置），当前不支持重新映射。

| 按键 | 描述 |
| ---- | ---- |
| `Escape`, `Ctrl-c` | 关闭提示框 |
| `Alt-b`, `Ctrl-Left` | 到上一个 word （nomal mode 下的 `b`） |
| `Ctrl-b`, `Left` | 到上一个 char （nomal mode 下的 `h`） |
| `Alt-f`, `Ctrl-Right` | 到下一个 word |
| `Ctrl-f`, `Right` | 到下一个 char（nomal mode 下的 `l`） |
| `Ctrl-e`, `End` | 到行结尾 |
| `Ctrl-a`, `Home` | 到行开头 |
| `Ctrl-w`, `Alt-Backspace`, `Ctrl-Backspace` | 删除前一个 word |
| `Alt-d`, `Alt-Delete`, `Ctrl-Delete` | 删除下一个 word |
| `Ctrl-u` | 删除到行开头 |
| `Ctrl-k` | 删除到行结尾 |
| `Backspace`, `Ctrl-h`, `Shift-Backspace` | 删除前一个 char |
| `Delete`, `Ctrl-d` | 删除下一个 char |
| `Ctrl-s` | 插入文档选区中的内容 |
| `Ctrl-p`, `Up` | 选择上一个历史 |
| `Ctrl-n`, `Down` | 选择下一个历史 |
| `Ctrl-r` | 插入所选寄存器的内容 |
| `Tab` | 选择下一个补全项 |
| `BackTab` | 选择上一个补全项 |
| `Enter` | 打开选定项 |

# 命令

按 `:` 进入 command mode

| Name | Description |
| ---- | ---- |
| `:quit`, `:q` | 关闭当前浏览 |
| `:quit!`, `:q!` | 强制关闭当前浏览，忽视未保存的文件 |
| `:open`, `:o` | 从磁盘中打开并浏览文件 |
| `:buffer-close`, `:bc`, `:bclose` | 关闭当前缓冲区 |
| `:buffer-close!`, `:bc!`, `:bclose!` | 强制关闭当前缓冲区，忽视未保存的更改 |
| `:buffer-close-others`, `:bco`, `:bcloseother` | 除了当前缓冲区之外，关闭其他缓冲区 |
| `:buffer-close-others!`, `:bco!`, `:bcloseother!` | 除了当前缓冲区之外，强制关闭其他缓冲区 |
| `:buffer-close-all`, `:bca`, `:bcloseall` | 关闭所有缓冲区，但不退出 Helix |
| `:buffer-close-all!`, `:bca!`, `:bcloseall!` | 强制关闭所有缓冲区，但不退出 Helix |
| `:buffer-next`, `:bn`, `:bnext` | 到下个缓冲区 |
| `:buffer-previous`, `:bp`, `:bprev` | 到上个缓冲区 |
| `:write`, `:w` | 把更改的内容写入到磁盘；接收一个可选的路径参数（如 :write some/path.txt） |
| `:write!`, `:w!` | 把更改的内容强制写入到磁盘，会创建必要的子目录；接收一个可选的路径参数 |
| `:write-buffer-close`, `:wbc` | 将更改写入磁盘并关闭缓冲区。接受一个可选路径（:write-buffer-close some/path.txt） |
| `:write-buffer-close!`, `:wbc!` | 强制将更改写入磁盘，创建必要的子目录并关闭缓冲区。接受一个可选路径（:write-buffer-close! some/path.txt） |
| `:new`, `:n` | 创建一个新的 scratch 缓冲区 |
| `:format`, `:fmt` | 使用 LSP 格式化工具对当前文件格式化 |
| `:indent-style` | 设置编辑的缩进样式：`t` 表示制表符，或者 `1`-`16` 为多个空格 |
| `:line-ending` | 设置当前文件的换行方式：`crlf` 或 `lf` |
| `:earlier`, `:ear` | 回退到前一个编辑历史；还可接收回退几步的数字或者时间跨度 |
| `:later`, `:lat` | 前进到后一个编辑历史；还可接收前进几步的数字或者时间跨度 |
| `:write-quit`, `:wq`, `:x` | 把更改的内容写入到磁盘，并退出；接收一个可选的路径参数 |
| `:write-quit!`, `:wq!`, `:x!` | 把更改的内容强制写入到磁盘，并退出；接收一个可选的路径参数 |
| `:write-all`, `:wa` | 把所有缓冲区的更改的内容写入到磁盘 |
| `:write-all!`, `:wa!` | 把所有缓冲区的更改的内容写入到磁盘 |
| `:write-quit-all`, `:wqa`, `:xa` | 把所有缓冲区的更改的内容写入到磁盘，并退出 |
| `:write-quit-all!`, `:wqa!`, `:xa!` | 把所有缓冲区的更改的内容强制写入到磁盘，并退出 |
| `:quit-all`, `:qa` | 关闭所有浏览（退出） |
| `:quit-all!`, `:qa!` | 强制关闭所有浏览 |
| `:cquit`, `:cq` | 退出，且带退出码，默认为 1；接收一个可选的整数参数 |
| `:cquit!`, `:cq!` | 强制退出，且带退出码，默认为 1；接收一个可选的整数参数 |
| `:theme` | 更换主题（按 `Tab` 和 `Shift-Tab` 选择下/上个主题） |
| `:yank-join` | 复制多选区内容，接受可选的分隔符，默认为换行 |
| `:clipboard-yank` | 复制主选区内容到系统粘贴板 |
| `:clipboard-yank-join` | 复制多选区到系统粘贴板；默认用换行符连接选区的文本；可提供第一个参数作为分隔符 |
| `:primary-clipboard-yank` | 复制主选区内容到系统 primary 粘贴板 |
| `:primary-clipboard-yank-join` | 复制所有选区到系统 primary 粘贴板；默认用换行符连接选区的文本；可提供第一个参数作为分隔符 |
| `:clipboard-paste-after` | 在所选内容之后粘贴系统粘贴板的内容 |
| `:clipboard-paste-before` | 在所选内容之前粘贴系统粘贴板的内容 |
| `:clipboard-paste-replace` | 把所选内容替换成系统粘贴板的内容 |
| `:primary-clipboard-paste-after` | 在所选内容之后粘贴系统 primary 粘贴板的内容 |
| `:primary-clipboard-paste-before` | 在所选内容之前粘贴系统 primary 粘贴板的内容 |
| `:primary-clipboard-paste-replace` | 把所选内容替换成系统粘 primary 粘贴板的内容 |
| `:show-clipboard-provider` | 显示粘贴板提供软件的名称 |
| `:change-current-directory`, `:cd` | 更改当前工作目录 |
| `:show-directory`, `:pwd` | 显示当前工作目录 |
| `:encoding` | 设置编码 |
| `:character-info`, `:char` | 获取光标下字符的信息 |
| `:reload`, `:rl` | 丢弃已修改的内容，重新加载文件 |
| `:reload-all`, `:rla` | 放弃更改并从源文件重新加载所有文件。 |
| `:update`, `:u` | 只有在文件被修改时才写入更改。 |
| `:lsp-workspace-command` | 打开工作区命令选择器 |
| `:lsp-restart` | 重启当前文件使用的语言服务器 |
| `:lsp-stop` | 停止当前文档使用的语言服务器 |
| `:tree-sitter-scopes` | 显示 tree-sitter 的范围，主要用于制作主题和开发 |
| `:tree-sitter-highlight-name` | 显示光标下 tree-sitter 高亮范围的名称。 |
| `:debug-start`, `:dbg` | 从给定参数的给定模版开始调试会话 |
| `:debug-remote`, `:dbg-tcp` | 通过 TCP 连接到 debug adapter，并从给定参数的给定模版开始调试会话 |
| `:debug-eval` | 在当前调试上下文计算表达式 |
| `:vsplit`, `:vs` | 水平拆分窗口来打开文件 |
| `:vsplit-new`, `:vnew` | 水平拆分窗口来打开新的 scratch 缓冲区 |
| `:hsplit`, `:hs`, `:sp` | 垂直拆分窗口来打开文件 |
| `:hsplit-new`, `:hnew` | 水平拆分窗口来打开新的 scratch 缓冲区 |
| `:tutor` | 打开教程 |
| `:goto`, `:g` | 去第几行 |
| `:set-language`, `:lang` | 设置当前缓冲区的编程语言 |
| `:set-option`, `:set` | 运行期间设置配置选项<br> |
| `:toggle-option`, `:toggle` | Toggle 某个选项 |
| `:get-option`, `:get` | 显示某个配置选项的当前值 |
| `:sort` | 对选区的内容排序（多选区排序） |
| `:rsort` | 对选区的内容排倒序 |
| `:reflow` | 根据给定宽度把选区拆成多行 重排 |
| `:tree-sitter-subtree`, `:ts-subtree` | 显示当前光标下的 tree-sitter 子树，主要用于调试查询 |
| `:config-reload` | 重载配置 |
| `:config-open` | 打开 config.toml 配置文件 |
| `:config-open-workspace` | 打开当前工作区的 config.toml 文件。 |
| `:log-open` | 打开 Helix 日志文件 |
| `:insert-output` | 运行 shell 命令，并把其结果插入到每个选区之前 |
| `:append-output` | 运行 shell 命令，并把其结果插入到每个选区之后 |
| `:pipe` | 把每个选区通过管道传给 shell 命令 |
| `:pipe-to` | 将每个选择转入 shell 命令，忽略输出。 |
| `:run-shell-command`, `:sh` | 运行一个 shell 命令 |
| `:reset-diff-change`, `:diffget`, `:diffg` | 重置光标位置的变化 **[useful]** |
| `:clear-register` | 清除给定寄存器。如果没有提供参数，则清除所有寄存器。 |
| `:redraw` | 清除并重新渲染整个用户界面 |
| `:move` | 将当前缓冲区及其相应文件移至不同路径 |

# 语言支持

支持以下语言和语言服务器。要使用语言服务器功能，你必须首先安装对应语言的 LSP Server。

使用 `hx --health` 检查你安装的 Helix 版本中的语言支持。

| 语言 | 语法高亮 | Treesitter 文本对象 | 自动缩进 | 默认 LSP |
| --- | --- | --- | --- | --- |
| agda | ✓ |  |  |  |
| astro | ✓ |  |  |  |
| awk | ✓ | ✓ |  | `awk-language-server` |
| bash | ✓ | ✓ | ✓ | `bash-language-server` |
| bass | ✓ |  |  | `bass` |
| beancount | ✓ |  |  |  |
| bibtex | ✓ |  |  | `texlab` |
| bicep | ✓ |  |  | `bicep-langserver` |
| blueprint | ✓ |  |  | `blueprint-compiler` |
| c | ✓ | ✓ | ✓ | `clangd` |
| c-sharp | ✓ | ✓ |  | `OmniSharp` |
| cabal |  |  |  | `haskell-language-server-wrapper` |
| cairo | ✓ | ✓ | ✓ | `cairo-language-server` |
| capnp | ✓ |  | ✓ |  |
| clojure | ✓ |  |  | `clojure-lsp` |
| cmake | ✓ | ✓ | ✓ | `cmake-language-server` |
| comment | ✓ |  |  |  |
| common-lisp | ✓ |  | ✓ | `cl-lsp` |
| cpon | ✓ |  | ✓ |  |
| cpp | ✓ | ✓ | ✓ | `clangd` |
| crystal | ✓ | ✓ |  | `crystalline` |
| css | ✓ |  |  | `vscode-css-language-server` |
| cue | ✓ |  |  | `cuelsp` |
| d | ✓ | ✓ | ✓ | `serve-d` |
| dart | ✓ |  | ✓ | `dart` |
| dbml | ✓ |  |  |  |
| devicetree | ✓ |  |  |  |
| dhall | ✓ | ✓ |  | `dhall-lsp-server` |
| diff | ✓ |  |  |  |
| dockerfile | ✓ |  |  | `docker-langserver` |
| dot | ✓ |  |  | `dot-language-server` |
| dtd | ✓ |  |  |  |
| edoc | ✓ |  |  |  |
| eex | ✓ |  |  |  |
| ejs | ✓ |  |  |  |
| elixir | ✓ | ✓ | ✓ | `elixir-ls` |
| elm | ✓ | ✓ |  | `elm-language-server` |
| elvish | ✓ |  |  | `elvish` |
| env | ✓ |  |  |  |
| erb | ✓ |  |  |  |
| erlang | ✓ | ✓ |  | `erlang_ls` |
| esdl | ✓ |  |  |  |
| fish | ✓ | ✓ | ✓ |  |
| forth | ✓ |  |  | `forth-lsp` |
| fortran | ✓ |  | ✓ | `fortls` |
| fsharp | ✓ |  |  | `fsautocomplete` |
| gas | ✓ | ✓ |  |  |
| gdscript | ✓ | ✓ | ✓ |  |
| gemini | ✓ |  |  |  |
| git-attributes | ✓ |  |  |  |
| git-commit | ✓ | ✓ |  |  |
| git-config | ✓ |  |  |  |
| git-ignore | ✓ |  |  |  |
| git-rebase | ✓ |  |  |  |
| gleam | ✓ | ✓ |  | `gleam` |
| glsl | ✓ | ✓ | ✓ |  |
| gn | ✓ |  |  |  |
| go | ✓ | ✓ | ✓ | `gopls`, `golangci-lint-langserver` |
| godot-resource | ✓ |  |  |  |
| gomod | ✓ |  |  | `gopls` |
| gotmpl | ✓ |  |  | `gopls` |
| gowork | ✓ |  |  | `gopls` |
| graphql | ✓ |  |  | `graphql-lsp` |
| hare | ✓ |  |  |  |
| haskell | ✓ | ✓ |  | `haskell-language-server-wrapper` |
| haskell-persistent | ✓ |  |  |  |
| hcl | ✓ |  | ✓ | `terraform-ls` |
| heex | ✓ | ✓ |  | `elixir-ls` |
| hocon | ✓ |  | ✓ |  |
| hosts | ✓ |  |  |  |
| html | ✓ |  |  | `vscode-html-language-server` |
| hurl | ✓ |  | ✓ |  |
| idris |  |  |  | `idris2-lsp` |
| iex | ✓ |  |  |  |
| ini | ✓ |  |  |  |
| janet | ✓ |  |  |  |
| java | ✓ | ✓ | ✓ | `jdtls` |
| javascript | ✓ | ✓ | ✓ | `typescript-language-server` |
| jinja | ✓ |  |  |  |
| jsdoc | ✓ |  |  |  |
| json | ✓ |  | ✓ | `vscode-json-language-server` |
| json5 | ✓ |  |  |  |
| jsonnet | ✓ |  |  | `jsonnet-language-server` |
| jsx | ✓ | ✓ | ✓ | `typescript-language-server` |
| julia | ✓ | ✓ | ✓ | `julia` |
| just | ✓ | ✓ | ✓ |  |
| kdl | ✓ | ✓ | ✓ |  |
| kotlin | ✓ |  |  | `kotlin-language-server` |
| latex | ✓ | ✓ |  | `texlab` |
| lean | ✓ |  |  | `lean` |
| ledger | ✓ |  |  |  |
| llvm | ✓ | ✓ | ✓ |  |
| llvm-mir | ✓ | ✓ | ✓ |  |
| llvm-mir-yaml | ✓ |  | ✓ |  |
| log | ✓ |  |  |  |
| lpf | ✓ |  |  |  |
| lua | ✓ | ✓ | ✓ | `lua-language-server` |
| make | ✓ |  |  |  |
| markdoc | ✓ |  |  | `markdoc-ls` |
| markdown | ✓ |  |  | `marksman` |
| markdown.inline | ✓ |  |  |  |
| matlab | ✓ | ✓ | ✓ |  |
| mermaid | ✓ |  |  |  |
| meson | ✓ |  | ✓ |  |
| mint |  |  |  | `mint` |
| msbuild | ✓ |  | ✓ |  |
| nasm | ✓ | ✓ |  |  |
| nickel | ✓ |  | ✓ | `nls` |
| nim | ✓ | ✓ | ✓ | `nimlangserver` |
| nix | ✓ |  |  | `nil` |
| nu | ✓ |  |  | `nu` |
| nunjucks | ✓ |  |  |  |
| ocaml | ✓ |  | ✓ | `ocamllsp` |
| ocaml-interface | ✓ |  |  | `ocamllsp` |
| odin | ✓ |  | ✓ | `ols` |
| opencl | ✓ | ✓ | ✓ | `clangd` |
| openscad | ✓ |  |  | `openscad-lsp` |
| org | ✓ |  |  |  |
| pascal | ✓ | ✓ |  | `pasls` |
| passwd | ✓ |  |  |  |
| pem | ✓ |  |  |  |
| perl | ✓ | ✓ | ✓ | `perlnavigator` |
| php | ✓ | ✓ | ✓ | `intelephense` |
| po | ✓ | ✓ |  |  |
| pod | ✓ |  |  |  |
| ponylang | ✓ | ✓ | ✓ |  |
| prisma | ✓ |  |  | `prisma-language-server` |
| prolog |  |  |  | `swipl` |
| protobuf | ✓ | ✓ | ✓ | `bufls`, `pb` |
| prql | ✓ |  |  |  |
| purescript | ✓ | ✓ |  | `purescript-language-server` |
| python | ✓ | ✓ | ✓ | `pylsp` |
| qml | ✓ |  | ✓ | `qmlls` |
| r | ✓ |  |  | `R` |
| racket | ✓ |  | ✓ | `racket` |
| regex | ✓ |  |  |  |
| rego | ✓ |  |  | `regols` |
| rescript | ✓ | ✓ |  | `rescript-language-server` |
| rmarkdown | ✓ |  | ✓ | `R` |
| robot | ✓ |  |  | `robotframework_ls` |
| ron | ✓ |  | ✓ |  |
| rst | ✓ |  |  |  |
| ruby | ✓ | ✓ | ✓ | `solargraph` |
| rust | ✓ | ✓ | ✓ | `rust-analyzer` |
| sage | ✓ | ✓ |  |  |
| scala | ✓ | ✓ | ✓ | `metals` |
| scheme | ✓ |  | ✓ |  |
| scss | ✓ |  |  | `vscode-css-language-server` |
| slint | ✓ |  | ✓ | `slint-lsp` |
| smali | ✓ |  | ✓ |  |
| smithy | ✓ |  |  | `cs` |
| sml | ✓ |  |  |  |
| solidity | ✓ |  |  | `solc` |
| sql | ✓ |  |  |  |
| sshclientconfig | ✓ |  |  |  |
| starlark | ✓ | ✓ |  |  |
| strace | ✓ |  |  |  |
| svelte | ✓ |  | ✓ | `svelteserver` |
| sway | ✓ | ✓ | ✓ | `forc` |
| swift | ✓ |  |  | `sourcekit-lsp` |
| t32 | ✓ |  |  |  |
| tablegen | ✓ | ✓ | ✓ |  |
| task | ✓ |  |  |  |
| templ | ✓ |  |  | `templ` |
| tfvars | ✓ |  | ✓ | `terraform-ls` |
| todotxt | ✓ |  |  |  |
| toml | ✓ |  |  | `taplo` |
| tsq | ✓ |  |  |  |
| tsx | ✓ | ✓ | ✓ | `typescript-language-server` |
| twig | ✓ |  |  |  |
| typescript | ✓ | ✓ | ✓ | `typescript-language-server` |
| typst | ✓ |  |  | `typst-lsp` |
| ungrammar | ✓ |  |  |  |
| unison | ✓ |  |  |  |
| uxntal | ✓ |  |  |  |
| v | ✓ | ✓ | ✓ | `v-analyzer` |
| vala | ✓ |  |  | `vala-language-server` |
| verilog | ✓ | ✓ |  | `svlangserver` |
| vhdl | ✓ |  |  | `vhdl_ls` |
| vhs | ✓ |  |  |  |
| vue | ✓ |  |  | `vue-language-server` |
| wast | ✓ |  |  |  |
| wat | ✓ |  |  |  |
| webc | ✓ |  |  |  |
| wgsl | ✓ |  |  | `wgsl_analyzer` |
| wit | ✓ |  | ✓ |  |
| wren | ✓ | ✓ | ✓ |  |
| xit | ✓ |  |  |  |
| xml | ✓ |  | ✓ |  |
| yaml | ✓ |  | ✓ | `yaml-language-server`, `ansible-language-server` |
| yuck | ✓ |  |  |  |
| zig | ✓ | ✓ | ✓ | `zls` |

# 从 Vim 迁移

Helix 遵循“选择 → 操作”模式

删除到单词结尾:
* vim: `dw`
* helix: `wd`

修改到单词结尾:
* vim: `cw`
* helix: `ec` or `wc` (包括单词后面的空格)

删除字符：
* vim: `x`
* helix: `d` or `;d` (`;` 将选区缩减到单个光标)

复制一行：
* vim: `yy`
* helix: `xy`

全局替换：
* vim: `:%s/word/replacement/g<ret>`
* helix: `%sword<ret>creplacement<esc>` （相当于不是用命令替换，而是通过多选区编辑）

转到最后一行:
* vim: `G`
* helix: `ge`

转到行首:
* vim: `0`
* helix: `gh`

转到行首第一个非空白字符:
* vim: `^`
* helix: `gs`

转到行尾:
* vim: `$`
* helix: `gl`

删除到行尾:
* vim: `D`
* helix: `vgld` or `t<ret>d`

跳转到匹配的括号:
* vim: `%`
* helix: `mm`

自动补全:
* vim: `C-p`
* helix: `C-x`

注释行:
* vim: 无默认快捷键
* helix: `C-c`

搜索光标下的单词:
* vim: `*`
* helix: `Alt-o * n` (有LSP的情况下) or `be * n` （其中`*`表示使用当前所选内容作为搜索模式）

区块选择:
* vim: `C-v`
* helix: 没有"block selection"模式, 取而代之的是多选区编辑，可以通过`C`和`Alt-C`添加下方或上方的行进入选区。

在当前选择中搜索“foo”并替换为“bar”:
* vim: `:s/foo/bar/g<ret>`
* helix: `sfoo<ret>cbar<esc>,`

选择整个文件:
* vim: `ggVG`
* helix: `%`

从磁盘重新加载文件:
* vim: `:e<ret>`
* helix: `:reload<ret>` 或 `:reload-all<ret>`

运行 shell 命令:
* vim: `:!command`
* helix: `:sh command`

设置书签:
* vim: `ma` 设置书签 `` `a `` 跳转到指定书签.
* helix: 没有书签取而代之的是跳转列表，用 `C-s` 保存当前位置至跳转列表中, 通过 `<space>-j` 选择位置, 或用 `C-o` 和 `C-i` 逐项跳转。

# 配置

要覆盖全局配置参数，请在你的配置目录中创建一个 `config.toml` 文件：

- Linux 和 Mac: `~/.config/helix/config.toml`
- Windows: `%AppData%\helix\config.toml`

> 提示：在 normal模式下输入 `:config-open` 即可轻松打开配置文件。

## Editor

### `[editor]` Section
| 键 | 描述 | 默认值 |
|--|--|---------|
| `scrolloff` | 滚动时屏幕边缘保留的填充行数 | `5` |
| `mouse` | 启用鼠标模式 | `true` |
| `middle-click-paste` | 启用中键单击粘贴 | `true` |
| `scroll-lines` | 每次滚轮所滚动的行数 | `3` |
| `shell` | 运行外部命令时使用的 shell 程序 | Unix: `["sh", "-c"]`<br/>Windows: `["cmd", "/C"]` |
| `line-number` | 显示行号：`absolute` 每行的编号，`relative` 离当前行的距离。未聚焦或处于 insert mode 时，`relative` 仍显示绝对行号 | `absolute` |
| `cursorline` | 高亮光标所在行 | `false` |
| `cursorcolumn` | 高亮光标所在列 | `false` |
| `gutters` | 编辑区左边栏显示的内容 | `["diagnostics", "spacer", "line-numbers", "spacer", "diff"]` |
| `auto-completion` | 自动补全时自动弹出 | `true` |
| `auto-format` | 保存时自动格式化 | `true` |
| `auto-save` | 自动保存 | `false` |
| `idle-timeout` | 自上次按键后空闲计时器触发前的时间，以毫秒为单位。用于自动补全，设置为 0 表示即时补全。 | `250` |
| `preview-completion-insert` | 自动补全选择时是否立即应用 | `true` |
| `completion-trigger-len` | 光标下触发自动补全的最小单词长度 | `2` |
| `completion-replace` | 设置为`true`使补全始终替换整个单词，而不仅仅是光标之前的部分 | `false` |
| `auto-info` | 是否显示信息框 | `true` |
| `true-color` | 在未能检测到终端真彩色时，设置此项为 `true` 来表明使用真彩色 | `false` |
| `undercurl` | 在未能检测到时，设置此项为 `true` 来表明终端undercurl | `false` |
| `rulers` | 显示标尺的列位置列表。可以在 `languages.toml` 中使用特定语言的 `rulers` 键覆盖这里的设置。 | `[]` |
| `bufferline` | 在编辑器顶部显示一行显示已打开的缓冲区，可以是 `always`、`never` 或 `multiple`（只在超过一个缓冲区存在时显式） | `never` |
| `color-modes` | 根据模式本身用不同的颜色给模式指示器上色 | `false` |
| `text-width` | 最大行宽. 用于 `:reflow` 命令和 设置了 `soft-wrap.wrap-at-text-width` 情况下的 soft-wrapping | `80` |
| `workspace-lsp-roots` | 相对于工作区根目录的目录，这些目录被视为 LSP 根目录。应仅设置在`.helix/config.toml` | `[]` |
| `default-line-ending` | 新文档默认行尾。可以是`native`, `lf`, `crlf`, `ff`, `cr` 或 `nel`. `native` 为自适应 (Windows 上是 `crlf` , 否则是 `lf`). | `native` |
| `insert-final-newline` | 是否在写入时自动插入尾行 | `true` |
| `popup-border` | 为什么绘制边框 `popup`, `menu`, `all`, 或者 `none` | `none` |
| `indent-heuristic` | 启发式缩进 | `hybrid`

### `[editor.statusline]` Section

配置在编辑器底部的状态栏。状态栏分成三个区域：

`[ ... ... LEFT ... ... | ... ... ... ... CENTER ... ... ... ... | ... ... RIGHT ... ... ]`

| 键 | 描述 | 默认值 |
| ---- | ---- | ---- |
| `left` | 左端的列表 | `["mode", "spinner", "file-name", "read-only-indicator", "file-modification-indicator"]` |
| `center` | 中间的列表 | `[]` |
| `right` | 右端的列表 | `["diagnostics", "selections", "register", "position", "file-encoding"]` |
| `separator` | 分隔元素的字符 | `"│"` |
| `mode.normal` | normal mode 下显示的文字 | `"NOR"` |
| `mode.insert` | insert mode 下显示的文字 | `"INS"` |
| `mode.select` | select mode 下显示的文字 | `"SEL"` |

可配置以下元素：

| 键 | 描述 |
| ---- | ---- |
| `mode` | 当前模式 |
| `spinner` | LSP 活动进度指示 |
| `file-name` | 文件路径或名称 |
| `file-base-name` | 文件名 |
| `file-modification-indicator` | 文件已修改标志 |
| `file-encoding` | 如果不是 UTF-8 编码，则显示文件编码 |
| `file-line-ending` | 换行符 CRLF 或 LF |
| `read-only-indicator` | 文件只读标志 |
| `total-line-numbers` | 总行数 |
| `file-type` | 文件类型 |
| `diagnostics` | warnings 和/或 errors 的数量 |
| `workspace-diagnostics` | 工作区warnings 和/或 errors 的数量 |
| `selections` | 选区的数量 |
| `primary-selection-length` | 当前在主选定内容中的字符数 |
| `position` | 光标位置 |
| `position-percentage` | 光标位置占总行数的百分比 |
| `separator` | 分隔符 |
| `spacer` | 在元素之间插入空格，可以指定多个/连续的空格 |
| `version-control` | 打开的工作区的当前分支名称或分离的提交哈希 |
| `register` | 当前选定的寄存器 |

### `[editor.lsp]` Section

| 键 | 描述 | 默认值 |
| ---- | ---- | ---- |
| `enable` | 启用LSP | `true` |
| `display-messages` | 在 statusline 下方显示 LSP 进度消息 | `false` |
| `auto-signature-help` | 自动弹出签名帮助（和参数提示） | `true` |
| `display-inlay-hints` | 显示嵌体提示 | `false` |
| `display-signature-help-docs` | 在签名帮助弹出菜单中显示文档 | `true` |
| `snippets` | 启用代码段 | `true` |
| `goto-reference-include-declaration` | 在 goto 引用弹出窗口中包含声明 | `true` |

### `[editor.cursor-shape]` Section

定义每种模式下光标的形状。注意，由于终端环境的限制，只有主光标可以更改形状。这些选项的有效值为 `block`、`bar`、`underline` 或 `hidden`。

| 键 | 描述 | 默认值 |
| ---- | ---- | ---- |
| `normal` | normal mode 下的光标形状 | `block` |
| `insert` | insert mode 下的光标形状 | `block` |
| `select` | select mode 下的光标形状 | `block` |

### `[editor.file-picker]` Section

设置文件选取器和全局搜索的选项。

| 键 | 描述 | 默认值 |
| ---- | ---- | ---- |
| `hidden` | 忽略隐藏文件 | `true` |
| `follow-symlinks` | 接受符号链接而不是忽略它们 | `true` |
| `deduplicate-links` | 忽略指向文件已经包含在选取器中的符号链接 | `true` |
| `parents` | 允许从父目录中读取忽略文件 | `true` |
| `ignore` | 启用读取文件`.ignore` | `true` |
| `git-ignore` | 启用读取文件`.gitignore` | `true` |
| `git-global` | 读取全局 `.gitignore`，其路径由 git config 指定 | `true` |
| `git-exclude` | 读取 `.git/info/exclude` 文件 | `true` |
| `max-depth` | 为递归的最大深度设置一个整数值 | `None` |

### `[editor.auto-pairs]` Section

启用自动插入配对符号，如圆括号、方括号等。可以是简单的布尔值，也可以是单字符配对映射。

要完全关闭自动配对，将 `auto-pairs` 设置为 `false`：

```toml
[editor]
auto-pairs = false # defaults to `true`
```

默认配对为

```toml
[editor.auto-pairs]
'(' = ')'
'{' = '}'
'[' = ']'
'"' = '"'
'`' = '`'
'<' = '>'
```

### `[editor.search]` Section

搜索选项。

| 键 | 描述 | 默认值 |
| ---- | ---- | ---- |
| `smart-case` | 正则表达式启用智能大小写：除非包含大写字符，否则对大小写不敏感 | `true` |
| `wrap-around` | 匹配达到最后一个之后是否回到第一个 | `true` |

### `[editor.whitespace]` Section

通过可见字符渲染空格。使用 `:set whitespace.render all` 可临时开启可见空格。

| 键 | 描述 | 默认值 |
| ---- | ---- | ---- |
| `render` | 是否渲染空格，要么是 `all` 或 `none`，要么是带子键的表，子键有 `space`、`tab`、`newline`. | `"none"` |
| `characters` | 渲染空格的字符；子键为 `tab`、`space`、`nbsp`、`newline`、`tabpad` 之一 | 参考下面示例 |

```toml
[editor.whitespace]
render = "all"
# or control each character
[editor.whitespace.render]
space = "all"
tab = "all"
newline = "none"

[editor.whitespace.characters]
space = "·"
nbsp = "⍽"
tab = "→"
newline = "⏎"
tabpad = "·"
```

### `[editor.indent-guides]` Section

渲染垂直缩进辅助线。

| 键 | 描述 | 默认值 |
| ---- | ---- | ---- |
| `render` | 是否渲染缩进辅助线 | `false` |
| `character` | 渲染辅助线的字符 | `│` |
| `skip-levels` | 跳过的缩进级别数 | `0` |

Example:

```toml
[editor.indent-guides]
render = true
character = "╎" # Some characters that work well: "▏", "┆", "┊", "⸽"
skip-levels = 1
```

### `[editor.gutters]` Section

为简单起见，接受一组装订线类型，这将对所有装订线组件使用默认设置

| 键 | 描述 | 默认值 |
| ---- | ---- | ---- |
| `layout` | 要显示的装订线矢量 | `["diagnostics", "spacer", "line-numbers", "spacer", "diff"]` |

#### `[editor.gutters.line-numbers]` Section

线号装订线的选项

| 键 | 描述 | 默认值 |
| ---- | ---- | ---- |
| `min-width` | 要使用的最小字符数 | `3` |

Example:

```toml
[editor.gutters.line-numbers]
min-width = 1
```

#### `[editor.gutters.diagnostics]` Section

当前未使用

#### `[editor.gutters.diff]` Section

当前未使用

#### `[editor.gutters.spacer]` Section

当前未使用

### `[editor.soft-wrap]` Section

超过视图宽度的wrap的选项:

| 键 | 描述 | 默认值 |
| ---- | ---- | ---- |
| `enable` | 是否启用 | `false` |
| `max-wrap` | 行末尾剩余的最大可用空间 | `20` |
| `max-indent-retain` | 要保留的最大缩进 | `40` |
| `wrap-indicator` | 在软换行之前插入的文本 | `↪ ` |
| `wrap-at-text-width` | 根据 `text-width` 换行而不是窗口大小 | `false` |

### `[editor.smart-tab]` Section


| 键 | 描述 | 默认值 |
| ---- | ---- | ---- |
| `enable` | 是否启用，tab键在有内容时用于跳转到下个语法点/切换选项，而不是输入制表符 | `true` |
| `supersede-menu` | 如果此选项设置为true，则智能tab命令始终优先，这意味着无法使用tab键循环浏览菜单项。 | `false` |

# 主题

要使用主题，请在配置文件 [`config.toml`](https://zjp-cn.github.io/helix-book/configuration.html) 最顶端，在第一个部分之前添加 `theme = "<name>"`，或者在运行中使用 `:theme <name>` 选择它。

## 自定义主题

略

# 按键重映射

暂时支持单向键重新映射，不支持重新映射按键

## ## 次要模式



```toml
[keys.insert.j]
k = "normal_mode" # Maps `jk` to exit insert mode

[keys.normal.g]
a = "code_action" # Maps `ga` to show possible code actions

# invert `j` and `k` in view mode
[keys.normal.z]
j = "scroll_up"
k = "scroll_down"

# create a new minor mode bound to `+`
[keys.normal."+"]
m = ":run-shell-command make"
c = ":run-shell-command cargo build"
t = ":run-shell-command cargo test"
```

## ## 特殊键

Ctrl、Shift 和 Alt 修饰符分别使用 `C-`、`S-` 和 `A-` 前缀进行编码。特殊按键的编码如下：

| 按键名     | 符号 |
| ---          | ---            |
| Backspace    | `"backspace"`  |
| Space        | `"space"`      |
| Return/Enter | `"ret"`        |
| \-           | `"minus"`      |
| Left         | `"left"`       |
| Right        | `"right"`      |
| Up           | `"up"`         |
| Down         | `"down"`       |
| Home         | `"home"`       |
| End          | `"end"`        |
| Page Up      | `"pageup"`     |
| Page Down    | `"pagedown"`   |
| Tab          | `"tab"`        |
| Delete       | `"del"`        |
| Insert       | `"ins"`        |
| Null         | `"null"`       |
| Escape       | `"esc"`        |

## 常用键位

选中当前单词 `<Alt-o>`
修改到行尾 `vglc` 自定义为 `\c`
删除到行尾 `vglc` 自定义为 `\d`
跳转到行首 `gs`
格式化文档 自定义为 `\f`
分屏 自定义为 `\\`

# 语言

特定的语言设置和语言服务器的设置在 `languages.toml` 文件中进行配置。

## `languages.toml` 文件

有三个可能的 `languages.toml` 文件位置:

1. 项目中默认的 `languages.toml`.

2. 配置目录中:

3. 项目目录下 `.helix` 文件夹中.

## Language configuration

每种语言都是通过在 `languages.toml` 文件中添加 `[[Language]]` 来配置的。例如：

```toml
[[language]]
name = "rust"
scope = "source.rust"
injection-regex = "rust"
file-types = ["rs"]
roots = ["Cargo.toml", "Cargo.lock"]
auto-format = true
comment-token = "//"
language-servers = [ "rust-analyzer" ]
indent = { tab-width = 4, unit = "    " }
persistent-diagnostic-sources = ["rustc", "clippy"]
```

支持以下配置键：

| 键                   | 描述                                                   |
| ----                  | -----------                                                   |
| `name`                | 语言的名称                                      |
| `language-id`         | 语言ID，参考[TextDocumentItem](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocumentItem)  |
| `scope`               | 像 `source.js` 的字符串，它标识了语言。通常是 `source.<name>` 或 `text.<name>` 形式（以防标记语言） |
| `injection-regex`     | 针对语言名称进行测试的正则模式 |
| `file-types`          | 语言的文件类型，比如 `["yml", "yaml"]`；支持拓展名和完整的文件名 |
| `shebangs`            | shebang 行的解释器，比如 `["sh", "bash"]` |
| `roots`               | 一组用于搜索标记文件，以找到工作空间的根目录比如 `Cargo.lock`、 `yarn.lock` |
| `auto-format`         | 是否保存文件时自动格式化               |
| `diagnostic-severity` | 用于显示的最低程度的诊断；允许的值有 `Error`, `Warning`, `Info`, `Hint` |
| `comment-token`       | 用于注释的标记                           |
| `indent`              | 使用什么样的缩进；子键有 `tab-width` （表示制表符显示宽度）和 `unit` （通常是`"    "`或者`"\t"`） |
| `language-servers`    | 用于此语言的语言服务器   |
| `grammar`             | 要使用的 tree-sitter 语法（默认为`name`) |
| `formatter`           | 语言的格式化程序，在定义时，它将优先于 lsp。格式化程序必须能够将原始文件作为 stdin 的输入，并将格式化文件写入 stdout |
| `soft-wrap` | 覆盖 `[editor.softwrap]`
| `text-width`          |  最大行宽，而不是根据窗口大小   |
| `workspace-lsp-roots`     | 为工作区设置的LSP目录，是一个相对目录。只能在 `.helix/config.toml` 中设置。 |
| `persistent-diagnostic-sources` | 当语言服务器重新发送同一组诊断时，假定 LSP 诊断源的数组保持不变。Helix 可以在内部跟踪这些诊断的位置。对于在保存时重新计算的诊断非常有用。

## 语言服务器配置

```toml
[language-server.rust-analyzer]
command = "rust-analyzer"

[language-server.rust-analyzer.config]
inlayHints.bindingModeHints.enable = false
inlayHints.closingBraceHints.minLines = 10
inlayHints.closureReturnTypeHints.enable = "with_block"
inlayHints.discriminantHints.enable = "fieldless"
inlayHints.lifetimeElisionHints.enable = "skip_trivial"
inlayHints.typeHints.hideClosureInitialization = false
```

支持以下配置键：

| 键 | 描述 |
| ---- | ---- |
| `command` | 要执行的语言服务器二进制文件的名称，二进制文件必须位于 `$PATH` |
| `args` | 传递给语言服务器二进制文件的参数列表 |
| `config` | LSP 初始化选项 |
| `timeout` | 向语言服务器发出请求可能需要的最长时间（以秒为单位）。默认为`20` |
| `environment` | 启动语言服务器时将使用的任何环境变量`{ "KEY1" = "Value1", "KEY2" = "Value2" }` |
支持的特性

- `format`
- `goto-definition`
- `goto-declaration`
- `goto-type-definition`
- `goto-reference`
- `goto-implementation`
- `signature-help`
- `hover`
- `document-highlight`
- `completion`
- `code-action`
- `workspace-command`
- `document-symbols`
- `workspace-symbols`
- `diagnostics`
- `rename-symbol`
- `inlay-hints`

具体语言参考：[helix Wiki (github.com)](https://github.com/helix-editor/helix/wiki/How-to-install-the-default-language-servers)

# 我的配置

## `config.toml`

```toml
theme = "dracula"

[editor]
mouse = false
line-number = "relative"
cursorline = true
# completion-replace = true
bufferline = "multiple"
color-modes = true
# undercurl = true
default-line-ending = "lf"

[editor.statusline]
left = [
  "mode",
  "spacer",
  "spacer",
  "version-control",
  "spacer",
  "spacer",
  "diagnostics",
  "spinner",
]
center = []
right = ["position", "file-encoding", "file-line-ending", "file-type"]
separator = "│"
mode.normal = "NORMAL"
mode.insert = "INSERT"
mode.select = "SELECT"

[editor.lsp]
display-inlay-hints = true

[editor.cursor-shape]
normal = "block"
insert = "bar"
select = "underline"

[editor.auto-pairs]
'(' = ')'
'{' = '}'
'[' = ']'
'"' = '"'
'`' = '`'
'<' = '>'
"'" = "'"

[editor.whitespace]
# render = "all"

[editor.indent-guides]
render = true
character = "▏"

[editor.gutters.line-numbers]
min-width = 1

[editor.soft-wrap]
enable = true

[editor.smart-tab]
supersede-menu = true

[keys.normal.'\']
c = ["select_mode", "goto_line_end", "change_selection"]
d = ["select_mode", "goto_line_end", "delete_selection"]
f = [":format"]
'\' = [":vsplit"]

[keys.insert]
up = "no_op"
down = "no_op"
left = "no_op"
right = "no_op"
pageup = "no_op"
pagedown = "no_op"
home = "no_op"
end = "no_op"
# j = { k = "normal_mode" }

[keys.insert.j]
k = "normal_mode"
```

## `languages.toml`

```toml
# HTML
[[language]]
name = "html"
auto-format = false
soft-wrap.enable = false

# JavaScript
[[language]]
name = "javascript"
auto-format = false
soft-wrap.enable = false

# JSON
[[language]]
name = "json"
auto-format = false
soft-wrap.enable = false

# Python
[[language]]
name = "python"
language-servers = ["pyright", "ruff"]

[language-server.pyright.config.python.analysis]
typeCheckingMode = "basic"

[language-server.ruff]
command = "ruff-lsp"

[language-server.ruff.config.settings]
args = ["--ignore", "E501"]

[language.formatter]
command = "black"
args = ["--line-length", "88", "--quiet", "-"]

# Rust
[language-server.rust-analyzer.config.check]
command = "clippy"

# TOML
[[language]]
name = "toml"
formatter = { command = "taplo", args = ["fmt", "-"] }
```