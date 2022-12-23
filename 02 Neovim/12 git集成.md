## 插件
`~/.config/nvim/lua/plugins.lua` 中写入
```lua
use("lewis6991/gitsigns.nvim") -- git集成
```
## 配置
`~/.config/nvim/lua/keymaps.lua` 中添加相关快捷键
```lua
keymap("n", "<Leader>dj", ":Gitsigns next_hunk<CR>", opts) -- 下一个块
keymap("n", "<Leader>dk", ":Gitsigns prev_hunk<CR>", opts) -- 上一个块
keymap("n", "<Leader>dp", ":Gitsigns preview_hunk<CR>", opts) -- 预览块
keymap("n", "<Leader>du", ":Gitsigns reset_hunk<CR>", opts) -- 重置块 撤销块
keymap("n", "<Leader>dl", ":Gitsigns blame_line<CR>", opts) -- 预览行
```
git集成配置：创建 `~/.config/nvim/lua/components/git_signs.lua` 并写入
```lua
local status_ok, gitsigns = pcall(require, "gitsigns")
if not status_ok then
	return
end

gitsigns.setup({
	signs = {
		add = { hl = "GitSignsAdd", text = "|", numhl = "GitSignsAddNr", linehl = "GitSignsAddLn" }, -- 添加
		change = { hl = "GitSignsChange", text = "|", numhl = "GitSignsChangeNr", linehl = "GitSignsChangeLn" }, -- 修改
		delete = { hl = "GitSignsDelete", text = "_", numhl = "GitSignsDeleteNr", linehl = "GitSignsDeleteLn" }, -- 删除
		topdelete = { hl = "GitSignsDelete", text = "‾", numhl = "GitSignsDeleteNr", linehl = "GitSignsDeleteLn" }, -- 删除
		changedelete = { hl = "GitSignsChange", text = "~", numhl = "GitSignsChangeNr", linehl = "GitSignsChangeLn" }, -- 修改删除
	},
    signcolumn = true, -- 显示标记列
    numhl      = false, -- 行号高亮
    linehl     = false, -- 行高亮关闭
    word_diff  = false, -- 词级别的差异关闭
})
```
## 引入
 `~/.config/nvim/lua/components/init.lua` 中引入
```lua
require("components.git_signs") -- git集成
```