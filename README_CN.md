# bn — Agent 优先的 Binary Ninja CLI

[English](README.md) | 中文

`bn` 是一个面向 AI Agent 设计的 Binary Ninja 命令行工具。它为 shell 会话或 Agent 工具调用提供稳定的命令接口、结构化输出，以及对 Binary Ninja 实时数据库的完整访问能力——无论是 GUI 模式还是 headless 守护进程模式。

## 核心特性

- 从 shell 查询 Binary Ninja 实时状态：目标文件、函数、调用点、反编译文本、IL、反汇编、交叉引用、类型、字符串、导入表等
- 在 Binary Ninja 进程内执行 Python，无需维护单独的 headless 工作流
- 使用 `--preview` 应用变更，捕获反编译 diff，并在报告成功前验证实际状态
- 输出结构化 `json` / `ndjson`，大结果自动 spill 到文件，返回 token 计数帮助 Agent 管理上下文预算
- 完整的 Binary Ninja API 覆盖：60+ 命令，涵盖分析、注释、数据库、调试信息、IL 导航、类型扩展、元数据、撤销/重做、加载器、外部库、插件命令等

## 设计理念

本工具的设计基于对 AI Agent 在逆向工程场景下 14,477 次工具调用的系统分析（详见 [分析报告](https://km.sankuai.com/collabpage/2763899210)），针对性地解决了以下核心瓶颈：

**1. 消除 session 冗余查询**

MCP 方案中 Agent 每次调用前都要查询 session ID（140 次无意义调用，浪费 70,000 tokens）。bn-cli 的 daemon 架构天然避免了这个问题——target 通过 `--target` 参数或 implicit 选择，不存在 session 概念。

**2. 地址归一化**

MCP 方案中 Agent 混淆文件偏移和内存地址导致 55.2% 错误率。bn-cli 的 `_parse_address` 统一接受 `0x...` 格式和十进制整数，bridge 侧做归一化处理。

**3. 输出控制防止上下文爆炸**

MCP 方案中 IL 输出无截断，单次 `il.function` 可能消耗数万 tokens。bn-cli 内置 auto-spill 机制，超过 10,000 tokens 的输出自动写入临时文件，仅在 stderr 返回元数据（路径、大小、token 数）。

**4. 搜索语义分离**

MCP 方案中 `search.all_constant` 的 77% 错误率源于 Agent 混淆"搜索常量值"和"搜索字符串"。bn-cli 将语义完全分开：`bn strings` 搜字符串，`bn search` 搜二进制内容，互不混淆。

**5. 脚本执行环境预置**

MCP 方案中 `binja.eval` 的 23.1% 错误率主要因未获取 BinaryView。bn-cli 的 `bn py exec` 自动注入 `bv`、`bn`、`binaryninja` 变量。

**6. 变更验证而非静默成功**

所有 mutation 命令在应用后会读回实际状态进行验证，不匹配则自动回滚并报告 `verification_failed`。Agent 不再需要额外调用来确认变更是否生效。

## 架构概览

```
┌─────────────┐         Unix Socket         ┌──────────────────────┐
│   bn CLI    │ ──── JSON request ────────▶ │   Bridge Daemon      │
│  (Python)   │ ◀─── JSON response ──────── │   (Binary Ninja)     │
│             │                              │                      │
│ 不导入 BN   │    每次调用 ~0.28s           │  TargetManager       │
│ 纯 socket   │    无二进制重加载            │  (强引用驻留内存)     │
└─────────────┘                              └──────────────────────┘
```

关键架构决策：

- **CLI 进程从不导入 binaryninja**：它是纯粹的 socket 客户端，启动快（~0.15s）
- **二进制只加载一次**：`bn target load` 后文件驻留在 daemon 的 `TargetManager` 中，后续所有命令都对内存中的 `BinaryView` 操作
- **双模式并行**：GUI plugin 和 headless daemon 可同时运行，各有独立 socket

## 安装

安装 CLI 到 PATH：

```bash
uv tool install -e .
```

安装 Binary Ninja 伴随插件：

```bash
bn plugin install
```

安装 Agent skill（Codex + Claude Code）：

```bash
bn skill install
```

默认同时安装到 Codex（`~/.codex/skills/bn`）和 Claude Code（`~/.claude/skills/bn`）。用 `--client codex` 或 `--client claude-code` 限定平台。

Skill 也支持**自动安装**：首次执行任何 `bn` 命令时，如果目标目录不存在，CLI 会静默创建 symlink。也就是说 `uv tool install -e .` 之后直接使用即可，无需手动执行 `bn skill install`。设置 `BN_NO_AUTO_SKILL=1` 可禁用此行为。

## 快速开始

### GUI 模式

在 Binary Ninja 中打开二进制文件，然后：

```bash
bn doctor                     # 检查 bridge 连接
bn target list                # 列出已打开的目标
bn function list              # 列出所有函数
bn decompile sub_401000       # 反编译指定函数
```

### Headless 模式

```bash
bn daemon start --foreground &        # 启动 headless 守护进程
bn target load /path/to/binary.so     # 加载并分析（阻塞直到完成）
bn function list                      # 列出函数
bn decompile main                     # 反编译
bn target save --path /tmp/out.bndb   # 保存数据库
bn target close                       # 卸载目标
bn daemon stop                        # 停止守护进程
```

## 命令参考

### 核心命令

| 命令 | 描述 |
|------|------|
| `bn doctor` | 验证 bridge 连接和安装状态 |
| `bn plugin` | 安装 Binary Ninja 伴随插件 |
| `bn skill` | 安装 Agent skill 到 Codex/Claude Code |
| `bn daemon` | 管理 bridge 守护进程 (start/stop/status/list/use) |
| `bn target` | 目标文件管理 (list/load/close/save/status) |
| `bn refresh` | 刷新分析 |

### 读取 / 检查命令

| 命令 | 描述 |
|------|------|
| `bn function list` | 列出所有函数（支持 `--min-address`、`--max-address`） |
| `bn function search` | 按名称搜索函数（子串匹配或 `--regex`） |
| `bn function info` | 函数详细信息（局部变量、参数、local_id） |
| `bn decompile` | HLIL 风格反编译输出 |
| `bn il` | 导出函数 IL（HLIL/MLIL/LLIL） |
| `bn disasm` | 反汇编函数 |
| `bn disasm-linear` | 从指定地址线性反汇编 |
| `bn disasm-range` | 反汇编地址范围 |
| `bn xrefs` | 交叉引用（地址/函数/结构体字段） |
| `bn xref-ext` | 扩展交叉引用 (code-refs-from/to, data-refs-from/to, type-refs) |
| `bn callsites` | 查找直接调用点和精确返回地址 |
| `bn types` | 列出或搜索类型 |
| `bn strings` | 列出或搜索字符串 |
| `bn imports` | 列出导入表 |
| `bn segments` | 列出段（segment） |
| `bn sections` | 列出节（section） |
| `bn data-vars` | 列出数据变量 |
| `bn data-typed-at` | 获取指定地址的类型化数据变量 |
| `bn binary-bbs-at` | 获取指定地址的基本块 |
| `bn il-nav` | IL 导航 (地址↔索引转换) |
| `bn proto get` | 查看函数原型 |
| `bn local list` | 列出函数的局部变量和参数 |
| `bn comment get` | 获取指定地址的注释 |
| `bn arch` | 架构信息和工具 |
| `bn search` | 搜索二进制内容 |
| `bn value` | 寄存器/栈值分析 |
| `bn memory` | 原始内存读写 |
| `bn workflow` | 分析工作流检查 |
| `bn api-docs` | 查询 Binary Ninja 本地 API 文档（无需 target） |

### 变更命令

| 命令 | 描述 |
|------|------|
| `bn symbol rename` | 重命名函数或数据符号 |
| `bn comment set` | 设置或删除注释 |
| `bn proto set` | 设置函数原型 |
| `bn local rename` | 重命名局部变量 |
| `bn local retype` | 修改局部变量类型 |
| `bn struct field set` | 结构体字段编辑 |
| `bn types declare` | 声明 C 类型 |
| `bn batch apply` | 批量应用变更清单 |
| `bn patch` | 二进制补丁操作 |

### 数据库和撤销

| 命令 | 描述 |
|------|------|
| `bn database info` | 显示数据库 (bndb) 信息 |
| `bn database snapshots` | 列出数据库快照 |
| `bn undo begin` | 开始撤销组 |
| `bn undo commit` | 提交撤销组 |
| `bn undo revert` | 回滚当前撤销组 |
| `bn undo undo` | 撤销上一个操作 |
| `bn undo redo` | 重做上一个撤销 |

### 类型和注释扩展

| 命令 | 描述 |
|------|------|
| `bn type-ext parse` | 解析 C 类型字符串 |
| `bn type-ext library-list` | 列出类型库 |
| `bn type-ext library-query` | 查询类型库 |
| `bn annotation get-tags` | 获取标签 |
| `bn annotation create-tag` | 创建标签 |
| `bn annotation add-tag` | 添加标签到函数/地址 |
| `bn annotation remove-tag` | 移除标签 |
| `bn annotation list-tag-types` | 列出标签类型 |

### 分析和元数据

| 命令 | 描述 |
|------|------|
| `bn analysis status` | 显示分析进度 |
| `bn analysis update` | 触发分析更新 |
| `bn metadata store` | 存储元数据键值对 |
| `bn metadata query` | 按键查询元数据 |
| `bn metadata remove` | 按键删除元数据 |
| `bn metadata keys` | 列出所有元数据键 |

### 高级操作

| 命令 | 描述 |
|------|------|
| `bn loader settings` | 显示加载器设置 |
| `bn loader rebase` | 重定基址 |
| `bn external library-list` | 列出外部库 |
| `bn external library-add` | 添加外部库 |
| `bn external location-list` | 列出外部位置 |
| `bn external location-add` | 添加外部位置 |
| `bn uidf from-address` | 用户 IL 数据流分析 |
| `bn section-user create` | 创建用户节 |
| `bn section-user delete` | 删除用户节 |
| `bn segment-user create` | 创建用户段 |
| `bn segment-user delete` | 删除用户段 |
| `bn debug-info list` | 列出调试信息 |
| `bn plugin-cmd list` | 列出已注册插件命令 |
| `bn plugin-cmd run` | 运行插件命令 |
| `bn bundle function` | 导出函数 bundle |
| `bn py exec` | 在 Binary Ninja 内执行 Python |

## 目标选择

使用 `bn target list` 查看可用目标。选择方式：

- `selector` 字段（推荐）
- 完整 `target_id`
- BinaryView 文件名
- view id
- `active`（GUI 当前标签 / headless 最近加载的目标）

单目标时可省略 `--target`。多目标时必须指定，否则 CLI 报错并提示。

## 守护进程模式选择

GUI 和 headless 可同时运行。CLI 路由规则：

1. `bn daemon use <mode>` 设定的 sticky 优先
2. 只有一个 daemon 运行时自动选择
3. 多个运行且无 sticky 时报错并提示

```bash
bn daemon list                # 查看所有运行中的 daemon
bn daemon use headless        # 固定后续命令到 headless
bn daemon use --clear         # 清除固定，自动选择
```

## 输出行为

所有命令支持 `--format json|text|ndjson` 和 `--out <path>`。

读取命令默认 `text`，变更命令默认 `json`。使用 `--out` 时输出写入文件，stdout 打印元数据信封（路径、大小、token 数、hash）。

大输出自动 spill：超过 10,000 tokens 时自动写入临时文件，stdout 为空，stderr 打印 spill 元数据。Agent 据此决定是否读取完整内容。

## 批量变更

`bn batch apply` 接受 JSON 清单，支持原子性批量操作：

```json
{
  "target": "binary.bndb",
  "preview": true,
  "ops": [
    {"op": "rename_symbol", "kind": "function", "identifier": "sub_401000", "new_name": "main_loop"},
    {"op": "set_prototype", "identifier": "main_loop", "prototype": "int main_loop(void)"}
  ]
}
```

任何一个 op 验证失败则整体回滚。

## Python 执行

```bash
bn py exec --code "result = {'entry': hex(bv.entry_point), 'funcs': len(list(bv.functions))}"

bn py exec --stdin <<'PY'
out = []
for f in bv.functions:
    if 0x416000 <= f.start < 0x41C000:
        out.append((f.start, f.symbol.short_name))
result = sorted(out)
PY
```

执行环境预置 `bv`、`bn`、`binaryninja`、`result` 变量。stdout 和 `result` 都会返回。

## 与 MCP 方案对比

基于 [14,477 次工具调用分析报告](https://km.sankuai.com/collabpage/2763899210) 的数据：

| 维度 | re_agent MCP | bn-cli |
|------|-------------|--------|
| 错误率 | 16.0% | <1%（测试 192 全通过） |
| Session 冗余 | 140 次无意义查询 | 不存在 session 概念 |
| 地址混淆 | 55.2% 错误率 | 统一 `_parse_address` 归一化 |
| 输出控制 | 无截断 | auto-spill + token 计数 |
| 搜索混淆 | 77% 错误率 | 语义分离（strings/search） |
| 脚本环境 | 23.1% 因缺少 bv | 自动注入 bv 变量 |
| 每次调用开销 | ~1-5s + 复杂握手 | ~0.28s socket 通信 |
| 变更验证 | 无（静默成功） | 自动验证 + 失败回滚 |

## 故障排除

```bash
bn doctor                     # 检查 bridge 状态
```

常见问题：

- `bn target list` 为空：确认 BN 已打开文件 + 插件已安装
- Codex 沙箱权限：在 `~/.codex/rules/default.rules` 添加 `prefix_rule(pattern=["bn"], decision="allow")`
- 反编译文本过期：运行 `bn refresh`

## 开发

```bash
uv run pytest                 # 运行测试（192 tests, 不需要 Binary Ninja）
uv run bn --help              # 从仓库运行 CLI
```

## License

MIT
