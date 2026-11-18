# bn — Agent 优先的 Binary Ninja CLI

[English](README.md) | 中文

`bn` 是一个面向 AI Agent 设计的 Binary Ninja 命令行工具。它为 shell 会话或 Agent 工具调用提供稳定的命令接口、结构化输出，以及对 Binary Ninja 实时数据库的完整访问能力——无论是 GUI 模式还是 headless 守护进程模式。


## 筛选、排序和统计

`bn query` 在 bridge 内筛选数据，只返回选定的字段和分页。可查询
`functions`（address、name、raw_name）、`strings`（address、length、type、value）
和 `imports`（address、name、library）。重复传入 `--filter` 表示同时满足各条件。
`~` 表示忽略大小写的包含匹配，支持 `=`、`!=`、`<`、`<=`、`>`、`>=`。
地址和长度按数值比较，`--sort=-length,address` 按长度降序、地址升序排列。

```sh
bn query strings --filter 'length>=12' --sort=-length,address --fields address,value --limit 10
bn query imports --filter 'name~open' --count
```

每页默认最多 1,000 行，`--offset` 指定跳过的行数，`--limit 0` 返回全部匹配行。
`--count` 返回分页前的匹配总数。

## 核心特性

- 从 shell 查询 Binary Ninja 实时状态：目标文件、函数、调用点、反编译文本、IL、反汇编、交叉引用、类型、字符串、导入表等
- 在 Binary Ninja 进程内执行 Python，无需维护单独的 headless 工作流
- 使用 `--preview` 应用变更，捕获反编译 diff，并在报告成功前验证实际状态
- 输出结构化 `json` / `ndjson`，大结果自动 spill 到文件，返回 token 计数帮助 Agent 管理上下文预算
- 多类 Binary Ninja API 命令，涵盖分析、注释、数据库、调试信息、IL 导航、类型扩展、元数据、撤销/重做、加载器、外部库、插件命令等

## 0.16：无头工作流与跨工具地址

无需打开 GUI。`bn --daemon headless ...` 只为本次调用选择 daemon，不修改共享选择；提交、等待和取结果固定使用同一个连接。多个客户端并行时，使用 `target load/list` 返回的具体 `--target`。`active` 由 `bn target use` 管理，与 GUI 焦点和加载先后无关。

仅显示基址不能解决地址混用。现在现有查询和修改命令接受显式坐标：

| 写法 | 含义 |
|---|---|
| `va:0x401010`，裸 `0x401010` | BN 虚拟地址；裸十进制保持原有规则 |
| `rva:0x1010` | 相对 **当前 `BinaryView.image_base`**，不是 `start` 或原始首选基址 |
| `file:0x210` | 按段和 BN API 转换的 backing-data 偏移，不是简单加基址 |
| `map:frida-123:0x7100001010` | 已注册外部地址空间中的地址 |
| `expr:main+0x10` | 显式调用 BN 原生表达式解析；注意 shell 引号 |

所有 target job 携带具体目标和地址上下文，CLI 默认在 stderr 显示提示。加 `--with-context --format json` 可将上下文一起放入结果和导出文件；原有默认结果形状保持兼容。BN 原生 `expr:` 的裸数字规则与普通 CLI 不同，通常按十六进制解析。IL 索引、栈偏移、整数宽度及其他外部库中的地址属于不同数值域。工具不会偷偷清除 Thumb 位、PAC 或指针标签。

```bash
bn --daemon headless target load /path/to/libexample.so
bn address context
bn address resolve rva:0x1010 file:0x210
bn inspect rva:0x1010
```

在已有 Frida 会话中取得实际模块快照，保存输出 JSON 为 `module.json`：

```javascript
const m = Process.getModuleByName('libexample.so');
console.log(JSON.stringify({name: m.name, path: m.path, base: m.base.toString(), size: m.size}));
```

```bash
bn address map import frida-123 module.json --kind frida-module --source pid:123/session:1
bn inspect map:frida-123:0x7100001010
bn address verify map:frida-123:0x7100001010 --bytes '554889e5'
bn decompile map:frida-123:0x7100001010 --with-context --format json
```

示例地址和字节须替换成实际观测。导入将 Frida `base` 对应到 BN 当前 `image_base`，并以模块 `size` 限定范围；如果 BN 的 `image_base != start`，必须用 `--bn-base` 明确指定与 Frida `Module.base` 对应的 BN 地址。也可手动使用 `address map add NAME --base EXTERNAL --size SIZE --bn-base va:BN_ADDRESS --source SESSION` 注册锚点。空洞继续保持未映射，范围外的 BN synthetic 区域不会被换算成运行时地址。

Unicorn 分段搬运应记录每段实际对应关系，例如 `unicorn-map.json`：

```json
{"regions": [
  {"bn_start": "0x401000", "external_start": "0x10000", "length": "0x100"},
  {"bn_start": "0x408000", "external_start": "0x90000000", "length": "0x1000"}
]}
```

```bash
bn address map import uc-run1 unicorn-map.json --source unicorn:run1
bn memory read map:uc-run1:0x10010 --length 16 --with-context --format json
bn address resolve map:uc-run1:0x10010
bn address map export uc-run1 --out /tmp/uc-run1.json
bn address map list
bn address map remove uc-run1
```

映射按目标和会话隔离；注册检查完整范围、空洞、溢出及双向重叠，重名需先显式删除。BN 基址或段布局变化后映射失效。外部进程重启或模拟器重新映射无法由 bn-cli 自动感知，必须重新登记。映射是用户声明，布局指纹也不是样本身份认证。`address verify` 用实际外部字节核对 BN 内容，不一致返回退出码 3；重定位、运行时补丁和不同构建也可能造成差异。

BSS 的文件偏移可能为 `null`。一个文件偏移对应多个 VA 时拒绝自动选择。容器或切片视图的偏移可能相对其 backing data，不一定相对最外层文件；Raw 视图按原始字节偏移处理。注册映射不会 rebase BN，也不修改字节。

新增的连续操作入口：

```bash
bn value reg main 0 rax                     # LLIL 索引 0
bn value reg main rax --address rva:0x1010 --after
bn value possible main 0 rax                # 原生 possible-register-values 查询
bn job watch JOB_ID                         # 仅输出变化的进度，最终返回原结果
bn job wait JOB_ID --with-context --out /tmp/job.json
bn result list
bn result show /tmp/job.json --key result --limit 20
bn result diff /tmp/before.json /tmp/after.json
bn schema address map import               # 从实际 parser 生成，无需 daemon
```

`value` 的 IL 索引与 `--address` 互斥；寄存器、栈、可能值和标志值直接使用 LLIL 指令原生 API。结果同时给出机器地址、映射后的 LLIL 地址及索引。`loader rebase` 会注册 BN 返回的新视图、返回新的 target id，并清除旧地址映射；后续命令须使用新 target。该操作不可取消。标志名按 `bn arch info` 输出，例如 x86 的 `z`。`memory reader --width` 读取整数，`memory read --length` 读取字节。`search text --il-type` 对字面查询选择原生图类型，正则查询匹配该表示中的单条指令文本；字节搜索目前要求精确十六进制字节。

新 bridge 使用服务端等待，旧 bridge 仍兼容轮询。超时和 Ctrl+C 只停止等待，已完成写入的结果不会被晚到的取消覆盖。自动落盘使用唯一文件名和原子写入。`result show` 对 NDJSON/文本分段读取；JSON 选择及 diff 会加载输入，diff 仅是结构/文本比较。NDJSON 输出格式本身不代表服务端流式传输。

修复了汇编、NOP 长度、reader、value、常量查询等参数未接通的问题。`patch assemble` 使用指令架构的 `Architecture.assemble`，字节写入在 undo group 中检查完整写入量并读回核对。NOP 范围必须在完整指令处结束，省略长度时处理一条指令。元数据应用异常会回滚，Workflow 预览必须确认恢复成功。上述检查验证具体编辑，不是全程序等价证明，也不覆盖任意 `py exec`。

新版 API 调研与可复现实测详见 [英文说明](README.md#bn-6x-api-review-and-validation)。自动化测试 **294 项通过**。本机验证版本为 BN **6.1.10530-dev**、Unicorn **2.1.4**、Frida **17.17.0**，包含真实 socket/CLI 和临时 `/bin/sleep` 进程的 ASLR 地址与字节核对。其他 loader、架构和版本仍需各自测试：

```bash
uv run pytest
PYTHONPATH=/path/to/binaryninja/python BN_DISABLE_USER_PLUGINS=1 \
  uv run --with unicorn --with frida python tools/smoke_headless.py --external
```

## 设计理念

本工具的设计基于对 AI Agent 在逆向工程场景下 14,477 次工具调用的系统分析（详见 [分析报告](https://km.sankuai.com/collabpage/2763899210)），针对性地解决了以下核心瓶颈：

**1. 消除 session 冗余查询**

MCP 方案中 Agent 每次调用前都要查询 session ID（140 次无意义调用，浪费 70,000 tokens）。bn-cli 的 daemon 架构天然避免了这个问题——target 通过 `--target` 参数或 implicit 选择，不存在 session 概念。

**2. 地址归一化**

文件偏移、RVA、BN VA 和外部进程地址属于不同坐标系。bn-cli 通过显式地址前缀、目标隔离映射、自动上下文和外部字节核对处理，具体边界见上文。

**3. 输出控制防止上下文爆炸**

MCP 方案中 IL 输出无截断，单次 `il.function` 可能消耗数万 tokens。bn-cli 内置 auto-spill 机制，超过 10,000 tokens 的输出自动写入临时文件，仅在 stderr 返回元数据（路径、大小、token 数）。

**4. 搜索语义分离**

MCP 方案中 `search.all_constant` 的 77% 错误率源于 Agent 混淆"搜索常量值"和"搜索字符串"。bn-cli 将语义完全分开：`bn strings` 搜字符串，`bn search` 搜二进制内容，互不混淆。

**5. 脚本执行环境预置**

MCP 方案中 `binja.eval` 的 23.1% 错误率主要因未获取 BinaryView。bn-cli 的 `bn py exec` 自动注入 `bv`、`bn`、`binaryninja` 变量。

**6. 变更验证而非静默成功**

元数据 mutation 会验证请求的实际状态；字节写入另行检查完整写入量与读回结果。任意 Python 和其他底层 API 包装不自动继承这些保证。

## 架构概览

```
┌─────────────┐       本地 Socket / TCP      ┌──────────────────────┐
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
- **跨平台本地传输**：Linux/macOS 使用 Unix-domain socket；Windows GUI 默认使用 `127.0.0.1:26765`，headless 默认使用 `127.0.0.1:26766`，并带随机认证令牌。可通过 `BN_BRIDGE_GUI_PORT` / `BN_BRIDGE_HEADLESS_PORT` 覆盖默认值

在 Windows 版 Binary Ninja 内运行 `BN Agent Bridge\Set GUI Port...` 可以保存新的用户端口并立即重启 bridge。也可以在 Settings 的 **BN Agent Bridge** 分组修改 **GUI Listen Port**，然后运行 `BN Agent Bridge\Restart Bridge`。新端口被占用时，插件会恢复之前的设置和监听端口。

## 安装

安装 CLI 到 PATH：

```bash
uv tool install -e .
```

然后运行一键安装，同时安装 Binary Ninja 插件和 Agent skill：

```bash
bn setup
```

这会完成两件事：

1. 将 `plugin/bn_agent_bridge` symlink 到 Binary Ninja 插件目录
2. 将 bundled skill 安装到 Codex（`~/.codex/skills/bn`）和 Claude Code（`~/.claude/skills/bn`）

用 `--force` 覆盖已有安装。也可以单独执行：

```bash
bn plugin install          # 只安装插件
bn skill install           # 只安装 skill（支持 --client, --mode, --dest）
```

用 `--client codex` 或 `--client claude-code` 限定平台。

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
bn daemon stop                        # 通过认证协议优雅停止守护进程
```

## 命令参考

### 核心命令

| 命令 | 描述 |
|------|------|
| `bn setup` | 一键安装：插件 + skill 全部就位 |
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
| `bn decompile` | 输出保留嵌套控制流的结构化 HLIL 文本 |
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
| `bn function create` | 在指定地址创建并验证用户函数 |
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
- `active`（`bn target use` 显式选中的目标，或唯一已加载目标）

单目标或存在显式 active 时可省略 `--target`；多目标且未选择 active 时必须指定。

## 守护进程模式选择

GUI 和 headless 可同时运行。CLI 路由规则：

1. 本次调用的 `--daemon MODE` 优先，其次为 `bn daemon use <mode>` 的 sticky 选择
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

token 计数完全支持离线：`o200k_base` BPE 表随包分发（`bn/_data/o200k_base.tiktoken`，以 sha256 固定），首次运行无需联网下载。若该表缺失，`bn` 会退回 tiktoken 自身缓存（`$BN_CACHE_DIR/tiktoken`），最后退回按字节估算，因此命令不会因为分词器而失败。`bn doctor` 会显示当前使用的来源。小于 spill 阈值的输出会跳过分词，保持短命令的响应速度。

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
