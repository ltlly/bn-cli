# bn

English | [中文](README_CN.md)

`bn` is an agent-first CLI for Binary Ninja with a persistent headless daemon, explicit address coordinates, structured queries, and verified metadata edits. A GUI bridge remains available; the workflows below work without opening the GUI.

## Headline Features

- Query live Binary Ninja state from the shell: targets, functions, callsites, decompile text, IL, disassembly, xrefs, types, strings, imports, and reusable bundles.
- Execute Python inside the Binary Ninja process instead of maintaining a separate headless workflow.
- Apply mutations with `--preview`, capture decompile diffs, and verify the live post-state before reporting success.
- Emit structured `json` or `ndjson` output, auto-spill large results to files, and return token counts so agents can budget context intelligently.
- Commands spanning analysis, annotation, database, debugging info, IL navigation, type extensions, metadata, undo/redo, loader, external libraries, and plugins. `bn schema <command...>` describes the actual installed command grammar offline.

## Headless address workflows (0.16)

Addresses are coordinates in a particular view or process, not interchangeable integers. Every target job carries its concrete target and address context. The CLI prints a compact context line on stderr; use `--with-context --format json` to include that context in the result or an exported file while preserving the default output shape for existing scripts. This context also remains available through `job status`, `job result --with-context`, and `job wait --with-context`.

| Input | Meaning |
|---|---|
| `0x401010`, `4198416`, `va:0x401010` | BN virtual address; bare decimal retains the existing CLI convention |
| `rva:0x1010` | Offset from **`BinaryView.image_base`**, not `view.start` or the original preferred base |
| `file:0x210` | BN backing-data offset translated through segment/API mappings; never `base + offset` |
| `map:frida-123:0x7100001010` | External address in the registered, target-scoped `frida-123` map |
| `expr:main+0x10` | Explicit native `BinaryView.parse_expression` syntax; quote shell metacharacters |

Native expression numbers use BN's conventions (including hexadecimal by default); ordinary CLI numbers remain decimal unless prefixed by `0x`. Integer widths, stack offsets, IL indices, and addresses in another external library are separate numeric domains. Pointer tags/PAC and Thumb bits are never silently removed.

```bash
bn --daemon headless target load /path/to/libexample.so
bn --daemon headless address context
bn --daemon headless address resolve rva:0x1010 file:0x210
bn --daemon headless inspect rva:0x1010
```

`--daemon headless` is a per-invocation choice; it does not change the shared sticky selection. The selected connection is pinned across discovery, job submission, waiting, and result retrieval. For parallel clients, also pass a concrete `--target` returned by `target load/list`. Active selection is CLI-managed by `target use`, independent of GUI focus and load order.

### Frida module snapshots

Capture the actual module in your existing Frida session (this code does not attach to anything):

```javascript
const m = Process.getModuleByName('libexample.so');
console.log(JSON.stringify({name: m.name, path: m.path, base: m.base.toString(), size: m.size}));
```

Save that JSON as `module.json`, then:

```bash
bn address map import frida-123 module.json --kind frida-module --source pid:123/session:1
bn inspect map:frida-123:0x7100001010
bn address verify map:frida-123:0x7100001010 --bytes '554889e5'
bn decompile map:frida-123:0x7100001010 --with-context --format json
```

The sample addresses/bytes above must be replaced with actual observations. A Frida import maps its `base` to BN's current `image_base` and bounds the mapping by the observed `size`. If BN's image base and lowest mapped address differ, import requires an explicit `--bn-base` identifying the BN address corresponding to Frida's `Module.base`. For an explicitly chosen anchor, `address map add NAME --base EXTERNAL --size SIZE --bn-base va:BN_ADDRESS --source SESSION` provides the same bounded slide. Sparse holes remain unmapped; BN synthetic regions outside the supplied module span are excluded.

### Unicorn and piecewise layouts

For independently placed memory regions, write exact pairs instead of supplying one global base. For example, `unicorn-map.json`:

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

Map registration checks bounds, mapped BN spans, and overlapping coordinates in both directions. It does not rebase BN or change bytes. Maps are session-scoped and target-isolated; duplicate names require explicit removal. A changed BN base/segment layout invalidates the map. Re-register after an external process restart or emulator remap: bn-cli cannot detect those external events. Exported maps carry a layout fingerprint, which validates layout only, not binary identity.

Mappings are **user-declared**, not proof of matching processes/builds. `address verify` compares observed external bytes with BN bytes and returns exit 3 on mismatch; runtime relocations, patches, or a different build may also explain a mismatch. BSS can have no file offset (`null`). Multiple VA mappings of one file offset are rejected rather than choosing the first; container/slice views may use offsets relative to their backing data rather than the outer file. Raw views use raw byte offsets.

### Continuous queries, tasks, and result reuse

```bash
bn inspect main                             # coordinates, bytes, containing functions, xrefs, decompile
bn value reg main 0 rax                     # LLIL index 0, before the instruction
bn value reg main rax --address rva:0x1010 --after
bn value possible main 0 rax                # native LLIL possible-register-values query
bn job watch JOB_ID                         # changed progress on stderr; original result on stdout
bn job wait JOB_ID --with-context --out /tmp/job.json
bn result list
bn result show /tmp/job.json --key result --limit 20
bn result show /tmp/functions.json --offset 20 --limit 20 --fields address,name
bn result diff /tmp/before.json /tmp/after.json
bn schema address map import
```

IL indices are explicitly distinct from machine addresses; `--address` is mutually exclusive with the positional LLIL index. `value reg/stack/possible/flags` use native instruction APIs, and `--after` selects the post-instruction query. Results distinguish the requested machine `address`, mapped `llil_address`, and `instruction_index`, since native source mappings may not preserve identical addresses. `memory reader --width {1,2,4,8}` reads an integer; `memory read --length N` reads bytes. `search text --il-type` selects the native graph type for literal searches; `--regex` matches individual instruction text in that representation. Exact byte searches do not accept wildcard bytes.

Jobs use bounded server waits on new bridges, with compatibility polling for older bridges. Wait timeout and Ctrl+C stop waiting without cancelling work. A completed write keeps its result even if cancellation arrives after completion. Automatic spill files use unique names and atomic writes. `result show` pages NDJSON/text without loading the entire file; JSON selection and structural/text diffs load their input, and do not claim program equivalence. NDJSON output formatting itself is not server streaming.

`patch assemble` now uses the architecture at the instruction and `Architecture.assemble`; writes check the complete byte count and read back bytes within an undo group. `patch nop --length N` covers an exact instruction-aligned range; omitting length affects one instruction. Metadata transactions roll back unexpected application errors, and Workflow preview success requires verified restoration. These checks cover the requested edit, not whole-program equivalence, and do not make arbitrary `py exec` code transactional.

### BN 6.x API review and validation

Reviewed the [BN 6.0 release](https://binary.ninja/2026/09/03/binary-ninja-6.0-krypton.html), [current BinaryView API](https://dev-api.binary.ninja/binaryninja.binaryview-module.html), [Frida JavaScript API](https://frida.re/docs/javascript-api/), and [Unicorn tutorial](https://www.unicorn-engine.org/docs/tutorial.html). BN 6.0 includes MCP, changes to calling conventions/structure values, and bundled Python 3.13. Compatibility follows installed API capabilities rather than assuming all 6.x builds match; `doctor` reports the actual BN version and selected capabilities. `image_base` and `original_image_base` have different meanings; the deprecated `original_base` alias is not used. Headless load uses `bn.load(..., update_analysis=False)` followed by explicit analysis on an ordinary thread; `rebase()` creates a new BinaryView and is not an address-conversion shortcut. `bn loader rebase` is headless-only and not cancellable: it analyzes/registers the returned view, returns a replacement target id, and discards old external maps. Subsequent commands must use that new target.

The automated suite passes **294 tests**. Real smoke coverage on BN **6.1.10530-dev** includes the actual socket/CLI, nonzero BN load base, scratch byte edits, and independent coordinates in **Unicorn 2.1.4** and **Frida 17.17.0** (a spawned local `/bin/sleep` under ASLR). These tests do not imply compatibility with every loader, architecture, or BN release. Reproduce without opening a GUI:

```bash
uv run pytest
PYTHONPATH=/path/to/binaryninja/python BN_DISABLE_USER_PLUGINS=1 \
  uv run python tools/smoke_headless.py --sample /bin/true
PYTHONPATH=/path/to/binaryninja/python BN_DISABLE_USER_PLUGINS=1 \
  uv run --with unicorn --with frida python tools/smoke_headless.py --external
```

## Install

Install the CLI on your PATH:

```bash
uv tool install -e .
```

Then run the one-command setup to install both the Binary Ninja companion plugin and the agent skill:

```bash
bn setup
```

This does two things:

1. Symlinks `plugin/bn_agent_bridge` into your Binary Ninja plugins directory
2. Installs the bundled skill into both Codex (`~/.codex/skills/bn`) and Claude Code (`~/.claude/skills/bn`)

Pass `--force` to overwrite existing installations. If you only need one piece, the individual commands are still available:

```bash
bn plugin install          # plugin only
bn skill install           # skill only (supports --client, --mode, --dest)
```

Limit skill installation to one client with `--client codex` or `--client claude-code`. Use `--mode copy` if you want a standalone copy instead of a symlink. Pass `--dest <path>` (with a single `--client`) to install elsewhere. Restart your agent to pick up a new or renamed skill.

If the plugin code changes, reload Binary Ninja Python plugins or restart Binary Ninja.

## How It Works

- `bn` has two parts:
  - a normal Python CLI that you can run from your shell or agent tool harness
  - a Binary Ninja bridge that exposes the API over a local transport: a Unix-domain socket on Unix, or authenticated loopback TCP on Windows
- The bridge runs in one of two **modes**:
  - **`gui`** — loaded as a Binary Ninja plugin inside the GUI process. Works with a personal license. Started automatically when Binary Ninja opens with the plugin installed.
  - **`headless`** — long-running daemon started with `bn daemon start`. Requires a Binary Ninja commercial (headless) license. Built for containers, CI, and AI agent driver loops.
- Each mode has its own endpoint and registry file under the platform cache directory, so both can run simultaneously on the same machine. On Windows, GUI defaults to `127.0.0.1:26765` and headless to `127.0.0.1:26766`; registry entries include a random authentication token and the CLI only accepts loopback endpoints. Override the defaults with `BN_BRIDGE_GUI_PORT` or `BN_BRIDGE_HEADLESS_PORT`.
- The CLI auto-discovers all running daemons. When only one is up, it routes to that one. When both are up, it routes to the **sticky** mode chosen via `bn daemon use <mode>` (see [Daemon Mode Selection](#daemon-mode-selection)).
- **No repeated loading**: The daemon keeps loaded binaries resident in memory. Each CLI invocation just opens a socket, sends a JSON request, and reads the response — the binary is never re-imported.

### Changing the GUI bridge port

On Windows, run `BN Agent Bridge\Set GUI Port...` inside Binary Ninja to save a new user-level port and restart the bridge immediately. You can also edit **GUI Listen Port** under the **BN Agent Bridge** group in Binary Ninja Settings, then run `BN Agent Bridge\Restart Bridge`. If the new port cannot be bound, the plugin restores the previous setting and listener instead of leaving the bridge offline.

## Quick Start

### GUI mode

Open a binary or `.bndb` in Binary Ninja, then run:

```bash
bn doctor
bn target list
bn refresh
bn function list
bn decompile sub_401000
```

### Headless daemon mode

```bash
bn daemon start --foreground &        # or run as PID 1 in Docker
bn daemon list                        # confirm it's up
bn target load /path/to/binary.so     # blocks until analysis is done
bn function list
bn target save --path /tmp/binary.bndb
bn target close
bn daemon stop
```

If exactly one BinaryView is loaded, target-specific commands can omit `--target` entirely. If multiple targets are open, pass `--target <selector>` from `bn target list`, or rely on the implicit fallback to the "active" target — the explicit selection made with `bn target use`.

## Command Reference

### Core Commands

| Command | Description |
|---------|-------------|
| `bn setup` | One-command setup: install plugin + skill into all clients |
| `bn doctor` | Validate bridge discovery and installation |
| `bn plugin` | Install the Binary Ninja companion plugin |
| `bn skill` | Install the bundled skill into Codex and/or Claude Code |
| `bn daemon` | Manage bn bridge daemons (start/stop/status/list/use) |
| `bn job` | Inspect, retrieve, and cooperatively cancel background jobs |
| `bn target` | Inspect/load/close/save Binary Ninja targets |
| `bn refresh` | Refresh analysis for the selected target |

### Read / Inspection Commands

| Command | Description |
|---------|-------------|
| `bn function list` | List all functions (supports `--min-address`, `--max-address`) |
| `bn function search` | Search functions by name (substring or `--regex`) |
| `bn function info` | Detailed function info (locals, params, local_ids) |
| `bn decompile` | Render HLIL-style decompile text |
| `bn il` | Dump IL for a function (HLIL/MLIL/LLIL variants) |
| `bn disasm` | Disassemble a function |
| `bn disasm-linear` | Disassemble linearly from an address |
| `bn disasm-range` | Disassemble an address range |
| `bn xrefs` | List xrefs to an address/function/struct field |
| `bn xref-ext` | Extended cross-references (code-refs-from/to, data-refs-from/to, type-refs) |
| `bn callsites` | Find direct native callsites with exact caller_static addresses |
| `bn types` | List or search types |
| `bn strings` | List or search strings |
| `bn imports` | List imports |
| `bn segments` | List binary segments |
| `bn sections` | List binary sections |
| `bn data-vars` | List data variables |
| `bn data-typed-at` | Get typed data variable at address |
| `bn binary-bbs-at` | Get basic blocks at address (binary-wide) |
| `bn il-nav` | IL navigation (addr-to-index, index-to-addr) |
| `bn proto get` | Inspect a function prototype |
| `bn local list` | List locals and parameters of a function |
| `bn comment get` | Get comment at address |
| `bn arch` | Architecture information and utilities |
| `bn search` | Search binary content |
| `bn value` | Register/stack value analysis at IL instructions |
| `bn memory` | Raw memory read/write operations |
| `bn workflow` | Inspect Binary Ninja analysis workflows |
| `bn api-docs` | Query Binary Ninja's local Python API docs (no target needed) |

### Mutation Commands

| Command | Description |
|---------|-------------|
| `bn function create` | Create and verify a user function at an address |
| `bn symbol rename` | Rename functions or data symbols |
| `bn comment set` | Set or delete comments |
| `bn proto set` | Set a user prototype |
| `bn local rename` | Rename a local variable |
| `bn local retype` | Retype a local variable |
| `bn struct field set` | Field-first structure editing |
| `bn types declare` | Declare types from C source |
| `bn batch apply` | Apply a batch manifest (multiple ops atomically) |
| `bn patch` | Binary patching operations |

### Database & Undo

| Command | Description |
|---------|-------------|
| `bn database info` | Show database (bndb) information |
| `bn database snapshots` | List database snapshots |
| `bn undo begin` | Begin an undo group |
| `bn undo commit` | Commit the current undo group |
| `bn undo revert` | Revert the current undo group |
| `bn undo undo` | Undo the last action |
| `bn undo redo` | Redo the last undone action |

### Type & Annotation Extensions

| Command | Description |
|---------|-------------|
| `bn type-ext parse` | Parse a C type string |
| `bn type-ext library-list` | List type libraries |
| `bn type-ext library-query` | Query a type library |
| `bn annotation get-tags` | Get tags (function or address) |
| `bn annotation create-tag` | Create a tag |
| `bn annotation add-tag` | Add a tag to a function/address |
| `bn annotation remove-tag` | Remove a tag |
| `bn annotation list-tag-types` | List tag types |

### Analysis & Metadata

| Command | Description |
|---------|-------------|
| `bn analysis status` | Show analysis progress |
| `bn analysis update` | Trigger analysis update |
| `bn metadata store` | Store metadata key-value |
| `bn metadata query` | Query metadata by key |
| `bn metadata remove` | Remove metadata by key |
| `bn schema metadata` | List all metadata keys |

### Advanced Operations

| Command | Description |
|---------|-------------|
| `bn loader settings` | Show loader settings |
| `bn loader rebase` | Rebase the binary |
| `bn external library-list` | List external libraries |
| `bn external library-add` | Add an external library |
| `bn external location-list` | List external locations |
| `bn external location-add` | Add an external location |
| `bn uidf from-address` | User IL data flow from address |
| `bn section-user create` | Create a user section |
| `bn section-user delete` | Delete a user section |
| `bn segment-user create` | Create a user segment |
| `bn segment-user delete` | Delete a user segment |
| `bn debug-info list` | List debug info parsers/types/functions |
| `bn plugin-cmd list` | List registered plugin commands |
| `bn plugin-cmd run` | Run a registered plugin command |
| `bn bundle function` | Export reusable function bundles |
| `bn py exec` | Execute Python inside Binary Ninja |

## Target Selection

Use `bn target list` to see available targets:

```bash
bn target list
```

Targets can be selected with:

- the `selector` field from `bn target list`
- the full `target_id`
- the BinaryView basename
- the full filename
- the view id
- `active` — the explicit CLI-managed selection, or the sole loaded target

In normal use, prefer the `selector` field. For a single open database, this is usually just the `.bndb` basename:

```bash
bn decompile update_player_movement_flags --target SnailMail_unwrapped.exe.bndb
```

Omitting `--target` works when exactly one target is open, or when exactly one target reports `active: true` (the explicit selection made with `bn target use`). With multiple targets and no clear "active" pick, the CLI rejects the command.

## Daemon Mode Selection

`bn` supports two daemon modes — `gui` and `headless` — that can run side by side on the same machine. Use `bn daemon list` to see which are alive, and `bn daemon use <mode>` to pin which one subsequent commands talk to:

```bash
bn daemon list                # show all running daemons + sticky mode
bn daemon use headless        # pin subsequent commands to the headless daemon
bn daemon use gui             # switch to the GUI bridge
bn daemon use --clear         # drop the pin; CLI auto-picks when only one runs
```

Resolution order when routing a command:

1. **Sticky mode** from `bn daemon use <mode>` if set
2. **Single running daemon** — auto-picked when only one mode is alive
3. **Multiple running, no sticky** — CLI errors with a hint to run `bn daemon use <mode>`

### Headless Daemon Lifecycle

The headless daemon imports `binaryninja` and requires a Binary Ninja commercial (headless) license on `PYTHONPATH`. The GUI bridge is auto-started by Binary Ninja itself; the headless daemon needs to be started explicitly:

```bash
bn daemon start --foreground   # block in foreground (Docker PID 1 / systemd)
bn daemon status               # pid, socket, target count
bn daemon stop                 # authenticated graceful shutdown + registry cleanup
```

`--foreground` is currently the only supported run mode. For true background usage, wrap with `&`, `nohup`, `screen`/`tmux`, or a process supervisor like `systemd`.

### Target Lifecycle (headless only)

In headless mode, targets are loaded explicitly via the CLI rather than by opening files in a GUI:

```bash
bn target load /path/to/binary.so                         # sync: block until analysis is done
bn target load /path/to/binary.so --async                 # detach: load + analysis run in background
bn target load /path/to/binary.so --no-update-analysis    # load only, no analysis (run `bn refresh` later)

bn target load /path/to/binary.so \
    --option loader.imageBase=0 \
    --option analysis.mode=full \
    --option analysis.linearSweep.autorun=true

bn target loads               # list recent --async load attempts with status + errors
bn target status              # analysis progress for the active target (poll after --async)
bn target save --path /tmp/binary.bndb   # first save: must specify path
bn target save                # subsequent saves: writes back to the same .bndb
bn target close               # unload a target, free the BinaryView
```

`--option KEY=VALUE` is repeatable; the value is JSON-parsed when possible (`true`/`false`/numbers/lists), otherwise treated as a string. `--options-json '{...}'` accepts an entire JSON object at once.

With `--async`, `bn target load` returns immediately with `{queued: true, load_id, path}`. The actual load + analysis happen in a background thread on the daemon. Poll `bn target list` to see when the target shows up, `bn target status` to track analysis progress, and `bn target loads` to see per-attempt status and any failure messages.

### Background Jobs and GUI Responsiveness

Target-scoped bridge operations run on ordinary Python background threads, not Binary Ninja's UI thread. Short commands keep their existing synchronous output. By default the CLI waits for 30 seconds; if the operation is still running it exits with code `124` and prints a `job_id` while the bridge continues the work.

```bash
bn strings --target active --wait-timeout 10
bn bundle function large_function --async
bn decompile large_function --danger-always-wait

bn job list
bn job status <job_id>
bn job result <job_id> --out /tmp/result.json
bn job cancel <job_id>
```

Multiple reads on one target can run concurrently. A read/write or write/write conflict returns immediately with the blocking job id instead of silently waiting. Cancellation is cooperative: searches, enumerations and analysis waits check for cancellation, while arbitrary `py exec` and third-party plugin commands are not force-killed. `Ctrl+C` only stops the CLI from waiting and leaves the job available through `bn job`.

## Output Behavior

Every command supports:

- `--format json`
- `--format text`
- `--format ndjson`
- `--out <path>`

Interactive read commands default to `text`. Mutation, setup, and export commands default to `json`.
Add `--format json` when you need stable fields for automation or piping into structured tooling.

Examples:

```bash
bn function list --format ndjson
bn function list --min-address 0x401000 --max-address 0x40ffff
bn function search --regex 'attach|detach'
bn decompile sample_track_floor_height_at_position --out /tmp/floor.json
```

If `--out` is set, the command writes the rendered result to that path and prints a compact JSON envelope with the artifact path, byte size, token count, tokenizer, hash, and summary. Agents can use that envelope to decide whether to read the full artifact, keep a summary, or defer loading it into context.

The only exception is `bn bundle function`, which writes the bundle artifact from inside the bridge and prints the envelope back to the CLI.

`bn function list` and `bn function search` support `--offset` and `--limit` (default `--limit -1` returns all for compatibility) for the selected target or address range. Large results auto-spill to an artifact. Spill is token-based and currently triggers above 10,000 tokens. When that happens, stdout stays empty and stderr carries the spill metadata as plain text, including the artifact path and size counts.

## Extraction Commands

Common read-only commands:

```bash
bn target list
bn target info

bn function list
bn function list --min-address 0x401000 --max-address 0x40ffff
bn function search attachment
bn function search --regex 'attach|detach|follow'
bn function info end_track_attachment_follow_state
bn callsites crt_rand --within bonus_pick_random_type
bn callsites crt_rand --within-file /tmp/rng-functions.txt --format ndjson
bn proto get end_track_attachment_follow_state
bn local list end_track_attachment_follow_state
bn refresh

bn decompile end_track_attachment_follow_state
bn il end_track_attachment_follow_state
bn disasm end_track_attachment_follow_state
bn xrefs end_track_attachment_follow_state
bn xrefs field TrackRowCell.tile_type
bn comment get --address 0x401000

bn types --query Player
bn types show Player
bn struct show Player
bn types declare --file /path/to/win32_min.h --preview
bn strings --query follow
bn imports

bn xref-ext code-refs-to 0x401000
bn xref-ext data-refs-from 0x401000
bn annotation get-tags 0x401000
bn schema metadata
bn analysis status
bn database info
```

`bn function search` stays case-insensitive substring matching by default. Add `--regex` when you need regular expressions. `bn function list` and `bn function search` both accept `--min-address` and `--max-address` to filter by function start address.

`bn callsites` is the direct-call lane for exact return-address recovery. It reports both the native `call_addr` and the post-call `caller_static`, where `caller_static = call_addr + instruction_length`. Scope it with `--within <function>` or `--within-file <path>`; the file format is one function identifier per non-empty line, with `#` comments ignored.

Each callsite row also includes:

- `call_index`: zero-based ordinal for matching callsites in the containing function, ordered by `call_addr`
- `within_query`: the original unresolved scope token from `--within` or `--within-file`
- `hlil_statement`: the smallest recoverable HLIL expression or statement containing the call, or `null` when Binary Ninja only exposes a coarse enclosing region
- `pre_branch_condition`: the nearest enclosing pre-call HLIL condition when it can be recovered confidently, otherwise `null`

`hlil_statement` is intentionally local-or-null. If the best available HLIL mapping expands to a broad whole-function or multi-statement blob, `bn callsites` suppresses it instead of returning noisy context.

## Bundles And Python

`bn decompile` is the HLIL-text convenience lane. It is useful for quick function reading, but typed layouts remain authoritative in `bn types show` and `bn struct show`.

Export a reusable function bundle:

```bash
bn bundle function end_track_attachment_follow_state --out /tmp/end_track_attachment_follow_state.json
```

Run Python inside the Binary Ninja process for one-off inspection and BN-native scripting:

```bash
bn py exec --code "print(hex(bv.entry_point)); result = {'functions': len(list(bv.functions))}"

bn py exec --stdin <<'PY'
print(hex(bv.entry_point))
result = {"functions": len(list(bv.functions))}
PY
```

Use `--stdin` or `--script` for multiline Python snippets. Use `--code` for true one-liners only.

```bash
bn py exec --stdin <<'PY'
out = []
for f in bv.functions:
    if 0x416000 <= f.start < 0x41C000:
        out.append((f.start, f.symbol.short_name))
out.sort()
print("\n".join(f"{addr:#x} {name}" for addr, name in out))
PY
```

Use a quoted heredoc for multiline Python snippets.

When you need counts from BN iterators such as `f.hlil.instructions`, materialize them explicitly with `list(...)` or consume them with `sum(1 for ...)` instead of assuming sequence semantics.

The `py exec` environment includes:

- `bn`
- `binaryninja`
- `bv`
- `result`

Stdout and `result` are both returned. If `result` is not JSON-serializable, `bn` returns `repr(result)` and includes a warning instead of silently stringifying the whole response.

## Mutation Commands

Mutations follow the same target-selection rules as other target-specific commands.

Examples:

```bash
bn symbol rename sub_401000 player_update --preview
bn comment set --address 0x401000 "interesting branch" --preview
bn comment get --address 0x401000
bn proto get sub_401000
bn proto set sub_401000 "int __cdecl player_update(Player* self)" --preview
bn local list sub_401000
bn local rename sub_401000 0x401000:local:StackVariableSourceType:-20:2:12345 speed --preview
bn local retype sub_401000 0x401000:local:StackVariableSourceType:-20:2:12345 float --preview
bn types declare "typedef struct Player { int hp; } Player;" --preview
bn struct field set Player 0x308 movement_flag_selector uint32_t --preview
bn function create 0x401000 --preview
```

Preview mode applies the change, refreshes analysis, captures affected decompile diffs, and then reverts the mutation.

Non-preview writes only report success after reading the live BN session back and verifying that the requested post-state actually landed. If verification fails, the CLI returns a nonzero exit code and reverts the whole mutation or batch.

After any live type or prototype mutation, do an explicit readback:

```bash
bn proto get sub_401000
bn struct show Player
bn types show Player
bn decompile sub_401000
```

After creating a function, verify it with `bn function info <address>` or `bn decompile <address>`.

For declaration and struct mutations, preview results also include `affected_types` with before/after layouts and a unified diff. If a field edit is already identical, the result is marked with `changed: false` and a `No effective change detected` message.

For the first few changed functions, `affected_functions` also includes short `before_excerpt` and `after_excerpt` snippets around the first changed HLIL lines.

Mutation results now distinguish:

- `verified`
- `noop`
- `unsupported`
- `verification_failed`

When verification fails, JSON output also includes `requested` and `observed` state for the failed op.

`bn types declare` now uses Binary Ninja's source parser when available. When you pass `--file`, the CLI also forwards the source path so relative includes resolve the same way they would during header import in the GUI.

If a declaration only parses functions or extern variables and introduces no named types to persist, `types declare` returns a verified no-op instead of failing with `No named types found in declaration`.

`bn local list` and `bn function info` return stable `local_id` values for parameters and locals. Prefer those IDs for `bn local rename`, `bn local retype`, and batch manifests; legacy name-based targeting still works for compatibility.

## Batch Manifests

`bn batch apply` accepts a JSON manifest:

```json
{
  "target": "SnailMail_unwrapped.exe.bndb",
  "preview": true,
  "ops": [
    {
      "op": "rename_symbol",
      "kind": "function",
      "identifier": "sub_401000",
      "new_name": "player_update"
    },
    {
      "op": "set_prototype",
      "identifier": "player_update",
      "prototype": "int __cdecl player_update(Player* self)"
    }
  ]
}
```

Apply it with:

```bash
bn batch apply manifest.json
```

Batch apply verifies the live session by default. If any op fails to apply or fails post-state verification, the entire batch is reverted.

## Troubleshooting

Check bridge state:

```bash
bn doctor
```

If `bn target list` is empty:

- make sure Binary Ninja is open
- make sure a binary or `.bndb` is open
- make sure the plugin is installed with `bn plugin install`
- reload Binary Ninja plugins or restart Binary Ninja after plugin changes

On Unix, if `bn doctor` sees a bridge registry but reports `Operation not permitted` under Codex,
the Codex sandbox is blocking the Unix socket that connects to the live Binary Ninja GUI
process. Let Codex run `bn` outside the sandbox by adding this rule to
`~/.codex/rules/default.rules`:

```text
prefix_rule(pattern=["bn"], decision="allow")
```

Restart Codex or reload rules after editing the file. This is only needed for Codex
sandboxed runs; normal shells can use `bn` without that rule.

If multiple targets are open, select one with `bn target use` or pass a concrete `--target <selector>` from `bn target list`. Parallel clients should prefer explicit targets.

If decompile text still looks stale after a type change, run:

```bash
bn refresh
```

That forces an analysis refresh, but it still may not fully eliminate Binary Ninja's stale `__offset(...)` presentation in every case.

## Development

Run tests with:

```bash
uv run pytest
```

Run the CLI from the repo without installing it globally:

```bash
uv run bn --help
```

## License

MIT
