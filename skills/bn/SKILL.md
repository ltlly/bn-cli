---
name: bn
description: Use the local bn CLI for Binary Ninja reversing work against either a running Binary Ninja GUI session or a headless daemon. Prefer this skill for decompilation, function search, callsite recovery, IL/disassembly, xrefs, type inspection, struct field edits, previewed mutations, headless target loading, inline Python execution, database operations, annotation, metadata, memory read/write, binary patching, and analysis control through the bn bridge.
---

# bn

Use this skill when the user wants reverse-engineering work driven by the local `bn` CLI. `bn` supports two backend modes that can coexist on the same machine:

- **GUI bridge** — connects to a running Binary Ninja GUI; the user opens files in the GUI.
- **Headless daemon** — long-running process that loads files explicitly via the CLI; used in Docker / container / agent-driver scenarios.


## Query analysis rows

`bn query` filters rows inside the bridge before returning a page. Query `functions`
(`address,name,raw_name`), `strings` (`address,length,type,value`), or `imports`
(`address,name,library`). Repeated filters are combined with AND. Use `~` for
case-insensitive containment or `=`, `!=`, `<`, `<=`, `>`, `>=` for comparisons.
Addresses and lengths compare numerically. Sort on multiple fields with a comma.

```sh
bn query strings --filter 'length>=12' --sort=-length,address --fields address,value --limit 10
bn query imports --filter 'name~open' --count
```

The default page contains up to 1,000 rows. Use `--offset` to page, `--limit 0`
for all rows, or `--count` for the total matches before pagination.

## Setup

```bash
bn setup                      # one-command: install BN plugin + agent skill into all clients
bn setup --force              # overwrite existing installations
```

Individual pieces if needed:

```bash
bn plugin install             # BN companion plugin only
bn skill install              # agent skill only (supports --client, --mode, --dest)
```

## Workflow

### Headless and cross-tool addresses (read before using Frida/Unicorn observations)

- Prefer `bn --daemon headless ...` in headless work. This selects and pins the daemon for this invocation without changing other clients' sticky selection. Use a concrete `--target` in parallel work.
- Every target job reports its BN address context on stderr. Bare numbers and `va:` mean **BN virtual addresses**. Never feed an unlabelled Frida/Unicorn address back as a BN VA, and never interpret an IL index as a machine address.
- Use `rva:0xOFFSET` relative to the current `BinaryView.image_base`. `view.start` and `original_image_base` can differ. Use `file:0xOFFSET` for backing-data offsets; do not calculate `base + file_offset`. Ambiguous file mappings are rejected and BSS can have no file offset.
- Start with `bn inspect ADDRESS` to get coordinates, bytes, containing functions, xrefs and decompilation. `bn address resolve ADDRESS...` returns corresponding registered external addresses. These typed inputs work in existing decompile, memory, xref, value and mutation commands.
- Capture Frida's actual module `{name,path,base: m.base.toString(),size}`. Save the JSON and run `bn address map import frida-SESSION module.json --kind frida-module --source pid:PID/session:SESSION`. If BN image base and view start differ, explicitly supply `--bn-base` identifying the BN address corresponding to `Module.base`. Then use `map:frida-SESSION:0xACTUAL_ADDRESS` directly.
- For Unicorn, import a JSON object with `regions`, each containing exact `bn_start`, `external_start`, and `length` (hex strings are accepted): `bn address map import uc-SESSION regions.json --source unicorn:SESSION`. This supports independently placed code/data regions. Do not invent a global slide for a piecewise layout.
- Use `bn address verify map:NAME:ADDRESS --bytes HEX` with **bytes actually read externally**. Exit 3 means mismatch; check the mapping, build identity, relocations and runtime modifications rather than guessing another base. This is a byte comparison, not process identity or whole-program equivalence verification.
- Maps are user-declared, session-scoped, target-isolated, bounded, and rejected after BN layout changes. Re-register after external process restart or emulator remap, which bn-cli cannot observe. Do not reuse another run's ASLR base. Pointer tags/PAC/Thumb bits are never silently stripped.
- Export reusable results with `--with-context --format json --out PATH`; without that flag the default result shape stays compatible. Use `bn job wait JOB --with-context` or `job watch` to resume tasks, and `bn result show PATH` to inspect saved results.
- `bn value reg FUNCTION INDEX REGISTER` uses an LLIL index. For a machine address, use `bn value reg FUNCTION REGISTER --address map:NAME:ADDRESS`. `--after` queries after the selected instruction. Read both `address` and `llil_address`: the native mapping may associate different addresses. Native BN flag names come from `bn arch info` (e.g. x86 `z`, not `zf`).
- `bn schema COMMAND...` is generated from the installed parser and requires no daemon; prefer it over guessing flags or relying on older examples. `bn doctor` reports actual BN version/capabilities. Native symbol arithmetic is explicitly `expr:SYMBOL+0xOFFSET`; its numeric rules are BN's, not ordinary CLI decimal rules.

1. Discover what's running:

```bash
bn doctor
bn daemon list                # see all running daemons + the sticky mode if set
bn target list                # see loaded BinaryViews on the active daemon
```

If `bn daemon list` shows both `gui` and `headless` running and no sticky mode is set, every command that needs a bridge will error with a hint. Run `bn daemon use <mode>` to pin one, or `bn daemon use --clear` to drop the pin.

On Windows, both modes default to authenticated fixed local Named Pipes: `\\.\pipe\bn-agent-bridge-gui` and `\\.\pipe\bn-agent-bridge-headless`. In the GUI, **BN Agent Bridge > GUI Transport** switches between Named Pipe and Loopback TCP, and **GUI Listen Port** configures the port; run `BN Agent Bridge > Restart Bridge` after changing either. Explicit `BN_BRIDGE_TRANSPORT=pipe|tcp` overrides the GUI setting and controls headless mode; TCP defaults to ports `26765`/`26766` and also supports `BN_BRIDGE_GUI_PORT` / `BN_BRIDGE_HEADLESS_PORT`. Keep using the `bn` CLI so it can validate the endpoint and read the authentication token from the daemon registry. Upgrade the CLI and plugin together. `bn daemon stop` requests an authenticated graceful shutdown; it does not force-kill the daemon.

2. Pick a target:
- If exactly one BinaryView is registered, target-scoped commands can omit `--target` entirely.
- With multiple targets, set the active one with `bn target use <selector>` (e.g. `bn target use libfoo.so`), then omit `--target` to use it. `bn target use --clear` drops the selection. (Active is CLI-managed and decoupled from the BN UI tab focus — clicking a tab in BN does not change `bn`'s active target.)
- Otherwise pass `--target <selector>` from `bn target list`. `selector` is usually the basename (e.g. `libfoo.so`).
- `--target active` always means "the active one".

3. Output modes (AI-first defaults):
- Read commands default to compact `text` — one item per line, no repeated JSON keys.
- `decompile` renders structured HLIL with nested branch bodies and indentation.
- Disassembly commands (`disasm`, `disasm-linear`, `disasm-range`, `arch disasm-bytes`) output `address  instruction` per line.
- List commands output one record per line:
  - `segments` → `start-end rwx len=N`
  - `sections` → `start-end name [type]`
  - `data-vars` → `address  type`
  - `types` → `name | kind | decl`
  - `strings` → `address  len=N  type  "value"`
  - `imports` / `function-callers` / `function-callees` → `address  name`
  - `function-bbs` → `start-end instr=N Nin->Nout`
  - `database-snapshots` → `id  name  [auto]`
- Search commands (`search-bytes`, `search-constant`, `search-text`) output one match address per line.
- `xrefs` → `c address [function]` for code refs, `d address [function]` for data refs.
- `callsites` → compact block per call with address, caller_static, context disasm, and hlil.
- `memory-read` → `address  hex  (N bytes)`
- `patch-status` → `address  available_ops`
- `analysis-status` / `analysis-progress` → `state count/total done=true/false`
- `arch` → `arch_name addr=N endianness platform=...`
- `data-typed-at` → `address  type  [name]`
- `binary-bbs-at` → `start-end function`
- `il-instruction` → `[index] text  (level)`
- Value commands (`value-reg`, `value-stack`, `value-possible`, `value-flags`) → `type  value`
- Mutation, preview, setup, and export commands default to `json` for structured status.
- Use `--format json` when you need structured/programmable data; `--format ndjson` for line-oriented output (the server result is still materialized).
- Use `--out <path>` to write output to a known file instead of stdout.
- Use supported `--offset`/`--limit` options (see `bn schema <command...>`), or `bn result show PATH --offset N --limit N --fields field1,field2` after spill.

Outputs above `10_000` `o200k_base` tokens auto-spill to disk. When that happens, stdout is empty and stderr carries the spill metadata. Use `--out <path>` when you want the full body at a known location, then inspect that artifact with `bn result show`; piping an already-spilled command to `head` cannot recover the empty stdout.

## Background Jobs

Target-scoped operations run outside Binary Ninja's UI thread. The CLI waits for 30 seconds by default and preserves the normal command output if the job finishes. When it takes longer, the CLI exits `124`, prints a `job_id`, and leaves the operation running:

```bash
bn strings --target active --wait-timeout 10
bn bundle function large_function --async
bn decompile large_function --danger-always-wait

bn job list
bn job status <job_id>
bn job wait <job_id>
bn job watch <job_id>
bn job result <job_id> --out /tmp/result.json
bn job cancel <job_id>
```

- Prefer the default bounded wait for agent work. Treat exit `124` as "still running", not failure; poll `bn job status` and retrieve the terminal value with `bn job result`.
- Use `--async` when you already expect a long operation. Use `--danger-always-wait` only when the caller intentionally accepts an unbounded wait.
- Read jobs may overlap. If a write conflicts with active work on the same target, the bridge returns `TargetBusyError` immediately with the blocking job id.
- Cancellation is cooperative. Never assume `job cancel` killed arbitrary Python or a third-party plugin callback; those jobs report `cancelable: false`.
- `Ctrl+C` stops waiting but does not cancel the bridge job.

## Headless Daemon Workflow

When you're driving `bn` from a container / CI / agent loop, you usually want headless mode. The daemon is started once (often as a container PID 1) and then receives per-task `bn target load` commands:

```bash
# One-time setup (the user / Docker image runs this once)
bn daemon start --foreground               # blocks; needs BN headless license

# Per-task
bn daemon use headless                     # pin the CLI to headless (skip if it's the only daemon)
bn target load /path/to/app.so             # sync: blocks until full analysis is done
bn target load /path/to/app.so --async     # detach: load + analysis in background, returns immediately
bn target load /path/to/app.so \
    --option loader.imageBase=0 \
    --option analysis.mode=full \
    --option analysis.linearSweep.autorun=true

bn target loads                            # check status / errors for recent --async loads
bn target status                           # analysis progress on the active target
bn target save --path /tmp/app.bndb        # first save: choose .bndb path
bn target save                             # subsequent: save_auto_snapshot to the same .bndb
bn target use <selector>                   # with multiple targets, set which one is active (then omit --target)
bn target close                            # unload, free the BV
```

Notes that bite agents:

- **Big `.so` + `linearSweep.autorun=true` can take **minutes** synchronously.** Prefer `--async` and poll `bn target status` until `done: true`, OR drop linear sweep with `--option analysis.linearSweep.autorun=false` for a much faster analysis at the cost of some discovery.
- **`--async` returns `{queued, load_id, path}` immediately.** The target only shows up in `bn target list` after `bn.load()` returns inside the daemon's worker thread. If the daemon-side load throws, the error surfaces in `bn target loads`, not in the original `bn target load --async` response.
- **During `state: AnalyzeState`**, read commands like `bn function list` may return partial or empty results. Wait until `done: true` for stable views.
- **Detached failures are not raised in the CLI.** Always check `bn target loads` after `--async` if the target doesn't appear in `bn target list` within the expected time.
- **`--no-update-analysis`** skips analysis entirely; run `bn refresh` later to trigger it synchronously.
- **`bn target load` does not steal active.** With multiple targets loaded, a freshly loaded target is not auto-selected as active; the response carries an `active_hint`. Run `bn target use <selector>` (or pass `--target`) to operate on it. The first target auto-selects while it is the only one.

## High-Value Read Commands

```bash
bn target list
bn target info
bn function list
bn function list --min-address 0x401000 --max-address 0x40ffff
bn function search attachment
bn function search --regex 'attach|detach|follow'
bn function info sample_track_floor_height_at_position
bn callsites crt_rand --within bonus_pick_random_type
bn callsites crt_rand --within-file /tmp/rng-functions.txt --format ndjson
bn proto get sample_track_floor_height_at_position
bn local list sample_track_floor_height_at_position
bn decompile sample_track_floor_height_at_position
bn il sample_track_floor_height_at_position
bn disasm sample_track_floor_height_at_position
bn disasm-linear 0x401000 --count 20
bn disasm-range 0x401000 0x401100
bn xrefs sample_track_floor_height_at_position
bn xrefs field TrackRowCell.tile_type
bn comment get --address 0x401000
bn types --query Player
bn types show Player
bn struct show Player
bn strings --query follow
bn imports
bn segments
bn sections
bn data-vars
```

`bn function search` is case-insensitive substring matching by default. Add `--regex` when you need regular expressions. `bn function list` and `bn function search` both accept `--min-address` and `--max-address`.

## Extended Read Commands

### Cross-References (Extended)

```bash
bn xref-ext code-refs-to 0x401000         # code references TO an address
bn xref-ext code-refs-from 0x401000       # code references FROM an address
bn xref-ext data-refs-to 0x401000         # data references TO an address
bn xref-ext data-refs-from 0x401000       # data references FROM an address
bn schema xref-ext                      # available reference queries
```

### IL Navigation

```bash
bn il-nav addr-to-index 0x401000 0x401010     # address → IL index
bn il-nav index-to-addr 0x401000 42           # IL index → address
```

### Memory and Binary Content

```bash
bn memory read 0x401000 --length 64       # raw memory read (hex output)
bn memory write 0x401000 "90909090" # raw memory write
bn search bytes "48 89 5c 24"           # search binary content by byte pattern
bn search text "error"                  # search binary content by text
bn data-typed-at 0x601000                 # typed data variable at address
bn binary-bbs-at 0x401000                 # basic blocks at address (binary-wide)
```

### Value Analysis

```bash
bn value reg 0x401000 rax --address 0x401010     # register value at IL instruction
bn value stack 0x401000 -8 --address 0x401010    # stack value at IL instruction
```

### Architecture

```bash
bn arch info                              # architecture info for the target
```

## Database & Undo

```bash
bn database info                          # show database (bndb) information
bn database snapshots                     # list database snapshots
bn undo begin                             # begin an undo group
bn undo commit                            # commit the current undo group
bn undo revert                            # revert the current undo group
bn undo undo                              # undo the last action
bn undo redo                              # redo the last undone action
```

## Type & Annotation Extensions

```bash
bn type-ext parse "int (*)(void*, int)"   # parse a C type string
bn type-ext library-list                  # list available type libraries
bn type-ext library-get libc              # inspect a library by id/name

bn annotation get-tags 0x401000                 # get tags at an address

bn py exec --code 'bv.create_tag_type("Important", "★")'  # create a tag type
bn annotation add-tag 0x401000 "Important" "review needed"

bn py exec --code 'result = list(bv.tag_types)'   # list tag types
```

## Analysis & Metadata

```bash
bn analysis status                        # show analysis progress
bn analysis update                        # trigger analysis update

bn metadata store mykey '{"foo": "bar"}'  # store metadata key-value
bn metadata query mykey                   # query metadata by key
bn metadata remove mykey                  # remove metadata by key
bn schema metadata                        # available metadata operations
```

## Advanced Operations

### Loader & Rebase

```bash
bn loader settings-get ELF                # show loader settings
bn loader rebase 0x10000                  # returns a NEW target id; old target/maps are retired
```

### External Libraries

```bash
bn external library-list                  # list external libraries
bn external library-add libfoo.so         # add an external library
bn external location-get 0x401000          # inspect an external location
bn external location-add 0x401000 --library-name libfoo.so --target-symbol foo
```

### User-Defined IL Data Flow

```bash
bn uidf list 0x401000                    # user-informed values for this function
```

### User Sections & Segments

```bash
bn section-user add .mytext 0x1000 256   # create a user section
bn section-user remove .mytext                # delete a user section
bn segment-user add 0x1000 256  # create a user segment
bn segment-user remove 0x1000                    # delete a user segment
```

### Debug Info & Plugin Commands

```bash
bn debug-info parsers                     # list debug info parsers
bn plugin-cmd list                        # list registered plugin commands
bn plugin-cmd execute "My Plugin Command"     # run a registered plugin command
```

### Binary Patching

```bash
bn memory write 0x401000 "90"    # patch bytes at address
bn patch assemble 0x401000 "nop"   # patch assembly at address
```

## API Documentation Lookup

`bn api-docs` queries the Sphinx HTML reference shipped with Binary Ninja (`/Applications/Binary Ninja.app/Contents/Resources/api-docs` on macOS, similar paths elsewhere). It does not require an open target. Override the location with `--docs-dir` or `BN_API_DOCS_DIR` if Binary Ninja is installed somewhere non-standard.

```bash
bn api-docs search read --kind method            # find methods named *read*
bn api-docs search --regex '^bn.*\.log_'         # regex over fully-qualified names
bn api-docs show binaryninja.BinaryView.read     # signature + docstring + source pointer
bn api-docs list --module binaryninja.highlevelil --kind class
bn api-docs refresh                              # rebuild the on-disk index after upgrading BN
```

`show` requires a unique match. If you pass a bare name (e.g. `read`) and several symbols share it, the command prints the qualified candidates and exits non-zero — pass the qualified name to disambiguate.

## Workflow Inspection

`bn workflow` exposes Binary Ninja's analysis workflow DAG so you can see which activities run and which are overridden. v1 is read-only.

```bash
bn workflow list                                          # all known workflows
bn workflow list --registered-only
bn workflow show core.function.metaAnalysis               # full activity tree
bn workflow show core.function.metaAnalysis --depth immediate
bn workflow show core.function.metaAnalysis --activity core.function.start
bn workflow show core.module.defaultAnalysis --with-config --out /tmp/wf.json
bn workflow active                                        # workflow bound to BV
bn workflow active --function 0x401000                    # function-level workflow
bn workflow machine status
bn workflow machine status --function 0x401000
bn workflow machine dump --out /tmp/machine.json
bn workflow machine overrides
bn workflow machine overrides --activity core.function.analyzeTailCalls
```

Typical flow: `bn workflow active` to see what is bound, then `bn workflow show <name>` to inspect the activity DAG, then `bn workflow machine status` / `overrides` for runtime state. `--function <id>` accepts the same identifier shape as `bn function info` (address, mangled, or demangled name).

`bn workflow machine` returns `available: false` with a `reason` when no machine is attached — that is normal for plain analysis sessions; the machine is opt-in.

### Override Mutations (preview first)

`bn workflow override set/clear` toggles individual activities on or off via the WorkflowMachine. They mutate runtime state outside Binary Ninja's undo system, so the bridge implements a snapshot+restore preview itself.

```bash
bn workflow override set core.function.analyzeTailCalls --disable --preview
bn workflow override set core.function.analyzeTailCalls --disable
bn workflow override clear core.function.analyzeTailCalls --preview
bn workflow override clear core.function.analyzeTailCalls
bn workflow override set core.function.analyzeTailCalls --enable --function 0x401000 --preview
```

Each call returns a JSON envelope with `before`, `after`, `expected`, `verified`, `accepted`, `reverted`, and a `status` field that follows the existing mutation vocabulary:

- `verified` — applied and observed post-state matches the request.
- `previewed` — `--preview` apply succeeded; the override was reverted to its prior state.
- `verification_failed` — apply was accepted but the post-state did not change. Exits 3.
- `unsupported` — the BN command was rejected (e.g. unknown activity). Exits 3.

Re-run `bn workflow machine overrides --activity <name>` to confirm the live state independently after a non-preview write.

### Machine Control + Breakpoints

`bn workflow machine` exposes the imperative WorkflowMachine verbs. These mutate runtime state with no preview lane — Binary Ninja itself does not provide one. Each command surfaces BN's `accepted` flag plus the post-call `machine_state` snapshot.

```bash
bn workflow machine enable
bn workflow machine disable
bn workflow machine step
bn workflow machine halt
bn workflow machine reset
bn workflow machine run                               # advanced=true, incremental=false
bn workflow machine run --no-advanced --incremental
bn workflow machine resume
bn workflow machine breakpoint list
bn workflow machine breakpoint set core.function.analyzeTailCalls core.function.checkForReturn
bn workflow machine breakpoint clear core.function.analyzeTailCalls
```

`accepted: false` is **not** an error in this lane — `halt` is rejected when the machine is idle, `step` is rejected with no breakpoints set, and so on. The CLI exits 0 in either case; inspect `accepted` and `machine_state` to decide what to do next. A typical introspection loop:

1. `bn workflow machine enable`
2. `bn workflow machine breakpoint set <activity>`
3. `bn workflow machine run`
4. `bn workflow machine status` to see where it stopped
5. `bn workflow machine step` / `resume` to continue

## Caller-Static Mapping

Prefer `bn callsites` over ad hoc `py exec` when the task is "find exact native RNG return-address callers" or any similar direct-call mapping workflow.

`bn callsites` reports both:
- `call_addr`: the native `call ...` instruction address
- `caller_static`: the exact post-call return address

The key rule is:
- `caller_static = call_addr + instruction_length`

Use it like this:

```bash
bn callsites crt_rand --within bonus_pick_random_type --caller-static
bn callsites crt_rand --within fx_queue_add_random --caller-static
bn callsites crt_rand --within-file /tmp/rng-functions.txt --format json
```

The `--within-file` format is one function identifier per non-empty line. Lines beginning with `#` are ignored.

For close-together callsites, `bn callsites` also returns:
- previous instructions
- next instructions
- `call_index` within the containing function
- `within_query` with the original unresolved scope token
- a local-or-null HLIL statement
- a best-effort `pre_branch_condition`

`hlil_statement` is intentionally local-or-null. If Binary Ninja only exposes a coarse enclosing region instead of the smallest call-containing expression or statement, expect `hlil_statement: null` rather than a noisy whole-function blob.

`pre_branch_condition` means the nearest enclosing pre-call HLIL condition when it can be recovered confidently. It is not a generic "related branch" field, so `null` is normal when the condition cannot be derived cleanly.

Use `bn xrefs` when you only need inbound references. Use `bn callsites` when you need exact return-address recovery and local context around the call.

## Bundles

Use bundles when you want a reusable artifact instead of pasting long output into context:

```bash
bn bundle function sample_track_floor_height_at_position --out /tmp/floor.json
```

With `--out`, the CLI returns a JSON envelope for the written artifact instead of dumping the whole bundle to stdout.

## Python Escape Hatch

Use inline Python as a normal lane for one-off Binary Ninja inspection that is awkward to express as a built-in command:

```bash
bn py exec --code "print(hex(bv.entry_point)); result = {'functions': len(list(bv.functions))}"
```

Use `--stdin` with a quoted heredoc for multiline Python snippets:

Shell details matter here:
- Quote the heredoc delimiter as `<<'PY'` so the shell does not expand `$vars`, backticks, or backslashes before Binary Ninja sees the Python.
- Keep the closing `PY` on its own line with no indentation or trailing spaces.
- Use `--script <file>` only for real files you want to keep on disk.
- Use `--code` for true one-liners only.
- If you are counting or collecting BN iterators such as `f.hlil.instructions`, materialize them explicitly with `list(...)` or a generator consumption pattern instead of assuming random-access behavior.

Use this pattern for larger inspection snippets:

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

The `py exec` environment includes:`bn`, `binaryninja`, `bv`, `result`.

`py exec` always returns `stdout` and `result`. If `result` is not JSON-serializable, the CLI returns `repr(result)` plus a warning instead of silently flattening it.

## Mutation Workflow

Prefer preview first:

```bash
bn function create 0x401000 --preview
bn types declare "typedef struct Player { int hp; } Player;" --preview
bn types declare --file /path/to/win32_min.h --preview
bn struct field set Player 0x308 movement_flag_selector uint32_t --preview
bn symbol rename sub_401000 player_update --preview
bn proto get sub_401000
bn local list sub_401000
bn proto set sub_401000 "int __cdecl player_update(Player* self)" --preview
bn local rename sub_401000 <local_id> speed --preview
bn local retype sub_401000 <local_id> float --preview
bn comment set --address 0x401000 "interesting branch" --preview
```

Preview mode applies the change, refreshes analysis, captures affected decompile diffs, and then reverts the mutation.

For struct previews, inspect:`results`, `affected_types`, `affected_functions`.

For the first few changed functions, `affected_functions` may also include `before_excerpt` and `after_excerpt` HLIL snippets around the first changed lines.

If a struct edit is already identical, preview may report `changed: false` with `No effective change detected`.

`bn types declare` uses Binary Ninja's source parser when available. With `--file`, it forwards the real source path so relative includes work like GUI header import.

If a declaration only introduces functions or extern variables and no named types, `types declare` now reports a no-op instead of failing with `No named types found in declaration`.

Non-preview writes are live-verified by default. If the requested state does not read back from Binary Ninja, the command exits nonzero and the whole mutation or batch is reverted.

After any live type or prototype mutation, do an explicit readback:

```bash
bn proto get sub_401000
bn struct show Player
bn types show Player
bn decompile sub_401000
```

After `bn function create <address>`, verify the new start with `bn function info <address>` or `bn decompile <address>`.

Key result statuses:
- `verified`
- `noop`
- `unsupported`
- `verification_failed`

When verification fails, JSON output also includes the requested and observed state for the failed operation.

If you need to force BN to recalculate presentation after a type change, run:

```bash
bn refresh
```

## Batch Manifests

`bn batch apply` accepts a JSON manifest for atomic multi-operation mutations:

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

```bash
bn batch apply manifest.json
```

If any op fails verification, the entire batch is reverted.

## Full Command Quick-Reference

### Core
`bn setup`, `bn doctor`, `bn plugin install`, `bn skill install`, `bn daemon {start,stop,status,list,use}`, `bn job {list,status,result,cancel}`, `bn target {list,load,use,close,save,status,loads,info}`, `bn refresh`

### Read / Inspect
`bn function {list,search,info}`, `bn decompile`, `bn il`, `bn disasm`, `bn disasm-linear`, `bn disasm-range`, `bn xrefs`, `bn xref-ext`, `bn callsites`, `bn types`, `bn strings`, `bn imports`, `bn segments`, `bn sections`, `bn data-vars`, `bn data-typed-at`, `bn binary-bbs-at`, `bn il-nav`, `bn proto get`, `bn local list`, `bn comment get`, `bn arch`, `bn search`, `bn value`, `bn memory read`, `bn workflow`, `bn api-docs`, `bn bundle function`

### Mutate
`bn function create`, `bn symbol rename`, `bn comment set`, `bn proto set`, `bn local rename`, `bn local retype`, `bn struct field set`, `bn types declare`, `bn batch apply`, `bn patch`, `bn memory write`

### Database & Undo
`bn database {info,snapshots}`, `bn undo {begin,commit,revert,undo,redo}`

### Type & Annotation
`bn type-ext {parse,library-list,library-query}`, `bn annotation {get-tags,create-tag,add-tag,remove-tag,list-tag-types}`

### Analysis & Metadata
`bn analysis {status,update}`, `bn metadata {store,query,remove,keys}`

### Advanced
`bn loader {settings,rebase}`, `bn external {library-list,library-add,location-list,location-add}`, `bn uidf from-address`, `bn section-user {create,delete}`, `bn segment-user {create,delete}`, `bn debug-info list`, `bn plugin-cmd {list,run}`, `bn py exec`
