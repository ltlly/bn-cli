---
name: bn
description: Use the local bn CLI for Binary Ninja reversing work against either a running Binary Ninja GUI session or a headless daemon. Prefer this skill for decompilation, function search, callsite recovery, IL/disassembly, xrefs, type inspection, struct field edits, previewed mutations, headless target loading, and inline Python execution through the bn bridge.
---

# bn

Use this skill when the user wants reverse-engineering work driven by the local `bn` CLI. `bn` supports two backend modes that can coexist on the same machine:

- **GUI bridge** — connects to a running Binary Ninja GUI; the user opens files in the GUI.
- **Headless daemon** — long-running process that loads files explicitly via the CLI; used in Docker / container / agent-driver scenarios.

## Workflow

1. Discover what's running:

```bash
bn doctor
bn daemon list                # see all running daemons + the sticky mode if set
bn target list                # see loaded BinaryViews on the active daemon
```

If `bn daemon list` shows both `gui` and `headless` running and no sticky mode is set, every command that needs a bridge will error with a hint. Run `bn daemon use <mode>` to pin one, or `bn daemon use --clear` to drop the pin.

2. Pick a target:
- If exactly one BinaryView is registered, target-scoped commands can omit `--target` entirely.
- If multiple targets are loaded and exactly one is `active` (GUI focus / most-recent headless load), omitting `--target` also works.
- Otherwise pass `--target <selector>` from `bn target list`. `selector` is usually the basename (e.g. `libfoo.so`).
- `--target active` always means "the active one" by the rules above.

3. Pick the right output mode:
- Read commands default to `text`.
- Mutation, preview, setup, and export commands default to `json`.
- Other options: `--format json`, `--format ndjson`, `--out <path>`.

Outputs above `10_000` `o200k_base` tokens auto-spill to disk. When that happens, stdout is empty and stderr carries the spill metadata as plain text, so do not chain `bn ... | rg ...` and expect to search the real output. Use `--out <path>` when you want the full body written to a known file.

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
bn target close                            # unload, free the BV
```

Notes that bite agents:

- **Big `.so` + `linearSweep.autorun=true` can take **minutes** synchronously.** Prefer `--async` and poll `bn target status` until `done: true`, OR drop linear sweep with `--option analysis.linearSweep.autorun=false` for a much faster analysis at the cost of some discovery.
- **`--async` returns `{queued, load_id, path}` immediately.** The target only shows up in `bn target list` after `bn.load()` returns inside the daemon's worker thread. If the daemon-side load throws, the error surfaces in `bn target loads`, not in the original `bn target load --async` response.
- **During `state: AnalyzeState`**, read commands like `bn function list` may return partial or empty results. Wait until `done: true` for stable views.
- **Detached failures are not raised in the CLI.** Always check `bn target loads` after `--async` if the target doesn't appear in `bn target list` within the expected time.
- **`--no-update-analysis`** skips analysis entirely; run `bn refresh` later to trigger it synchronously.

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
bn xrefs sample_track_floor_height_at_position
bn xrefs field TrackRowCell.tile_type
bn comment get --address 0x401000
bn types --query Player
bn types show Player
bn struct show Player
bn strings --query follow
bn imports
```

`bn function search` is case-insensitive substring matching by default. Add `--regex` when you need regular expressions. `bn function list` and `bn function search` both accept `--min-address` and `--max-address`.

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
bn types declare "typedef struct Player { int hp; } Player;" --preview
bn types declare --file /path/to/win32_min.h --preview
bn struct field set Player 0x308 movement_flag_selector uint32_t --preview
bn symbol rename sub_401000 player_update --preview
bn proto get sub_401000
bn local list sub_401000
bn proto set sub_401000 "int __cdecl player_update(Player* self)" --preview
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
