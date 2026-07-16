# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## What This Is

`bn` is an agent-first CLI for Binary Ninja. It is split into a CLI and a long-running bridge that talks over a Unix-domain socket:

- **CLI** (`src/bn/`, entry point `bn.cli:main`, exposed as the `bn` console script). A normal Python 3.14+ tool that an agent harness or shell can invoke. **Never** imports `binaryninja`.
- **Bridge** (`plugin/bn_agent_bridge/bridge.py`). One codebase, two run modes:
  - **`gui`** — auto-loaded as a Binary Ninja plugin. Works with a personal license. Started by `__init__.py` calling `start_bridge(mode="gui")` when BN imports the plugin.
  - **`headless`** — long-running daemon. Started by `bn daemon start` → `_run_headless(...)` in `bridge.py`. Imports `binaryninja` directly; requires a commercial (headless) license.

Both modes can run on the same machine at the same time. Each owns a mode-specific socket (`bn_agent_bridge.{mode}.sock`) and registry file (`daemons/{mode}.json`) under `cache_home()`. A sticky pointer at `cache_home() / "current_daemon"` decides which one the CLI talks to when both are alive.

## Common Commands

```bash
# Run tests (the CI surface — the bridge is exercised with fake binaryninja stubs)
uv run pytest

# Run a single test
uv run pytest tests/test_cli.py::test_function_list_returns_full_result_set

# Run the CLI from the repo without installing
uv run bn --help

# Install the CLI on $PATH (also wires the `bn` script)
uv tool install -e .

# Install the BN companion plugin (symlinks plugin/bn_agent_bridge into the BN plugins dir)
bn plugin install

# Install the bundled agent skill into Codex and Codex (both by default)
bn skill install

# Smoke-check the running bridge(s)
bn doctor
bn daemon list                # mode + pid + socket + target count per running daemon

# Start a headless daemon (needs BN headless license on PYTHONPATH)
PYTHONPATH=/path/to/binaryninja/python bn daemon start --foreground
```

Tests do **not** require Binary Ninja. `tests/test_bridge.py` constructs a fake `binaryninja` module (and `binaryninja.mainthread` / `binaryninja.plugin`), then `importlib.util.spec_from_file_location`s `plugin/bn_agent_bridge/bridge.py` under a synthetic package name (`bn_test_bridge`). When editing the bridge, keep that stubbing pattern in mind — direct attribute access on `bn.foo` outside hot paths must still be stubable from the test scaffolding.

## Architecture

### Wire path

1. A bridge is running: GUI auto-starts when Binary Ninja loads the plugin; headless is started by `bn daemon start`.
2. `BinaryNinjaBridge.start()` binds an `AF_UNIX` socket at `paths.bridge_socket_path(mode)` and writes a registry JSON at `paths.bridge_registry_path(mode)` (i.e. `cache_home()/daemons/{mode}.json`) carrying `pid`, `socket_path`, `plugin_version`, `plugin_build_id`, and `mode`.
3. The CLI (`src/bn/transport.py`) calls `list_instances()` which scans `cache_home()/daemons/`. `choose_instance()` picks one via the sticky pointer at `cache_home()/current_daemon`, falling back to "the only one running" when no sticky is set. With both `gui` and `headless` alive and no sticky, the CLI errors and hints the user to run `bn daemon use <mode>`.
4. The CLI opens the chosen socket and sends a one-line JSON request: `{"id", "op", "params", "target"}`. It then `shutdown(SHUT_WR)` and reads the whole response until EOF.
5. `BridgeHandler.handle` parses the request and calls `BinaryNinjaBridge.dispatch`. Target-scoped operations are submitted to `JobManager`, which resolves the target to a concrete id, reserves read/write access, and executes `_execute_operation` on an ordinary Python background thread. Multiple reads may run concurrently; read/write and write/write conflicts fail immediately with the blocking job id instead of waiting.
6. The bridge replies with `{"ok", "result", "error"}`; the CLI raises `BridgeError` if `ok` is false.

When adding a new operation: add the dispatch branch in `_execute_operation`, add the op name to either `READ_LOCKED_OPS` or `WRITE_LOCKED_OPS` (or deliberately leave it lock-free for state that has its own mutex), and add the matching CLI subparser + handler in `src/bn/cli.py`.

### Background jobs and thread model

The CLI submits target-scoped bridge operations through `job_submit`. It waits up to 30 seconds by default, then returns exit code 124 plus a job id while the operation continues. `--async` returns immediately and `--danger-always-wait` preserves unlimited waiting. Job control is available through `bn job list/status/result/cancel` and the lock-free `job_*` wire operations.

Only Binary Ninja **UI** APIs belong on the UI main thread: `_collect_open_views`, dialogs/settings, and arbitrary third-party `PluginCommand` callbacks use `_run_on_main_thread`. Core `BinaryView`, function, IL, type, analysis, and database work runs on ordinary Python background threads. In particular, Binary Ninja documents that `update_analysis_and_wait()` must not run on the UI thread or a Binary Ninja worker-queue thread.

Cancellation is cooperative. Long loops must call `_check_job_cancelled()` and may update `_set_job_progress(...)`; analysis-backed jobs use `abort_analysis()`. Never kill a Python thread. `py_exec` and third-party plugin commands are explicitly not safely cancellable.

### Daemon mode selection

`paths.py` exposes `DAEMON_MODES = ("gui", "headless")` and per-mode getters. `transport.py` discovery + selection lives in:

- `list_instances()` — scans the registry directory; each instance has a `mode` field.
- `read_current_daemon_mode()` / `write_current_daemon_mode(mode|None)` — manages the sticky file.
- `choose_instance()` — sticky → single auto → error with hint.

The `bn daemon` family in `cli.py` wires these into `start` / `stop` / `status` / `list` / `use`. `bn daemon start --mode headless --foreground` is the only working start path — it imports `bn_agent_bridge.bridge` and calls `_run_headless(foreground=True)`, which blocks on a SIGTERM/SIGINT event.

### Targets

`TargetManager` (in `bridge.py`) is **mode-aware**:

- **GUI mode** — every `refresh()` rescans the UI via `_collect_open_views()` (touches `ui.UIContext.*`) to *enumerate* open views; active is **not** read from the UI focus. Records are stored by `view_id` and held by `weakref`.
- **Headless mode** — `refresh()` does **not** touch any UI APIs. Targets are added/removed explicitly via `register(bv)` and `unregister(view_id)` driven by the `load_target` / `close_target` ops. Strong references live in `_explicit_refs` to prevent GC.

**Active target is decoupled from the BN UI focus and CLI-managed.** `TargetManager._active_view_id` is an explicit pointer set by the `set_active_target` op (in `GLOBAL_OPS`, alongside `load_target`/`close_target`) — CLI: `bn target use <selector>` / `bn target use --clear`. `_default_view()` and the `active` flag in `list_targets` resolve to: the explicit pointer → else the single live target (auto-select) → else `None` (and `resolve("active")` raises). `most_recent()`/`_load_order` no longer drive active; `load_target` does **not** steal active (its response carries an `active_hint` when the new target isn't active). Closing the active target, or the view disappearing from the GUI, clears the pointer. The CLI's `_implicit_target` (`cli.py:225-`) stays mode-agnostic: omitting `--target` works when exactly one BV is registered or exactly one is `active`.

Don't add commands that silently default to a fixed selector. Always plumb selection through `_resolve_target(..., allow_implicit_target=True)`. The strict fallback contract is covered by tests in `test_cli.py`.

### Mutations and verification

`bridge.py:_mutation` is the single funnel for every write op (`rename_symbol`, `set_prototype`, `local_rename`, `struct_field_*`, `types_declare`, `batch_apply`, …). It always:

1. Snapshots affected functions and types.
2. Opens an undo group with `bv.begin_undo_actions()`.
3. Applies each operation via `_apply_operation` (which raises `OperationFailure` on the unsupported / `verification_failed` path).
4. `update_analysis_and_wait()`, then re-snapshots and runs per-op `_verify_*` to compare requested vs observed state.
5. If `--preview`, OR any op failed verification, it `revert_undo_actions`. Otherwise `commit_undo_actions`.

So every mutation lane has four possible result statuses — `verified`, `previewed`, `noop`, `unsupported`, `verification_failed`. The CLI maps the failing two (`FAILED_MUTATION_STATUSES` in `cli.py`) to exit code 3 via `_mutation_exit_code`. If you add a new mutation op, the verifier is required, not optional — without one the post-state check will fall through and the verb will silently report `verified` when it didn't actually land.

`bn workflow override set/clear` is the exception: WorkflowMachine state is *not* in BN's undo system, so `_workflow_override_apply` implements its own snapshot+restore preview lane that still produces the same `status` vocabulary.

### Output and spilling

`src/bn/output.py` is the rendering choke point. Every command goes through `write_output_result`, which:

- Renders to `json` / `ndjson` / `text` (read commands default to `text`, mutation/setup/export default to `json` — see `_common_io_options` calls in `build_parser`).
- Counts tokens with `tiktoken` using `o200k_base` (the GPT-5.4 tokenizer alias).
- If `--out` is set, writes there and prints a compact JSON envelope (`artifact_path`, `bytes`, `tokens`, `tokenizer`, `sha256`, `summary`).
- Otherwise, if the rendered output exceeds `DEFAULT_SPILL_TOKEN_LIMIT` (10,000 tokens), auto-spills into `paths.spill_root()` and prints the spill metadata as plain text **on stderr**, leaving stdout empty. Don't break this contract — agents rely on it to keep large lists out of context.

`bn bundle function` is the one place where the bridge writes the artifact itself (because it composes a large structured object). The CLI threads `bridge_writes_output=True` so it doesn't double-write.

### `paths.py` is the single source of truth for filesystem layout

`src/bn/paths.py` and the symlinked `plugin/bn_agent_bridge/paths.py` define every path the system uses: per-mode bridge socket (`bridge_socket_path(mode)`), per-mode registry (`bridge_registry_path(mode)` under `bridge_registry_dir()`), sticky daemon mode pointer (`current_daemon_mode_path()`), cache home, spill root, plugin install dir, skill install dirs for both Codex (`$CODEX_HOME/skills/bn`) and Codex (`$CLAUDE_CONFIG_DIR/skills/bn`). The plugin's `paths.py` and `version.py` are **symlinks** into `src/bn/` — keep them as symlinks so the GUI plugin and the CLI agree on path layout without duplication.

### Async load tracking

`bn target load --async` returns immediately with `{queued, load_id, path}` and runs the entire `bn.load()` + `update_analysis_and_wait()` flow in a daemon-side thread. The bridge keeps a bounded FIFO of `LoadAttempt` records (cap = `LOAD_ATTEMPTS_LIMIT = 50`) protected by `_load_attempts_lock`. Success → status `succeeded` + `target_id`. Failure → status `failed` + `error`. Exposed via the `list_loads` op and the `bn target loads` CLI command. Without this tracking, detached loads that throw inside the worker thread would only surface in BN's stderr log; the load tracker is how the CLI / agent learns about silent failures.

### `bn api-docs`

`src/bn/api_docs.py` does not touch the bridge. It parses Binary Ninja's bundled Sphinx `objects.inv` and HTML on disk, caches a flat index at `paths.api_docs_index_path()`, and serves `search` / `show` / `list` / `refresh` locally. Use it when you need API reference without an open target.

## Conventions

- **Argparse style:** `BnArgumentParser` (in `cli.py`) is a thin subclass that adds `--help-full` (recursively dumps every subparser). New subcommands should use it via `subparsers.add_parser(...)`, get a handler attached via `set_defaults(handler=_my_handler)`, and call `_common_io_options(parser)` to inherit `--format` / `--out`. Use `_target_option(parser, required=False)` for target-scoped verbs.
- **Text renderers are optional:** the JSON shape is the source of truth; text output is a render of the JSON via `text_renderer=` passed into `_call`. If the renderer isn't provided, `_render_fallback_text` pretty-prints JSON.
- **Address parsing:** use `_parse_address` (bridge side) — it accepts both `0x...` strings and ints. Don't reinvent.
- **Read vs write scheduling:** new target op names *must* be added to `READ_LOCKED_OPS` or `WRITE_LOCKED_OPS`. Read/read jobs may overlap; any conflict involving a write returns `TargetBusyError` with blocker job metadata.
- **Main thread:** use `_run_on_main_thread(...)` only for `binaryninjaui`, dialogs/settings, or third-party plugin callbacks that may touch UI state. Normal `BinaryView` work must stay on the bridge/job background thread so the GUI remains responsive.

## Testing Notes

- `tests/test_bridge.py` imports the bridge with a hand-built fake `binaryninja` (no GUI required). To test new bridge ops, extend the fakes in that file rather than importing real BN.
- `tests/test_cli.py` patches `bn.cli.send_request` with a fake that returns canned `{"ok": True, "result": ...}` payloads. The CLI tests focus on argparse plumbing, target selection rules, text rendering, spill behavior, and exit-code mapping.
- `tests/test_api_docs.py` uses tiny synthetic Sphinx fixtures in `tests/fixtures/api_docs/`.
- `tests/test_output.py` and `tests/test_transport.py` exercise the spill/envelope and Unix-socket retry logic in isolation.
