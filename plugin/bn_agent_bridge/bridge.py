from __future__ import annotations

import atexit
import contextlib
import difflib
import errno
import hashlib
import hmac
import io
import json
import multiprocessing.connection
import os
import re
import secrets
import socket
import socketserver
import threading
import traceback
import uuid
import weakref
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import binaryninja as bn
from binaryninja.mainthread import execute_on_main_thread_and_wait, is_main_thread
from binaryninja.plugin import PluginCommand

from .paths import (
    DEFAULT_BRIDGE_TCP_PORTS,
    PLUGIN_NAME,
    bridge_registry_path,
    bridge_job_root,
    bridge_pipe_name,
    bridge_socket_path,
    bridge_tcp_port,
    bridge_transport,
)
from .version import VERSION, bridge_build_id
from .addressing import AddressResolver, AddressError
from .artifacts import atomic_write

try:
    import binaryninjaui as ui
except Exception:  # pragma: no cover - headless raises UIPluginInHeadlessError; CI just lacks the module
    ui = None


PLUGIN_BUILD_ID = bridge_build_id(Path(__file__).resolve())
SETTINGS_GROUP = "bnAgentBridge"
GUI_TRANSPORT_SETTING = f"{SETTINGS_GROUP}.guiTransport"
GUI_PORT_SETTING = f"{SETTINGS_GROUP}.guiPort"
GUI_TRANSPORTS = ("pipe", "tcp")


def _default_tcp_port(mode: str) -> int:
    try:
        return bridge_tcp_port(mode)
    except ValueError as exc:
        fallback = DEFAULT_BRIDGE_TCP_PORTS[mode]
        bn.log_error(f"BN Agent Bridge ignored an invalid port override: {exc}; using {fallback}")
        return fallback


def _register_gui_settings() -> None:
    if ui is None or not hasattr(bn, "Settings"):
        return
    settings = bn.Settings()
    settings.register_group(SETTINGS_GROUP, "BN Agent Bridge")
    settings.register_setting(
        GUI_TRANSPORT_SETTING,
        json.dumps(
            {
                "title": "GUI Transport",
                "type": "string",
                "default": "pipe",
                "enum": list(GUI_TRANSPORTS),
                "enumDescriptions": ["Named Pipe", "Loopback TCP"],
                "description": (
                    "Local transport used by the GUI bridge on Windows. Explicit "
                    "BN_BRIDGE_TRANSPORT values override this setting."
                ),
                "requiresRestart": True,
                "ignore": ["SettingsProjectScope", "SettingsResourceScope"],
            }
        ),
    )
    settings.register_setting(
        GUI_PORT_SETTING,
        json.dumps(
            {
                "title": "GUI Listen Port",
                "type": "number",
                "default": _default_tcp_port("gui"),
                "minValue": 1,
                "maxValue": 65535,
                "description": (
                    "Authenticated loopback TCP port used when GUI Transport is Loopback TCP. "
                    "Run 'BN Agent Bridge > Restart Bridge' after changing it."
                ),
                "requiresRestart": True,
                "ignore": ["SettingsProjectScope", "SettingsResourceScope"],
            }
        ),
    )


def _configured_transport(mode: str) -> str:
    selected = bridge_transport()
    env_value = os.environ.get("BN_BRIDGE_TRANSPORT", "auto").strip().lower()
    if (
        mode != "gui"
        or selected != "pipe"
        or env_value != "auto"
        or ui is None
        or not hasattr(bn, "Settings")
    ):
        return selected

    configured = str(bn.Settings().get_string(GUI_TRANSPORT_SETTING)).strip().lower()
    if configured in GUI_TRANSPORTS:
        return configured
    bn.log_error(
        f"BN Agent Bridge setting {GUI_TRANSPORT_SETTING} is invalid ({configured!r}); "
        f"using {selected}"
    )
    return selected


def _configured_tcp_port(mode: str) -> int:
    if mode == "gui" and ui is not None and hasattr(bn, "Settings"):
        port = int(bn.Settings().get_integer(GUI_PORT_SETTING))
        if 1 <= port <= 65535:
            return port
        bn.log_error(
            f"BN Agent Bridge setting {GUI_PORT_SETTING} is invalid ({port}); "
            "using the configured default instead"
        )
    return _default_tcp_port(mode)


def _json_response(*, ok: bool, result: Any = None, error: str | None = None) -> dict[str, Any]:
    return {"ok": ok, "result": result, "error": error}


class OperationFailure(RuntimeError):
    def __init__(
        self,
        status: str,
        message: str,
        *,
        requested: dict[str, Any] | None = None,
        observed: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.status = status
        self.message = message
        self.requested = requested or {}
        self.observed = observed or {}


class JobCancelled(RuntimeError):
    pass


class TargetBusyError(RuntimeError):
    def __init__(self, blockers: list[dict[str, Any]]):
        self.blockers = blockers
        details = ", ".join(
            f"job_id={item['job_id']} op={item['op']} state={item['state']}"
            for item in blockers
        )
        super().__init__(f"Target busy: {details}")


class _ReadWriteLock:
    def __init__(self):
        self._condition = threading.Condition()
        self._readers = 0
        self._writer = False

    @contextlib.contextmanager
    def read(self):
        with self._condition:
            while self._writer:
                self._condition.wait()
            self._readers += 1
        try:
            yield
        finally:
            with self._condition:
                self._readers -= 1
                if self._readers == 0:
                    self._condition.notify_all()

    @contextlib.contextmanager
    def write(self):
        with self._condition:
            while self._writer or self._readers:
                self._condition.wait()
            self._writer = True
        try:
            yield
        finally:
            with self._condition:
                self._writer = False
                self._condition.notify_all()


READ_LOCKED_OPS = {
    "function_info",
    "get_prototype",
    "address_context", "address_resolve", "address_verify", "address_map_list", "address_map_export", "inspect", "value_query",
    "list_functions",
    "list_locals",
    "search_functions",
    "callsites",
    "decompile",
    "il",
    "disasm",
    "xrefs",
    "field_xrefs",
    "types",
    "type_info",
    "strings",
    "imports",
    "bundle_function",
    "get_comment",
    "workflow_list",
    "workflow_show",
    "workflow_active",
    "workflow_machine_status",
    "workflow_machine_dump",
    "workflow_machine_overrides",
    "workflow_machine_breakpoint_list",
    "analysis_status",
    # --- patch (read) ---
    "patch_status",
    # --- memory (read) ---
    "memory_read",
    "memory_reader_read",
    # --- value ---
    "value_flags_at",
    "value_possible",
    "value_reg",
    "value_stack",
    # --- search ---
    "search_bytes",
    "search_constant",
    "search_text",
    # --- arch (read) ---
    "arch_info",
    "arch_disasm_bytes",
    # --- segments/sections/data_vars ---
    "list_segments",
    "list_sections",
    "list_data_vars",
    # --- disasm extended ---
    "disasm_linear",
    "disasm_range",
    # --- function extended ---
    "function_containing",
    "function_basic_blocks",
    "function_callers",
    "function_callees",
    "function_ssa_var_def_use",
    "function_ssa_memory_def_use",
    "function_var_refs",
    "function_var_refs_from",
    "function_metadata_query",
    # --- database ---
    "database_info",
    "database_read_global",
    "database_snapshots",
    # --- type extended ---
    "type_parse_string",
    "type_library_list",
    "type_library_get",
    "type_archive_list",
    "type_archive_get",
    # --- annotation ---
    "annotation_get_tags",
    "annotation_list_tag_types",
    # --- uidf ---
    "uidf_list_user_var_values",
    "uidf_parse_possible_value",
    "uidf_from_address",
    # --- loader ---
    "loader_load_settings_get",
    "loader_load_settings_types",
    # --- external ---
    "external_library_list",
    "external_location_get",
    "external_location_list",
    # --- analysis ---
    "analysis_status",
    "analysis_progress",
    # --- metadata (view-level) ---
    "metadata_query",
    "metadata_keys",
    # --- data ---
    "data_typed_at",
    # --- xref extended ---
    "xref_code_refs_from",
    "xref_code_refs_to",
    "xref_data_refs_from",
    "xref_data_refs_to",
    "xref_type_refs",
    # --- il extended ---
    "il_address_to_index",
    "il_index_to_address",
    "il_instruction_by_addr",
    # --- debug ---
    "debug_parsers",
    # --- plugin ---
    "plugin_valid_commands",
    # --- binary extended ---
    "binary_basic_blocks_at",
}


WRITE_LOCKED_OPS = {
    "py_exec",
    "create_function",
    "rename_symbol",
    "set_comment",
    "delete_comment",
    "set_prototype",
    "local_rename",
    "local_retype",
    "struct_field_set",
    "struct_field_rename",
    "struct_field_delete",
    "types_declare",
    "batch_apply",
    "refresh",
    "workflow_override_set",
    "workflow_override_clear",
    "workflow_machine_enable",
    "workflow_machine_disable",
    "workflow_machine_run",
    "workflow_machine_step",
    "workflow_machine_halt",
    "workflow_machine_reset",
    "workflow_machine_resume",
    "workflow_machine_breakpoint_set",
    "workflow_machine_breakpoint_clear",
    "save_target",
    # --- patch (write) ---
    "patch_assemble",
    "address_map_add", "address_map_import", "address_map_remove",
    "patch_nop",
    "patch_always_branch",
    "patch_invert_branch",
    "patch_never_branch",
    "patch_skip_and_return",
    # --- memory (write) ---
    "memory_write",
    "memory_insert",
    "memory_remove",
    "memory_writer_write",
    # --- arch (write — assembles) ---
    "arch_assemble",
    # --- function extended (write) ---
    "function_force_analysis",
    "function_metadata_store",
    "function_metadata_remove",
    # --- database (write) ---
    "database_write_global",
    "database_save_auto_snapshot",
    "database_create_bndb",
    # --- type extended (write) ---
    "type_rename",
    "type_undefine_user",
    "type_import_library_type",
    "type_import_library_object",
    "type_export_to_library",
    "type_library_create",
    "type_library_load",
    "type_archive_create",
    "type_archive_open",
    "type_archive_pull",
    "type_archive_push",
    # --- annotation (write) ---
    "annotation_add_tag",
    "annotation_create_tag_type",
    "annotation_remove_tag",
    "annotation_define_data_var",
    "annotation_undefine_data_var",
    "annotation_define_symbol",
    "annotation_undefine_symbol",
    "annotation_rename_data_var",
    # --- undo ---
    "undo_begin",
    "undo_commit",
    "undo_revert",
    "undo_undo",
    "undo_redo",
    # --- uidf (write) ---
    "uidf_set_user_var_value",
    "uidf_clear_user_var_value",
    # --- loader (write) ---
    "loader_load_settings_set",
    "loader_rebase",
    # --- external (write) ---
    "external_library_add",
    "external_library_remove",
    "external_location_add",
    "external_location_remove",
    # --- analysis (write) ---
    "analysis_abort",
    "analysis_set_hold",
    "analysis_update",
    "analysis_update_and_wait",
    # --- metadata (write) ---
    "metadata_store",
    "metadata_remove",
    # --- section/segment (write) ---
    "section_add_user",
    "section_remove_user",
    "segment_add_user",
    "segment_remove_user",
    # --- debug (write) ---
    "debug_parse_and_apply",
    # --- plugin (write) ---
    "plugin_execute",
}


# Ops that operate on TargetManager structure (registry-level), not a specific BV.
# Held under the bridge's global write lock so the locks dict stays consistent.
GLOBAL_OPS = {
    "load_target",
    "close_target",
    "set_active_target",
}


# Ops that maintain their own locking (no need to acquire bridge-level locks).
NO_LOCK_OPS = {
    "job_list",
    "job_status",
    "job_result",
    "job_cancel",
    "job_submit",
    "list_loads",
    "list_targets",
    "target_info",
    "analysis_status",
    "analysis_progress",
    "analysis_abort",
    "doctor",
    "shutdown",
}

ANALYSIS_WAIT_OPS = {
    "refresh",
    "analysis_update_and_wait",
    "function_force_analysis",
    "create_function",
    "rename_symbol",
    "set_comment",
    "delete_comment",
    "set_prototype",
    "local_rename",
    "local_retype",
    "struct_field_set",
    "struct_field_rename",
    "struct_field_delete",
    "types_declare",
    "batch_apply",
}


def _run_on_main_thread(func):
    if is_main_thread():
        return func()

    holder: dict[str, Any] = {}

    def wrapper():
        try:
            holder["result"] = func()
        except Exception as exc:  # pragma: no cover - exercised inside GUI
            holder["error"] = exc
            holder["traceback"] = traceback.format_exc()

    execute_on_main_thread_and_wait(wrapper)
    if "error" in holder:
        exc = holder["error"]
        if "traceback" in holder:
            bn.log_error(holder["traceback"])
        raise exc
    return holder.get("result")


def _parse_address(value: Any) -> int:
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if text.lower().startswith("0x"):
        return int(text, 16)
    return int(text, 10)


def _value_text(value: Any, limit: int = 200) -> str:
    """Compact, bounded text for API objects echoed back to the CLI."""
    text = str(value)
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _artifact_summary(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return {"kind": "object", "keys": sorted(value.keys())[:10], "count": len(value)}
    if isinstance(value, list):
        return {"kind": "array", "count": len(value)}
    if isinstance(value, str):
        return {"kind": "string", "chars": len(value)}
    return {"kind": type(value).__name__}


def _write_json_artifact(path_text: str | None, payload: Any) -> dict[str, Any] | None:
    if not path_text:
        return None

    path = Path(path_text).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    atomic_write(path, data)
    return {
        "ok": True,
        "artifact_path": str(path),
        "format": "json",
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "summary": _artifact_summary(payload),
    }


def _active_binary_view():
    if ui is None:
        return None

    def resolve():
        try:
            context = ui.UIContext.activeContext()
            if context is not None:
                frame = context.getCurrentViewFrame()
                view = frame.getCurrentBinaryView() if frame is not None else None
                if view is not None:
                    return view

            contexts = list(ui.UIContext.allContexts())
            if len(contexts) == 1:
                frame = contexts[0].getCurrentViewFrame()
                return frame.getCurrentBinaryView() if frame is not None else None
        except Exception:
            return None
        return None

    return _run_on_main_thread(resolve)


def _collect_open_views() -> list[Any]:
    if ui is None:
        active = _active_binary_view()
        return [active] if active is not None else []

    def collect():
        found: list[Any] = []
        try:
            contexts = list(ui.UIContext.allContexts())
        except Exception:
            contexts = []
        if not contexts:
            active_context = ui.UIContext.activeContext()
            if active_context is not None:
                contexts = [active_context]

        def collect_binary_view(view):
            if view is not None:
                found.append(view)

        def collect_from_frame(frame):
            if frame is None:
                return
            collect_binary_view(frame.getCurrentBinaryView())

        def collect_from_tab(context, tab):
            try:
                collect_from_frame(context.getViewFrameForTab(tab))
            except Exception:
                pass
            try:
                view = context.getViewForTab(tab)
                collect_binary_view(view.getData() if view is not None else None)
            except Exception:
                pass

        for context in contexts:
            try:
                collect_from_frame(context.getCurrentViewFrame())
            except Exception:
                pass
            try:
                tabs = list(context.getTabs())
            except Exception:
                tabs = []
            for tab in tabs:
                collect_from_tab(context, tab)

        unique: list[Any] = []
        seen: set[int] = set()
        for bv in found:
            marker = id(bv)
            if marker not in seen:
                seen.add(marker)
                unique.append(bv)
        return unique

    return _run_on_main_thread(collect)


@dataclass(slots=True)
class TargetRecord:
    view_id: str
    ref: weakref.ReferenceType
    session_id: str
    filename: str
    basename: str
    view_name: str
    source: str = "gui"

    def target_id(self) -> str:
        return f"{os.getpid()}:{self.view_id}:{self.session_id}"


class TargetManager:
    def __init__(self, mode: str = "gui"):
        self._mode = mode
        self._lock = threading.RLock()
        self._records: dict[str, TargetRecord] = {}
        self._ids_by_object: dict[int, str] = {}
        self._next_id = 1
        self._explicit_refs: dict[str, Any] = {}
        self._load_order: list[str] = []
        # CLI-managed active target, decoupled from the BN UI focus. ``None`` means
        # "no explicit selection" — falls back to single-target auto-select.
        self._active_view_id: str | None = None

    def set_active(self, view_id: str | None) -> None:
        with self._lock:
            self._active_view_id = view_id

    def _view_name(self, bv) -> str:
        for attr in ("view_type", "name"):
            try:
                value = getattr(bv, attr, None)
                if value:
                    return str(getattr(value, "name", value))
            except Exception:
                continue
        return type(bv).__name__

    def _preferred_selector(self, record: TargetRecord, basename_counts: dict[str, int]) -> str:
        if record.basename and basename_counts.get(record.basename, 0) == 1:
            return record.basename
        return record.target_id()

    def _matches_record(self, record: TargetRecord, selector: str | None) -> bool:
        if selector is None:
            return False
        candidate = str(selector).strip()
        if candidate in ("", "active"):
            return False
        return candidate in (
            record.target_id(),
            record.view_id,
            record.filename,
            record.basename,
        )

    def _build_record(self, bv, *, source: str) -> TargetRecord:
        key = id(bv)
        view_id = self._ids_by_object.get(key)
        if view_id is None:
            view_id = str(self._next_id)
            self._next_id += 1
            self._ids_by_object[key] = view_id

        try:
            session_id = str(bv.file.session_id) if bv.file else str(key)
        except Exception:
            session_id = str(key)
        try:
            filename = str(getattr(bv.file, "filename", "")) if bv.file else ""
        except Exception:
            filename = ""

        return TargetRecord(
            view_id=view_id,
            ref=weakref.ref(bv),
            session_id=session_id,
            filename=filename,
            basename=os.path.basename(filename) if filename else "",
            view_name=self._view_name(bv),
            source=source,
        )

    def register(self, bv) -> TargetRecord:
        """Explicit registration used by headless `load_target`. Holds a strong reference."""
        with self._lock:
            record = self._build_record(bv, source="explicit")
            self._records[record.view_id] = record
            self._explicit_refs[record.view_id] = bv
            if record.view_id in self._load_order:
                self._load_order.remove(record.view_id)
            self._load_order.append(record.view_id)
            return record

    def unregister(self, view_id: str) -> TargetRecord | None:
        with self._lock:
            record = self._records.pop(view_id, None)
            self._explicit_refs.pop(view_id, None)
            try:
                self._load_order.remove(view_id)
            except ValueError:
                pass
            if view_id == self._active_view_id:
                self._active_view_id = None
            if record is not None:
                bv = record.ref()
                if bv is not None:
                    self._ids_by_object.pop(id(bv), None)
            return record

    def view_id_for(self, bv) -> str | None:
        with self._lock:
            return self._ids_by_object.get(id(bv))

    def target_id_for(self, bv) -> str | None:
        with self._lock:
            view_id = self._ids_by_object.get(id(bv))
            record = self._records.get(view_id) if view_id is not None else None
            return record.target_id() if record is not None else None

    def most_recent(self):
        with self._lock:
            for view_id in reversed(self._load_order):
                bv = self._explicit_refs.get(view_id)
                if bv is not None:
                    return bv
        return None

    def _default_view(self):
        with self._lock:
            # 1. Explicit CLI-managed active target wins (GUI + headless alike).
            if self._active_view_id is not None and self._active_view_id in self._records:
                record = self._records[self._active_view_id]
                view = self._explicit_refs.get(self._active_view_id) or record.ref()
                if view is not None:
                    return view
            # Decoupled from the BN UI focus: no _active_binary_view(), no most_recent().
            # 2. Single-target auto-select.
            live = [
                (vid, self._explicit_refs.get(vid) or rec.ref())
                for vid, rec in self._records.items()
            ]
            live = [(vid, view) for vid, view in live if view is not None]
            if len(live) == 1:
                return live[0][1]
            # 3. Multiple targets, no active selection -> None (resolve() reports it).
            return None

    def _serialize_records(self) -> list[dict[str, Any]]:
        with self._lock:
            basename_counts: dict[str, int] = {}
            live_view_ids: list[str] = []
            for view_id, record in self._records.items():
                if record.basename:
                    basename_counts[record.basename] = basename_counts.get(record.basename, 0) + 1
                view = self._explicit_refs.get(view_id) or record.ref()
                if view is not None:
                    live_view_ids.append(view_id)
            single = len(live_view_ids) == 1
            single_view_id = live_view_ids[0] if single else None

            result: list[dict[str, Any]] = []
            for view_id in sorted(self._records, key=lambda item: int(item)):
                record = self._records[view_id]
                view = self._explicit_refs.get(view_id) or record.ref()
                if view is None:
                    continue
                # Decoupled from UI focus: active is the explicit pointer, or the
                # single live target when no pointer is set.
                if self._active_view_id is not None:
                    is_active = view_id == self._active_view_id
                else:
                    is_active = view_id == single_view_id
                result.append(
                    {
                        "target_id": record.target_id(),
                        "view_id": record.view_id,
                        "session_id": record.session_id,
                        "filename": record.filename,
                        "basename": record.basename,
                        "selector": self._preferred_selector(record, basename_counts),
                        "view_name": record.view_name,
                        "active": is_active,
                        "source": record.source,
                    }
                )
            return result

    def refresh(self) -> list[dict[str, Any]]:
        if self._mode == "headless":
            return self._serialize_records()

        views = _collect_open_views()

        with self._lock:
            alive: dict[str, TargetRecord] = {}
            for bv in views:
                record = self._build_record(bv, source="gui")
                alive[record.view_id] = record
            self._records = alive
            # Drop the active pointer if its view was closed in the UI.
            if self._active_view_id is not None and self._active_view_id not in self._records:
                self._active_view_id = None

        return self._serialize_records()

    def resolve(self, selector: str | None):
        targets = self.refresh()
        if not targets:
            scope = "headless daemon" if self._mode == "headless" else "Binary Ninja GUI"
            raise RuntimeError(f"No BinaryView targets are loaded in the {scope}")

        if selector in (None, "", "active"):
            active = self._default_view()
            if active is None:
                raise RuntimeError("No active BinaryView is selected and multiple targets are open")
            return active

        with self._lock:
            for record in self._records.values():
                if self._matches_record(record, selector):
                    view = self._explicit_refs.get(record.view_id) or record.ref()
                    if view is not None:
                        return view
            # Build hint with available targets
            available = []
            for record in self._records.values():
                available.append(record.filename or record.view_id)
            hint = ""
            if available:
                hint = f". Available targets: {', '.join(available[:5])}"
                if len(available) > 5:
                    hint += f" (+{len(available) - 5} more)"
        raise RuntimeError(f"Unknown target selector: {selector}{hint}")


def _process_bridge_request(bridge, raw: bytes, *, on_authenticated=None) -> tuple[bytes, str | None, str | None, bool]:
    op = None
    request_id = None
    try:
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("request must be a JSON object")
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        response = _json_response(ok=False, error="Invalid JSON request")
    else:
        op = payload.get("op")
        request_id = payload.get("id")
        expected_auth = bridge.auth_token
        supplied_auth = payload.get("auth")
        if expected_auth is not None and (
            not isinstance(supplied_auth, str)
            or not supplied_auth.isascii()
            or not hmac.compare_digest(supplied_auth, expected_auth)
        ):
            response = _json_response(ok=False, error="Unauthorized bridge request")
        else:
            if on_authenticated is not None:
                on_authenticated()
            response = bridge.dispatch(payload)
    encoded = json.dumps(response, sort_keys=True, default=str).encode("utf-8")
    should_shutdown = op == "shutdown" and bool(response.get("ok"))
    return encoded, op, request_id, should_shutdown


def _log_disconnected_client(op: str | None, request_id: str | None) -> None:
    details = []
    if op:
        details.append(f"op={op}")
    if request_id:
        details.append(f"id={request_id}")
    suffix = f" ({', '.join(details)})" if details else ""
    bn.log_warn(f"BN Agent Bridge client disconnected before response could be delivered{suffix}")


class BridgeHandler(socketserver.StreamRequestHandler):
    def _write_response(
        self,
        encoded: bytes,
        *,
        op: str | None = None,
        request_id: str | None = None,
    ) -> bool:
        try:
            self.wfile.write(encoded)
            self.wfile.flush()
            return True
        except OSError as exc:
            if exc.errno not in {errno.EPIPE, errno.ECONNRESET}:
                raise
            _log_disconnected_client(op, request_id)
            return False

    def handle(self):  # pragma: no cover - exercised from CLI
        raw = self.rfile.readline()
        if not raw:
            return
        encoded, op, request_id, should_shutdown = _process_bridge_request(
            self.server.bridge, raw
        )
        delivered = self._write_response(encoded, op=op, request_id=request_id)
        if delivered and should_shutdown:
            self.server.bridge.request_shutdown()


class _ThreadedServerMixin(socketserver.ThreadingMixIn):
    daemon_threads = True
    # Avoid TIME_WAIT blocking a quick restart. This does not permit binding
    # over another process that is actively listening on the same TCP port.
    allow_reuse_address = True
    request_queue_size = 64


if hasattr(socketserver, "UnixStreamServer"):
    class ThreadedUnixServer(_ThreadedServerMixin, socketserver.UnixStreamServer):
        def __init__(self, socket_path: str, handler, bridge):
            self.bridge = bridge
            super().__init__(socket_path, handler)
else:  # pragma: no cover - exercised on Windows
    ThreadedUnixServer = None


class ThreadedTcpServer(_ThreadedServerMixin, socketserver.TCPServer):
    def __init__(self, address: tuple[str, int], handler, bridge):
        self.bridge = bridge
        super().__init__(address, handler)


class ThreadedNamedPipeServer:
    max_pending_requests = 32
    first_message_timeout = 2.0

    def __init__(self, pipe_name: str, bridge):
        self.pipe_name = pipe_name
        self.bridge = bridge
        self._listener = multiprocessing.connection.Listener(
            pipe_name,
            family="AF_PIPE",
            backlog=64,
            authkey=None,
        )
        self._stopping = threading.Event()
        self._stopped = threading.Event()
        self._pending = threading.BoundedSemaphore(self.max_pending_requests)
        self._connections: set[Any] = set()
        self._connections_lock = threading.Lock()

    def serve_forever(self) -> None:
        try:
            while not self._stopping.is_set():
                # Backpressure stays in the OS pipe queue until a reader is free.
                if not self._pending.acquire(timeout=0.1):
                    continue
                if self._stopping.is_set():
                    self._pending.release()
                    return
                try:
                    connection = self._listener.accept()
                except (EOFError, OSError) as exc:
                    self._pending.release()
                    if not self._stopping.is_set():
                        bn.log_error(f"BN Agent Bridge Named Pipe accept failed: {exc}")
                    return
                if self._stopping.is_set():
                    self._pending.release()
                    connection.close()
                    return
                with self._connections_lock:
                    self._connections.add(connection)
                try:
                    threading.Thread(
                        target=self._handle_connection, args=(connection,), daemon=True,
                    ).start()
                except RuntimeError:
                    self._pending.release()
                    with self._connections_lock:
                        self._connections.discard(connection)
                    connection.close()
                    raise
        finally:
            self._stopped.set()

    def _handle_connection(self, connection) -> None:
        op = None
        request_id = None
        try:
            with contextlib.ExitStack() as pending:
                pending.callback(self._pending.release)
                try:
                    if not connection.poll(self.first_message_timeout):
                        return
                    raw = connection.recv_bytes()
                except (EOFError, OSError):
                    return
                # Once authenticated, a slow analysis occupies no admission slot.
                encoded, op, request_id, should_shutdown = _process_bridge_request(
                    self.bridge, raw, on_authenticated=pending.close
                )
            try:
                connection.send_bytes(encoded)
            except (BrokenPipeError, EOFError, OSError):
                _log_disconnected_client(op, request_id)
                return
            if should_shutdown:
                self.bridge.request_shutdown()
        finally:
            with self._connections_lock:
                self._connections.discard(connection)
            with contextlib.suppress(OSError):
                connection.close()

    def shutdown(self) -> None:
        if self._stopping.is_set():
            return
        self._stopping.set()
        # A busy listener already has a client to wake accept(). Client(AF_PIPE)
        # would instead retry for 20 seconds if all kernel instances were busy.
        import _winapi
        with contextlib.suppress(OSError):
            handle = _winapi.CreateFile(
                self.pipe_name, _winapi.GENERIC_READ | _winapi.GENERIC_WRITE, 0,
                _winapi.NULL, _winapi.OPEN_EXISTING, _winapi.FILE_FLAG_OVERLAPPED, _winapi.NULL,
            )
            _winapi.CloseHandle(handle)
        self._stopped.wait(timeout=2.0)

    def server_close(self) -> None:
        with contextlib.suppress(Exception):
            self._listener.close()
        with self._connections_lock:
            connections = list(self._connections)
            self._connections.clear()
        for connection in connections:
            with contextlib.suppress(OSError):
                connection.close()


LOAD_ATTEMPTS_LIMIT = 50
COMPLETED_JOBS_LIMIT = 50


@dataclass(slots=True)
class LoadAttempt:
    load_id: str
    path: str
    started_at: str
    status: str
    completed_at: str | None = None
    error: str | None = None
    traceback: str | None = None
    target_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "load_id": self.load_id,
            "path": self.path,
            "started_at": self.started_at,
            "status": self.status,
            "completed_at": self.completed_at,
            "error": self.error,
            "traceback": self.traceback,
            "target_id": self.target_id,
        }


@dataclass(slots=True)
class JobRecord:
    job_id: str
    op: str
    params: dict[str, Any]
    target: str | None
    target_id: str
    view_id: str
    access: str
    created_at: str
    cancelable: bool
    state: str = "queued"
    started_at: str | None = None
    completed_at: str | None = None
    progress: str | None = None
    error: str | None = None
    traceback: str | None = None
    artifact_path: str | None = None
    cancel_event: threading.Event | None = None
    done_event: threading.Event | None = None
    bv: Any = None
    background_task: Any = None
    address_context: dict | None = None

    def __post_init__(self) -> None:
        if self.cancel_event is None:
            self.cancel_event = threading.Event()
        if self.done_event is None:
            self.done_event = threading.Event()

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "wait_supported": True,
            "op": self.op,
            "target_id": self.target_id,
            "access": self.access,
            "state": self.state,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "progress": self.progress,
            "cancelable": self.cancelable,
            "error": self.error,
            "artifact_path": self.artifact_path,
            "address_context": self.address_context,
        }


class JobManager:
    """Owns job lifecycle, target reservations, cancellation, and result artifacts."""

    def __init__(self, bridge: "BinaryNinjaBridge"):
        self._bridge = bridge
        self._jobs: dict[str, JobRecord] = {}
        self._lock = threading.RLock()
        self._readers: dict[str, set[str]] = {}
        self._writers: dict[str, str] = {}
        self._root = bridge_job_root(bridge.mode)
        self._stopping = False

    def _blockers(self, view_id: str, access: str) -> list[JobRecord]:
        ids: set[str] = set()
        writer = self._writers.get(view_id)
        if writer is not None:
            ids.add(writer)
        if access == "write":
            ids.update(self._readers.get(view_id, set()))
        return [self._jobs[job_id] for job_id in ids if job_id in self._jobs]

    def _reserve(self, job: JobRecord) -> None:
        blockers = self._blockers(job.view_id, job.access)
        if blockers:
            raise TargetBusyError([item.to_dict() for item in blockers])
        if job.access == "write":
            self._writers[job.view_id] = job.job_id
        else:
            self._readers.setdefault(job.view_id, set()).add(job.job_id)

    def _release(self, job: JobRecord) -> None:
        with self._lock:
            if job.access == "write":
                if self._writers.get(job.view_id) == job.job_id:
                    self._writers.pop(job.view_id, None)
            else:
                readers = self._readers.get(job.view_id)
                if readers is not None:
                    readers.discard(job.job_id)
                    if not readers:
                        self._readers.pop(job.view_id, None)

    def submit(self, op: str, params: dict[str, Any], target: str | None) -> dict[str, Any]:
        if self._stopping:
            raise RuntimeError("Bridge is shutting down and cannot accept new jobs")
        if op not in READ_LOCKED_OPS and op not in WRITE_LOCKED_OPS:
            raise RuntimeError(f"Operation is not job-capable: {op}")
        with self._bridge._global_lock.read():
            bv = self._bridge.targets.resolve(target)
            view_id = self._bridge.targets.view_id_for(bv)
            if view_id is None:
                raise RuntimeError(f"Target not registered: {target!r}")
            target_id = self._bridge.targets.target_id_for(bv)
            if target_id is None:
                raise RuntimeError(f"Target not registered: {target!r}")

        job = JobRecord(
            job_id=uuid.uuid4().hex[:12],
            op=op,
            params=dict(params),
            target=target_id,
            target_id=target_id,
            view_id=view_id,
            access="write" if op in WRITE_LOCKED_OPS else "read",
            created_at=datetime.now(timezone.utc).isoformat(),
            cancelable=op not in {"py_exec", "plugin_execute", "plugin_valid_commands", "loader_rebase"},
            bv=bv,
        )
        with self._lock:
            self._jobs[job.job_id] = job
            try:
                self._reserve(job)
            except Exception:
                self._jobs.pop(job.job_id, None)
                raise
        threading.Thread(target=self._run, args=(job,), daemon=True).start()
        return job.to_dict()

    def _artifact_for(self, job: JobRecord) -> Path:
        return self._root / f"{job.job_id}.json"

    def _write_result(self, job: JobRecord, result: Any) -> None:
        self._root.mkdir(parents=True, exist_ok=True)
        path = self._artifact_for(job)
        atomic_write(path, json.dumps(result, sort_keys=True, default=str).encode("utf-8"))
        job.artifact_path = str(path)

    def _run(self, job: JobRecord) -> None:
        try:
            task_type = getattr(bn, "BackgroundTask", None)
            if self._bridge.mode == "gui" and task_type is not None:
                with contextlib.suppress(Exception):
                    job.background_task = task_type(
                        f"bn job {job.job_id}: {job.op}",
                        job.cancelable,
                    )
                    threading.Thread(
                        target=self._monitor_background_task,
                        args=(job,),
                        daemon=True,
                    ).start()
            if job.cancel_event is not None and job.cancel_event.is_set():
                raise JobCancelled("Cancelled before execution")
            job.state = "running"
            job.started_at = datetime.now(timezone.utc).isoformat()
            job.progress = "running"
            result = self._bridge._execute_job(job)
            # A completed operation (possibly a committed write) owns its outcome.
            # Cancellation is checked inside operations before their commit point.
            self._write_result(job, result)
            with self._lock:
                job.state = "succeeded"
                job.progress = "completed"
        except JobCancelled as exc:
            with self._lock:
                job.state = "cancelled"
                job.error = str(exc)
                job.progress = "cancelled"
        except Exception as exc:
            with self._lock:
                job.state = "failed"
                job.error = f"{type(exc).__name__}: {exc}"
                job.traceback = traceback.format_exc()
                job.progress = "failed"
            bn.log_error(job.traceback)
        finally:
            job.completed_at = datetime.now(timezone.utc).isoformat()
            if job.done_event is not None:
                job.done_event.set()
            if job.background_task is not None:
                with contextlib.suppress(Exception):
                    job.background_task.finish()
            job.bv = None
            self._release(job)
            self._evict_completed()

    def _monitor_background_task(self, job: JobRecord) -> None:
        assert job.done_event is not None
        while not job.done_event.wait(timeout=0.1):
            try:
                cancelled = bool(job.background_task.cancelled)
            except Exception:
                return
            if cancelled:
                self.cancel(job.job_id)
                return

    def _evict_completed(self) -> None:
        terminal = {"cancelled", "succeeded", "failed"}
        with self._lock:
            completed = [job for job in self._jobs.values() if job.state in terminal]
            completed.sort(key=lambda item: item.completed_at or item.created_at)
            for job in completed[:-COMPLETED_JOBS_LIMIT]:
                self._jobs.pop(job.job_id, None)
                if job.artifact_path:
                    with contextlib.suppress(OSError):
                        Path(job.artifact_path).unlink()

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            return [job.to_dict() for job in reversed(list(self._jobs.values()))]

    def get(self, job_id: str) -> JobRecord:
        with self._lock:
            job = self._jobs.get(job_id)
        if job is None:
            raise RuntimeError(f"Unknown or expired job: {job_id}")
        return job

    def status(self, job_id: str) -> dict[str, Any]:
        return self.get(job_id).to_dict()

    def result(self, job_id: str) -> dict[str, Any]:
        job = self.get(job_id)
        if job.state not in {"succeeded", "failed", "cancelled"}:
            return {"ready": False, "job": job.to_dict(), "result": None}
        result = None
        if job.state == "succeeded" and job.artifact_path:
            result = json.loads(Path(job.artifact_path).read_text(encoding="utf-8"))
        return {"ready": True, "job": job.to_dict(), "result": result}

    def cancel(self, job_id: str) -> dict[str, Any]:
        job = self.get(job_id)
        with self._lock:
            if not job.cancelable:
                return {"accepted": False, "reason": "operation is not safely cancellable", "job": job.to_dict()}
            if job.state in {"succeeded", "failed", "cancelled"}:
                return {"accepted": False, "reason": "job already completed", "job": job.to_dict()}
            job.state = "cancel_requested"
            job.progress = "cancellation requested"
            assert job.cancel_event is not None
            job.cancel_event.set()
        if job.background_task is not None:
            with contextlib.suppress(Exception):
                job.background_task.cancel()
        if job.op in ANALYSIS_WAIT_OPS:
            with contextlib.suppress(Exception):
                job.bv.abort_analysis()
        return {"accepted": True, "job": job.to_dict()}

    def blockers_for(self, view_id: str) -> list[dict[str, Any]]:
        with self._lock:
            ids = set(self._readers.get(view_id, set()))
            writer = self._writers.get(view_id)
            if writer:
                ids.add(writer)
            return [self._jobs[item].to_dict() for item in ids if item in self._jobs]

    def stop(self) -> None:
        self._stopping = True
        with self._lock:
            jobs = list(self._jobs.values())
        for job in jobs:
            if job.cancelable and job.cancel_event is not None:
                job.cancel_event.set()
            if job.artifact_path:
                with contextlib.suppress(OSError):
                    Path(job.artifact_path).unlink()
        with contextlib.suppress(OSError):
            self._root.rmdir()


class BinaryNinjaBridge:
    def __init__(self, mode: str = "gui"):
        self.mode = mode
        self.targets = TargetManager(mode=mode)
        self._address_spaces: dict[str, dict] = {}
        self.socket_path = bridge_socket_path(mode)
        self.registry_path = bridge_registry_path(mode)
        self.transport = _configured_transport(mode)
        self.host: str | None = None
        self.port: int | None = None
        self.pipe_name: str | None = None
        self.auth_token: str | None = None
        self._server: Any = None
        self._thread: threading.Thread | None = None
        self.shutdown_event = threading.Event()
        self._target_locks: dict[str, _ReadWriteLock] = {}
        self._target_locks_lock = threading.Lock()
        self._global_lock = _ReadWriteLock()
        self._load_attempts: list[LoadAttempt] = []
        self._load_attempts_lock = threading.Lock()
        self._load_lock = threading.Lock()
        self._job_local = threading.local()
        self.jobs = JobManager(self)

    def _get_target_lock(self, view_id: str) -> _ReadWriteLock:
        with self._target_locks_lock:
            lock = self._target_locks.get(view_id)
            if lock is None:
                lock = _ReadWriteLock()
                self._target_locks[view_id] = lock
            return lock

    def _remove_target_lock(self, view_id: str) -> None:
        with self._target_locks_lock:
            self._target_locks.pop(view_id, None)

    def _record_load_start(self, path: str) -> str:
        import uuid as _uuid

        attempt = LoadAttempt(
            load_id=_uuid.uuid4().hex[:12],
            path=path,
            started_at=datetime.now(timezone.utc).isoformat(),
            status="loading",
        )
        with self._load_attempts_lock:
            self._load_attempts.append(attempt)
            while len(self._load_attempts) > LOAD_ATTEMPTS_LIMIT:
                self._load_attempts.pop(0)
        return attempt.load_id

    def _record_load_done(
        self,
        load_id: str,
        *,
        success: bool,
        error: str | None = None,
        traceback_text: str | None = None,
        target_id: str | None = None,
    ) -> None:
        with self._load_attempts_lock:
            for attempt in self._load_attempts:
                if attempt.load_id == load_id:
                    attempt.status = "succeeded" if success else "failed"
                    attempt.completed_at = datetime.now(timezone.utc).isoformat()
                    attempt.error = error
                    attempt.traceback = traceback_text
                    attempt.target_id = target_id
                    return

    def _list_loads(self) -> list[dict[str, Any]]:
        with self._load_attempts_lock:
            return [attempt.to_dict() for attempt in self._load_attempts]

    def start(self) -> bool:  # pragma: no cover - requires GUI runtime
        self.shutdown_event.clear()
        if self.transport == "unix":
            if ThreadedUnixServer is None or not hasattr(socket, "AF_UNIX"):
                bn.log_error("BN Agent Bridge Unix-domain sockets are unavailable")
                return False
            self.socket_path.parent.mkdir(parents=True, exist_ok=True)
            if self.socket_path.exists():
                self.socket_path.unlink()
            assert ThreadedUnixServer is not None
            self._server = ThreadedUnixServer(str(self.socket_path), BridgeHandler, self)
        elif self.transport == "pipe":
            self.auth_token = secrets.token_urlsafe(32)
            self.pipe_name = bridge_pipe_name(self.mode)
            try:
                self._server = ThreadedNamedPipeServer(self.pipe_name, self)
            except (OSError, ValueError) as exc:
                self._server = None
                self.auth_token = None
                bn.log_error(
                    f"BN Agent Bridge could not create Named Pipe {self.pipe_name}: {exc}. "
                    "Check the current user's Named Pipe permissions or set "
                    "BN_BRIDGE_TRANSPORT=tcp for explicit compatibility mode."
                )
                return False
        elif self.transport == "tcp":
            self.auth_token = secrets.token_urlsafe(32)
            requested_port = _configured_tcp_port(self.mode)
            try:
                self._server = ThreadedTcpServer(
                    ("127.0.0.1", requested_port), BridgeHandler, self
                )
            except OSError as exc:
                self._server = None
                self.auth_token = None
                self.host = None
                self.port = None
                env_name = f"BN_BRIDGE_{self.mode.upper()}_PORT"
                configuration_hint = (
                    "change the port in Binary Ninja Settings"
                    if self.mode == "gui"
                    else f"set {env_name}"
                )
                bn.log_error(
                    "BN Agent Bridge could not listen on "
                    f"tcp://127.0.0.1:{requested_port} for {self.mode} mode: {exc}. "
                    f"Close the process using that port or {configuration_hint}."
                )
                return False
            self.host, self.port = self._server.server_address
        else:
            bn.log_error(f"BN Agent Bridge does not support transport {self.transport!r}")
            return False
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self._write_registry()
        bn.log_info(f"BN Agent Bridge listening on {self.endpoint}")
        return True

    def request_shutdown(self) -> None:
        self.shutdown_event.set()

    @property
    def endpoint(self) -> str:
        if self.transport == "tcp":
            return f"tcp://{self.host}:{self.port}"
        if self.transport == "pipe":
            return f"pipe://{self.pipe_name}"
        return str(self.socket_path)

    def stop(self):  # pragma: no cover - requires GUI runtime
        self.jobs.stop()
        if self._server is not None:
            with contextlib.suppress(Exception):
                self._server.shutdown()
            with contextlib.suppress(Exception):
                self._server.server_close()
        if self.transport == "unix" and self.socket_path.exists():
            with contextlib.suppress(OSError):
                self.socket_path.unlink()
        if self.registry_path.exists():
            with contextlib.suppress(OSError):
                self.registry_path.unlink()

    def _write_registry(self):
        payload = {
            "pid": os.getpid(),
            "socket_path": str(self.socket_path) if self.transport == "unix" else None,
            "transport": self.transport,
            "plugin_name": PLUGIN_NAME,
            "plugin_version": VERSION,
            "plugin_build_id": PLUGIN_BUILD_ID,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "mode": self.mode,
        }
        if self.transport == "tcp":
            payload.update(
                {
                    "host": self.host,
                    "port": self.port,
                    "auth_token": self.auth_token,
                }
            )
        elif self.transport == "pipe":
            payload.update(
                {
                    "pipe_name": self.pipe_name,
                    "auth_token": self.auth_token,
                }
            )
        self.registry_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        atomic_write(self.registry_path, json.dumps(payload, indent=2).encode("utf-8"))

    def dispatch(self, payload: dict[str, Any]) -> dict[str, Any]:  # pragma: no cover - GUI runtime
        op = payload.get("op")
        params = payload.get("params") or {}
        target = payload.get("target")
        try:
            if op == "job_submit":
                operation = str(params.get("operation", ""))
                operation_params = params.get("params") or {}
                if not isinstance(operation_params, dict):
                    raise RuntimeError("job_submit params.params must be an object")
                result = self.jobs.submit(operation, operation_params, target)
                return _json_response(ok=True, result=result)
            if op == "job_list":
                return _json_response(ok=True, result=self.jobs.list())
            if op == "job_status":
                return _json_response(ok=True, result=self.jobs.status(str(params["job_id"])))
            if op == "job_wait":
                wait = float(params.get("timeout", 1))
                if not 0 <= wait <= 30:
                    raise ValueError("job_wait timeout must be between 0 and 30 seconds")
                job = self.jobs.get(str(params["job_id"]))
                job.done_event.wait(wait)
                return _json_response(ok=True, result=job.to_dict())
            if op == "job_result":
                return _json_response(ok=True, result=self.jobs.result(str(params["job_id"])))
            if op == "job_cancel":
                return _json_response(ok=True, result=self.jobs.cancel(str(params["job_id"])))
            if op in NO_LOCK_OPS:
                result = self._execute_operation(op, params, target)
                return _json_response(ok=True, result=result)
            if op in GLOBAL_OPS:
                with self._global_lock.write():
                    result = self._execute_operation(op, params, target)
                return _json_response(ok=True, result=result)
            if op in WRITE_LOCKED_OPS or op in READ_LOCKED_OPS:
                # Legacy direct requests use the same job module and wait forever.
                # The CLI normally uses job_submit so it can return a job id on timeout.
                job = self.jobs.submit(op, params, target)
                record = self.jobs.get(job["job_id"])
                assert record.done_event is not None
                record.done_event.wait()
                outcome = self.jobs.result(record.job_id)
                if record.state != "succeeded":
                    raise RuntimeError(record.error or f"Job {record.state}")
                response = _json_response(ok=True, result=outcome["result"])
                response["address_context"] = record.address_context
                return response
            # Fallback for ops without a declared lock class.
            result = self._execute_operation(op, params, target)
            return _json_response(ok=True, result=result)
        except Exception as exc:
            return _json_response(ok=False, error=f"{type(exc).__name__}: {exc}")

    def _execute_job(self, job: JobRecord):
        self._job_local.record = job
        try:
            with self._global_lock.read():
                # Resolve the concrete target id again while close_target is excluded.
                self.targets.resolve(job.target_id)
                job.address_context = self._address_context(job.bv)
                result = self._execute_operation(job.op, job.params, job.target_id)
                job.address_context = self._address_context(job.bv)
                return result
        finally:
            self._job_local.record = None

    def _check_job_cancelled(self) -> None:
        job = getattr(getattr(self, "_job_local", None), "record", None)
        if job is not None:
            ui_cancelled = False
            if job.background_task is not None:
                with contextlib.suppress(Exception):
                    ui_cancelled = bool(job.background_task.cancelled)
            if ui_cancelled and job.cancel_event is not None:
                job.cancel_event.set()
            if job.cancel_event is not None and job.cancel_event.is_set():
                raise JobCancelled(f"Job {job.job_id} was cancelled")

    def _set_job_progress(self, message: str) -> None:
        job = getattr(self._job_local, "record", None)
        if job is not None:
            job.progress = message
            if job.background_task is not None:
                with contextlib.suppress(Exception):
                    job.background_task.progress = message

    def _execute_operation(self, op: str, params: dict[str, Any], target: str | None):
        if op.startswith("address_"):
            return self._address_operation(op, params, target)
        if op == "inspect":
            return self._inspect(target, params["identifier"])
        if op == "shutdown":
            if self.mode != "headless":
                raise RuntimeError("The shutdown operation is only available in headless mode")
            return {"accepted": True, "mode": self.mode, "pid": os.getpid()}
        if op == "doctor":
            return self._doctor()
        if op == "list_targets":
            return self.targets.refresh()
        if op == "target_info":
            return self._target_info(params.get("selector") or target)
        if op == "set_active_target":
            return self._set_active_target(params)
        if op == "refresh":
            return self._refresh(target)

        if op == "list_functions":
            return self._list_functions(
                target,
                min_address=params.get("min_address"),
                max_address=params.get("max_address"),
                offset=int(params.get("offset", 0)), limit=params.get("limit"),
            )
        if op == "search_functions":
            return self._search_functions(
                target,
                str(params.get("query", "")),
                regex=bool(params.get("regex", False)),
                min_address=params.get("min_address"),
                max_address=params.get("max_address"),
                offset=int(params.get("offset", 0)), limit=params.get("limit"),
            )
        if op == "callsites":
            return self._callsites(
                target,
                str(params["callee"]),
                within_identifiers=list(params.get("within_identifiers") or []),
                context=int(params.get("context", 3)),
            )
        if op == "function_info":
            return self._function_info(target, params["identifier"])
        if op == "get_prototype":
            return self._get_prototype(target, params["identifier"])
        if op == "list_locals":
            return self._list_locals_for_function(target, params["identifier"])
        if op == "decompile":
            return self._decompile(target, params["identifier"])
        if op == "il":
            return self._il(target, params["identifier"], str(params.get("view", "hlil")), bool(params.get("ssa")))
        if op == "disasm":
            return self._disasm(target, params["identifier"])
        if op == "xrefs":
            return self._xrefs(target, params["identifier"])
        if op == "field_xrefs":
            return self._field_xrefs(target, str(params["field"]))
        if op == "types":
            return self._types(target, query=params.get("query"))
        if op == "type_info":
            return self._type_info(
                target,
                str(params["type_name"]),
                require_struct=bool(params.get("require_struct")),
            )
        if op == "strings":
            return self._strings(target, query=params.get("query"))
        if op == "imports":
            return self._imports(target)
        if op == "workflow_list":
            return self._workflow_list(
                target,
                registered_only=bool(params.get("registered_only", False)),
            )
        if op == "workflow_show":
            return self._workflow_show(
                target,
                name=str(params["name"]),
                activity=params.get("activity"),
                depth=str(params.get("depth", "all")),
                with_config=bool(params.get("with_config", False)),
            )
        if op == "workflow_active":
            return self._workflow_active(target, function=params.get("function"))
        if op == "workflow_machine_status":
            return self._workflow_machine_call(target, "status", params)
        if op == "workflow_machine_dump":
            return self._workflow_machine_call(target, "dump", params)
        if op == "workflow_machine_overrides":
            return self._workflow_machine_call(target, "overrides", params)
        if op == "workflow_override_set":
            return self._workflow_override_apply(
                target,
                action="set",
                activity=str(params["activity"]),
                enable=bool(params["enable"]),
                function=params.get("function"),
                preview=bool(params.get("preview", False)),
            )
        if op == "workflow_override_clear":
            return self._workflow_override_apply(
                target,
                action="clear",
                activity=str(params["activity"]),
                enable=None,
                function=params.get("function"),
                preview=bool(params.get("preview", False)),
            )
        if op in (
            "workflow_machine_enable",
            "workflow_machine_disable",
            "workflow_machine_step",
            "workflow_machine_halt",
            "workflow_machine_reset",
            "workflow_machine_breakpoint_list",
        ):
            command = op[len("workflow_machine_") :]
            return self._workflow_machine_command(
                target,
                command=command,
                function=params.get("function"),
            )
        if op in ("workflow_machine_run", "workflow_machine_resume"):
            command = op[len("workflow_machine_") :]
            return self._workflow_machine_command(
                target,
                command=command,
                function=params.get("function"),
                advanced=bool(params.get("advanced", True)),
                incremental=bool(params.get("incremental", False)),
            )
        if op in ("workflow_machine_breakpoint_set", "workflow_machine_breakpoint_clear"):
            command = op[len("workflow_machine_") :]
            return self._workflow_machine_command(
                target,
                command=command,
                function=params.get("function"),
                activities=list(params.get("activities") or []),
            )
        if op == "bundle_function":
            return self._bundle_function(target, params["identifier"], params.get("out_path"))
        if op == "py_exec":
            return self._py_exec(target, str(params["script"]))
        if op == "load_target":
            return self._load_target(
                path=str(params["path"]),
                analysis=str(params.get("analysis", "wait")),
                options=params.get("options"),
            )
        if op == "close_target":
            return self._close_target(str(params["target"]))
        if op == "save_target":
            return self._save_target(target, path=params.get("path"))
        if op == "analysis_status":
            return self._analysis_status(target)
        if op == "list_loads":
            return self._list_loads()

        if op == "rename_symbol":
            return self._mutation(target, bool(params.get("preview")), [params])
        if op == "create_function":
            return self._mutation(
                target,
                bool(params.get("preview")),
                [{"op": "create_function", "address": params["address"]}],
            )
        if op == "get_comment":
            return self._get_comment(target, params.get("address"), params.get("function"))
        if op == "set_comment":
            return self._mutation(target, bool(params.get("preview")), [{"op": "set_comment", **params}])
        if op == "delete_comment":
            return self._mutation(target, bool(params.get("preview")), [{"op": "delete_comment", **params}])
        if op == "set_prototype":
            return self._mutation(target, bool(params.get("preview")), [{"op": "set_prototype", **params}])
        if op == "local_rename":
            return self._mutation(target, bool(params.get("preview")), [{"op": "local_rename", **params}])
        if op == "local_retype":
            return self._mutation(target, bool(params.get("preview")), [{"op": "local_retype", **params}])
        if op == "struct_field_set":
            return self._mutation(target, bool(params.get("preview")), [{"op": "struct_field_set", **params}])
        if op == "struct_field_rename":
            return self._mutation(target, bool(params.get("preview")), [{"op": "struct_field_rename", **params}])
        if op == "struct_field_delete":
            return self._mutation(target, bool(params.get("preview")), [{"op": "struct_field_delete", **params}])
        if op == "types_declare":
            return self._mutation(target, bool(params.get("preview")), [{"op": "types_declare", **params}])
        if op == "batch_apply":
            manifest = dict(params)
            preview = bool(manifest.get("preview"))
            target = str(manifest.get("target") or target)
            operations = list(manifest.get("ops") or [])
            return self._mutation(target, preview, operations)

        # --- patch ops ---
        if op == "patch_status":
            return self._patch_status(target, params["address"])
        if op == "patch_assemble":
            return self._patch_assemble(target, params["address"], str(params["asm"]))
        if op == "patch_nop":
            return self._patch_nop(target, params["address"], params.get("length"))
        if op == "patch_always_branch":
            return self._patch_always_branch(target, params["address"])
        if op == "patch_invert_branch":
            return self._patch_invert_branch(target, params["address"])
        if op == "patch_never_branch":
            return self._patch_never_branch(target, params["address"])
        if op == "patch_skip_and_return":
            return self._patch_skip_and_return(target, params["address"], int(params["value"]))

        # --- memory ops ---
        if op == "memory_read":
            return self._memory_read(target, params["address"], int(params["length"]))
        if op == "memory_write":
            return self._memory_write(target, params["address"], str(params["data_hex"]))
        if op == "memory_insert":
            return self._memory_insert(target, params["address"], str(params["data_hex"]))
        if op == "memory_remove":
            return self._memory_remove(target, params["address"], int(params["length"]))
        if op == "memory_reader_read":
            return self._memory_reader_read(
                target, params["address"], int(params["width"]),
                endian=str(params.get("endian", "little")),
            )
        if op == "memory_writer_write":
            return self._memory_writer_write(
                target, params["address"], int(params["width"]),
                _parse_address(params["value"]), endian=str(params.get("endian", "little")),
            )

        # --- value ops ---
        if op == "value_query":
            return self._value_query(target, params)
        if op == "value_flags_at":
            return self._value_flags_at(
                target, params.get("function_start"), params["address"]
            )
        if op == "value_possible":
            return self._value_possible(
                target, params.get("function_start"), params["address"],
                level=str(params.get("level", "hlil")),
                ssa=bool(params.get("ssa", False)),
            )
        if op == "value_reg":
            return self._value_reg(
                target, params.get("function_start"), params["address"],
                str(params["register"]), after=bool(params.get("after", False)),
            )
        if op == "value_stack":
            return self._value_stack(
                target, params.get("function_start"), params["address"],
                int(params["stack_offset"]), int(params["size"]),
                after=bool(params.get("after", False)),
            )

        # --- search ops ---
        if op == "search_bytes":
            return self._search_bytes(
                target, str(params["data_hex"]),
                start=params.get("start"), end=params.get("end"),
                limit=params.get("limit"),
            )
        if op == "search_constant":
            return self._search_constant(
                target, _parse_address(params["constant"]),
                start=params.get("start"), end=params.get("end"),
                limit=params.get("limit"),
            )
        if op == "search_text":
            return self._search_text(
                target, str(params["query"]),
                start=params.get("start"), end=params.get("end"),
                regex=bool(params.get("regex", False)),
                il_type=str(params.get("il_type", "hlil")),
                limit=params.get("limit"),
            )

        # --- arch ops ---
        if op == "arch_info":
            return self._arch_info(target)
        if op == "arch_assemble":
            return self._arch_assemble(
                target, str(params["asm"]),
                address=params.get("address"),
                arch_name=params.get("arch_name"),
            )
        if op == "arch_disasm_bytes":
            return self._arch_disasm_bytes(
                target, str(params["data_hex"]),
                address=params.get("address"),
                arch_name=params.get("arch_name"),
                count=params.get("count"),
            )

        # --- segments/sections/data_vars ---
        if op == "list_segments":
            return self._list_segments(target)
        if op == "list_sections":
            return self._list_sections(target)
        if op == "list_data_vars":
            return self._list_data_vars(target)

        # --- disasm extended ---
        if op == "disasm_linear":
            return self._disasm_linear(
                target, params["address"],
                count=int(params.get("count", 20)),
            )
        if op == "disasm_range":
            return self._disasm_range(target, params["start"], params["end"])

        # --- function extended ---
        if op == "function_containing":
            return self._function_containing(target, params["address"])
        if op == "function_basic_blocks":
            return self._function_basic_blocks(target, params["identifier"])
        if op == "function_callers":
            return self._function_callers(target, params["identifier"])
        if op == "function_callees":
            return self._function_callees(target, params["identifier"])
        if op == "function_force_analysis":
            return self._function_force_analysis(target, params["identifier"])
        if op == "function_ssa_var_def_use":
            return self._function_ssa_var_def_use(
                target, params["identifier"],
                var_name=str(params["var"]),
                version=int(params["version"]),
                il_level=str(params.get("level", "mlil")),
            )
        if op == "function_ssa_memory_def_use":
            return self._function_ssa_memory_def_use(
                target, params["identifier"],
                version=int(params["version"]),
                il_level=str(params.get("level", "mlil")),
            )
        if op == "function_var_refs":
            return self._function_var_refs(
                target, params["identifier"],
                var_name=str(params["var"]),
                il_level=str(params.get("level", "hlil")),
            )
        if op == "function_var_refs_from":
            return self._function_var_refs_from(
                target, params["identifier"],
                address=params["address"],
                il_level=str(params.get("level", "hlil")),
            )
        if op == "function_metadata_query":
            return self._function_metadata_query(target, params["identifier"], str(params["key"]))
        if op == "function_metadata_store":
            return self._function_metadata_store(target, params["identifier"], str(params["key"]), params["value"])
        if op == "function_metadata_remove":
            return self._function_metadata_remove(target, params["identifier"], str(params["key"]))

        # --- database ---
        if op == "database_info":
            return self._database_info(target)
        if op == "database_read_global":
            return self._database_read_global(target, str(params["key"]))
        if op == "database_write_global":
            return self._database_write_global(target, str(params["key"]), str(params["value"]))
        if op == "database_snapshots":
            return self._database_snapshots(target)
        if op == "database_save_auto_snapshot":
            return self._database_save_auto_snapshot(target)
        if op == "database_create_bndb":
            return self._database_create_bndb(target, str(params["path"]))

        # --- type extended ---
        if op == "type_rename":
            return self._type_rename(target, str(params["old_name"]), str(params["new_name"]))
        if op == "type_undefine_user":
            return self._type_undefine_user(target, str(params["name"]))
        if op == "type_parse_string":
            return self._type_parse_string(target, str(params["type_source"]))
        if op == "type_import_library_type":
            return self._type_import_library_type(target, str(params["name"]), lib_id=params.get("type_library_id"))
        if op == "type_import_library_object":
            return self._type_import_library_object(target, str(params["name"]), lib_id=params.get("type_library_id"))
        if op == "type_export_to_library":
            return self._type_export_to_library(target, str(params["type_library_id"]), str(params["type_source"]), name=params.get("name"))
        if op == "type_library_list":
            return self._type_library_list(target)
        if op == "type_library_get":
            return self._type_library_get(target, str(params["type_library_id"]))
        if op == "type_library_create":
            return self._type_library_create(target, str(params["name"]), path=params.get("path"), add_to_view=bool(params.get("add_to_view", False)))
        if op == "type_library_load":
            return self._type_library_load(target, str(params["path"]), add_to_view=bool(params.get("add_to_view", True)))
        if op == "type_archive_list":
            return self._type_archive_list(target)
        if op == "type_archive_get":
            return self._type_archive_get(target, str(params["type_archive_id"]))
        if op == "type_archive_create":
            return self._type_archive_create(target, str(params["path"]), attach=bool(params.get("attach", False)))
        if op == "type_archive_open":
            return self._type_archive_open(target, str(params["path"]), attach=bool(params.get("attach", False)))
        if op == "type_archive_pull":
            return self._type_archive_pull(target, str(params["type_archive_id"]), list(params["names"]))
        if op == "type_archive_push":
            return self._type_archive_push(target, str(params["type_archive_id"]), list(params["names"]))

        # --- annotation ---
        if op == "annotation_add_tag":
            return self._annotation_add_tag(
                target,
                params.get("address"),
                str(params["tag_type"]),
                str(params["data"]),
                function=params.get("function"),
            )
        if op == "annotation_get_tags":
            return self._annotation_get_tags(
                target, params.get("address"), function=params.get("function")
            )
        if op == "annotation_create_tag_type":
            return self._annotation_create_tag_type(
                target, str(params["tag_type"]), params.get("icon")
            )
        if op == "annotation_list_tag_types":
            return self._annotation_list_tag_types(target)
        if op == "annotation_remove_tag":
            return self._annotation_remove_tag(
                target,
                str(params["tag_type"]),
                function=params.get("function"),
                address=params.get("address"),
            )
        if op == "annotation_define_data_var":
            return self._annotation_define_data_var(target, params["address"], type_name=params.get("type_name"), name=params.get("name"), width=params.get("width"))
        if op == "annotation_undefine_data_var":
            return self._annotation_undefine_data_var(target, params["address"])
        if op == "annotation_define_symbol":
            return self._annotation_define_symbol(target, params["address"], str(params["name"]), symbol_type=params.get("symbol_type"))
        if op == "annotation_undefine_symbol":
            return self._annotation_undefine_symbol(target, params["address"])
        if op == "annotation_rename_data_var":
            return self._annotation_rename_data_var(target, params["address"], str(params["new_name"]))

        # --- undo ---
        if op == "undo_begin":
            return self._undo_begin(target)
        if op == "undo_commit":
            return self._undo_commit(target)
        if op == "undo_revert":
            return self._undo_revert(target)
        if op == "undo_undo":
            return self._undo_undo(target)
        if op == "undo_redo":
            return self._undo_redo(target)

        # --- uidf ---
        if op == "uidf_set_user_var_value":
            return self._uidf_set(target, params)
        if op == "uidf_clear_user_var_value":
            return self._uidf_clear(target, params)
        if op == "uidf_list_user_var_values":
            return self._uidf_list(target, params["function_start"])
        if op == "uidf_parse_possible_value":
            return self._uidf_parse(target, str(params["value"]), str(params["state"]))
        if op == "uidf_from_address":
            return self._uidf_from_address(target, params["address"])

        # --- loader ---
        if op == "loader_load_settings_get":
            type_name = params.get("type_name")
            return self._loader_settings_get(
                target, str(type_name) if type_name else None
            )
        if op == "loader_load_settings_set":
            return self._loader_settings_set(target, str(params["type_name"]), str(params["key"]), params["value"])
        if op == "loader_load_settings_types":
            return self._loader_settings_types(target)
        if op == "loader_rebase":
            return self._loader_rebase(target, params["address"], force=bool(params.get("force", False)))

        # --- external ---
        if op == "external_library_add":
            return self._external_library_add(target, str(params["name"]))
        if op == "external_library_list":
            return self._external_library_list(target)
        if op == "external_library_remove":
            return self._external_library_remove(target, str(params["name"]))
        if op == "external_location_add":
            return self._external_location_add(target, params)
        if op == "external_location_get":
            return self._external_location_get(target, params["source_address"])
        if op == "external_location_remove":
            return self._external_location_remove(target, params["source_address"])
        if op == "external_location_list":
            return self._external_location_list(target)

        # --- analysis ---
        if op == "analysis_status":
            return self._analysis_status(target)
        if op == "analysis_progress":
            return self._analysis_progress(target)
        if op == "analysis_abort":
            return self._analysis_abort(target)
        if op == "analysis_set_hold":
            return self._analysis_set_hold(target, bool(params["hold"]))
        if op == "analysis_update":
            return self._analysis_update(target)
        if op == "analysis_update_and_wait":
            return self._analysis_update_and_wait(target)

        # --- metadata (view-level) ---
        if op == "metadata_query":
            return self._metadata_query(target, str(params["key"]))
        if op == "metadata_store":
            return self._metadata_store(target, str(params["key"]), params["value"])
        if op == "metadata_remove":
            return self._metadata_remove(target, str(params["key"]))
        if op == "metadata_keys":
            return self._metadata_keys(target)

        # --- data ---
        if op == "data_typed_at":
            return self._data_typed_at(target, params["address"])

        # --- xref extended ---
        if op == "xref_code_refs_from":
            return self._xref_code_refs_from(target, params["address"], length=params.get("length"))
        if op == "xref_code_refs_to":
            return self._xref_code_refs_to(target, params["address"], limit=int(params.get("limit", 100)))
        if op == "xref_data_refs_from":
            return self._xref_data_refs_from(target, params["address"], length=params.get("length"))
        if op == "xref_data_refs_to":
            return self._xref_data_refs_to(target, params["address"], limit=int(params.get("limit", 100)))
        if op == "xref_type_refs":
            return self._xref_type_refs(
                target, str(params["name"]), limit=params.get("limit")
            )

        # --- il extended ---
        if op == "il_address_to_index":
            return self._il_address_to_index(target, params["function_start"], params["address"], level=params.get("level", "hlil"))
        if op == "il_index_to_address":
            return self._il_index_to_address(target, params["function_start"], int(params["index"]), level=params.get("level", "hlil"))
        if op == "il_instruction_by_addr":
            return self._il_instruction_by_addr(target, params["function_start"], params["address"], level=params.get("level", "hlil"))

        # --- section/segment user ---
        if op == "section_add_user":
            return self._section_add_user(target, params)
        if op == "section_remove_user":
            return self._section_remove_user(target, str(params["name"]))
        if op == "segment_add_user":
            return self._segment_add_user(target, params)
        if op == "segment_remove_user":
            return self._segment_remove_user(target, params["start"], length=params.get("length"))

        # --- debug ---
        if op == "debug_parsers":
            return self._debug_parsers(target)
        if op == "debug_parse_and_apply":
            return self._debug_parse_and_apply(target, parser_name=params.get("parser_name"), debug_path=params.get("debug_path"))

        # --- plugin ---
        if op == "plugin_valid_commands":
            return self._plugin_valid_commands(target, address=params.get("address"))
        if op == "plugin_execute":
            return self._plugin_execute(target, str(params["name"]), address=params.get("address"))

        # --- binary extended ---
        if op == "binary_basic_blocks_at":
            return self._binary_basic_blocks_at(target, params["address"])

        raise ValueError(f"Unknown operation: {op}")

    def _doctor(self):
        return {
            "plugin_name": PLUGIN_NAME,
            "plugin_version": VERSION,
            "plugin_build_id": PLUGIN_BUILD_ID,
            "pid": os.getpid(),
            "socket_path": self.endpoint,
            "endpoint": self.endpoint,
            "transport": self.transport,
            "mode": self.mode,
            "binaryninja_version": getattr(bn, "core_version", lambda: "unknown")(),
            "capabilities": {
                "job_wait": True, "explicit_address_spaces": True,
                "image_base": hasattr(getattr(bn, "BinaryView", None), "image_base"),
                "parse_expression": hasattr(getattr(bn, "BinaryView", None), "parse_expression"),
                "file_offset_mapping": hasattr(getattr(bn, "BinaryView", None), "get_data_offset_for_address"),
            },
            "targets": self.targets.refresh(),
        }

    def _target_info(self, selector: str | None):
        bv = self.targets.resolve(selector)
        record = None
        for item in self.targets.refresh():
            if item["active"] and selector in (None, "", "active"):
                record = item
                break
            if selector and any(
                self.targets._matches_record(target_record, selector)
                for target_record in self.targets._records.values()
                if target_record.target_id() == item["target_id"]
            ):
                record = item
                break
        return {
            **(record or {}),
            "arch": str(getattr(bv, "arch", "")),
            "platform": str(getattr(bv, "platform", "")),
            "entry_point": hex(getattr(bv, "entry_point", 0)),
            "address_context": self._address_context(bv),
        }

    def _set_active_target(self, params: dict[str, Any]):
        """Set/clear the CLI-managed active target (decoupled from the BN UI focus)."""
        if params.get("clear"):
            self.targets.set_active(None)
            return {"cleared": True, "targets": self.targets.refresh()}
        selector = params.get("target") or params.get("selector")
        if not selector or selector == "active":
            raise RuntimeError(
                "set_active_target requires an explicit target selector (not 'active')"
            )
        bv = self.targets.resolve(selector)
        view_id = self.targets.view_id_for(bv)
        if view_id is None:
            raise RuntimeError(f"Target not registered: {selector!r}")
        self.targets.set_active(view_id)
        return self._target_info(self.targets._records[view_id].target_id())

    def _refresh(self, selector: str | None):
        bv = self._resolve_view(selector)
        bv.update_analysis_and_wait()
        return {
            "refreshed": True,
            "target": self._target_info(selector),
        }

    def _load_target(self, *, path: str, analysis: str = "wait", options: Any = None):
        if self.mode != "headless":
            raise RuntimeError(
                "load_target is only supported in headless mode; "
                "open files via Binary Ninja itself in GUI mode."
            )
        if analysis not in ("wait", "async", "skip"):
            raise RuntimeError(
                f"analysis must be one of 'wait', 'async', 'skip'; got {analysis!r}"
            )

        if analysis == "async":
            load_id = self._record_load_start(path)

            def _detached() -> None:
                try:
                    result = self._do_load(path, options, True)
                    target_id = result.get("target_id") if isinstance(result, dict) else None
                    self._record_load_done(load_id, success=True, target_id=target_id)
                except Exception as exc:  # noqa: BLE001
                    self._record_load_done(
                        load_id,
                        success=False,
                        error=f"{type(exc).__name__}: {exc}",
                        traceback_text=traceback.format_exc(),
                    )

            threading.Thread(
                target=_detached,
                daemon=True,
                name=f"bn-load-{os.path.basename(path)}",
            ).start()
            return {
                "queued": True,
                "load_id": load_id,
                "path": path,
                "message": (
                    "Load detached. Poll `bn target list` for the target to appear, "
                    "or `bn target loads` to see per-load status / errors."
                ),
            }

        return self._do_load(path, options, analysis == "wait")

    def _do_load(self, path: str, options: Any, run_analysis: bool):
        load_kwargs: dict[str, Any] = {"update_analysis": False}
        if isinstance(options, dict):
            load_kwargs["options"] = options
        # Serialize concurrent bn.load() calls; BN core is not guaranteed
        # thread-safe for simultaneous BinaryView creation. Analysis ran outside
        # the lock so different BVs can analyze in parallel.
        with self._load_lock:
            try:
                bv = bn.load(path, **load_kwargs)
            except Exception as exc:
                bn.log_error(f"bn load_target failed for {path}: {exc}")
                raise
            if bv is None:
                bn.log_error(f"bn load_target returned None for {path}")
                raise RuntimeError(f"Binary Ninja could not load: {path}")
            record = self.targets.register(bv)
        if run_analysis:
            bv.update_analysis_and_wait()
        result = self._target_info(record.target_id())
        if not result.get("active"):
            # Multiple targets open and this one isn't the active selection.
            result["active_hint"] = (
                "Multiple targets are open and this one is not active. "
                "Run `bn target use <selector>` to make it the active target."
            )
        return result

    def _close_target(self, selector: str):
        if self.mode != "headless":
            raise RuntimeError(
                "close_target is only supported in headless mode; "
                "close files via Binary Ninja itself in GUI mode."
            )
        bv = self._resolve_view(selector)
        view_id = self.targets.view_id_for(bv)
        if view_id is None:
            raise RuntimeError(f"Target not found in registry: {selector}")
        # Acquire the per-target write lock to wait for any in-flight ops on this BV
        # before we unregister + close. dispatch() already holds _global_lock.write
        # for close_target, so no new target-bound ops can start during this.
        with self._get_target_lock(view_id).write():
            record = self.targets.unregister(view_id)
            self._remove_target_lock(view_id)
            target_id = record.target_id() if record is not None else None
            self._address_spaces.pop(target_id, None)
            try:
                if bv.file is not None:
                    bv.file.close()
            except Exception:
                pass
        return {
            "closed": True,
            "target_id": target_id,
            "selector": selector,
        }

    def _save_target(self, selector: str | None, *, path: Any):
        bv = self._resolve_view(selector)
        path_text = str(path) if path else None
        if path_text:
            ok = bv.create_database(path_text)
            if not ok:
                raise RuntimeError(f"Binary Ninja refused to write database to: {path_text}")
            saved_to = path_text
            is_new = True
        else:
            current = ""
            try:
                current = str(getattr(bv.file, "filename", "")) if bv.file else ""
            except Exception:
                current = ""
            if not current.endswith(".bndb"):
                raise RuntimeError(
                    "No .bndb path on record for this target; pass --path to choose one."
                )
            ok = bv.save_auto_snapshot()
            if not ok:
                raise RuntimeError(f"save_auto_snapshot() failed for: {current}")
            saved_to = current
            is_new = False
        try:
            size = os.path.getsize(saved_to)
        except OSError:
            size = None
        return {
            "saved": True,
            "saved_to": saved_to,
            "is_new_database": is_new,
            "bytes": size,
        }

    def _analysis_status(self, selector: str | None):
        bv = self._resolve_view(selector)
        progress = getattr(bv, "analysis_progress", None)
        state = getattr(progress, "state", None)
        count = getattr(progress, "count", None)
        total = getattr(progress, "total", None)
        state_name = getattr(state, "name", None) or (str(state) if state is not None else None)
        info: dict[str, Any] = {
            "state": state_name,
            "count": int(count) if isinstance(count, int) else count,
            "total": int(total) if isinstance(total, int) else total,
        }
        if state_name and "Idle" in state_name:
            info["done"] = True
        else:
            info["done"] = bool(state_name and "Done" in state_name)
        return info

    def _workflow_list(self, selector: str | None, *, registered_only: bool = False):
        workflows = list(getattr(bn.Workflow, "list", []) or [])
        items: list[dict[str, Any]] = []
        for wf in workflows:
            registered = bool(getattr(wf, "registered", False))
            if registered_only and not registered:
                continue
            items.append({"name": str(wf.name), "registered": registered})
        items.sort(key=lambda r: r["name"])
        return items

    def _lookup_workflow(self, name: str):
        workflows = list(getattr(bn.Workflow, "list", []) or [])
        known = {str(wf.name): wf for wf in workflows}
        if name not in known:
            raise RuntimeError(f"Workflow not found: {name}")
        return known[name]

    def _workflow_show(
        self,
        selector: str | None,
        *,
        name: str,
        activity: str | None = None,
        depth: str = "all",
        with_config: bool = False,
    ):
        wf = self._lookup_workflow(name)
        scope = activity or ""
        immediate = depth == "immediate"
        roots = list(wf.activity_roots(scope))
        activities = list(wf.subactivities(scope, immediate=immediate))
        try:
            eligibility = list(wf.eligibility_settings())
        except Exception:
            eligibility = []
        payload: dict[str, Any] = {
            "name": str(wf.name),
            "registered": bool(getattr(wf, "registered", False)),
            "scope_activity": activity,
            "depth": "immediate" if immediate else "all",
            "roots": roots,
            "activities": activities,
            "eligibility_settings": eligibility,
        }
        if with_config:
            try:
                payload["configuration"] = wf.configuration(scope)
            except Exception as exc:
                payload["configuration_error"] = f"{type(exc).__name__}: {exc}"
        return payload

    def _workflow_active(self, selector: str | None, *, function: Any = None):
        bv = self._resolve_view(selector)
        scope = "binaryview" if function is None else "function"
        owner = bv if function is None else self._find_function(bv, function)
        wf = getattr(owner, "workflow", None)
        if wf is None:
            return {"workflow": None, "scope": scope}
        try:
            activities = list(wf.subactivities("", immediate=False))
        except Exception:
            activities = []
        try:
            roots = list(wf.activity_roots(""))
        except Exception:
            roots = []
        info: dict[str, Any] = {
            "name": str(wf.name),
            "registered": bool(getattr(wf, "registered", False)),
            "roots": roots,
            "activity_count": len(activities),
        }
        if scope == "function":
            info["function"] = hex(int(getattr(owner, "start", 0)))
        return {"workflow": info, "scope": scope}

    def _resolve_workflow_machine(self, selector: str | None, function: Any):
        bv = self._resolve_view(selector)
        scope = "binaryview" if function is None else "function"
        owner = bv if function is None else self._find_function(bv, function)
        wf = getattr(owner, "workflow", None)
        if wf is None:
            raise OperationFailure(
                "unsupported",
                f"No workflow bound to {scope}",
            )
        try:
            machine = wf.machine
        except AttributeError:
            machine = None
        if machine is None:
            raise OperationFailure(
                "unsupported",
                f"Workflow machine not enabled on {scope}",
            )
        return owner, scope, machine

    @staticmethod
    def _read_override(machine: Any, activity: str) -> bool | None:
        resp = machine.override_query(activity)
        if not BinaryNinjaBridge._command_accepted(resp):
            raise OperationFailure("unsupported", "Workflow override query was not accepted; state is unknown")
        response = resp.get("response")
        if not isinstance(response, dict):
            raise OperationFailure("unsupported", "Workflow override query has no state response")
        info = response.get("activity")
        if not isinstance(info, dict):
            raise OperationFailure("unsupported", "Workflow override query has no activity state")
        if "override" not in info:
            return None
        if not isinstance(info["override"], bool):
            raise OperationFailure("unsupported", "Workflow override state is not boolean")
        return info["override"]

    @staticmethod
    def _command_accepted(resp: Any) -> bool:
        if not isinstance(resp, dict):
            return False
        cs = resp.get("commandStatus")
        if not isinstance(cs, dict):
            return False
        return bool(cs.get("accepted"))

    def _workflow_override_apply(
        self,
        selector: str | None,
        *,
        action: str,
        activity: str,
        enable: bool | None,
        function: Any,
        preview: bool,
    ) -> dict[str, Any]:
        if not activity:
            raise OperationFailure("unsupported", "activity name is required")
        owner, scope, machine = self._resolve_workflow_machine(selector, function)
        before = self._read_override(machine, activity)
        def restore_before() -> bool:
            try:
                response = machine.override_clear(activity) if before is None else machine.override_set(activity, before)
                return self._command_accepted(response) and self._read_override(machine, activity) == before
            except Exception:
                return False

        try:
            if action == "set":
                cmd_resp = machine.override_set(activity, bool(enable))
                expected: bool | None = bool(enable)
            elif action == "clear":
                cmd_resp = machine.override_clear(activity)
                expected = None
            else:
                raise OperationFailure("unsupported", f"Unknown override action: {action}")

            accepted = self._command_accepted(cmd_resp)
            after = self._read_override(machine, activity)
            verified = after == expected

        except Exception as exc:
            if not restore_before():
                raise RuntimeError("Workflow override failed and restoration could not be verified") from exc
            raise

        reverted = False
        if preview or not accepted or not verified:
            reverted = restore_before()

        if preview:
            status = "previewed" if (accepted and verified and reverted) else "verification_failed"
        elif accepted and verified:
            status = "verified"
        elif not accepted:
            status = "unsupported"
        else:
            status = "verification_failed"

        success = status in ("verified", "previewed")
        committed = status == "verified"

        payload: dict[str, Any] = {
            "preview": bool(preview),
            "success": success,
            "committed": committed,
            "status": status,
            "applied": action,
            "activity": activity,
            "scope": scope,
            "before": before,
            "after": after,
            "expected": expected,
            "verified": verified,
            "accepted": accepted,
            "reverted": reverted,
        }
        if action == "set":
            payload["enable"] = bool(enable)
        if isinstance(cmd_resp, dict):
            payload["command_status"] = cmd_resp.get("commandStatus")
        if scope == "function":
            payload["function"] = hex(int(getattr(owner, "start", 0)))
        return payload

    def _workflow_machine_command(
        self,
        selector: str | None,
        *,
        command: str,
        function: Any = None,
        advanced: bool | None = None,
        incremental: bool | None = None,
        activities: list[str] | None = None,
    ) -> dict[str, Any]:
        owner, scope, machine = self._resolve_workflow_machine(selector, function)

        if command == "enable":
            resp = machine.enable()
        elif command == "disable":
            resp = machine.disable()
        elif command == "step":
            resp = machine.step()
        elif command == "halt":
            resp = machine.halt()
        elif command == "reset":
            resp = machine.reset()
        elif command == "run":
            resp = machine.run(
                advanced=bool(advanced) if advanced is not None else True,
                incremental=bool(incremental) if incremental is not None else False,
            )
        elif command == "resume":
            resp = machine.resume(
                advanced=bool(advanced) if advanced is not None else True,
                incremental=bool(incremental) if incremental is not None else False,
            )
        elif command == "breakpoint_set":
            if not activities:
                raise OperationFailure(
                    "unsupported",
                    "breakpoint set requires at least one activity",
                )
            resp = machine.breakpoint_set(list(activities))
        elif command == "breakpoint_clear":
            if not activities:
                raise OperationFailure(
                    "unsupported",
                    "breakpoint clear requires at least one activity",
                )
            resp = machine.breakpoint_delete(list(activities))
        elif command == "breakpoint_list":
            resp = machine.breakpoint_query()
        else:
            raise OperationFailure("unsupported", f"unknown machine command: {command}")

        accepted = self._command_accepted(resp)
        machine_state = None
        response_payload = None
        if isinstance(resp, dict):
            ms = resp.get("machineState")
            if isinstance(ms, dict):
                machine_state = dict(ms)
            response_payload = resp.get("response")

        payload: dict[str, Any] = {
            "scope": scope,
            "command": command,
            "accepted": accepted,
            "machine_state": machine_state,
            "response": response_payload,
        }
        if scope == "function":
            payload["function"] = hex(int(getattr(owner, "start", 0)))
        if command == "breakpoint_list":
            bp_activities: list[str] = []
            if isinstance(response_payload, dict):
                items = response_payload.get("activities")
                if isinstance(items, list):
                    bp_activities = [str(item) for item in items]
            payload["activities"] = bp_activities
        if command in ("breakpoint_set", "breakpoint_clear"):
            payload["requested_activities"] = list(activities or [])
        if command in ("run", "resume"):
            payload["options"] = {
                "advanced": bool(advanced) if advanced is not None else True,
                "incremental": bool(incremental) if incremental is not None else False,
            }
        return payload

    def _workflow_machine_call(
        self,
        selector: str | None,
        verb: str,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        bv = self._resolve_view(selector)
        function = params.get("function")
        scope = "binaryview" if function is None else "function"
        owner = bv if function is None else self._find_function(bv, function)
        wf = getattr(owner, "workflow", None)
        envelope: dict[str, Any] = {"available": False, "scope": scope, verb: None}
        if wf is None:
            envelope["reason"] = "no workflow bound"
            return envelope
        try:
            machine = wf.machine
        except AttributeError:
            envelope["reason"] = "machine not enabled"
            return envelope
        if machine is None:
            envelope["reason"] = "machine not enabled"
            return envelope
        if verb == "status":
            result = machine.status()
        elif verb == "dump":
            result = machine.dump()
        elif verb == "overrides":
            activity = params.get("activity") or ""
            result = machine.override_query(activity)
        else:
            raise RuntimeError(f"Unknown machine verb: {verb}")
        envelope.update({"available": True, verb: result})
        if scope == "function":
            envelope["function"] = hex(int(getattr(owner, "start", 0)))
        return envelope

    def _resolve_view(self, selector: str | None):
        return self.targets.resolve(selector)

    def _address_resolver(self, bv) -> AddressResolver:
        targets = getattr(self, "targets", None)
        key = targets.target_id_for(bv) if targets is not None else None
        spaces = getattr(self, "_address_spaces", {}).get(key, {})
        return AddressResolver(bv, spaces)

    def _address(self, bv, value, *, endpoint=False) -> int:
        return self._address_resolver(bv).resolve(value, endpoint=endpoint)

    def _address_context(self, bv) -> dict:
        context = self._address_resolver(bv).context()
        context["target_id"] = self.targets.target_id_for(bv)
        context["filename"] = str(getattr(getattr(bv, "file", None), "filename", ""))
        return context

    def _address_operation(self, op, params, target):
        bv = self._resolve_view(target)
        if op in {"address_map_add", "address_map_import"}:
            key = self.targets.target_id_for(bv)
            self._address_spaces.setdefault(key, {})
        resolver = self._address_resolver(bv)
        if op == "address_context":
            return {**self._address_context(bv), "segments": [
                {key: hex(value) for key, value in row.items()} for row in resolver.segments()]}
        if op == "address_resolve":
            rows = [resolver.describe(value) for value in params["addresses"]]
            for row in rows:
                row.pop("address_context")
            return {"address_context": self._address_context(bv),
                    "addresses": rows}
        if op == "address_verify":
            location = resolver.describe(params["address"])
            location.pop("address_context")
            data = bytes.fromhex(params["bytes"])
            if not data or len(data) > 65536:
                raise AddressError("Verification requires 1..65536 observed bytes")
            address = int(location["bn_va"], 16)
            resolver.require_mapped(address, len(data))
            observed = bv.read(address, len(data))
            return {"location": location, "address_context": self._address_context(bv), "matches": data == observed, "success": data == observed, "external_bytes": data.hex(),
                    "bn_bytes": observed.hex(), "meaning": "Byte comparison only; runtime relocations and patches may differ"}
        if op == "address_map_add":
            return resolver.add_slide(params["name"], params["base"], params["source"], params["size"], params.get("bn_base"))
        if op == "address_map_import":
            manifest = params["manifest"]
            if params.get("kind") == "frida-module":
                if params.get("bn_base") is None and resolver.base != bv.start:
                    raise AddressError("BN image_base differs from view.start; specify --bn-base for the BN address corresponding to Frida Module.base")
                return resolver.add_slide(params["name"], manifest["base"], params["source"], manifest["size"], params.get("bn_base"))
            if params.get("bn_base") is not None:
                raise AddressError("--bn-base applies to frida-module imports; region manifests already specify exact bn_start addresses")
            return resolver.add_space(params["name"], manifest["regions"], params["source"], layout_id=manifest.get("layout_id"))
        if op == "address_map_list":
            return {"address_context": self._address_context(bv), "maps": list(resolver.spaces)}
        if op == "address_map_export":
            return resolver.export_space(params["name"])
        if op == "address_map_remove":
            if params["name"] not in resolver.spaces:
                raise AddressError(f"Unknown address map {params['name']!r}")
            del resolver.spaces[params["name"]]
            return {"removed": params["name"]}
        raise AddressError(f"Unknown address operation: {op}")

    def _inspect(self, selector, identifier):
        bv = self._resolve_view(selector)
        resolver = self._address_resolver(bv)
        try:
            address = resolver.resolve(identifier)
        except (ValueError, TypeError):
            address = int(self._find_function(bv, identifier).start)
        location = resolver.describe(address)
        location.pop("address_context")
        functions = self._functions_containing(bv, address)
        at = bv.get_function_at(address)
        if at is not None and all(int(fn.start) != address for fn in functions):
            functions.insert(0, at)
        return {
            "location": location, "address_context": self._address_context(bv),
            "functions": [{"name": fn.name, "address": hex(fn.start)} for fn in functions],
            "disassembly": bv.get_disassembly(address),
            "bytes_hex": bv.read(address, 16).hex(),
            "xrefs": self._xrefs_to_address(bv, address),
            "analysis_state": str(getattr(getattr(bv, "analysis_info", None), "state", "unknown")),
            "decompile": self._decompile(selector, functions[0].start) if len(functions) == 1 else None,
        }

    def _find_function(self, bv, identifier):
        try:
            addr = self._address(bv, identifier)
            fn = bv.get_function_at(addr)
            if fn is not None:
                return fn
            # Address parsed but no function starts there — try containing
            containing = self._functions_containing(bv, addr)
            if len(containing) == 1:
                return containing[0]
            if len(containing) > 1:
                hints = ", ".join(f"{fn.name} @ {hex(fn.start)}" for fn in containing[:5])
                raise RuntimeError(
                    f"No function starts at {hex(addr)}, but {len(containing)} functions contain it: {hints}. "
                    f"Use one of their start addresses instead."
                )
            # No function contains this address either
            raise RuntimeError(self._function_not_found_hint(bv, identifier, addr))
        except RuntimeError:
            raise
        except Exception:
            pass

        text = str(identifier)
        exact = self._find_functions_by_name(bv, text, case_sensitive=True)
        if len(exact) == 1:
            return exact[0]
        if len(exact) > 1:
            raise RuntimeError(f"Ambiguous function identifier: {identifier}")

        folded = self._find_functions_by_name(bv, text, case_sensitive=False)
        if len(folded) == 1:
            return folded[0]
        if len(folded) > 1:
            raise RuntimeError(f"Ambiguous function identifier: {identifier}")

        symbol = bv.get_symbol_by_raw_name(text)
        if symbol is not None:
            fn = bv.get_function_at(symbol.address)
            if fn is not None:
                return fn
        raise RuntimeError(f"Function not found: {identifier}")

    def _function_not_found_hint(self, bv, identifier, addr: int | None = None) -> str:
        """Build an error message with nearby function suggestions."""
        msg = f"Function not found: {identifier}"
        if addr is None:
            return msg
        # Find nearest function before and after this address
        nearest: list[str] = []
        prev_fn = None
        for fn in sorted(bv.functions, key=lambda f: f.start):
            if fn.start > addr:
                nearest.append(f"{fn.name} @ {hex(fn.start)} (next)")
                break
            prev_fn = fn
        if prev_fn is not None:
            nearest.insert(0, f"{prev_fn.name} @ {hex(prev_fn.start)} (prev)")
        if nearest:
            msg += f". Nearest functions: {', '.join(nearest)}"
        return msg

    def _find_functions_by_name(self, bv, text: str, *, case_sensitive: bool) -> list[Any]:
        matches = []
        needle = text if case_sensitive else text.lower()
        seen: set[int] = set()
        for fn in list(bv.functions):
            names = [str(fn.name), str(getattr(fn, "raw_name", fn.name))]
            haystacks = names if case_sensitive else [name.lower() for name in names]
            if needle not in haystacks:
                continue
            marker = int(fn.start)
            if marker in seen:
                continue
            seen.add(marker)
            matches.append(fn)
        return matches

    def _resolve_scope_functions(self, bv, identifiers: list[Any]) -> list[tuple[str, Any]]:
        if not identifiers:
            raise OperationFailure("invalid_scope", "callsites requires at least one scoped function")

        resolved = []
        seen: set[int] = set()
        for identifier in identifiers:
            fn = self._find_function(bv, identifier)
            marker = int(fn.start)
            if marker in seen:
                continue
            seen.add(marker)
            resolved.append((str(identifier), fn))
        return resolved

    def _find_symbols_by_name(self, bv, text: str, *, case_sensitive: bool) -> list[Any]:
        matches = []
        seen: set[tuple[int, str]] = set()

        if case_sensitive:
            candidates = list(bv.get_symbols_by_name(text))
            raw_match = bv.get_symbol_by_raw_name(text)
            if raw_match is not None:
                candidates.append(raw_match)
        else:
            folded = text.lower()
            candidates = []
            for symbol in list(bv.get_symbols()):
                names = [str(getattr(symbol, "name", "")), str(getattr(symbol, "raw_name", ""))]
                if folded in {name.lower() for name in names if name}:
                    candidates.append(symbol)

        for symbol in candidates:
            marker = (int(symbol.address), str(symbol.type))
            if marker in seen:
                continue
            seen.add(marker)
            matches.append(symbol)
        return matches

    def _resolve_rename_target(self, bv, identifier: Any, kind: str) -> dict[str, Any]:
        requested = {
            "kind": kind,
            "identifier": str(identifier),
        }

        try:
            address = self._address(bv, identifier)
        except AddressError:
            raise
        except (ValueError, TypeError):
            address = None

        if address is not None:
            fn = bv.get_function_at(address)
            symbol = bv.get_symbol_at(address)
            if kind == "function":
                if fn is None:
                    raise OperationFailure("unsupported", f"Function not found: {identifier}", requested=requested)
                return {
                    "kind": "function",
                    "address": int(fn.start),
                    "before_name": str(fn.name),
                }
            if kind == "data":
                return {
                    "kind": "data",
                    "address": int(address),
                    "before_name": str(symbol.name) if symbol is not None else None,
                }
            if fn is not None:
                return {
                    "kind": "function",
                    "address": int(fn.start),
                    "before_name": str(fn.name),
                }
            return {
                "kind": "data",
                "address": int(address),
                "before_name": str(symbol.name) if symbol is not None else None,
            }

        if kind in {"auto", "function"}:
            exact_functions = self._find_functions_by_name(bv, str(identifier), case_sensitive=True)
            if len(exact_functions) == 1:
                fn = exact_functions[0]
                return {
                    "kind": "function",
                    "address": int(fn.start),
                    "before_name": str(fn.name),
                }
            if len(exact_functions) > 1:
                raise OperationFailure("unsupported", f"Ambiguous function identifier: {identifier}", requested=requested)

            folded_functions = self._find_functions_by_name(bv, str(identifier), case_sensitive=False)
            if len(folded_functions) == 1:
                fn = folded_functions[0]
                return {
                    "kind": "function",
                    "address": int(fn.start),
                    "before_name": str(fn.name),
                }
            if len(folded_functions) > 1:
                raise OperationFailure("unsupported", f"Ambiguous function identifier: {identifier}", requested=requested)

        if kind == "function":
            raise OperationFailure("unsupported", f"Function not found: {identifier}", requested=requested)

        exact_symbols = [
            symbol
            for symbol in self._find_symbols_by_name(bv, str(identifier), case_sensitive=True)
            if symbol.type != bn.SymbolType.FunctionSymbol
        ]
        if len(exact_symbols) == 1:
            symbol = exact_symbols[0]
            return {
                "kind": "data",
                "address": int(symbol.address),
                "before_name": str(symbol.name),
            }
        if len(exact_symbols) > 1:
            raise OperationFailure("unsupported", f"Ambiguous symbol identifier: {identifier}", requested=requested)

        folded_symbols = [
            symbol
            for symbol in self._find_symbols_by_name(bv, str(identifier), case_sensitive=False)
            if symbol.type != bn.SymbolType.FunctionSymbol
        ]
        if len(folded_symbols) == 1:
            symbol = folded_symbols[0]
            return {
                "kind": "data",
                "address": int(symbol.address),
                "before_name": str(symbol.name),
            }
        if len(folded_symbols) > 1:
            raise OperationFailure("unsupported", f"Ambiguous symbol identifier: {identifier}", requested=requested)

        raise OperationFailure("unsupported", f"Symbol not found: {identifier}", requested=requested)

    def _functions_containing(self, bv, address: int):
        try:
            return list(bv.get_functions_containing(address))
        except Exception:
            fn = bv.get_function_at(address)
            return [fn] if fn is not None else []

    def _find_variable_by_storage(self, func, storage: int, *, is_parameter: bool | None = None):
        collections = []
        if is_parameter is True:
            collections = [(func.parameter_vars, True)]
        elif is_parameter is False:
            collections = [(func.stack_layout, False)]
        else:
            collections = [(func.parameter_vars, True), (func.stack_layout, False)]

        for collection, marker in collections:
            for var in list(collection):
                if int(var.storage) == int(storage):
                    return var, marker
        raise RuntimeError(f"Variable not found at storage {storage}")

    def _variable_source_name(self, var) -> str:
        source_type = getattr(var, "source_type", None)
        if source_type is None:
            return "unknown"
        return str(getattr(source_type, "name", source_type))

    def _variable_identifier(self, var) -> int | None:
        try:
            return int(getattr(var, "identifier"))
        except Exception:
            return None

    def _local_id(self, func, var, *, is_parameter: bool) -> str:
        role = "param" if is_parameter else "local"
        storage = int(getattr(var, "storage", 0))
        index = int(getattr(var, "index", 0))
        identifier = self._variable_identifier(var)
        source_name = self._variable_source_name(var)
        return ":".join(
            [
                hex(int(func.start)),
                role,
                source_name,
                str(storage),
                str(index),
                str(identifier if identifier is not None else "none"),
            ]
        )

    def _variable_entry(self, func, var, *, is_parameter: bool) -> dict[str, Any]:
        return {
            "name": str(var.name),
            "storage": int(var.storage),
            "type": str(var.type),
            "is_parameter": is_parameter,
            "index": int(getattr(var, "index", 0)),
            "identifier": self._variable_identifier(var),
            "source_type": self._variable_source_name(var),
            "local_id": self._local_id(func, var, is_parameter=is_parameter),
        }

    def _variable_marker(self, var) -> tuple[int | None, int]:
        return (self._variable_identifier(var), int(getattr(var, "storage", 0)))

    def _iter_canonical_variables(self, func):
        seen: set[tuple[int | None, int]] = set()

        for var in list(func.parameter_vars):
            marker = self._variable_marker(var)
            if marker in seen:
                continue
            seen.add(marker)
            yield var, True

        for var in list(func.stack_layout):
            marker = self._variable_marker(var)
            if marker in seen:
                continue
            seen.add(marker)
            yield var, False

    def _il_status(self, bv, func) -> dict[str, Any] | None:
        """Check why IL might be unavailable. Returns None if IL should be available."""
        # Check if BV is still analyzing
        progress = getattr(bv, "analysis_progress", None)
        if progress is not None:
            state_name = progress.state.name if hasattr(progress, "state") and hasattr(progress.state, "name") else str(progress)
            if state_name not in ("Idle", "IdleState"):
                return {
                    "status": "analyzing",
                    "reason": f"Binary is currently being analyzed (state: {state_name})",
                    "hint": "Wait for analysis to complete, or use `bn analysis status` to check progress.",
                }
        # Check if function analysis was skipped
        if hasattr(func, "analysis_skipped") and func.analysis_skipped:
            reason_enum = getattr(func, "analysis_skip_reason", None)
            reason_name = reason_enum.name if reason_enum is not None else "unknown"
            reason_map = {
                "ExceedFunctionSizeSkipReason": "Function exceeds maximum size limit",
                "ExceedFunctionAnalysisTimeSkipReason": "Function analysis exceeded time limit",
                "ExceedFunctionUpdateCountSkipReason": "Function exceeded update count limit",
                "AlwaysSkipReason": "Function is set to always skip analysis",
                "NewAutoFunctionAnalysisSuppressedReason": "Auto analysis suppressed",
                "BasicAnalysisSkipReason": "Basic analysis mode — advanced IL not generated",
                "IntermediateAnalysisSkipReason": "Intermediate analysis mode — full IL not generated",
                "AnalysisPipelineSuspendedReason": "Analysis pipeline suspended",
            }
            human_reason = reason_map.get(reason_name, f"Analysis skipped ({reason_name})")
            return {
                "status": "analysis_skipped",
                "skip_reason": reason_name,
                "reason": human_reason,
                "hint": "Use `bn function force-analysis <function>` to force full analysis (may take a long time for large functions).",
            }
        # Check too_large flag (may not have been skipped yet but is flagged)
        if hasattr(func, "too_large") and func.too_large:
            return {
                "status": "too_large",
                "reason": "Function is flagged as too large for default analysis",
                "hint": "Use `bn function force-analysis <function>` to force full analysis.",
            }
        return None

    def _function_text(self, bv, func, *, view: str = "hlil", ssa: bool = False) -> str | dict[str, Any]:
        """Return IL text as string, or a dict with il_unavailable info if IL cannot be obtained."""
        il_name = {"hlil": "hlil", "mlil": "mlil", "llil": "llil"}.get(view, "hlil")
        try:
            il = getattr(func, il_name)
            if il is None:
                raise AttributeError(f"{il_name} is None")
            if ssa and hasattr(il, "ssa_form") and il.ssa_form is not None:
                il = il.ssa_form
            if il_name == "hlil" and not ssa:
                # Basic-block instructions omit nested bodies; render the whole HLIL AST instead.
                root = il.root
                items = root.lines if root is not None else ()
            else:
                items = il.instructions
            lines = []
            for item in items:
                self._check_job_cancelled()
                address = getattr(item, "address", func.start)
                prefix = f"{int(address):08x}" if address is not None else " " * 8
                lines.append(f"{prefix}        {item}")
            if lines:
                return "\n".join(lines)
            # IL object exists but produced no lines — might still be generating
        except JobCancelled:
            raise
        except Exception:
            pass
        # IL not available — figure out why
        status = self._il_status(bv, func)
        if status is not None:
            return {"il_unavailable": True, **status}
        # Fallback: IL attr exists but empty/broken without a clear reason
        return {"il_unavailable": True, "status": "unknown", "reason": f"Could not obtain {il_name} for this function", "hint": "Try `bn function force-analysis <function>` or `bn refresh`."}

    def _instruction_length(self, bv, address: int) -> int:
        arch = getattr(bv, "arch", None)
        try:
            max_length = int(getattr(arch, "max_instr_length", 16) or 16)
        except Exception:
            max_length = 16

        if arch is not None and hasattr(arch, "get_instruction_info"):
            try:
                data = bv.read(address, max_length)
                info = arch.get_instruction_info(data, address)
                length = int(getattr(info, "length", 0))
                if length > 0:
                    return length
            except Exception:
                pass

        try:
            length = int(bv.get_instruction_length(address))
            if length > 0:
                return length
        except Exception:
            pass
        return 1

    def _disasm_entry(self, bv, address: int) -> dict[str, Any]:
        return {
            "address": hex(int(address)),
            "text": bv.get_disassembly(address) or "",
        }

    def _structured_disasm_entries(self, bv, func) -> list[dict[str, Any]]:
        entries = []
        for block in list(func.basic_blocks):
            addr = int(block.start)
            end = int(block.end)
            while addr < end:
                entry = self._disasm_entry(bv, addr)
                if entry["text"]:
                    entry["_address_int"] = addr
                    entries.append(entry)
                addr += max(1, self._instruction_length(bv, addr))
        entries.sort(key=lambda item: int(item["_address_int"]))
        return entries

    def _disasm_text(self, bv, func) -> str:
        lines = []
        for block in list(func.basic_blocks):
            addr = block.start
            while addr < block.end:
                length = max(1, self._instruction_length(bv, int(addr)))
                disasm = bv.get_disassembly(addr) or ""
                raw = bv.read(addr, length)
                hex_bytes = raw.hex(" ") if raw else ""
                lines.append(f"{addr:08x}  {hex_bytes:<16} {disasm}")
                addr += length
        return "\n".join(lines)

    def _sort_variable_entries(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(
            items,
            key=lambda item: (
                0 if item.get("is_parameter") else 1,
                str(item.get("source_type", "")),
                int(item.get("storage", 0)),
                int(item.get("identifier") or 0),
                str(item.get("name", "")),
            ),
        )

    def _list_locals(self, func) -> list[dict[str, Any]]:
        variables = [
            self._variable_entry(func, var, is_parameter=is_parameter)
            for var, is_parameter in self._iter_canonical_variables(func)
        ]
        return self._sort_variable_entries(variables)

    def _find_variables_by_name(self, func, name: str) -> list[tuple[Any, bool]]:
        matches = []
        for var, is_parameter in self._iter_canonical_variables(func):
            if str(var.name) == name:
                matches.append((var, is_parameter))
        return matches

    def _find_variable_selector(self, func, selector: str) -> tuple[Any, bool]:
        locals_by_id: dict[str, tuple[Any, bool]] = {}
        for var, is_parameter in self._iter_canonical_variables(func):
            locals_by_id[self._local_id(func, var, is_parameter=is_parameter)] = (var, is_parameter)
        if selector in locals_by_id:
            return locals_by_id[selector]

        matches = self._find_variables_by_name(func, selector)
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise RuntimeError(f"Ambiguous variable selector: {selector}")
        raise RuntimeError(f"Variable not found: {selector}")

    def _function_size(self, func) -> int | None:
        try:
            total = getattr(func, "total_bytes", None)
            if total is not None:
                return int(total)
        except Exception:
            pass
        try:
            end = max(int(block.end) for block in list(func.basic_blocks))
            return end - int(func.start)
        except Exception:
            return None

    def _function_metadata(self, func) -> dict[str, Any]:
        func_type = getattr(func, "type", None)
        calling_convention = getattr(func, "calling_convention", None)
        if calling_convention is None and func_type is not None:
            calling_convention = getattr(func_type, "calling_convention", None)
        return_type = getattr(func, "return_type", None)
        if return_type is None and func_type is not None:
            return_type = getattr(func_type, "return_value", None)
        return {
            "prototype": str(func_type),
            "return_type": str(return_type) if return_type is not None else None,
            "calling_convention": str(calling_convention) if calling_convention is not None else None,
            "size": self._function_size(func),
        }

    def _comment_map(self, bv, func) -> dict[str, str]:
        comments: dict[str, str] = {}
        for block in list(func.basic_blocks):
            addr = block.start
            while addr < block.end:
                text = bv.get_comment_at(addr)
                if text:
                    comments[hex(addr)] = text
                addr += max(1, self._instruction_length(bv, int(addr)))
        return comments

    def _il_op_name(self, item) -> str:
        operation = getattr(item, "operation", None)
        name = getattr(operation, "name", None)
        if name:
            return str(name)
        return str(operation)

    def _llil_constant_value(self, expr) -> int | None:
        if expr is None:
            return None
        if self._il_op_name(expr) not in {"LLIL_CONST", "LLIL_CONST_PTR"}:
            return None
        constant = getattr(expr, "constant", None)
        if constant is not None:
            return int(constant)
        value = getattr(expr, "value", None)
        if value is None:
            return None
        nested_value = getattr(value, "value", None)
        if nested_value is not None:
            return int(nested_value)
        try:
            return int(value)
        except Exception:
            return None

    def _coerce_il_list(self, value: Any) -> list[Any]:
        if value is None:
            return []
        if isinstance(value, (list, tuple, set)):
            return list(value)
        return [value]

    def _iter_llil_instructions(self, func) -> list[Any]:
        il = getattr(func, "low_level_il", None)
        if il is None:
            il = getattr(func, "llil", None)
        if il is None:
            return []

        instructions = []
        try:
            blocks = list(il)
        except Exception:
            blocks = list(getattr(il, "basic_blocks", []) or [])
        for block in blocks:
            try:
                instructions.extend(list(block))
            except Exception:
                continue
        instructions.sort(key=lambda item: int(getattr(item, "address", 0)))
        return instructions

    def _hlil_candidates_for_llil(self, insn) -> list[Any]:
        candidates = []
        seen: set[tuple[str, int]] = set()

        def add(candidate: Any) -> None:
            if candidate is None:
                return
            expr_index = getattr(candidate, "expr_index", None)
            marker = (type(candidate).__name__, int(expr_index) if expr_index is not None else id(candidate))
            if marker in seen:
                return
            seen.add(marker)
            candidates.append(candidate)

        for attr in ("hlils", "hlil"):
            for candidate in self._coerce_il_list(getattr(insn, attr, None)):
                add(candidate)

        mapped_mlil = getattr(insn, "mapped_medium_level_il", None)
        if mapped_mlil is not None:
            for attr in ("hlils", "hlil"):
                for candidate in self._coerce_il_list(getattr(mapped_mlil, attr, None)):
                    add(candidate)

        for mlil in self._coerce_il_list(getattr(insn, "mlils", None)):
            for attr in ("hlils", "hlil"):
                for candidate in self._coerce_il_list(getattr(mlil, attr, None)):
                    add(candidate)

        return candidates

    def _il_parent(self, instruction) -> Any | None:
        for attr in ("parent", "parent_instruction"):
            parent = getattr(instruction, attr, None)
            if parent is not None and parent is not instruction:
                return parent
        return None

    def _hlil_marker(self, instruction) -> tuple[str, int]:
        expr_index = getattr(instruction, "expr_index", None)
        return (
            type(instruction).__name__,
            int(expr_index) if expr_index is not None else id(instruction),
        )

    def _hlil_type_name(self, instruction) -> str:
        return type(instruction).__name__

    def _hlil_text_is_local(self, text: str) -> bool:
        stripped = text.strip()
        if not stripped:
            return False
        if len(stripped) > 240:
            return False
        if stripped.count("\n") > 1:
            return False
        return True

    def _hlil_condition_is_meaningful(self, text: str) -> bool:
        stripped = text.strip()
        if not stripped:
            return False
        if "\n" in stripped:
            return False
        if re.search(r"\bcond:\d", stripped):
            return False
        return True

    def _is_hlil_assignment_like(self, instruction) -> bool:
        return self._hlil_type_name(instruction) in {
            "HighLevelILAssign",
            "HighLevelILVarAssign",
            "HighLevelILVarInit",
            "HighLevelILAssignMem",
            "HighLevelILAssignUnpack",
            "HighLevelILVarDeclare",
        }

    def _is_hlil_control_flow(self, instruction) -> bool:
        return self._hlil_type_name(instruction) in {
            "HighLevelILIf",
            "HighLevelILWhile",
            "HighLevelILDoWhile",
            "HighLevelILFor",
            "HighLevelILSwitch",
            "HighLevelILCase",
        }

    def _is_hlil_hard_boundary(self, instruction) -> bool:
        if self._is_hlil_assignment_like(instruction) or self._is_hlil_control_flow(instruction):
            return True
        return self._hlil_type_name(instruction) in {
            "HighLevelILRet",
            "HighLevelILBlock",
            "HighLevelILCall",
            "HighLevelILTailcall",
        }

    def _is_hlil_trivial_wrapper(self, instruction) -> bool:
        return self._hlil_type_name(instruction) in {
            "HighLevelILCall",
            "HighLevelILSx",
            "HighLevelILZx",
            "HighLevelILLowPart",
            "HighLevelILIntToFloat",
            "HighLevelILFloatToInt",
            "HighLevelILBoolToInt",
            "HighLevelILFloatConv",
            "HighLevelILAddressOf",
            "HighLevelILAddressOfField",
            "HighLevelILArrayIndex",
        }

    def _hlil_call_roots(self, insn) -> list[Any]:
        roots = []
        seen: set[tuple[str, int]] = set()
        for candidate in self._hlil_candidates_for_llil(insn):
            current = candidate
            while current is not None:
                if self._hlil_type_name(current) == "HighLevelILCall":
                    marker = self._hlil_marker(current)
                    if marker not in seen:
                        seen.add(marker)
                        roots.append(current)
                    break
                current = self._il_parent(current)
        return roots

    def _select_local_hlil_node(self, insn) -> Any | None:
        roots = self._hlil_call_roots(insn)
        if not roots:
            return None

        for root in roots:
            current = root
            best_expression = None
            assignment_candidate = None
            seen: set[tuple[str, int]] = set()
            while current is not None:
                marker = self._hlil_marker(current)
                if marker in seen:
                    break
                seen.add(marker)

                parent = self._il_parent(current)
                if parent is None:
                    break
                if self._is_hlil_control_flow(parent):
                    break
                if self._is_hlil_assignment_like(parent):
                    text = str(parent)
                    if self._hlil_text_is_local(text):
                        assignment_candidate = parent
                    break
                if self._is_hlil_hard_boundary(parent):
                    break

                parent_text = str(parent)
                if not self._is_hlil_trivial_wrapper(parent) and self._hlil_text_is_local(parent_text):
                    best_expression = parent
                current = parent

            if best_expression is not None:
                return best_expression
            if assignment_candidate is not None:
                return assignment_candidate
        return None

    def _hlil_statement_text(self, insn) -> str | None:
        node = self._select_local_hlil_node(insn)
        if node is None:
            return None
        text = str(node)
        return text if self._hlil_text_is_local(text) else None

    def _hlil_pre_branch_condition(self, insn) -> str | None:
        current = self._select_local_hlil_node(insn)
        if current is None:
            return None

        seen: set[tuple[str, int]] = set()
        while current is not None:
            marker = self._hlil_marker(current)
            if marker in seen:
                break
            seen.add(marker)
            parent = self._il_parent(current)
            if parent is None:
                break
            if self._is_hlil_control_flow(parent):
                condition = getattr(parent, "condition", None)
                if condition is None:
                    return None
                text = str(condition).strip()
                return text if self._hlil_condition_is_meaningful(text) else None
            current = parent
        return None

    def _callsites_within_function(self, bv, callee, func, *, context: int) -> list[dict[str, Any]]:
        disasm_entries = self._structured_disasm_entries(bv, func)
        index_by_addr = {
            int(item["_address_int"]): index for index, item in enumerate(disasm_entries)
        }
        callee_address = int(callee.start)
        rows = []
        for insn in self._iter_llil_instructions(func):
            op_name = self._il_op_name(insn)
            if op_name not in {"LLIL_CALL", "LLIL_CALL_STACK_ADJUST"}:
                continue
            dest_value = self._llil_constant_value(getattr(insn, "dest", None))
            if dest_value != callee_address:
                continue

            call_addr = int(getattr(insn, "address", 0))
            instruction_length = self._instruction_length(bv, call_addr)
            caller_static = call_addr + instruction_length
            disasm_index = index_by_addr.get(call_addr)
            if disasm_index is None:
                continue

            previous = [
                {
                    "address": item["address"],
                    "text": item["text"],
                }
                for item in disasm_entries[max(0, disasm_index - context) : disasm_index]
            ]
            next_instructions = [
                {
                    "address": item["address"],
                    "text": item["text"],
                }
                for item in disasm_entries[disasm_index + 1 : disasm_index + 1 + context]
            ]
            call_instruction = {
                "address": disasm_entries[disasm_index]["address"],
                "text": disasm_entries[disasm_index]["text"],
            }
            rows.append(
                {
                    "callee": {
                        "name": str(callee.name),
                        "address": hex(callee_address),
                    },
                    "containing_function": {
                        "name": str(func.name),
                        "address": hex(int(func.start)),
                    },
                    "call_addr": hex(call_addr),
                    "instruction_length": instruction_length,
                    "caller_static": hex(caller_static),
                    "call_instruction": call_instruction,
                    "previous_instructions": previous,
                    "next_instructions": next_instructions,
                    "hlil_statement": self._hlil_statement_text(insn),
                    "pre_branch_condition": self._hlil_pre_branch_condition(insn),
                }
            )
        rows.sort(key=lambda item: int(item["call_addr"], 16))
        return rows

    def _callsites(
        self,
        selector: str | None,
        callee_identifier: str,
        *,
        within_identifiers: list[Any],
        context: int = 3,
    ) -> list[dict[str, Any]]:
        if context < 0:
            raise OperationFailure("invalid_context", f"Invalid callsite context size: {context}")

        bv = self._resolve_view(selector)
        callee = self._find_function(bv, callee_identifier)
        scope_functions = self._resolve_scope_functions(bv, within_identifiers)

        rows = []
        for within_query, func in scope_functions:
            function_rows = self._callsites_within_function(bv, callee, func, context=context)
            for call_index, row in enumerate(function_rows):
                row["call_index"] = call_index
                row["within_query"] = str(within_query)
            rows.extend(function_rows)
        return rows

    def _xrefs_to_address(self, bv, address: int) -> dict[str, Any]:
        code_refs = []
        data_refs = []
        for ref in sorted(list(bv.get_code_refs(address)), key=lambda item: int(item.address)):
            code_refs.append(
                {
                    "function": ref.function.name if getattr(ref, "function", None) else None,
                    "address": hex(ref.address),
                }
            )
        for ref_addr in sorted(list(bv.get_data_refs(address))):
            functions = self._functions_containing(bv, ref_addr)
            data_refs.append(
                {
                    "function": functions[0].name if functions else None,
                    "address": hex(ref_addr),
                }
            )
        return {"address": hex(address), "code_refs": code_refs, "data_refs": data_refs}

    def _parse_function_address_bounds(
        self,
        min_address: Any = None,
        max_address: Any = None,
        bv=None,
    ) -> tuple[int | None, int | None]:
        lower = self._address(bv, min_address) if min_address not in (None, "") else None
        upper = self._address(bv, max_address) if max_address not in (None, "") else None
        if lower is not None and upper is not None and lower > upper:
            raise OperationFailure(
                "invalid_address_range",
                f"Invalid function address range: {hex(lower)} is greater than {hex(upper)}",
            )
        return lower, upper

    def _filtered_functions(
        self,
        bv,
        *,
        min_address: Any = None,
        max_address: Any = None,
    ) -> list[Any]:
        lower, upper = self._parse_function_address_bounds(min_address, max_address, bv=bv)
        functions = []
        for fn in list(bv.functions):
            self._check_job_cancelled()
            address = int(fn.start)
            if lower is not None and address < lower:
                continue
            if upper is not None and address > upper:
                continue
            functions.append(fn)
        functions.sort(key=lambda fn: (int(fn.start), fn.name))
        return functions

    def _list_functions(
        self,
        selector: str | None,
        *,
        min_address: Any = None,
        max_address: Any = None,
        offset: int = 0,
        limit: int | None = None,
    ):
        bv = self._resolve_view(selector)
        if offset < 0 or (limit is not None and limit < 0):
            raise ValueError("Pagination values must be nonnegative")
        functions = self._filtered_functions(bv, min_address=min_address, max_address=max_address)
        functions = functions[offset:None if limit is None else offset + limit]
        items = [
            {"name": fn.name, "address": hex(fn.start), "raw_name": getattr(fn, "raw_name", fn.name)}
            for fn in functions
        ]
        return items

    def _search_functions(
        self,
        selector: str | None,
        query: str,
        *,
        regex: bool = False,
        min_address: Any = None,
        max_address: Any = None,
        offset: int = 0,
        limit: int | None = None,
    ):
        bv = self._resolve_view(selector)
        if offset < 0 or (limit is not None and limit < 0):
            raise ValueError("Pagination values must be nonnegative")
        items = []
        if regex:
            try:
                pattern = re.compile(query, re.IGNORECASE)
            except re.error as exc:
                raise OperationFailure("invalid_regex", f"Invalid function regex: {exc}") from exc

            def matches(name: str) -> bool:
                return bool(pattern.search(name))

        else:
            needle = query.lower()

            def matches(name: str) -> bool:
                return needle in name.lower()

        for fn in self._filtered_functions(bv, min_address=min_address, max_address=max_address):
            self._check_job_cancelled()
            if matches(fn.name):
                if offset:
                    offset -= 1
                    continue
                if limit is not None and len(items) >= limit:
                    break
                items.append({"name": fn.name, "address": hex(fn.start), "raw_name": getattr(fn, "raw_name", fn.name)})
        return items

    def _decompile(self, selector: str | None, identifier):
        bv = self._resolve_view(selector)
        func = self._find_function(bv, identifier)
        text = self._function_text(bv, func, view="hlil")
        if isinstance(text, dict) and text.get("il_unavailable"):
            return {
                "function": {"name": func.name, "address": hex(func.start)},
                "text": None,
                "il_unavailable": True,
                **{k: v for k, v in text.items() if k != "il_unavailable"},
            }
        warnings = self._render_warnings(text)
        return {
            "function": {"name": func.name, "address": hex(func.start)},
            "text": text,
            "warnings": warnings,
        }

    def _function_info(self, selector: str | None, identifier):
        bv = self._resolve_view(selector)
        func = self._find_function(bv, identifier)
        metadata = self._function_metadata(func)
        variables = self._list_locals(func)
        parameters = [item for item in variables if item["is_parameter"]]
        locals_only = [item for item in variables if not item["is_parameter"]]
        return {
            "function": {
                "name": func.name,
                "address": hex(func.start),
                "raw_name": getattr(func, "raw_name", func.name),
            },
            **metadata,
            "parameters": parameters,
            "locals": locals_only,
        }

    def _get_prototype(self, selector: str | None, identifier):
        bv = self._resolve_view(selector)
        func = self._find_function(bv, identifier)
        return {
            "function": {
                "name": func.name,
                "address": hex(func.start),
                "raw_name": getattr(func, "raw_name", func.name),
            },
            **self._function_metadata(func),
        }

    def _list_locals_for_function(self, selector: str | None, identifier):
        bv = self._resolve_view(selector)
        func = self._find_function(bv, identifier)
        variables = self._list_locals(func)
        return {
            "function": {
                "name": func.name,
                "address": hex(func.start),
                "raw_name": getattr(func, "raw_name", func.name),
            },
            "locals": variables,
        }

    def _il(self, selector: str | None, identifier, view: str, ssa: bool):
        bv = self._resolve_view(selector)
        func = self._find_function(bv, identifier)
        text = self._function_text(bv, func, view=view, ssa=ssa)
        if isinstance(text, dict) and text.get("il_unavailable"):
            return {
                "function": {"name": func.name, "address": hex(func.start)},
                "view": view,
                "ssa": ssa,
                "text": None,
                "il_unavailable": True,
                **{k: v for k, v in text.items() if k != "il_unavailable"},
            }
        return {
            "function": {"name": func.name, "address": hex(func.start)},
            "view": view,
            "ssa": ssa,
            "text": text,
            "warnings": self._render_warnings(text),
        }

    def _disasm(self, selector: str | None, identifier):
        bv = self._resolve_view(selector)
        func = self._find_function(bv, identifier)
        return {
            "function": {"name": func.name, "address": hex(func.start)},
            "text": self._disasm_text(bv, func),
        }

    def _xrefs(self, selector: str | None, identifier):
        bv = self._resolve_view(selector)
        try:
            address = self._address(bv, identifier)
        except AddressError:
            raise
        except (ValueError, TypeError):
            address = self._find_function(bv, identifier).start
        return self._xrefs_to_address(bv, address)

    def _resolve_type_field(self, bv, field_spec: str):
        type_name, sep, field_name = str(field_spec).rpartition(".")
        if not sep or not type_name or not field_name:
            raise RuntimeError("Field selector must be in the form Struct.field")

        resolved_name, type_obj = self._find_type(bv, type_name)
        members = getattr(type_obj, "members", None)
        if members is None:
            raise RuntimeError(f"Type is not a struct-like type: {resolved_name}")

        member_list = list(members)

        def field_info(member, index: int):
            return {
                "type_name": resolved_name,
                "field_name": str(getattr(member, "name", "")) or field_name,
                "offset": int(getattr(member, "offset", 0)),
                "member_index": index,
                "field_type": str(getattr(member, "type", "")),
            }

        for index, member in enumerate(member_list):
            if str(getattr(member, "name", "")) != field_name:
                continue
            return field_info(member, index)

        folded_matches = [
            (index, member)
            for index, member in enumerate(member_list)
            if str(getattr(member, "name", "")).lower() == field_name.lower()
        ]
        if len(folded_matches) == 1:
            index, member = folded_matches[0]
            return field_info(member, index)

        try:
            requested_offset = _parse_address(field_name)
        except Exception:
            requested_offset = None
        if requested_offset is not None:
            for index, member in enumerate(member_list):
                if int(getattr(member, "offset", 0)) != requested_offset:
                    continue
                return field_info(member, index)
            raise RuntimeError(f"Field not found: {resolved_name}.0x{requested_offset:x}")

        available = [str(getattr(member, "name", "")) for member in member_list if str(getattr(member, "name", ""))]
        suggestions = difflib.get_close_matches(field_name, available, n=5, cutoff=0.5)
        if suggestions:
            raise RuntimeError(
                f"Field not found: {resolved_name}.{field_name}. Did you mean: {', '.join(suggestions)}"
            )
        raise RuntimeError(f"Field not found: {resolved_name}.{field_name}")

    def _field_xrefs(self, selector: str | None, field_spec: str):
        bv = self._resolve_view(selector)
        field = self._resolve_type_field(bv, field_spec)

        code_refs = []
        for ref in sorted(
            list(bv.get_code_refs_for_type_field(field["type_name"], field["offset"])),
            key=lambda item: int(getattr(item, "address", 0)),
        ):
            func = getattr(ref, "func", None)
            address = int(getattr(ref, "address", 0))
            code_refs.append(
                {
                    "function": func.name if func is not None else None,
                    "address": hex(address),
                    "size": int(getattr(ref, "size", 0)),
                    "incoming_type": str(getattr(ref, "incomingType", "")) or None,
                    "disasm": bv.get_disassembly(address) or "",
                }
            )

        data_refs = []
        for address in sorted(list(bv.get_data_refs_for_type_field(field["type_name"], field["offset"]))):
            symbol = bv.get_symbol_at(address)
            type_obj = bv.get_type_at(address)
            data_refs.append(
                {
                    "address": hex(address),
                    "symbol": symbol.name if symbol is not None else None,
                    "type": str(type_obj) if type_obj is not None else None,
                }
            )

        return {
            "field": field,
            "code_refs": code_refs,
            "data_refs": data_refs,
        }

    def _types(self, selector: str | None, *, query):
        bv = self._resolve_view(selector)
        items = []
        needle = str(query).lower() if query else None
        for name, type_obj in list(bv.types.items()):
            self._check_job_cancelled()
            entry = self._type_entry(name, type_obj)
            if needle and needle not in entry["name"].lower() and needle not in entry["decl"].lower():
                continue
            items.append(entry)
        items.sort(key=lambda item: item["name"].lower())
        return items

    def _find_type(self, bv, type_name: str):
        type_obj = bv.get_type_by_name(type_name)
        if type_obj is not None:
            return type_name, type_obj

        needle = str(type_name).lower()
        for name, candidate in list(bv.types.items()):
            if str(name).lower() == needle:
                return str(name), candidate
        raise RuntimeError(f"Type not found: {type_name}")

    def _type_entry(self, type_name, type_obj):
        return {
            "name": str(type_name),
            "kind": str(getattr(type_obj, "type_class", "unknown")),
            "decl": str(type_obj),
            "layout": self._render_type_layout(type_obj),
        }

    def _current_type_entry(self, bv, type_name: str):
        type_obj = bv.get_type_by_name(type_name)
        if type_obj is None:
            return None
        return self._type_entry(type_name, type_obj)

    def _type_info(self, selector: str | None, type_name: str, *, require_struct: bool = False):
        bv = self._resolve_view(selector)
        resolved_name, type_obj = self._find_type(bv, type_name)
        members = getattr(type_obj, "members", None)
        if require_struct and members is None:
            raise RuntimeError(f"Type is not a struct-like type: {resolved_name}")
        return self._type_entry(resolved_name, type_obj)

    def _strings(self, selector: str | None, *, query):
        bv = self._resolve_view(selector)
        items = []
        needle = str(query).lower() if query else None
        for item in list(getattr(bv, "strings", [])):
            self._check_job_cancelled()
            value = str(getattr(item, "value", ""))
            entry = {
                "address": hex(int(getattr(item, "start", 0))),
                "length": int(getattr(item, "length", 0)),
                "type": str(getattr(item, "type", "")),
                "value": value,
            }
            if needle and needle not in value.lower():
                continue
            items.append(entry)
        items.sort(key=lambda item: (int(item["address"], 16), item["value"]))
        return items

    def _imports(self, selector: str | None):
        bv = self._resolve_view(selector)
        items = []
        for sym in list(bv.get_symbols_of_type(bn.SymbolType.ImportedFunctionSymbol)):
            self._check_job_cancelled()
            items.append(
                {
                    "name": sym.name,
                    "address": hex(sym.address),
                    "library": str(getattr(sym, "namespace", "") or ""),
                }
            )
        items.sort(key=lambda item: (item["library"], item["name"], int(item["address"], 16)))
        return items

    def _get_comment(self, selector: str | None, address, function):
        bv = self._resolve_view(selector)
        if function:
            fn = self._find_function(bv, function)
            comment = bv.get_comment_at(fn.start)
            return {
                "function": fn.name,
                "address": hex(fn.start),
                "comment": comment or "",
                "has_comment": bool(comment),
            }

        if address is None:
            raise RuntimeError("comment get requires --address or --function")

        comment_address = self._address(bv, address)
        comment = bv.get_comment_at(comment_address)
        return {
            "address": hex(comment_address),
            "comment": comment or "",
            "has_comment": bool(comment),
        }

    def _bundle_function(self, selector: str | None, identifier, out_path: str | None):
        bv = self._resolve_view(selector)
        func = self._find_function(bv, identifier)
        decompile = self._function_text(bv, func, view="hlil")
        self._check_job_cancelled()
        self._set_job_progress("collecting IL and disassembly")
        bundle = {
            "target": self._target_info(selector),
            "function": {
                "name": func.name,
                "address": hex(func.start),
                "raw_name": getattr(func, "raw_name", func.name),
                "type": str(func.type),
            },
            "decompile": decompile,
            "warnings": self._render_warnings(decompile),
            "il": {
                "hlil": decompile,
                "mlil": self._function_text(bv, func, view="mlil"),
            },
            "disassembly": self._disasm_text(bv, func),
            "locals": self._list_locals(func),
            "comments": dict(sorted(self._comment_map(bv, func).items())),
            "xrefs": self._xrefs_to_address(bv, func.start),
        }
        artifact = _write_json_artifact(out_path, bundle)
        return artifact or bundle

    def _normalize_py_result(self, value: Any) -> tuple[Any, list[str]]:
        def normalize(item: Any) -> Any:
            if item is None or isinstance(item, (bool, int, float, str)):
                return item
            if isinstance(item, (list, tuple)):
                return [normalize(part) for part in item]
            if isinstance(item, dict):
                return {str(key): normalize(val) for key, val in item.items()}
            raise TypeError(type(item).__name__)

        try:
            return normalize(value), []
        except TypeError:
            return repr(value), ["`result` was not JSON-serializable; returned repr(result) instead."]

    def _py_exec(self, selector: str | None, script: str):
        bv = self._resolve_view(selector)
        stdout = io.StringIO()
        scope = {
            "bn": bn,
            "binaryninja": bn,
            "bv": bv,
            "result": None,
        }
        with contextlib.redirect_stdout(stdout):
            exec(script, scope, scope)
        result_value, warnings = self._normalize_py_result(scope.get("result"))
        result = {
            "stdout": stdout.getvalue(),
            "result": result_value,
            "warnings": warnings,
        }
        return result

    def _render_warnings(self, text: str) -> list[str]:
        warnings: list[str] = []
        if "__offset(" in text:
            warnings.append(
                "Decompile still contains raw __offset(...) expressions; use `bn types show` or `bn struct show` as the authoritative layout until Binary Ninja refreshes the presentation."
            )
        return warnings

    def _guess_type_affected_functions(self, bv, type_name: str, limit: int = 10):
        matches = []
        needle = type_name.lower()
        for fn in list(bv.functions):
            text = str(fn.type).lower()
            if needle in text:
                matches.append(fn)
                if len(matches) >= limit:
                    break
        return matches

    def _parse_declaration_source(self, bv, declaration: str, *, source_path: str | None = None):
        parse_result = None
        source_error: Exception | None = None
        platform = getattr(bv, "platform", None)
        if platform is not None and hasattr(platform, "parse_types_from_source"):
            kwargs: dict[str, Any] = {}
            if source_path:
                kwargs["filename"] = source_path
                kwargs["include_dirs"] = [str(Path(source_path).expanduser().resolve().parent)]
            try:
                parse_result = platform.parse_types_from_source(declaration, **kwargs)
            except Exception as exc:
                source_error = exc

        if parse_result is None:
            try:
                parse_result = bv.parse_types_from_string(declaration)
            except Exception:
                if source_error is not None:
                    raise source_error
                raise

        return {
            "types": [(str(name), type_obj) for name, type_obj in list(getattr(parse_result, "types", {}).items())],
            "variables": [(str(name), type_obj) for name, type_obj in list(getattr(parse_result, "variables", {}).items())],
            "functions": [(str(name), type_obj) for name, type_obj in list(getattr(parse_result, "functions", {}).items())],
        }

    def _operation_type_names(self, bv, op: dict[str, Any]) -> list[str]:
        kind = op.get("op") or "rename_symbol"
        if kind.startswith("struct_") and op.get("struct_name"):
            return [str(op["struct_name"])]
        if kind == "types_declare":
            return [name for name, _ in self._parse_declaration_source(
                bv,
                str(op["declaration"]),
                source_path=op.get("source_path"),
            )["types"]]
        return []

    def _guess_affected_functions(self, bv, operations: list[dict[str, Any]]):
        affected = []
        seen = set()
        for op in operations:
            kind = op.get("op") or "rename_symbol"
            functions = []
            try:
                if kind == "create_function":
                    fn = bv.get_function_at(self._address(bv, op["address"]))
                    functions = [fn] if fn is not None else []
                elif kind == "rename_symbol" and op.get("kind") != "data":
                    functions = [self._find_function(bv, op["identifier"])]
                elif kind in {"set_prototype", "local_rename", "local_retype"}:
                    ident = op.get("identifier") or op.get("function")
                    functions = [self._find_function(bv, ident)]
                elif kind in {"set_comment", "delete_comment"}:
                    if op.get("function"):
                        functions = [self._find_function(bv, op["function"])]
                    elif op.get("address"):
                        functions = self._functions_containing(bv, self._address(bv, op["address"]))
                elif kind.startswith("struct_") or kind == "types_declare":
                    for type_name in self._operation_type_names(bv, op):
                        functions.extend(self._guess_type_affected_functions(bv, type_name))
            except Exception:
                functions = []

            for fn in functions:
                if fn is None:
                    continue
                marker = int(fn.start)
                if marker not in seen:
                    seen.add(marker)
                    affected.append(fn)
        return affected

    def _affected_type_names(self, bv, operations: list[dict[str, Any]]) -> list[str]:
        names: list[str] = []
        seen: set[str] = set()
        for op in operations:
            for type_name in self._operation_type_names(bv, op):
                if type_name not in seen:
                    seen.add(type_name)
                    names.append(type_name)
        return names

    def _render_type_layout(self, type_obj) -> str:
        header = str(type_obj)
        try:
            width = int(getattr(type_obj, "width", 0))
            header = f"{header} // size=0x{width:x}"
        except Exception:
            pass

        members = getattr(type_obj, "members", None)
        if members is None:
            return header

        lines = [header]
        for member in list(members):
            try:
                offset = int(getattr(member, "offset", 0))
            except Exception:
                offset = 0
            name = str(getattr(member, "name", "<anonymous>"))
            member_type = str(getattr(member, "type", "<unknown>"))
            lines.append(f"0x{offset:04x}: {member_type} {name}")
        return "\n".join(lines)

    def _capture_type_snapshots(self, bv, operations: list[dict[str, Any]]):
        snapshots: dict[str, dict[str, Any]] = {}
        for type_name in self._affected_type_names(bv, operations):
            type_obj = bv.get_type_by_name(type_name)
            if type_obj is None:
                continue
            snapshots[type_name] = {
                "type_name": type_name,
                "decl": str(type_obj),
                "layout": self._render_type_layout(type_obj),
            }
        return snapshots

    def _diff_type_snapshots(self, before: dict[str, Any], after: dict[str, Any]):
        diffs = []
        for type_name in sorted(set(before) | set(after)):
            old = before.get(type_name, {"decl": "", "layout": ""})
            new = after.get(type_name, {"decl": "", "layout": ""})
            layout_diff = "\n".join(
                difflib.unified_diff(
                    old["layout"].splitlines(),
                    new["layout"].splitlines(),
                    fromfile=f"before:{type_name}",
                    tofile=f"after:{type_name}",
                    lineterm="",
                )
            )
            changed = old["decl"] != new["decl"] or old["layout"] != new["layout"]
            entry = {
                "type_name": type_name,
                "before_decl": old["decl"],
                "after_decl": new["decl"],
                "before_layout": old["layout"],
                "after_layout": new["layout"],
                "layout_diff": layout_diff,
                "changed": changed,
            }
            if not changed:
                entry["message"] = "No effective change detected"
            diffs.append(entry)
        return diffs

    def _annotate_operation_results(self, results: list[dict[str, Any]], type_diffs: list[dict[str, Any]]):
        type_changes = {item["type_name"]: item for item in type_diffs}
        annotated = []
        for result in results:
            item = dict(result)
            type_name = item.get("struct_name")
            if type_name and type_name in type_changes:
                change = type_changes[type_name]
                item["changed"] = bool(change["changed"])
                if not change["changed"]:
                    item["message"] = change["message"]
                    if item.get("status") == "verified":
                        item["status"] = "noop"
            defined_types = dict(item.get("defined_types") or {})
            if defined_types:
                changed_types = {name: bool(type_changes.get(name, {}).get("changed")) for name in defined_types}
                item["changed_types"] = changed_types
                if item.get("status") == "verified" and not any(changed_types.values()):
                    item["status"] = "noop"
                    item["message"] = "No effective change detected"
            annotated.append(item)
        return annotated

    def _capture_function_snapshots(self, bv, functions):
        snapshots = {}
        for fn in functions:
            snapshots[int(fn.start)] = {
                "name": fn.name,
                "address": hex(fn.start),
                "text": self._function_text(bv, fn, view="hlil"),
            }
        return snapshots

    def _snippet_for_change(self, before_text: str, after_text: str, *, context_lines: int = 3, max_lines: int = 10):
        before_lines = before_text.splitlines()
        after_lines = after_text.splitlines()
        line_count = max(len(before_lines), len(after_lines))

        changed_line = None
        for index in range(line_count):
            before_line = before_lines[index] if index < len(before_lines) else None
            after_line = after_lines[index] if index < len(after_lines) else None
            if before_line != after_line:
                changed_line = index
                break

        if changed_line is None:
            return None

        start = max(0, changed_line - context_lines)
        end = min(line_count, start + max_lines)
        return {
            "start_line": start + 1,
            "before_excerpt": "\n".join(before_lines[start:end]),
            "after_excerpt": "\n".join(after_lines[start:end]),
        }

    def _diff_snapshots(self, before: dict[int, Any], after: dict[int, Any]):
        diffs = []
        snippets_added = 0
        for address in sorted(set(before) | set(after)):
            old = before.get(address, {"text": ""})
            new = after.get(address, {"text": ""})
            text_changed = old.get("text", "") != new.get("text", "")
            name_changed = old.get("name") != new.get("name")
            diff = "\n".join(
                difflib.unified_diff(
                    old["text"].splitlines(),
                    new["text"].splitlines(),
                    fromfile=f"before:{old.get('name', hex(address))}",
                    tofile=f"after:{new.get('name', hex(address))}",
                    lineterm="",
                )
            )
            if not diff and name_changed:
                diff = "\n".join(
                    [
                        f"--- before:{old.get('name', hex(address))}",
                        f"+++ after:{new.get('name', hex(address))}",
                    ]
                )
            diffs.append(
                {
                    "address": hex(address),
                    "before_name": old.get("name"),
                    "after_name": new.get("name"),
                    "changed": bool(text_changed or name_changed),
                    "diff": diff,
                }
            )
            if text_changed and snippets_added < 3:
                snippet = self._snippet_for_change(old.get("text", ""), new.get("text", ""))
                if snippet is not None:
                    diffs[-1].update(snippet)
                    snippets_added += 1
        return diffs

    def _operation_requested(self, op: dict[str, Any]) -> dict[str, Any]:
        return {key: value for key, value in op.items() if key != "preview"}

    def _operation_failure_result(self, op: dict[str, Any], exc: OperationFailure) -> dict[str, Any]:
        result = {
            "op": str(op.get("op") or "rename_symbol"),
            "status": exc.status,
            "message": exc.message,
            "requested": exc.requested or self._operation_requested(op),
        }
        if exc.observed:
            result["observed"] = exc.observed
        return result

    def _mark_unverified_results(self, results: list[dict[str, Any]], message: str) -> list[dict[str, Any]]:
        annotated = []
        for result in results:
            item = dict(result)
            item["status"] = "unsupported"
            item["message"] = message
            annotated.append(item)
        return annotated

    def _has_failed_results(self, results: list[dict[str, Any]]) -> bool:
        return any(item.get("status") in {"unsupported", "verification_failed"} for item in results)

    def _find_member(self, type_obj, *, offset: int | None = None, name: str | None = None):
        members = getattr(type_obj, "members", None)
        if members is None:
            return None
        for member in list(members):
            member_offset = int(getattr(member, "offset", 0))
            member_name = str(getattr(member, "name", ""))
            if offset is not None and member_offset != int(offset):
                continue
            if name is not None and member_name != name:
                continue
            return member
        return None

    def _verify_operation(self, bv, result: dict[str, Any]) -> dict[str, Any]:
        op = result.get("op")
        try:
            if op == "create_function":
                return self._verify_create_function(bv, result)
            if op == "rename_symbol":
                return self._verify_rename_symbol(bv, result)
            if op == "set_comment":
                return self._verify_set_comment(bv, result)
            if op == "delete_comment":
                return self._verify_delete_comment(bv, result)
            if op == "set_prototype":
                return self._verify_set_prototype(bv, result)
            if op == "local_rename":
                return self._verify_local_rename(bv, result)
            if op == "local_retype":
                return self._verify_local_retype(bv, result)
            if op == "struct_field_set":
                return self._verify_struct_field_set(bv, result)
            if op == "struct_field_rename":
                return self._verify_struct_field_rename(bv, result)
            if op == "struct_field_delete":
                return self._verify_struct_field_delete(bv, result)
            if op == "types_declare":
                return self._verify_declared_types(bv, result)
            raise OperationFailure("unsupported", f"Unsupported verification path: {op}", requested=result.get("requested"))
        except OperationFailure as exc:
            item = dict(result)
            item["status"] = exc.status
            item["message"] = exc.message
            if exc.requested:
                item["requested"] = exc.requested
            if exc.observed:
                item["observed"] = exc.observed
            return item
        except Exception as exc:
            item = dict(result)
            item["status"] = "verification_failed"
            item["message"] = f"{type(exc).__name__}: {exc}"
            if item.get("requested") is None:
                item["requested"] = {}
            return item

    def _verify_create_function(self, bv, result: dict[str, Any]) -> dict[str, Any]:
        item = dict(result)
        address = self._address(bv, item["address"])
        fn = bv.get_function_at(address)
        observed = {
            "address": item["address"],
            "exists": fn is not None,
            "name": str(fn.name) if fn is not None else None,
        }
        item["observed"] = observed
        if fn is None:
            raise OperationFailure(
                "verification_failed",
                f"Function missing after creation at {item['address']}",
                requested=item.get("requested"),
                observed=observed,
            )
        item["status"] = "noop" if item.get("before_exists") else "verified"
        return item

    def _verify_rename_symbol(self, bv, result: dict[str, Any]) -> dict[str, Any]:
        item = dict(result)
        address = self._address(bv, item["address"])
        requested_name = str(item["new_name"])
        before_name = item.get("before_name")
        observed_name = None
        if item.get("kind") == "function":
            fn = bv.get_function_at(address)
            if fn is None:
                raise OperationFailure(
                    "verification_failed",
                    f"Function missing after rename at {item['address']}",
                    requested=item.get("requested"),
                    observed={"address": item["address"], "name": None},
                )
            observed_name = str(fn.name)
        else:
            symbol = bv.get_symbol_at(address)
            observed_name = str(symbol.name) if symbol is not None else None
        item["observed"] = {"address": item["address"], "name": observed_name}
        if observed_name != requested_name:
            raise OperationFailure(
                "verification_failed",
                f"Live rename verification failed at {item['address']}",
                requested=item.get("requested"),
                observed=item["observed"],
            )
        item["status"] = "noop" if before_name == requested_name else "verified"
        return item

    def _verify_set_comment(self, bv, result: dict[str, Any]) -> dict[str, Any]:
        item = dict(result)
        address = self._address(bv, item["address"])
        expected = str(item["requested"]["comment"])
        observed = bv.get_comment_at(address) or ""
        item["observed"] = {"address": item["address"], "comment": observed}
        if observed != expected:
            raise OperationFailure(
                "verification_failed",
                f"Live comment verification failed at {item['address']}",
                requested=item.get("requested"),
                observed=item["observed"],
            )
        item["status"] = "noop" if item.get("before_comment", "") == expected else "verified"
        return item

    def _verify_delete_comment(self, bv, result: dict[str, Any]) -> dict[str, Any]:
        item = dict(result)
        address = self._address(bv, item["address"])
        observed = bv.get_comment_at(address) or ""
        item["observed"] = {"address": item["address"], "comment": observed}
        if observed:
            raise OperationFailure(
                "verification_failed",
                f"Live comment deletion verification failed at {item['address']}",
                requested=item.get("requested"),
                observed=item["observed"],
            )
        item["status"] = "noop" if not item.get("before_comment") else "verified"
        return item

    def _verify_set_prototype(self, bv, result: dict[str, Any]) -> dict[str, Any]:
        item = dict(result)
        address = self._address(bv, item["address"])
        fn = bv.get_function_at(address)
        if fn is None:
            raise OperationFailure(
                "verification_failed",
                f"Function missing after prototype change at {item['address']}",
                requested=item.get("requested"),
                observed={"address": item["address"], "prototype": None},
            )
        observed = str(fn.type)
        item["observed"] = {"address": item["address"], "prototype": observed}
        if observed != item["expected_prototype"]:
            raise OperationFailure(
                "verification_failed",
                f"Live prototype verification failed at {item['address']}",
                requested=item.get("requested"),
                observed=item["observed"],
            )
        item["status"] = "noop" if item.get("before_prototype") == item["expected_prototype"] else "verified"
        return item

    def _verify_local_rename(self, bv, result: dict[str, Any]) -> dict[str, Any]:
        item = dict(result)
        address = self._address(bv, item["address"])
        fn = bv.get_function_at(address)
        if fn is None:
            raise OperationFailure(
                "verification_failed",
                f"Function missing after local rename at {item['address']}",
                requested=item.get("requested"),
                observed={"address": item["address"], "variable": None},
            )
        var, _ = self._find_variable_by_storage(
            fn,
            int(item["storage"]),
            is_parameter=bool(item["is_parameter"]),
        )
        observed_name = str(var.name)
        item["observed"] = {"address": item["address"], "variable": observed_name, "storage": int(item["storage"])}
        if observed_name != item["new_name"]:
            raise OperationFailure(
                "verification_failed",
                f"Live local rename verification failed at {item['address']}",
                requested=item.get("requested"),
                observed=item["observed"],
            )
        item["status"] = "noop" if item.get("before_name") == item["new_name"] else "verified"
        return item

    def _verify_local_retype(self, bv, result: dict[str, Any]) -> dict[str, Any]:
        item = dict(result)
        address = self._address(bv, item["address"])
        fn = bv.get_function_at(address)
        if fn is None:
            raise OperationFailure(
                "verification_failed",
                f"Function missing after local retype at {item['address']}",
                requested=item.get("requested"),
                observed={"address": item["address"], "type": None},
            )
        var, _ = self._find_variable_by_storage(
            fn,
            int(item["storage"]),
            is_parameter=bool(item["is_parameter"]),
        )
        observed_type = str(var.type)
        item["observed"] = {"address": item["address"], "variable": str(var.name), "type": observed_type}
        if observed_type != item["expected_type"]:
            raise OperationFailure(
                "verification_failed",
                f"Live local retype verification failed at {item['address']}",
                requested=item.get("requested"),
                observed=item["observed"],
            )
        item["status"] = "noop" if item.get("before_type") == item["expected_type"] else "verified"
        return item

    def _verify_struct_field_set(self, bv, result: dict[str, Any]) -> dict[str, Any]:
        item = dict(result)
        type_obj = bv.get_type_by_name(item["struct_name"])
        if type_obj is None:
            raise OperationFailure(
                "verification_failed",
                f"Struct missing after field set: {item['struct_name']}",
                requested=item.get("requested"),
                observed={"type_name": item["struct_name"]},
            )
        member = self._find_member(type_obj, offset=int(item["member_offset"]), name=item["field_name"])
        observed = {
            "type_name": item["struct_name"],
            "offset": item["offset"],
            "field_name": getattr(member, "name", None),
            "field_type": str(getattr(member, "type", "")) if member is not None else None,
        }
        item["observed"] = observed
        if member is None or observed["field_type"] != item["field_type"]:
            raise OperationFailure(
                "verification_failed",
                f"Live struct field verification failed for {item['struct_name']} at {item['offset']}",
                requested=item.get("requested"),
                observed=observed,
            )
        previous = item.get("before_member")
        if previous and previous.get("field_name") == item["field_name"] and previous.get("field_type") == item["field_type"]:
            item["status"] = "noop"
        else:
            item["status"] = "verified"
        return item

    def _verify_struct_field_rename(self, bv, result: dict[str, Any]) -> dict[str, Any]:
        item = dict(result)
        type_obj = bv.get_type_by_name(item["struct_name"])
        if type_obj is None:
            raise OperationFailure(
                "verification_failed",
                f"Struct missing after field rename: {item['struct_name']}",
                requested=item.get("requested"),
                observed={"type_name": item["struct_name"]},
            )
        member = self._find_member(type_obj, name=item["new_name"])
        old_member = self._find_member(type_obj, name=item["old_name"])
        observed = {
            "type_name": item["struct_name"],
            "new_name": getattr(member, "name", None),
            "old_name_present": old_member is not None,
        }
        item["observed"] = observed
        if member is None or old_member is not None:
            raise OperationFailure(
                "verification_failed",
                f"Live struct field rename verification failed for {item['struct_name']}",
                requested=item.get("requested"),
                observed=observed,
            )
        item["status"] = "noop" if item["old_name"] == item["new_name"] else "verified"
        return item

    def _verify_struct_field_delete(self, bv, result: dict[str, Any]) -> dict[str, Any]:
        item = dict(result)
        type_obj = bv.get_type_by_name(item["struct_name"])
        if type_obj is None:
            raise OperationFailure(
                "verification_failed",
                f"Struct missing after field delete: {item['struct_name']}",
                requested=item.get("requested"),
                observed={"type_name": item["struct_name"]},
            )
        member = self._find_member(type_obj, name=item["field_name"])
        item["observed"] = {"type_name": item["struct_name"], "field_present": member is not None}
        if member is not None:
            raise OperationFailure(
                "verification_failed",
                f"Live struct field delete verification failed for {item['struct_name']}",
                requested=item.get("requested"),
                observed=item["observed"],
            )
        item["status"] = "verified"
        return item

    def _verify_declared_types(self, bv, result: dict[str, Any]) -> dict[str, Any]:
        item = dict(result)
        defined_types = dict(item.get("defined_types") or {})
        defined_type_layouts = dict(item.get("defined_type_layouts") or {})
        if not defined_types:
            item["observed"] = {
                "defined_types": {},
                "parsed_functions": list(item.get("parsed_functions") or []),
                "parsed_variables": list(item.get("parsed_variables") or []),
            }
            item["status"] = "noop"
            item["message"] = "Parsed declarations but no named types were defined."
            return item
        observed_types: dict[str, str | None] = {}
        observed_type_layouts: dict[str, str | None] = {}
        for name, expected in defined_types.items():
            type_obj = bv.get_type_by_name(name)
            observed_types[name] = str(type_obj) if type_obj is not None else None
            observed_type_layouts[name] = self._render_type_layout(type_obj) if type_obj is not None else None
            if observed_types[name] != expected:
                if defined_type_layouts.get(name) and observed_type_layouts[name] == defined_type_layouts[name]:
                    continue
                raise OperationFailure(
                    "verification_failed",
                    f"Live type verification failed for {name}",
                    requested=item.get("requested"),
                    observed={
                        "defined_types": observed_types,
                        "defined_type_layouts": observed_type_layouts,
                    },
                )
        item["observed"] = {
            "defined_types": observed_types,
            "defined_type_layouts": observed_type_layouts,
        }
        before = dict(item.get("before_defined_types") or {})
        item["status"] = "noop" if before and all(before.get(name) == expected for name, expected in defined_types.items()) else "verified"
        return item

    def _apply_operation(self, bv, op: dict[str, Any]):
        kind = op.get("op") or "rename_symbol"
        try:
            if kind == "create_function":
                return self._op_create_function(bv, op)
            if kind == "rename_symbol":
                return self._op_rename_symbol(bv, op)
            if kind == "set_comment":
                return self._op_set_comment(bv, op)
            if kind == "delete_comment":
                return self._op_delete_comment(bv, op)
            if kind == "set_prototype":
                return self._op_set_prototype(bv, op)
            if kind == "local_rename":
                return self._op_local_rename(bv, op)
            if kind == "local_retype":
                return self._op_local_retype(bv, op)
            if kind == "struct_field_set":
                return self._op_struct_field_set(bv, op)
            if kind == "struct_field_rename":
                return self._op_struct_field_rename(bv, op)
            if kind == "struct_field_delete":
                return self._op_struct_field_delete(bv, op)
            if kind == "types_declare":
                return self._op_types_declare(bv, op)
            raise OperationFailure("unsupported", f"Unsupported batch operation: {kind}", requested=self._operation_requested(op))
        except OperationFailure:
            raise
        except Exception as exc:
            raise OperationFailure(
                "unsupported",
                f"{type(exc).__name__}: {exc}",
                requested=self._operation_requested(op),
            ) from exc

    def _mutation(self, selector: str | None, preview: bool, operations: list[dict[str, Any]]):
        if not operations:
            raise ValueError("Batch operation list is empty")

        bv = self._resolve_view(selector)
        affected = self._guess_affected_functions(bv, operations)
        before = self._capture_function_snapshots(bv, affected)
        type_before = self._capture_type_snapshots(bv, operations)
        state = bv.begin_undo_actions()
        results = []
        try:
            for op in operations:
                results.append(self._apply_operation(bv, op))
        except OperationFailure as exc:
            bv.revert_undo_actions(state)
            return {
                "preview": preview,
                "success": False,
                "committed": False,
                "message": "Rolled back before post-state verification because an operation failed to apply.",
                "results": self._mark_unverified_results(results, "Rolled back before post-state verification.")
                + [self._operation_failure_result(operations[len(results)], exc)],
                "affected_functions": [],
                "affected_types": [],
            }
        except Exception:
            bv.revert_undo_actions(state)
            raise

        try:
            bv.update_analysis_and_wait()
            self._check_job_cancelled()
            after_affected = {}
            for fn in affected:
                address = int(fn.start)
                current = bv.get_function_at(address)
                if current is not None:
                    after_affected[address] = current
            if any((op.get("op") or "rename_symbol") == "create_function" for op in operations):
                for fn in self._guess_affected_functions(bv, operations):
                    after_affected[int(fn.start)] = fn
            after = self._capture_function_snapshots(bv, after_affected.values())
            type_after = self._capture_type_snapshots(bv, operations)
            diffs = self._diff_snapshots(before, after)
            type_diffs = self._diff_type_snapshots(type_before, type_after)
            verified_results = [self._verify_operation(bv, result) for result in results]
            annotated_results = self._annotate_operation_results(verified_results, type_diffs)
            failed = self._has_failed_results(annotated_results)
            if preview or failed:
                bv.revert_undo_actions(state)
            else:
                bv.commit_undo_actions(state)
            message = None
            if preview:
                message = "Preview verified and reverted."
            elif failed:
                message = "Rolled back because live-session verification failed."
            else:
                message = "Applied and verified in the live Binary Ninja session."
            return {
                "preview": preview,
                "success": not failed,
                "committed": bool((not preview) and (not failed)),
                "message": message,
                "results": annotated_results,
                "affected_functions": diffs,
                "affected_types": type_diffs,
            }
        except Exception:
            bv.revert_undo_actions(state)
            raise

    def _op_create_function(self, bv, op: dict[str, Any]):
        address = self._address(bv, op["address"])
        requested = self._operation_requested(op)
        before = bv.get_function_at(address)
        if before is None:
            create = getattr(bv, "create_user_function", None)
            if create is None:
                raise OperationFailure(
                    "unsupported",
                    "BinaryView.create_user_function is unavailable",
                    requested=requested,
                )
            create(address)
        return {
            "op": "create_function",
            "address": hex(address),
            "before_exists": before is not None,
            "before_name": str(before.name) if before is not None else None,
            "requested": requested,
        }

    def _op_rename_symbol(self, bv, op: dict[str, Any]):
        kind = str(op.get("kind", "auto"))
        identifier = op["identifier"]
        new_name = str(op["new_name"])
        target = self._resolve_rename_target(bv, identifier, kind)
        requested = self._operation_requested(op)
        if target["kind"] == "function":
            fn = bv.get_function_at(target["address"])
            if fn is None:
                raise OperationFailure("unsupported", f"Function not found: {identifier}", requested=requested)
            if target["before_name"] != new_name:
                fn.name = new_name
            return {
                "op": "rename_symbol",
                "kind": "function",
                "address": hex(target["address"]),
                "before_name": target["before_name"],
                "new_name": new_name,
                "requested": requested,
            }
        address = int(target["address"])
        if target["before_name"] != new_name:
            bv.define_user_symbol(bn.Symbol(bn.SymbolType.DataSymbol, address, new_name))
        return {
            "op": "rename_symbol",
            "kind": "data",
            "address": hex(address),
            "before_name": target["before_name"],
            "new_name": new_name,
            "requested": requested,
        }

    def _op_set_comment(self, bv, op: dict[str, Any]):
        comment = str(op["comment"])
        if op.get("function"):
            fn = self._find_function(bv, op["function"])
            before_comment = bv.get_comment_at(fn.start) or ""
            if before_comment != comment:
                bv.set_comment_at(fn.start, comment)
            return {
                "op": "set_comment",
                "address": hex(fn.start),
                "function": fn.name,
                "before_comment": before_comment,
                "requested": self._operation_requested(op),
            }
        address = self._address(bv, op["address"])
        before_comment = bv.get_comment_at(address) or ""
        if before_comment != comment:
            bv.set_comment_at(address, comment)
        return {
            "op": "set_comment",
            "address": hex(address),
            "before_comment": before_comment,
            "requested": self._operation_requested(op),
        }

    def _op_delete_comment(self, bv, op: dict[str, Any]):
        if op.get("function"):
            fn = self._find_function(bv, op["function"])
            before_comment = bv.get_comment_at(fn.start) or ""
            if before_comment:
                bv.set_comment_at(fn.start, None)
            return {
                "op": "delete_comment",
                "address": hex(fn.start),
                "function": fn.name,
                "before_comment": before_comment,
                "requested": self._operation_requested(op),
            }
        address = self._address(bv, op["address"])
        before_comment = bv.get_comment_at(address) or ""
        if before_comment:
            bv.set_comment_at(address, None)
        return {
            "op": "delete_comment",
            "address": hex(address),
            "before_comment": before_comment,
            "requested": self._operation_requested(op),
        }

    def _op_set_prototype(self, bv, op: dict[str, Any]):
        fn = self._find_function(bv, op["identifier"])
        expected_type, _ = bv.parse_type_string(str(op["prototype"]))
        before_prototype = str(fn.type)
        expected_prototype = str(expected_type)
        if before_prototype != expected_prototype:
            try:
                fn.set_user_type(expected_prototype)
            except TypeError:
                fn.set_user_type(expected_type)
        return {
            "op": "set_prototype",
            "function": fn.name,
            "address": hex(fn.start),
            "before_prototype": before_prototype,
            "expected_prototype": expected_prototype,
            "requested": self._operation_requested(op),
        }

    def _op_local_rename(self, bv, op: dict[str, Any]):
        fn = self._find_function(bv, op["function"])
        var, is_parameter = self._find_variable_selector(fn, str(op["variable"]))
        new_name = str(op["new_name"])
        if str(var.name) != new_name:
            fn.create_user_var(var, var.type, new_name)
        return {
            "op": "local_rename",
            "function": fn.name,
            "address": hex(fn.start),
            "variable": str(op["variable"]),
            "local_id": self._local_id(fn, var, is_parameter=is_parameter),
            "storage": int(var.storage),
            "identifier": self._variable_identifier(var),
            "source_type": self._variable_source_name(var),
            "is_parameter": is_parameter,
            "before_name": str(var.name),
            "new_name": new_name,
            "requested": self._operation_requested(op),
        }

    def _op_local_retype(self, bv, op: dict[str, Any]):
        fn = self._find_function(bv, op["function"])
        var, is_parameter = self._find_variable_selector(fn, str(op["variable"]))
        expected_type, _ = bv.parse_type_string(str(op["new_type"]))
        if str(var.type) != str(expected_type):
            fn.create_user_var(var, expected_type, var.name)
        return {
            "op": "local_retype",
            "function": fn.name,
            "address": hex(fn.start),
            "variable": str(op["variable"]),
            "local_id": self._local_id(fn, var, is_parameter=is_parameter),
            "storage": int(var.storage),
            "identifier": self._variable_identifier(var),
            "source_type": self._variable_source_name(var),
            "is_parameter": is_parameter,
            "before_type": str(var.type),
            "expected_type": str(expected_type),
            "requested": self._operation_requested(op),
        }

    def _struct_builder(self, bv, struct_name: str):
        type_obj = bv.get_type_by_name(struct_name)
        if type_obj is None:
            raise RuntimeError(f"Struct not found: {struct_name}")
        return type_obj.mutable_copy()

    def _commit_struct_builder(self, bv, struct_name: str, builder):
        bv.define_user_type(struct_name, builder)

    def _op_struct_field_set(self, bv, op: dict[str, Any]):
        struct_name = str(op["struct_name"])
        builder = self._struct_builder(bv, struct_name)
        field_type, _ = bv.parse_type_string(str(op["field_type"]))
        offset = _parse_address(op["offset"])
        overwrite = bool(op.get("overwrite_existing", True))
        before_type = bv.get_type_by_name(struct_name)
        before_member = None
        if before_type is not None:
            member = self._find_member(before_type, offset=offset)
            if member is not None:
                before_member = {
                    "field_name": str(getattr(member, "name", "")),
                    "field_type": str(getattr(member, "type", "")),
                    "offset": hex(int(getattr(member, "offset", offset))),
                }
        builder.add_member_at_offset(str(op["field_name"]), field_type, offset, overwrite)
        try:
            builder.width = max(int(builder.width), int(offset) + int(field_type.width))
        except Exception:
            pass
        self._commit_struct_builder(bv, struct_name, builder)
        return {
            "op": "struct_field_set",
            "struct_name": struct_name,
            "offset": hex(offset),
            "field_name": str(op["field_name"]),
            "field_type": str(field_type),
            "member_offset": int(offset),
            "before_member": before_member,
            "requested": self._operation_requested(op),
        }

    def _op_struct_field_rename(self, bv, op: dict[str, Any]):
        struct_name = str(op["struct_name"])
        builder = self._struct_builder(bv, struct_name)
        index = builder.index_by_name(str(op["old_name"]))
        if index is None:
            raise RuntimeError(f"Field not found: {op['old_name']}")
        member = builder[str(op["old_name"])]
        if member is None:
            raise RuntimeError(f"Field not found: {op['old_name']}")
        builder.replace(index, member.type, str(op["new_name"]), True)
        self._commit_struct_builder(bv, struct_name, builder)
        return {
            "op": "struct_field_rename",
            "struct_name": struct_name,
            "old_name": str(op["old_name"]),
            "new_name": str(op["new_name"]),
            "requested": self._operation_requested(op),
        }

    def _op_struct_field_delete(self, bv, op: dict[str, Any]):
        struct_name = str(op["struct_name"])
        builder = self._struct_builder(bv, struct_name)
        index = builder.index_by_name(str(op["field_name"]))
        if index is None:
            raise RuntimeError(f"Field not found: {op['field_name']}")
        builder.remove(index)
        self._commit_struct_builder(bv, struct_name, builder)
        return {
            "op": "struct_field_delete",
            "struct_name": struct_name,
            "field_name": str(op["field_name"]),
            "requested": self._operation_requested(op),
        }

    def _op_types_declare(self, bv, op: dict[str, Any]):
        parsed = self._parse_declaration_source(
            bv,
            str(op["declaration"]),
            source_path=op.get("source_path"),
        )
        named_types = list(parsed["types"])
        defined_types = {}
        defined_type_layouts = {}
        before_defined_types = {}
        for name, type_obj in named_types:
            existing = self._current_type_entry(bv, str(name))
            before_defined_types[str(name)] = existing["decl"] if existing is not None else None
            bv.define_user_type(name, type_obj)
            current = self._current_type_entry(bv, str(name))
            defined_types[str(name)] = current["decl"] if current is not None else str(type_obj)
            defined_type_layouts[str(name)] = current["layout"] if current is not None else self._render_type_layout(type_obj)
        return {
            "op": "types_declare",
            "defined_types": defined_types,
            "defined_type_layouts": defined_type_layouts,
            "before_defined_types": before_defined_types,
            "count": len(defined_types),
            "parsed_functions": [name for name, _ in parsed["functions"]],
            "parsed_variables": [name for name, _ in parsed["variables"]],
            "parsed_type_count": len(named_types),
            "parsed_function_count": len(parsed["functions"]),
            "parsed_variable_count": len(parsed["variables"]),
            "requested": self._operation_requested(op),
        }

    # =========================================================================
    # Patch operations
    # =========================================================================

    def _patch_status(self, selector, address_raw):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address_raw)
        return {
            "address": hex(addr),
            "can_assemble": bv.arch.can_assemble if bv.arch else False,
            "is_never_branch_patch_available": bv.is_never_branch_patch_available(addr),
            "is_always_branch_patch_available": bv.is_always_branch_patch_available(addr),
            "is_invert_branch_patch_available": bv.is_invert_branch_patch_available(addr),
            "is_skip_and_return_zero_patch_available": bv.is_skip_and_return_zero_patch_available(addr),
            "is_skip_and_return_value_patch_available": bv.is_skip_and_return_value_patch_available(addr),
        }

    def _instruction_arch(self, bv, address):
        get_blocks = getattr(bv, "get_basic_blocks_at", None)
        arches = {str(block.arch): block.arch for block in get_blocks(address)} if get_blocks else {}
        if len(arches) > 1:
            raise RuntimeError(f"Ambiguous instruction architecture at {hex(address)}: {list(arches)}")
        arch = next(iter(arches.values()), bv.arch)
        if arch is None:
            raise RuntimeError("No architecture available")
        return arch

    def _write_bytes(self, bv, address, data):
        if not data:
            raise RuntimeError("Refusing an empty byte write")
        self._address_resolver(bv).require_mapped(address, len(data))
        before = bv.read(address, len(data))
        if len(before) != len(data):
            raise RuntimeError(f"Cannot read full write range at {hex(address)}")
        state = bv.begin_undo_actions()
        try:
            written = bv.write(address, data)
            if written != len(data) or bv.read(address, len(data)) != data:
                raise RuntimeError(f"Write verification failed at {hex(address)}: wrote {written}/{len(data)} bytes")
            self._check_job_cancelled()
            bv.commit_undo_actions(state)
        except Exception:
            bv.revert_undo_actions(state)
            raise
        return {"address": hex(address), "bytes_written": written, "before_hex": before.hex(), "data_hex": data.hex()}

    def _patch_assemble(self, selector, address_raw, asm_text: str):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address_raw)
        arch = self._instruction_arch(bv, addr)
        result = arch.assemble(asm_text, addr)
        if not isinstance(result, bytes) or not result:
            raise RuntimeError(f"Assembly failed at {hex(addr)}: {asm_text!r}")
        write = self._write_bytes(bv, addr, result)
        return {**write, "asm": asm_text, "arch": str(arch), "bytes_hex": result.hex(), "length": len(result)}

    def _patch_nop(self, selector, address_raw, length=None):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address_raw)
        arch = self._instruction_arch(bv, addr)
        size = bv.get_instruction_length(addr, arch) if length is None else int(length)
        if size <= 0:
            raise RuntimeError("NOP length must be positive")
        self._address_resolver(bv).require_mapped(addr, size)
        original = bv.read(addr, size)
        cursor = 0
        while cursor < size:
            self._check_job_cancelled()
            if str(self._instruction_arch(bv, addr + cursor)) != str(arch):
                raise RuntimeError("NOP range crosses instruction architectures")
            info = arch.get_instruction_info(original[cursor:], addr + cursor)
            if info is None or info.length <= 0 or cursor + info.length > size:
                raise RuntimeError("NOP range must end on an instruction boundary")
            cursor += info.length
        result = arch.convert_to_nop(original, addr)
        if result is None or len(result) != size:
            raise RuntimeError(f"convert_to_nop failed at {hex(addr)}")
        return {**self._write_bytes(bv, addr, result), "patched": True, "kind": "nop", "length": size}

    def _patch_always_branch(self, selector, address_raw):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address_raw)
        def _do():
            if not bv.always_branch(addr):
                raise RuntimeError(f"always_branch failed at {hex(addr)}")
            return {"address": hex(addr), "patched": True, "kind": "always_branch"}
        return _do()

    def _patch_invert_branch(self, selector, address_raw):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address_raw)
        def _do():
            if not bv.invert_branch(addr):
                raise RuntimeError(f"invert_branch failed at {hex(addr)}")
            return {"address": hex(addr), "patched": True, "kind": "invert_branch"}
        return _do()

    def _patch_never_branch(self, selector, address_raw):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address_raw)
        def _do():
            if not bv.never_branch(addr):
                raise RuntimeError(f"never_branch failed at {hex(addr)}")
            return {"address": hex(addr), "patched": True, "kind": "never_branch"}
        return _do()

    def _patch_skip_and_return(self, selector, address_raw, value: int):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address_raw)
        def _do():
            if not bv.skip_and_return_value(addr, value):
                raise RuntimeError(f"skip_and_return_value failed at {hex(addr)}")
            return {"address": hex(addr), "patched": True, "kind": "skip_and_return_value", "value": value}
        return _do()

    # =========================================================================
    # Memory operations
    # =========================================================================

    def _memory_read(self, selector, address_raw, length: int):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address_raw)
        if length < 1 or length > 65536:
            raise RuntimeError(f"length must be 1..65536, got {length}")
        self._address_resolver(bv).require_mapped(addr, length)
        data = bv.read(addr, length)
        if len(data) != length:
            raise AddressError(f"Short read at {hex(addr)}: {len(data)}/{length} bytes")
        return {"address": hex(addr), "length": len(data), "data_hex": data.hex()}

    def _memory_write(self, selector, address_raw, data_hex: str):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address_raw)
        data = bytes.fromhex(data_hex)
        return self._write_bytes(bv, addr, data)

    def _memory_insert(self, selector, address_raw, data_hex: str):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address_raw)
        data = bytes.fromhex(data_hex)
        result = bv.insert(addr, data)
        return {"address": hex(addr), "bytes_inserted": result, "data_hex": data_hex}

    def _memory_remove(self, selector, address_raw, length: int):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address_raw)
        result = bv.remove(addr, length)
        return {"address": hex(addr), "bytes_removed": result, "length": length}

    def _memory_reader_read(self, selector, address_raw, width: int, *, endian: str = "little"):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address_raw)
        if width not in (1, 2, 4, 8):
            raise RuntimeError(f"width must be 1, 2, 4, or 8; got {width}")
        def _do():
            reader = bn.BinaryReader(bv)
            reader.seek(addr)
            reader.endianness = bn.Endianness.LittleEndian if endian == "little" else bn.Endianness.BigEndian
            if width == 1:
                val = reader.read8()
            elif width == 2:
                val = reader.read16()
            elif width == 4:
                val = reader.read32()
            else:
                val = reader.read64()
            if val is None:
                raise RuntimeError(f"BinaryReader failed to read {width} bytes at {hex(addr)}")
            return {"address": hex(addr), "width": width, "endian": endian, "value": val, "value_hex": hex(val)}
        return _do()

    def _memory_writer_write(self, selector, address_raw, width: int, value: int, *, endian: str = "little"):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address_raw)
        if width not in (1, 2, 4, 8):
            raise RuntimeError(f"width must be 1, 2, 4, or 8; got {width}")
        data = value.to_bytes(width, byteorder=endian, signed=False)
        return {**self._write_bytes(bv, addr, data), "width": width, "endian": endian, "value": value, "written": True}

    # =========================================================================
    # Value analysis operations
    # =========================================================================

    def _value_query(self, selector, params):
        bv = self._resolve_view(selector)
        fn = self._find_function(bv, params["function_start"])
        index, address = params.get("instruction_index"), params.get("address")
        if (index is None) == (address is None):
            raise ValueError("Specify exactly one LLIL instruction_index or machine address")
        if index is not None:
            if not isinstance(index, int) or not 0 <= index < len(fn.llil):
                raise ValueError("LLIL instruction index is out of range")
            instruction = fn.llil[index]
            requested_address = None
        else:
            requested_address = self._address(bv, address)
            instruction = fn.get_low_level_il_at(requested_address)
        if instruction is None:
            raise AddressError("No LLIL instruction at this machine address; inspect analysis status and address coordinates")
        kind = params["kind"]
        methods = {"reg": "get_reg_value", "possible": "get_possible_reg_values",
                   "stack": "get_stack_contents", "flags": "get_flag_value"}
        if kind not in methods:
            raise ValueError(f"Unknown value query: {kind}")
        after = bool(params.get("after"))
        method = getattr(instruction, methods[kind] + ("_after" if after else ""), None)
        if method is None:
            raise RuntimeError(f"Installed Binary Ninja does not support {methods[kind]}")
        if kind == "stack":
            size = int(params.get("size", 8))
            if size not in (1, 2, 4, 8):
                raise ValueError("Stack value size must be 1, 2, 4 or 8")
            value = method(int(params["offset"]), size)
        else:
            operand = str(params["flag" if kind == "flags" else "register"])
            try:
                value = method(operand)
            except KeyError as exc:
                raise ValueError(f"Unknown {'flag' if kind == 'flags' else 'register'} {operand!r}; use names from `bn arch info`") from exc
        return {"function": hex(fn.start), "address": hex(instruction.address if requested_address is None else requested_address),
                "llil_address": hex(instruction.address),
                "instruction_index": int(instruction.instr_index), "level": "llil", "after": after,
                "kind": kind, "type": str(value.type), "value": str(value),
                "query": {key: params[key] for key in ("register", "flag", "offset", "size") if key in params}}

    def _resolve_value_function(self, bv, function_start_raw, addr: int):
        identifier = addr if function_start_raw is None else function_start_raw
        return self._find_function(bv, identifier)

    def _value_flags_at(self, selector, function_start_raw, address_raw):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address_raw)
        fn = self._resolve_value_function(bv, function_start_raw, addr)
        flags_read, flags_written = set(), set()
        for instruction in fn.get_lifted_ils_at(addr):
            index = instruction.instr_index
            flags_read.update(fn.get_flags_read_by_lifted_il_instruction(index))
            flags_written.update(fn.get_flags_written_by_lifted_il_instruction(index))
        return {
            "function": hex(fn.start), "address": hex(addr),
            "flags_read": sorted(flags_read), "flags_written": sorted(flags_written),
        }

    def _value_possible(self, selector, function_start_raw, address_raw, *, level: str = "hlil", ssa: bool = False):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address_raw)
        def _do():
            fn = self._resolve_value_function(bv, function_start_raw, addr)
            if level == "llil":
                il_func = fn.llil if not ssa else fn.llil.ssa_form
            elif level == "mlil":
                il_func = fn.mlil if not ssa else fn.mlil.ssa_form
            else:
                il_func = fn.hlil if not ssa else fn.hlil.ssa_form
            # Find the IL instruction at the given address
            for block in il_func:
                for instr in block:
                    if instr.address == addr:
                        pv = instr.possible_values
                        return {
                            "function": hex(fn.start),
                            "address": hex(addr),
                            "level": level,
                            "ssa": ssa,
                            "type": str(pv.type) if hasattr(pv, "type") else str(type(pv).__name__),
                            "value": str(pv),
                        }
            return {"function": hex(fn.start), "address": hex(addr), "level": level, "ssa": ssa, "type": "not_found", "value": None}
        return _do()

    def _value_reg(self, selector, function_start_raw, address_raw, register: str, *, after: bool = False):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address_raw)
        def _do():
            fn = self._resolve_value_function(bv, function_start_raw, addr)
            if after:
                val = fn.get_reg_value_after(addr, register)
            else:
                val = fn.get_reg_value_at(addr, register)
            return {
                "function": hex(fn.start),
                "address": hex(addr),
                "register": register,
                "after": after,
                "type": str(val.type) if hasattr(val, "type") else str(type(val).__name__),
                "value": val.value if hasattr(val, "value") else str(val),
            }
        return _do()

    def _value_stack(self, selector, function_start_raw, address_raw, stack_offset: int, size: int, *, after: bool = False):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address_raw)
        def _do():
            fn = self._resolve_value_function(bv, function_start_raw, addr)
            if after:
                val = fn.get_stack_contents_after(addr, stack_offset, size)
            else:
                val = fn.get_stack_contents_at(addr, stack_offset, size)
            return {
                "function": hex(fn.start),
                "address": hex(addr),
                "stack_offset": stack_offset,
                "size": size,
                "after": after,
                "type": str(val.type) if hasattr(val, "type") else str(type(val).__name__),
                "value": val.value if hasattr(val, "value") else str(val),
            }
        return _do()

    # =========================================================================
    # Search operations
    # =========================================================================

    def _search_bytes(self, selector, data_hex: str, *, start=None, end=None, limit=None):
        bv = self._resolve_view(selector)
        search_data = bytes.fromhex(data_hex)
        s = self._address(bv, start) if start is not None else bv.start
        e = self._address(bv, end, endpoint=True) if end is not None else bv.end
        max_results = int(limit) if limit else 1000
        def _do():
            results = []
            offset = s
            while offset < e and len(results) < max_results:
                self._check_job_cancelled()
                found = bv.find_next_data(offset, search_data)
                if found is None or found >= e:
                    break
                results.append(hex(found))
                offset = found + 1
            return {"pattern": data_hex, "start": hex(s), "end": hex(e), "matches": results, "count": len(results)}
        return _do()

    def _search_constant(self, selector, constant: int, *, start=None, end=None, limit=None):
        bv = self._resolve_view(selector)
        s = self._address(bv, start) if start is not None else bv.start
        e = self._address(bv, end, endpoint=True) if end is not None else bv.end
        max_results = int(limit) if limit else 1000
        def _do():
            results = []
            offset = s
            while offset < e and len(results) < max_results:
                self._check_job_cancelled()
                found = bv.find_next_constant(offset, constant)
                if found is None or found >= e:
                    break
                results.append(hex(found))
                offset = found + 1
            return {"constant": constant, "constant_hex": hex(constant), "start": hex(s), "end": hex(e), "matches": results, "count": len(results)}
        return _do()

    def _search_text(self, selector, query: str, *, start=None, end=None, regex: bool = False, limit=None, il_type="hlil"):
        bv = self._resolve_view(selector)
        s = self._address(bv, start) if start is not None else bv.start
        e = self._address(bv, end, endpoint=True) if end is not None else bv.end
        max_results = int(limit) if limit else 1000
        graph_names = {"hlil": "HighLevelILFunctionGraph", "mlil": "MediumLevelILFunctionGraph",
                       "llil": "LowLevelILFunctionGraph", "disasm": "NormalFunctionGraph"}
        if il_type not in graph_names:
            raise ValueError(f"Unknown IL type: {il_type}")
        def _do():
            results = []
            if regex:
                pattern = re.compile(query)
                seen = set()
                for fn in bv.functions:
                    self._check_job_cancelled()
                    if il_type == "disasm":
                        lines = ((address, "".join(str(t) for t in tokens)) for tokens, address in fn.instructions)
                    else:
                        il = getattr(fn, il_type)
                        if il is None:
                            continue
                        lines = ((instruction.address, str(instruction)) for block in il for instruction in block)
                    for address, text in lines:
                        self._check_job_cancelled()
                        if s <= address < e and address not in seen and pattern.search(text):
                            results.append(hex(address))
                            seen.add(address)
                            if len(results) >= max_results:
                                break
                    if len(results) >= max_results:
                        break
                return {"query": query, "regex": True, "il_type": il_type, "start": hex(s), "end": hex(e),
                        "matches": results, "count": len(results), "scope": "individual instruction text"}
            offset = s
            while offset < e and len(results) < max_results:
                self._check_job_cancelled()
                found = bv.find_next_text(offset, query, graph_type=getattr(bn.FunctionGraphType, graph_names[il_type]))
                if found is None or found >= e:
                    break
                results.append(hex(found))
                offset = found + 1
            return {"query": query, "regex": regex, "il_type": il_type, "start": hex(s), "end": hex(e), "matches": results, "count": len(results)}
        return _do()

    # =========================================================================
    # Architecture operations
    # =========================================================================

    def _arch_info(self, selector):
        bv = self._resolve_view(selector)
        def _do():
            arch = bv.arch
            platform = bv.platform
            return {
                "arch_name": str(arch) if arch else None,
                "address_size": arch.address_size if arch else None,
                "default_int_size": arch.default_int_size if arch else None,
                "max_instr_length": arch.max_instr_length if arch else None,
                "endianness": str(arch.endianness) if arch else None,
                "registers": list(arch.regs.keys()) if arch else [],
                "flags": list(arch.flags) if arch else [],
                "platform": str(platform) if platform else None,
            }
        return _do()

    def _arch_assemble(self, selector, asm_text: str, *, address=None, arch_name=None):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address) if address is not None else 0
        def _do():
            arch = bv.arch
            if arch_name:
                arch = bn.Architecture[arch_name]
                if arch is None:
                    raise RuntimeError(f"Unknown architecture: {arch_name}")
            if arch is None:
                raise RuntimeError("No architecture available")
            result = arch.assemble(asm_text, addr)
            if result is None or (isinstance(result, tuple) and result[0] is None):
                err = result[1] if isinstance(result, tuple) and len(result) > 1 else "unknown error"
                raise RuntimeError(f"Assembly failed: {err}")
            encoded = result[0] if isinstance(result, tuple) else result
            return {"asm": asm_text, "address": hex(addr), "bytes_hex": encoded.hex(), "length": len(encoded)}
        return _do()

    def _arch_disasm_bytes(self, selector, data_hex: str, *, address=None, arch_name=None, count=None):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address) if address is not None else 0
        data = bytes.fromhex(data_hex)
        if count is not None and int(count) < 0:
            raise ValueError("--count must be nonnegative")
        def _do():
            arch = bv.arch
            if arch_name:
                arch = bn.Architecture[arch_name]
                if arch is None:
                    raise RuntimeError(f"Unknown architecture: {arch_name}")
            if arch is None:
                raise RuntimeError("No architecture available")
            instructions = []
            offset = 0
            while offset < len(data) and (count is None or len(instructions) < int(count)):
                info = arch.get_instruction_info(data[offset:], addr + offset)
                text_result = arch.get_instruction_text(data[offset:], addr + offset)
                if info is None or text_result is None:
                    break
                tokens, length = text_result
                if length <= 0:
                    raise RuntimeError("Architecture returned a zero-length instruction")
                text = "".join(str(t) for t in tokens)
                instructions.append({
                    "address": hex(addr + offset),
                    "text": text,
                    "length": length,
                    "bytes_hex": data[offset:offset + length].hex(),
                })
                offset += length
            return {"data_hex": data_hex, "address": hex(addr), "instructions": instructions, "count": len(instructions)}
        return _do()

    # =========================================================================
    # Segments / Sections / Data Variables
    # =========================================================================

    def _list_segments(self, selector):
        bv = self._resolve_view(selector)
        def _do():
            return [
                {
                    "start": hex(seg.start),
                    "end": hex(seg.end),
                    "length": seg.length,
                    "data_offset": seg.data_offset,
                    "data_length": seg.data_length,
                    "readable": seg.readable,
                    "writable": seg.writable,
                    "executable": seg.executable,
                }
                for seg in bv.segments
            ]
        return _do()

    def _list_sections(self, selector):
        bv = self._resolve_view(selector)
        def _do():
            return [
                {
                    "name": name,
                    "start": hex(section.start),
                    "end": hex(section.end),
                    "length": section.length,
                    "type": str(section.type) if hasattr(section, "type") else None,
                    "semantics": str(section.semantics) if hasattr(section, "semantics") else None,
                }
                for name, section in bv.sections.items()
            ]
        return _do()

    def _list_data_vars(self, selector):
        bv = self._resolve_view(selector)
        def _do():
            result = []
            for addr in bv.data_vars:
                dv = bv.get_data_var_at(addr)
                result.append(
                    {
                        "address": hex(addr),
                        "type": str(dv.type) if dv.type else None,
                        "auto_discovered": dv.auto_discovered if hasattr(dv, "auto_discovered") else None,
                    }
                )
            return result
        return _do()

    # =========================================================================
    # Disassembly extended (linear, range)
    # =========================================================================

    def _disasm_linear(self, selector, address_raw, *, count: int = 20):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address_raw)
        def _do():
            lines = []
            settings = bn.DisassemblySettings()
            lv = bn.LinearViewObject.disassembly(bv, settings)
            cursor = bn.LinearViewCursor(lv)
            cursor.seek_to_address(addr)
            for _ in range(count):
                self._check_job_cancelled()
                cur_lines = cursor.lines
                if not cur_lines:
                    break
                for line in cur_lines:
                    tokens_text = "".join(str(t) for t in line.contents.tokens)
                    lines.append({
                        "address": hex(line.contents.address) if hasattr(line.contents, "address") else None,
                        "text": tokens_text,
                    })
                if not cursor.next():
                    break
            return lines[:count]
        return _do()

    def _disasm_range(self, selector, start_raw, end_raw):
        bv = self._resolve_view(selector)
        s = self._address(bv, start_raw)
        e = self._address(bv, end_raw, endpoint=True)
        def _do():
            lines = []
            arch = bv.arch
            if arch is None:
                raise RuntimeError("No architecture")
            offset = s
            while offset < e:
                self._check_job_cancelled()
                data = bv.read(offset, min(arch.max_instr_length, e - offset))
                if not data:
                    break
                text_result = arch.get_instruction_text(data, offset)
                if text_result is None:
                    offset += 1
                    continue
                tokens, length = text_result
                text = "".join(str(t) for t in tokens)
                lines.append({"address": hex(offset), "text": text, "length": length})
                offset += length
            return lines
        return _do()

    # =========================================================================
    # Function extended operations
    # =========================================================================

    def _function_containing(self, selector, address_raw):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address_raw)
        containing = self._functions_containing(bv, addr)
        if not containing:
            raise RuntimeError(self._function_not_found_hint(bv, hex(addr), addr))
        return [
            {
                "name": fn.name,
                "start": hex(fn.start),
                "end": hex(fn.start + fn.total_bytes) if hasattr(fn, "total_bytes") else None,
                "address_offset": hex(addr - fn.start),
            }
            for fn in containing
        ]

    def _function_basic_blocks(self, selector, identifier):
        bv = self._resolve_view(selector)
        fn = self._find_function(bv, identifier)
        def _do():
            return [
                {
                    "start": hex(bb.start),
                    "end": hex(bb.end),
                    "length": bb.length,
                    "incoming_edges": [hex(e.source.start) for e in bb.incoming_edges],
                    "outgoing_edges": [hex(e.target.start) for e in bb.outgoing_edges],
                    "instruction_count": bb.instruction_count if hasattr(bb, "instruction_count") else None,
                }
                for bb in fn.basic_blocks
            ]
        return _do()

    def _function_callers(self, selector, identifier):
        bv = self._resolve_view(selector)
        fn = self._find_function(bv, identifier)
        def _do():
            callers = []
            for ref in fn.callers:
                callers.append({
                    "name": ref.name,
                    "address": hex(ref.start),
                })
            return callers
        return _do()

    def _function_callees(self, selector, identifier):
        bv = self._resolve_view(selector)
        fn = self._find_function(bv, identifier)
        def _do():
            callees = []
            for ref in fn.callees:
                callees.append({
                    "name": ref.name if hasattr(ref, "name") else str(ref),
                    "address": hex(ref.start) if hasattr(ref, "start") else None,
                })
            return callees
        return _do()

    def _function_force_analysis(self, selector, identifier):
        bv = self._resolve_view(selector)
        fn = self._find_function(bv, identifier)
        def _do():
            # Record prior state
            was_skipped = getattr(fn, "analysis_skipped", False)
            prior_skip_reason = None
            if was_skipped:
                reason_enum = getattr(fn, "analysis_skip_reason", None)
                prior_skip_reason = reason_enum.name if reason_enum is not None else "unknown"

            # Match BN UI "Force Analysis": set NeverSkipFunctionAnalysis override
            try:
                from binaryninja.enums import FunctionAnalysisSkipOverride
                fn.analysis_skip_override = FunctionAnalysisSkipOverride.NeverSkipFunctionAnalysis
            except Exception:
                # Fallback for older API: set analysis_skipped = False
                fn.analysis_skipped = False

            fn.reanalyze()
            bv.update_analysis_and_wait()

            # Verify IL is now available
            il_available = False
            try:
                hlil = fn.hlil
                if hlil is not None:
                    instrs = list(hlil.instructions)
                    il_available = len(instrs) > 0
            except Exception:
                pass

            result = {
                "function": fn.name,
                "address": hex(fn.start),
                "reanalyzed": True,
                "il_available": il_available,
            }
            if was_skipped:
                result["prior_skip_reason"] = prior_skip_reason
            if not il_available:
                # Check if still analyzing or some other issue
                status = self._il_status(bv, fn)
                if status:
                    result["il_status"] = status
            return result
        return _do()

    def _function_ssa_var_def_use(self, selector, identifier, *, var_name: str, version: int, il_level: str = "mlil"):
        bv = self._resolve_view(selector)
        fn = self._find_function(bv, identifier)
        def _do():
            if il_level == "mlil":
                il_func = fn.mlil.ssa_form
            elif il_level == "hlil":
                il_func = fn.hlil.ssa_form
            else:
                il_func = fn.llil.ssa_form
            # Find the SSA variable
            ssa_var = None
            for var in il_func.vars:
                if str(var.var.name) == var_name:
                    ssa_var = bn.SSAVariable(var.var, version) if not isinstance(var, bn.SSAVariable) else var
                    break
            if ssa_var is None:
                # Try from non-SSA vars
                for var in fn.vars:
                    if str(var.name) == var_name:
                        ssa_var = bn.SSAVariable(var, version)
                        break
            if ssa_var is None:
                raise RuntimeError(f"Variable {var_name!r} not found in {fn.name}")
            definition = il_func.get_ssa_var_definition(ssa_var)
            uses = il_func.get_ssa_var_uses(ssa_var)
            return {
                "function": fn.name,
                "var": var_name,
                "version": version,
                "level": il_level,
                "definition": {"index": definition.instr_index, "address": hex(definition.address)} if definition else None,
                "uses": [{"index": u.instr_index, "address": hex(u.address)} for u in uses],
            }
        return _do()

    def _function_ssa_memory_def_use(self, selector, identifier, *, version: int, il_level: str = "mlil"):
        bv = self._resolve_view(selector)
        fn = self._find_function(bv, identifier)
        def _do():
            if il_level == "mlil":
                il_func = fn.mlil.ssa_form
            elif il_level == "hlil":
                il_func = fn.hlil.ssa_form
            else:
                il_func = fn.llil.ssa_form
            definition = il_func.get_ssa_memory_definition(version)
            uses = il_func.get_ssa_memory_uses(version)
            return {
                "function": fn.name,
                "memory_version": version,
                "level": il_level,
                "definition": {"index": definition.instr_index, "address": hex(definition.address)} if definition else None,
                "uses": [{"index": u.instr_index, "address": hex(u.address)} for u in uses],
            }
        return _do()

    def _function_var_refs(self, selector, identifier, *, var_name: str, il_level: str = "hlil"):
        bv = self._resolve_view(selector)
        fn = self._find_function(bv, identifier)
        def _do():
            target_var = None
            for var in fn.vars:
                if str(var.name) == var_name:
                    target_var = var
                    break
            if target_var is None:
                raise RuntimeError(f"Variable {var_name!r} not found in {fn.name}")
            if il_level == "hlil":
                refs = fn.get_hlil_var_refs(target_var)
            else:
                refs = fn.get_mlil_var_refs(target_var)
            return [
                {
                    "address": hex(ref.address) if hasattr(ref, "address") else None,
                    "type": str(type(ref).__name__),
                }
                for ref in refs
            ]
        return _do()

    def _function_var_refs_from(self, selector, identifier, *, address, il_level: str = "hlil"):
        bv = self._resolve_view(selector)
        fn = self._find_function(bv, identifier)
        addr = self._address(bv, address)
        def _do():
            if il_level == "hlil":
                refs = fn.get_hlil_var_refs_from(addr)
            else:
                refs = fn.get_mlil_var_refs_from(addr)
            return [
                {
                    "var": str(ref.var.name) if hasattr(ref, "var") else str(ref),
                    "address": hex(ref.address) if hasattr(ref, "address") else hex(addr),
                    "type": str(type(ref).__name__),
                }
                for ref in refs
            ]
        return _do()

    def _function_metadata_query(self, selector, identifier, key: str):
        bv = self._resolve_view(selector)
        fn = self._find_function(bv, identifier)
        def _do():
            val = fn.query_user_metadata(key)
            if val is None:
                return {"key": key, "found": False, "value": None}
            return {"key": key, "found": True, "value": val}
        return _do()

    def _function_metadata_store(self, selector, identifier, key: str, value):
        bv = self._resolve_view(selector)
        fn = self._find_function(bv, identifier)
        def _do():
            fn.store_user_metadata(key, value)
            return {"key": key, "stored": True}
        return _do()

    def _function_metadata_remove(self, selector, identifier, key: str):
        bv = self._resolve_view(selector)
        fn = self._find_function(bv, identifier)
        def _do():
            fn.remove_user_metadata(key)
            return {"key": key, "removed": True}
        return _do()

    # =========================================================================
    # Database operations
    # =========================================================================

    def _database_info(self, selector):
        bv = self._resolve_view(selector)
        def _do():
            db = bv.file.database
            if db is None:
                return {"has_database": False}
            return {
                "has_database": True,
                "global_keys": list(db.read_global_data("").keys()) if hasattr(db, "read_global_data") else [],
                "snapshot_count": len(db.snapshots) if hasattr(db, "snapshots") else 0,
                "current_snapshot": db.current_snapshot.id if hasattr(db, "current_snapshot") and db.current_snapshot else None,
            }
        return _do()

    def _database_read_global(self, selector, key: str):
        bv = self._resolve_view(selector)
        def _do():
            db = bv.file.database
            if db is None:
                raise RuntimeError("No database (save as .bndb first)")
            val = db.read_global(key)
            return {"key": key, "value": val}
        return _do()

    def _database_write_global(self, selector, key: str, value: str):
        bv = self._resolve_view(selector)
        def _do():
            db = bv.file.database
            if db is None:
                raise RuntimeError("No database (save as .bndb first)")
            db.write_global(key, value)
            return {"key": key, "written": True}
        return _do()

    def _database_snapshots(self, selector):
        bv = self._resolve_view(selector)
        def _do():
            db = bv.file.database
            if db is None:
                raise RuntimeError("No database (save as .bndb first)")
            return [
                {
                    "id": s.id,
                    "name": s.name if hasattr(s, "name") else None,
                    "is_auto_save": s.is_auto_save if hasattr(s, "is_auto_save") else None,
                }
                for s in db.snapshots
            ]
        return _do()

    def _database_save_auto_snapshot(self, selector):
        bv = self._resolve_view(selector)
        def _do():
            bv.file.create_database(bv.file.filename)
            return {"saved": True, "path": bv.file.filename}
        return _do()

    def _database_create_bndb(self, selector, path: str):
        bv = self._resolve_view(selector)
        def _do():
            bv.create_database(path)
            return {"created": True, "path": path}
        return _do()

    # =========================================================================
    # Type extended operations
    # =========================================================================

    def _type_rename(self, selector, old_name: str, new_name: str):
        bv = self._resolve_view(selector)
        def _do():
            t = bv.get_type_by_name(old_name)
            if t is None:
                raise RuntimeError(f"Type {old_name!r} not found")
            bv.rename_type(old_name, new_name)
            return {"old_name": old_name, "new_name": new_name, "renamed": True}
        return _do()

    def _type_undefine_user(self, selector, name: str):
        bv = self._resolve_view(selector)
        def _do():
            t = bv.get_type_by_name(name)
            if t is None:
                raise RuntimeError(f"Type {name!r} not found")
            bv.undefine_user_type(name)
            return {"name": name, "undefined": True}
        return _do()

    def _type_parse_string(self, selector, type_source: str):
        bv = self._resolve_view(selector)
        def _do():
            result = bv.parse_type_string(type_source)
            if result is None:
                raise RuntimeError(f"Failed to parse type string: {type_source!r}")
            parsed_type, name = result
            return {"source": type_source, "parsed": str(parsed_type), "name": str(name) if name else None}
        return _do()

    def _type_import_library_type(self, selector, name: str, *, lib_id=None):
        bv = self._resolve_view(selector)
        def _do():
            if lib_id:
                for lib in bv.type_libraries:
                    if lib.name == lib_id or str(lib.guid) == lib_id:
                        t = lib.get_named_type(name)
                        if t:
                            bv.define_user_type(name, t)
                            return {"name": name, "imported": True, "library": lib.name}
                raise RuntimeError(f"Type library {lib_id!r} not found or type {name!r} not in it")
            # Search all type libraries
            for lib in bv.type_libraries:
                t = lib.get_named_type(name)
                if t:
                    bv.define_user_type(name, t)
                    return {"name": name, "imported": True, "library": lib.name}
            raise RuntimeError(f"Type {name!r} not found in any type library")
        return _do()

    def _type_import_library_object(self, selector, name: str, *, lib_id=None):
        bv = self._resolve_view(selector)
        def _do():
            if lib_id:
                for lib in bv.type_libraries:
                    if lib.name == lib_id or str(lib.guid) == lib_id:
                        obj = lib.get_named_object(name)
                        if obj:
                            bv.define_user_type(name, obj)
                            return {"name": name, "imported": True, "library": lib.name}
                raise RuntimeError(f"Type library {lib_id!r} not found or object {name!r} not in it")
            for lib in bv.type_libraries:
                obj = lib.get_named_object(name)
                if obj:
                    bv.define_user_type(name, obj)
                    return {"name": name, "imported": True, "library": lib.name}
            raise RuntimeError(f"Object {name!r} not found in any type library")
        return _do()

    def _type_export_to_library(self, selector, type_library_id: str, type_source: str, *, name=None):
        bv = self._resolve_view(selector)
        def _do():
            target_lib = None
            for lib in bv.type_libraries:
                if lib.name == type_library_id or str(lib.guid) == type_library_id:
                    target_lib = lib
                    break
            if target_lib is None:
                raise RuntimeError(f"Type library {type_library_id!r} not found")
            result = bv.parse_type_string(type_source)
            if result is None:
                raise RuntimeError(f"Failed to parse type: {type_source!r}")
            parsed_type, parsed_name = result
            export_name = name or str(parsed_name)
            target_lib.add_named_type(export_name, parsed_type)
            return {"name": export_name, "exported": True, "library": target_lib.name}
        return _do()

    def _type_library_list(self, selector):
        bv = self._resolve_view(selector)
        def _do():
            return [
                {
                    "name": lib.name,
                    "guid": str(lib.guid) if hasattr(lib, "guid") else None,
                    "platform": str(lib.platform) if hasattr(lib, "platform") and lib.platform else None,
                }
                for lib in bv.type_libraries
            ]
        return _do()

    def _type_library_get(self, selector, type_library_id: str):
        bv = self._resolve_view(selector)
        def _do():
            for lib in bv.type_libraries:
                if lib.name == type_library_id or str(lib.guid) == type_library_id:
                    named_types = list(lib.named_types.keys()) if hasattr(lib, "named_types") else []
                    named_objects = list(lib.named_objects.keys()) if hasattr(lib, "named_objects") else []
                    return {
                        "name": lib.name,
                        "guid": str(lib.guid) if hasattr(lib, "guid") else None,
                        "named_types": [str(t) for t in named_types[:100]],
                        "named_objects": [str(o) for o in named_objects[:100]],
                        "type_count": len(named_types),
                        "object_count": len(named_objects),
                    }
            raise RuntimeError(f"Type library {type_library_id!r} not found")
        return _do()

    def _type_library_create(self, selector, name: str, *, path=None, add_to_view: bool = False):
        bv = self._resolve_view(selector)
        def _do():
            lib = bn.TypeLibrary.new(bv.arch, name)
            if path:
                lib.write_to_file(path)
            if add_to_view:
                bv.add_type_library(lib)
            return {"name": lib.name, "created": True, "added_to_view": add_to_view}
        return _do()

    def _type_library_load(self, selector, path: str, *, add_to_view: bool = True):
        bv = self._resolve_view(selector)
        def _do():
            lib = bn.TypeLibrary(path)
            if add_to_view:
                bv.add_type_library(lib)
            return {"name": lib.name, "loaded": True, "added_to_view": add_to_view}
        return _do()

    def _type_archive_list(self, selector):
        bv = self._resolve_view(selector)
        def _do():
            archives = bv.type_archives if hasattr(bv, "type_archives") else []
            return [
                {
                    "id": str(a.id) if hasattr(a, "id") else None,
                    "path": str(a.path) if hasattr(a, "path") else None,
                }
                for a in archives
            ]
        return _do()

    def _type_archive_get(self, selector, type_archive_id: str):
        bv = self._resolve_view(selector)
        def _do():
            for a in (bv.type_archives if hasattr(bv, "type_archives") else []):
                if str(getattr(a, "id", "")) == type_archive_id:
                    type_names = a.get_type_names_and_ids() if hasattr(a, "get_type_names_and_ids") else {}
                    return {
                        "id": str(a.id),
                        "path": str(a.path) if hasattr(a, "path") else None,
                        "types": [{"name": str(n), "id": str(i)} for n, i in list(type_names.items())[:100]],
                        "count": len(type_names),
                    }
            raise RuntimeError(f"Type archive {type_archive_id!r} not found")
        return _do()

    def _type_archive_create(self, selector, path: str, *, attach: bool = False):
        bv = self._resolve_view(selector)
        def _do():
            archive = bn.TypeArchive.create(path)
            if attach and hasattr(bv, "attach_type_archive"):
                bv.attach_type_archive(archive)
            return {"created": True, "path": path, "attached": attach}
        return _do()

    def _type_archive_open(self, selector, path: str, *, attach: bool = False):
        bv = self._resolve_view(selector)
        def _do():
            archive = bn.TypeArchive.open(path)
            if attach and hasattr(bv, "attach_type_archive"):
                bv.attach_type_archive(archive)
            return {"opened": True, "path": path, "attached": attach}
        return _do()

    def _type_archive_pull(self, selector, type_archive_id: str, names: list):
        bv = self._resolve_view(selector)
        def _do():
            for a in (bv.type_archives if hasattr(bv, "type_archives") else []):
                if str(getattr(a, "id", "")) == type_archive_id:
                    pulled = []
                    for name in names:
                        t = a.get_type_by_name(name) if hasattr(a, "get_type_by_name") else None
                        if t:
                            bv.define_user_type(name, t)
                            pulled.append(name)
                    return {"pulled": pulled, "count": len(pulled)}
            raise RuntimeError(f"Type archive {type_archive_id!r} not found")
        return _do()

    def _type_archive_push(self, selector, type_archive_id: str, names: list):
        bv = self._resolve_view(selector)
        def _do():
            for a in (bv.type_archives if hasattr(bv, "type_archives") else []):
                if str(getattr(a, "id", "")) == type_archive_id:
                    pushed = []
                    for name in names:
                        t = bv.get_type_by_name(name)
                        if t and hasattr(a, "add_type"):
                            a.add_type(name, t)
                            pushed.append(name)
                    return {"pushed": pushed, "count": len(pushed)}
            raise RuntimeError(f"Type archive {type_archive_id!r} not found")
        return _do()

    # =========================================================================
    # Annotation operations
    # =========================================================================

    def _tag_scope(self, bv, function, address):
        if address is None and function is None:
            raise ValueError("Tag operation requires a scope: pass --function <id> or --address <addr>")
        addr = self._address(bv, address) if address is not None else None
        if function is not None:
            return addr, [self._find_function(bv, function)]
        return addr, self._functions_containing(bv, addr)

    def _annotation_add_tag(self, selector, address, tag_type: str, data: str, *, function=None):
        bv = self._resolve_view(selector)
        addr, functions = self._tag_scope(bv, function, address)
        if len(functions) > 1:
            raise ValueError("Multiple functions contain this address; select one with --function")
        if bv.get_tag_type(tag_type) is None:
            bv.create_tag_type(tag_type, "⭐")
        result = {"tag_type": tag_type, "data": data, "added": True}
        if addr is not None:
            result["address"] = hex(addr)
        if functions:
            fn = functions[0]
            fn.add_tag(tag_type, data, addr)
            if function is not None:
                result.update(function=fn.name, function_start=hex(fn.start))
        else:
            bv.add_tag(addr, tag_type, data)
        return result

    def _annotation_get_tags(self, selector, address, *, function=None):
        bv = self._resolve_view(selector)
        addr, functions = self._tag_scope(bv, function, address)
        if addr is None:
            tags = functions[0].get_function_tags()
            scope = "function"
        else:
            tags = [tag for fn in functions for tag in fn.get_tags_at(addr)]
            if function is None:
                tags.extend(bv.get_tags_at(addr))
            scope = "address"
        return [{"type": tag.type.name, "data": tag.data, "scope": scope} for tag in tags]

    def _annotation_create_tag_type(self, selector, tag_type: str, icon=None):
        bv = self._resolve_view(selector)
        def _do():
            resolved_icon = str(icon) if icon else "⭐"
            existing = bv.get_tag_type(tag_type) if hasattr(bv, "get_tag_type") else None
            if existing is not None:
                return {
                    "tag_type": getattr(existing, "name", tag_type),
                    "icon": getattr(existing, "icon", None),
                    "created": False,
                }
            if not hasattr(bv, "create_tag_type"):
                raise RuntimeError("create_tag_type not available")
            created = bv.create_tag_type(tag_type, resolved_icon)
            return {
                "tag_type": getattr(created, "name", tag_type),
                "icon": getattr(created, "icon", resolved_icon),
                "created": True,
            }
        return _do()

    def _annotation_list_tag_types(self, selector):
        bv = self._resolve_view(selector)
        def _do():
            raw = getattr(bv, "tag_types", None) or {}
            pairs = raw.items() if hasattr(raw, "items") else []
            entries = []
            for name, value in pairs:
                candidates = value if isinstance(value, (list, tuple)) else [value]
                for tag_type in candidates:
                    entries.append(
                        {
                            "name": getattr(tag_type, "name", name),
                            "icon": getattr(tag_type, "icon", None),
                            "visible": getattr(tag_type, "visible", None),
                        }
                    )
            entries.sort(key=lambda entry: str(entry["name"]))
            return entries
        return _do()

    def _annotation_remove_tag(self, selector, tag_type: str, *, function=None, address=None):
        bv = self._resolve_view(selector)
        addr, functions = self._tag_scope(bv, function, address)
        removed = 0
        if addr is None:
            fn = functions[0]
            for tag in fn.get_function_tags(auto=False, tag_type=tag_type):
                fn.remove_user_function_tag(tag)
                removed += 1
        else:
            for fn in functions:
                for tag in fn.get_tags_at(addr, auto=False):
                    if tag.type.name == tag_type:
                        fn.remove_user_address_tag(addr, tag)
                        removed += 1
            if function is None:
                for tag in bv.get_tags_at(addr, auto=False):
                    if tag.type.name == tag_type:
                        bv.remove_user_data_tag(addr, tag)
                        removed += 1
        return {
            "tag_type": tag_type,
            "function": functions[0].name if len(functions) == 1 else None,
            "address": hex(addr) if addr is not None else None,
            "removed": removed,
        }

    def _annotation_define_data_var(self, selector, address, *, type_name=None, name=None, width=None):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address)
        def _do():
            if type_name:
                t = bv.parse_type_string(type_name)
                if t is None:
                    raise RuntimeError(f"Failed to parse type: {type_name!r}")
                bv.define_user_data_var(addr, t[0])
            elif width:
                bv.define_user_data_var(addr, bn.Type.int(int(width)))
            else:
                bv.define_user_data_var(addr, bn.Type.int(4))
            if name:
                sym = bn.Symbol(bn.SymbolType.DataSymbol, addr, name)
                bv.define_user_symbol(sym)
            return {"address": hex(addr), "defined": True, "type": type_name, "name": name}
        return _do()

    def _annotation_undefine_data_var(self, selector, address):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address)
        def _do():
            bv.undefine_user_data_var(addr)
            return {"address": hex(addr), "undefined": True}
        return _do()

    def _annotation_define_symbol(self, selector, address, name: str, *, symbol_type=None):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address)
        def _do():
            st = bn.SymbolType.DataSymbol
            if symbol_type:
                mapping = {
                    "function": bn.SymbolType.FunctionSymbol,
                    "data": bn.SymbolType.DataSymbol,
                    "import": bn.SymbolType.ImportedFunctionSymbol,
                    "external": bn.SymbolType.ExternalSymbol,
                }
                st = mapping.get(symbol_type, bn.SymbolType.DataSymbol)
            sym = bn.Symbol(st, addr, name)
            bv.define_user_symbol(sym)
            return {"address": hex(addr), "name": name, "symbol_type": str(st), "defined": True}
        return _do()

    def _annotation_undefine_symbol(self, selector, address):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address)
        def _do():
            sym = bv.get_symbol_at(addr)
            if sym is None:
                raise RuntimeError(f"No symbol at {hex(addr)}")
            bv.undefine_user_symbol(sym)
            return {"address": hex(addr), "undefined": True}
        return _do()

    def _annotation_rename_data_var(self, selector, address, new_name: str):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address)
        def _do():
            sym = bv.get_symbol_at(addr)
            if sym:
                bv.undefine_user_symbol(sym)
            new_sym = bn.Symbol(bn.SymbolType.DataSymbol, addr, new_name)
            bv.define_user_symbol(new_sym)
            return {"address": hex(addr), "new_name": new_name, "renamed": True}
        return _do()

    # =========================================================================
    # Undo operations
    # =========================================================================

    def _undo_begin(self, selector):
        bv = self._resolve_view(selector)
        def _do():
            bv.begin_undo_actions()
            return {"begun": True}
        return _do()

    def _undo_commit(self, selector):
        bv = self._resolve_view(selector)
        def _do():
            bv.commit_undo_actions()
            return {"committed": True}
        return _do()

    def _undo_revert(self, selector):
        bv = self._resolve_view(selector)
        def _do():
            bv.revert_undo_actions()
            return {"reverted": True}
        return _do()

    def _undo_undo(self, selector):
        bv = self._resolve_view(selector)
        def _do():
            bv.undo()
            return {"undone": True}
        return _do()

    def _undo_redo(self, selector):
        bv = self._resolve_view(selector)
        def _do():
            bv.redo()
            return {"redone": True}
        return _do()

    # =========================================================================
    # UIDF (User IL Data Flow) operations
    # =========================================================================

    def _uidf_set(self, selector, params):
        bv = self._resolve_view(selector)
        fn_start = self._address(bv, params["function_start"])
        address = self._address(bv, params["address"])
        var_name = str(params["var_name"])
        def_site_addr = self._address(bv, params.get("def_site_address", address))
        value_raw = params["value"]
        state_raw = params.get("state", "ConstantValue")
        def _do():
            fn = bv.get_function_at(fn_start)
            if fn is None:
                raise RuntimeError(f"No function at {hex(fn_start)}")
            target_var = None
            for var in fn.vars:
                if str(var.name) == var_name:
                    target_var = var
                    break
            if target_var is None:
                raise RuntimeError(f"Variable {var_name!r} not found")
            from binaryninja import PossibleValueSet, RegisterValueType
            state_map = {
                "ConstantValue": RegisterValueType.ConstantValue,
                "ConstantPointerValue": RegisterValueType.ConstantPointerValue,
            }
            pv = PossibleValueSet.constant(int(value_raw))
            def_site = bn.ArchAndAddr(fn.arch, def_site_addr) if hasattr(bn, "ArchAndAddr") else None
            if def_site and hasattr(fn, "set_user_var_value"):
                fn.set_user_var_value(target_var, def_site, pv)
            elif hasattr(fn, "set_user_var_value"):
                fn.set_user_var_value(target_var, fn.arch, address, pv)
            else:
                raise RuntimeError("set_user_var_value not available")
            return {"function": fn.name, "var": var_name, "value": value_raw, "set": True}
        return _do()

    def _uidf_clear(self, selector, params):
        bv = self._resolve_view(selector)
        fn_start = self._address(bv, params["function_start"])
        address = self._address(bv, params["address"])
        var_name = str(params["var_name"])
        def _do():
            fn = bv.get_function_at(fn_start)
            if fn is None:
                raise RuntimeError(f"No function at {hex(fn_start)}")
            target_var = None
            for var in fn.vars:
                if str(var.name) == var_name:
                    target_var = var
                    break
            if target_var is None:
                raise RuntimeError(f"Variable {var_name!r} not found")
            if hasattr(fn, "clear_user_var_value"):
                def_site = bn.ArchAndAddr(fn.arch, address) if hasattr(bn, "ArchAndAddr") else None
                if def_site:
                    fn.clear_user_var_value(target_var, def_site)
                else:
                    fn.clear_user_var_value(target_var, fn.arch, address)
            else:
                raise RuntimeError("clear_user_var_value not available")
            return {"function": fn.name, "var": var_name, "cleared": True}
        return _do()

    def _uidf_list(self, selector, function_start):
        bv = self._resolve_view(selector)
        fn_start = self._address(bv, function_start)
        def _do():
            fn = bv.get_function_at(fn_start)
            if fn is None:
                raise RuntimeError(f"No function at {hex(fn_start)}")
            if not hasattr(fn, "user_var_values") or fn.user_var_values is None:
                return []
            results = []
            for var, val_info in fn.user_var_values.items() if hasattr(fn.user_var_values, "items") else []:
                results.append({
                    "var": str(var.name) if hasattr(var, "name") else str(var),
                    "info": str(val_info),
                })
            return results
        return _do()

    def _uidf_parse(self, selector, value: str, state: str):
        bv = self._resolve_view(selector)
        def _do():
            from binaryninja import PossibleValueSet, RegisterValueType
            state_map = {
                "ConstantValue": RegisterValueType.ConstantValue,
                "ConstantPointerValue": RegisterValueType.ConstantPointerValue,
                "UndeterminedValue": RegisterValueType.UndeterminedValue,
            }
            rv_type = state_map.get(state)
            if rv_type is None:
                return {"value": value, "state": state, "valid": False, "error": f"Unknown state: {state}"}
            return {"value": value, "state": state, "valid": True, "parsed_value": int(value, 0) if isinstance(value, str) else value}
        return _do()

    def _uidf_from_address(self, selector, address):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address)
        def _do():
            fn = self._find_function(bv, addr)
            values = {}
            if hasattr(fn, "get_all_user_var_values"):
                try:
                    values = fn.get_all_user_var_values() or {}
                except Exception:
                    values = {}
            if not values and hasattr(fn, "user_var_values"):
                values = fn.user_var_values or {}
            variables = []
            for var, def_sites in (values.items() if hasattr(values, "items") else []):
                definitions = []
                for site, value in (def_sites.items() if hasattr(def_sites, "items") else []):
                    site_address = site.addr
                    definitions.append(
                        {
                            "address": hex(site_address) if isinstance(site_address, int) else None,
                            "arch": str(getattr(site, "arch", "") or "") or None,
                            "value": _value_text(value),
                            "at_address": site_address == addr,
                        }
                    )
                definitions.sort(key=lambda item: item["address"] or "")
                variables.append(
                    {
                        "var": str(getattr(var, "name", var)),
                        "definitions": definitions,
                    }
                )
            variables.sort(key=lambda item: item["var"])
            return {
                "address": hex(addr),
                "function": fn.name,
                "function_start": hex(fn.start),
                "variables": variables,
            }
        return _do()

    # =========================================================================
    # Loader operations
    # =========================================================================

    def _loader_settings_get(self, selector, type_name: str | None = None):
        bv = self._resolve_view(selector)
        def _do():
            resolved = type_name or str(getattr(bv, "view_type", "") or "")
            if not resolved:
                raise RuntimeError(
                    "type_name is required: pass a view type (e.g. ELF) explicitly"
                )
            settings = bn.Settings(f"loader.{resolved}")
            keys = settings.keys() if hasattr(settings, "keys") else []
            result = {}
            for key in keys:
                result[key] = settings.get_string(key) if hasattr(settings, "get_string") else None
            return {"type_name": resolved, "settings": result}
        return _do()

    def _loader_settings_set(self, selector, type_name: str, key: str, value):
        bv = self._resolve_view(selector)
        def _do():
            settings = bn.Settings(f"loader.{type_name}")
            if isinstance(value, bool):
                settings.set_bool(key, value)
            elif isinstance(value, int):
                settings.set_integer(key, value)
            else:
                settings.set_string(key, str(value))
            return {"type_name": type_name, "key": key, "set": True}
        return _do()

    def _loader_settings_types(self, selector):
        bv = self._resolve_view(selector)
        def _do():
            return {"view_type": bv.view_type, "available_view_types": [str(v) for v in bv.available_view_types] if hasattr(bv, "available_view_types") else []}
        return _do()

    def _loader_rebase(self, selector, address, *, force: bool = False):
        if self.mode != "headless":
            raise RuntimeError("CLI rebase requires a headless target; GUI views must be rebased through Binary Ninja")
        bv = self._resolve_view(selector)
        addr = self._address(bv, address)
        if not hasattr(bv, "rebase"):
            raise RuntimeError("BinaryView does not support rebase")
        old_id = self.targets.target_id_for(bv)
        old_view_id = self.targets.view_id_for(bv)
        self._check_job_cancelled()
        new_view = bv.rebase(addr, force=force)
        if new_view is None:
            raise RuntimeError("BinaryView.rebase failed; no replacement target was registered")
        # The native API returns a new view sharing the same FileMetadata. Closing
        # the old file here would also close the replacement view.
        new_view.update_analysis_and_wait()
        if new_view.start != addr:
            raise RuntimeError(f"Rebase returned unexpected view start {hex(new_view.start)} instead of {hex(addr)}")
        with self.targets._lock:
            was_active = self.targets._active_view_id == old_view_id
            record = self.targets.register(new_view)
            self.targets.unregister(old_view_id)
            if was_active:
                self.targets.set_active(record.view_id)
        removed_maps = list(self._address_spaces.pop(old_id, {}))
        job = getattr(self._job_local, "record", None)
        if job is not None:
            job.bv = new_view
        return {"rebased": True, "new_base": hex(new_view.image_base), "new_start": hex(new_view.start),
                "previous_target_id": old_id, "target_id": record.target_id(),
                "removed_address_maps": removed_maps, "target": self._target_info(record.target_id())}

    # =========================================================================
    # External library/location operations
    # =========================================================================

    def _external_library_add(self, selector, name: str):
        bv = self._resolve_view(selector)
        def _do():
            lib = bv.add_external_library(name, None) if hasattr(bv, "add_external_library") else None
            if lib is None:
                raise RuntimeError("add_external_library not available or failed")
            return {"name": name, "added": True}
        return _do()

    def _external_library_list(self, selector):
        bv = self._resolve_view(selector)
        def _do():
            libs = bv.external_libraries if hasattr(bv, "external_libraries") else []
            return [
                {
                    "name": lib.name if hasattr(lib, "name") else str(lib),
                    "backing_file": str(lib.backing_file) if hasattr(lib, "backing_file") and lib.backing_file else None,
                }
                for lib in libs
            ]
        return _do()

    def _external_library_remove(self, selector, name: str):
        bv = self._resolve_view(selector)
        def _do():
            if hasattr(bv, "remove_external_library"):
                bv.remove_external_library(name)
            else:
                raise RuntimeError("remove_external_library not available")
            return {"name": name, "removed": True}
        return _do()

    def _external_location_add(self, selector, params):
        bv = self._resolve_view(selector)
        source_addr = self._address(bv, params["source_address"])
        library_name = params.get("library_name")
        target_symbol = params.get("target_symbol")
        target_address = params.get("target_address")
        def _do():
            if hasattr(bv, "add_external_location"):
                lib = None
                if library_name:
                    for l in (bv.external_libraries if hasattr(bv, "external_libraries") else []):
                        if (hasattr(l, "name") and l.name == library_name):
                            lib = l
                            break
                bv.add_external_location(source_addr, lib, target_symbol, _parse_address(target_address) if target_address else None)
            else:
                raise RuntimeError("add_external_location not available")
            return {"source_address": hex(source_addr), "added": True}
        return _do()

    def _external_location_get(self, selector, source_address):
        bv = self._resolve_view(selector)
        addr = self._address(bv, source_address)
        def _do():
            if hasattr(bv, "get_external_location_at"):
                loc = bv.get_external_location_at(addr)
                if loc is None:
                    return {"address": hex(addr), "found": False}
                return {
                    "address": hex(addr),
                    "found": True,
                    "library": loc.library.name if hasattr(loc, "library") and loc.library else None,
                    "symbol": loc.symbol if hasattr(loc, "symbol") else None,
                    "target_address": hex(loc.target_address) if hasattr(loc, "target_address") and loc.target_address else None,
                }
            raise RuntimeError("get_external_location_at not available")
        return _do()

    def _external_location_list(self, selector):
        bv = self._resolve_view(selector)
        entries = []
        for location in sorted(bv.get_external_locations(), key=lambda loc: loc.source_symbol.address):
            target = location.target_address
            library = location.library
            entries.append({
                "source_address": hex(location.source_symbol.address),
                "library": library.name if library is not None else None,
                "symbol": location.target_symbol,
                "target_address": hex(target) if target is not None else None,
            })
        return entries

    def _external_location_remove(self, selector, source_address):
        bv = self._resolve_view(selector)
        addr = self._address(bv, source_address)
        def _do():
            if hasattr(bv, "remove_external_location"):
                bv.remove_external_location(addr)
            else:
                raise RuntimeError("remove_external_location not available")
            return {"address": hex(addr), "removed": True}
        return _do()

    # =========================================================================
    # Analysis operations
    # =========================================================================

    def _analysis_status(self, selector):
        bv = self._resolve_view(selector)
        def _do():
            progress = bv.analysis_progress
            state_name = progress.state.name if hasattr(progress, "state") and hasattr(progress.state, "name") else str(progress)
            count = progress.count if hasattr(progress, "count") else 0
            total = progress.total if hasattr(progress, "total") else 0
            done = (state_name == "Idle" or (total > 0 and count >= total))
            return {
                "state": state_name,
                "count": count,
                "total": total,
                "done": done,
            }
        return _do()

    def _analysis_progress(self, selector):
        bv = self._resolve_view(selector)
        def _do():
            progress = bv.analysis_progress
            state_name = progress.state.name if hasattr(progress, "state") and hasattr(progress.state, "name") else str(progress)
            count = progress.count if hasattr(progress, "count") else 0
            total = progress.total if hasattr(progress, "total") else 0
            done = (state_name == "Idle" or (total > 0 and count >= total))
            return {
                "state": state_name,
                "count": count,
                "total": total,
                "done": done,
            }
        return _do()

    def _analysis_abort(self, selector):
        bv = self._resolve_view(selector)
        def _do():
            bv.abort_analysis()
            return {"aborted": True}
        return _do()

    def _analysis_set_hold(self, selector, hold: bool):
        bv = self._resolve_view(selector)
        def _do():
            if hold:
                bv.abort_analysis()
            return {"hold": hold, "set": True}
        return _do()

    def _analysis_update(self, selector):
        bv = self._resolve_view(selector)
        def _do():
            bv.update_analysis()
            return {"update_requested": True}
        return _do()

    def _analysis_update_and_wait(self, selector):
        bv = self._resolve_view(selector)
        def _do():
            bv.update_analysis_and_wait()
            return {"updated": True}
        return _do()

    # =========================================================================
    # Metadata (view-level) operations
    # =========================================================================

    def _metadata_query(self, selector, key: str):
        bv = self._resolve_view(selector)
        def _do():
            try:
                val = bv.query_metadata(key)
            except KeyError:
                return {"key": key, "found": False, "value": None}
            if val is None:
                return {"key": key, "found": False, "value": None}
            return {"key": key, "found": True, "value": str(val)}
        return _do()

    def _metadata_store(self, selector, key: str, value):
        bv = self._resolve_view(selector)
        def _do():
            bv.store_metadata(key, value)
            return {"key": key, "stored": True}
        return _do()

    def _metadata_keys(self, selector):
        bv = self._resolve_view(selector)
        def _do():
            metadata = getattr(bv, "metadata", None)
            if metadata is None:
                return []
            if hasattr(metadata, "get_dict"):
                data = metadata.get_dict() or {}
            else:
                data = metadata
            keys = list(data.keys()) if hasattr(data, "keys") else []
            return sorted(str(key) for key in keys)
        return _do()

    def _metadata_remove(self, selector, key: str):
        bv = self._resolve_view(selector)
        def _do():
            try:
                bv.remove_metadata(key)
            except KeyError:
                return {"key": key, "removed": False, "error": "key not found"}
            return {"key": key, "removed": True}
        return _do()

    # =========================================================================
    # Data typed at address
    # =========================================================================

    def _data_typed_at(self, selector, address):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address)
        def _do():
            dv = bv.get_data_var_at(addr)
            if dv is None:
                return {"address": hex(addr), "found": False}
            return {
                "address": hex(addr),
                "found": True,
                "type": str(dv.type) if dv.type else None,
                "auto_discovered": dv.auto_discovered if hasattr(dv, "auto_discovered") else None,
                "name": str(dv.name) if hasattr(dv, "name") else None,
            }
        return _do()

    # =========================================================================
    # Xref extended operations
    # =========================================================================

    def _xref_code_refs_from(self, selector, address, *, length=None):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address)
        def _do():
            if length:
                refs = bv.get_code_refs_from(addr, int(length))
            else:
                refs = bv.get_code_refs_from(addr)
            return [
                {
                    "address": hex(ref) if isinstance(ref, int) else hex(ref.address) if hasattr(ref, "address") else str(ref),
                }
                for ref in refs
            ]
        return _do()

    def _xref_code_refs_to(self, selector, address, *, limit: int = 100):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address)
        def _do():
            refs = list(bv.get_code_refs(addr))[:limit]
            return [
                {
                    "address": hex(ref.address) if hasattr(ref, "address") else str(ref),
                    "function": ref.function.name if hasattr(ref, "function") and ref.function else None,
                }
                for ref in refs
            ]
        return _do()

    def _xref_data_refs_from(self, selector, address, *, length=None):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address)
        def _do():
            if length:
                refs = bv.get_data_refs_from(addr, int(length))
            else:
                refs = bv.get_data_refs_from(addr)
            return [{"address": hex(ref)} for ref in refs]
        return _do()

    def _xref_data_refs_to(self, selector, address, *, limit: int = 100):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address)
        def _do():
            refs = list(bv.get_data_refs(addr))[:limit]
            return [{"address": hex(ref)} for ref in refs]
        return _do()

    def _xref_type_refs(self, selector, name: str, *, limit=None):
        bv = self._resolve_view(selector)
        def _do():
            if not hasattr(bv, "get_type_refs_for_type"):
                raise RuntimeError("get_type_refs_for_type not available")
            refs = bv.get_type_refs_for_type(name, int(limit) if limit else None)
            entries = []
            for ref in refs or []:
                ref_name = getattr(ref, "name", None)
                offset = getattr(ref, "offset", None)
                ref_type = getattr(ref, "ref_type", None)
                entries.append(
                    {
                        "type": str(ref_name) if ref_name is not None else str(ref),
                        "offset": hex(offset) if isinstance(offset, int) else None,
                        "reference_type": str(ref_type) if ref_type is not None else None,
                    }
                )
            return entries
        return _do()

    # =========================================================================
    # IL extended operations
    # =========================================================================

    def _il_address_to_index(self, selector, function_start, address, *, level: str = "hlil"):
        bv = self._resolve_view(selector)
        fn_start = self._address(bv, function_start)
        addr = self._address(bv, address)
        def _do():
            fn = bv.get_function_at(fn_start)
            if fn is None:
                raise RuntimeError(f"No function at {hex(fn_start)}")
            if level == "hlil":
                il = fn.hlil
            elif level == "mlil":
                il = fn.mlil
            else:
                il = fn.llil
            # find instruction at address
            for i, instr in enumerate(il.instructions):
                if instr.address == addr:
                    return {"function": fn.name, "address": hex(addr), "index": i, "level": level}
            return {"function": fn.name, "address": hex(addr), "index": None, "level": level, "note": "no instruction at exact address"}
        return _do()

    def _il_index_to_address(self, selector, function_start, index: int, *, level: str = "hlil"):
        bv = self._resolve_view(selector)
        fn_start = self._address(bv, function_start)
        def _do():
            fn = bv.get_function_at(fn_start)
            if fn is None:
                raise RuntimeError(f"No function at {hex(fn_start)}")
            if level == "hlil":
                il = fn.hlil
            elif level == "mlil":
                il = fn.mlil
            else:
                il = fn.llil
            if index < 0 or index >= len(il):
                raise RuntimeError(f"Index {index} out of range (0..{len(il)-1})")
            instr = il[index]
            return {"function": fn.name, "index": index, "address": hex(instr.address), "level": level}
        return _do()

    def _il_instruction_by_addr(self, selector, function_start, address, *, level: str = "hlil"):
        bv = self._resolve_view(selector)
        fn_start = self._address(bv, function_start)
        addr = self._address(bv, address)
        def _do():
            fn = bv.get_function_at(fn_start)
            if fn is None:
                raise RuntimeError(f"No function at {hex(fn_start)}")
            if level == "hlil":
                il = fn.hlil
            elif level == "mlil":
                il = fn.mlil
            else:
                il = fn.llil
            for i, instr in enumerate(il.instructions):
                if instr.address == addr:
                    return {
                        "function": fn.name,
                        "address": hex(addr),
                        "index": i,
                        "level": level,
                        "text": str(instr),
                        "operation": str(instr.operation) if hasattr(instr, "operation") else None,
                    }
            raise RuntimeError(f"No {level} instruction at {hex(addr)} in {fn.name}")
        return _do()

    # =========================================================================
    # Section/Segment user operations
    # =========================================================================

    def _section_add_user(self, selector, params):
        bv = self._resolve_view(selector)
        name = str(params["name"])
        start = self._address(bv, params["start"])
        length = int(params["length"])
        def _do():
            bv.add_user_section(name, start, length)
            return {"name": name, "start": hex(start), "length": length, "added": True}
        return _do()

    def _section_remove_user(self, selector, name: str):
        bv = self._resolve_view(selector)
        def _do():
            bv.remove_user_section(name)
            return {"name": name, "removed": True}
        return _do()

    def _segment_add_user(self, selector, params):
        bv = self._resolve_view(selector)
        start = self._address(bv, params["start"])
        length = int(params["length"])
        data_offset = int(params.get("data_offset", 0))
        data_length = int(params.get("data_length", length))
        flags = int(params.get("flags", 0))
        def _do():
            bv.add_user_segment(start, length, data_offset, data_length, flags)
            return {"start": hex(start), "length": length, "added": True}
        return _do()

    def _segment_remove_user(self, selector, start, *, length=None):
        bv = self._resolve_view(selector)
        s = self._address(bv, start)
        def _do():
            if length:
                bv.remove_user_segment(s, int(length))
            else:
                bv.remove_user_segment(s, 0)
            return {"start": hex(s), "removed": True}
        return _do()

    # =========================================================================
    # Debug info operations
    # =========================================================================

    def _debug_parsers(self, selector):
        bv = self._resolve_view(selector)
        def _do():
            parsers = bn.DebugInfoParser.get_parsers_for_view(bv) if hasattr(bn, "DebugInfoParser") else []
            return [{"name": p.name if hasattr(p, "name") else str(p)} for p in parsers]
        return _do()

    def _debug_parse_and_apply(self, selector, *, parser_name=None, debug_path=None):
        bv = self._resolve_view(selector)
        def _do():
            if parser_name:
                parser = None
                for p in (bn.DebugInfoParser.get_parsers_for_view(bv) if hasattr(bn, "DebugInfoParser") else []):
                    if (hasattr(p, "name") and p.name == parser_name):
                        parser = p
                        break
                if parser is None:
                    raise RuntimeError(f"Debug info parser {parser_name!r} not found")
                debug_info = parser.parse_debug_info(bv, debug_path) if debug_path else parser.parse_debug_info(bv)
            else:
                debug_info = bv.debug_info
            if debug_info and hasattr(bv, "apply_debug_info"):
                bv.apply_debug_info(debug_info)
                bv.update_analysis_and_wait()
                return {"applied": True, "parser": parser_name}
            return {"applied": False, "reason": "no debug info or apply_debug_info unavailable"}
        return _do()

    # =========================================================================
    # Plugin command operations
    # =========================================================================

    def _plugin_valid_commands(self, selector, *, address=None):
        bv = self._resolve_view(selector)
        def _do():
            commands = []
            for cmd in bn.PluginCommand:
                if hasattr(cmd, "is_valid"):
                    if cmd.is_valid(bv):
                        commands.append({"name": cmd.name, "description": cmd.description if hasattr(cmd, "description") else None})
                else:
                    commands.append({"name": cmd.name, "description": cmd.description if hasattr(cmd, "description") else None})
            return commands
        return _run_on_main_thread(_do)

    def _plugin_execute(self, selector, name: str, *, address=None):
        bv = self._resolve_view(selector)
        def _do():
            for cmd in bn.PluginCommand:
                if cmd.name == name:
                    if hasattr(cmd, "execute"):
                        cmd.execute(bv)
                    return {"name": name, "executed": True}
            raise RuntimeError(f"Plugin command {name!r} not found")
        return _run_on_main_thread(_do)

    # =========================================================================
    # Binary basic blocks at address
    # =========================================================================

    def _binary_basic_blocks_at(self, selector, address):
        bv = self._resolve_view(selector)
        addr = self._address(bv, address)
        def _do():
            bbs = bv.get_basic_blocks_at(addr)
            return [
                {
                    "start": hex(bb.start),
                    "end": hex(bb.end),
                    "length": bb.length,
                    "function": bb.function.name if bb.function else None,
                    "function_start": hex(bb.function.start) if bb.function else None,
                }
                for bb in bbs
            ]
        return _do()


_bridge: BinaryNinjaBridge | None = None


def _show_gui_message(text: str) -> None:  # pragma: no cover - GUI runtime
    show = getattr(bn, "show_message_box", None)
    if show is not None:
        show("BN Agent Bridge", text)
    else:
        bn.log_info(text)


def _set_gui_port_setting(port: int) -> bool:
    settings = bn.Settings()
    scope = getattr(getattr(bn, "SettingsScope", None), "SettingsUserScope", None)
    if scope is None:
        return bool(settings.set_integer(GUI_PORT_SETTING, port))
    return bool(settings.set_integer(GUI_PORT_SETTING, port, scope=scope))


def _set_gui_transport_setting(transport: str) -> bool:
    if transport not in GUI_TRANSPORTS:
        raise ValueError(f"Unsupported GUI transport: {transport!r}")
    settings = bn.Settings()
    scope = getattr(getattr(bn, "SettingsScope", None), "SettingsUserScope", None)
    if scope is None:
        return bool(settings.set_string(GUI_TRANSPORT_SETTING, transport))
    return bool(settings.set_string(GUI_TRANSPORT_SETTING, transport, scope=scope))


def _restart_gui_bridge(
    previous_transport: str | None,
    previous_port: int | None,
) -> tuple[BinaryNinjaBridge | None, bool]:
    desired_transport = _configured_transport("gui")
    desired_port = _configured_tcp_port("gui")
    _stop_bridge()
    restarted = start_bridge(mode="gui")
    if restarted is not None:
        return restarted, False

    restored_setting = False
    if previous_transport is not None and previous_transport != desired_transport:
        restored_setting = _set_gui_transport_setting(previous_transport)
    elif (
        desired_transport == "tcp"
        and previous_port is not None
        and previous_port != desired_port
    ):
        restored_setting = _set_gui_port_setting(previous_port)

    if not restored_setting:
        return None, False

    restored = start_bridge(mode="gui")
    return restored, restored is not None


def _restart_bridge_command(_):  # pragma: no cover - GUI runtime
    try:
        selected_transport = _configured_transport("gui")
    except ValueError as exc:
        _show_gui_message(f"Transport configuration is invalid: {exc}")
        return
    previous_transport = _bridge.transport if _bridge is not None else None
    previous_port = (
        int(_bridge.port)
        if _bridge is not None and _bridge.transport == "tcp" and _bridge.port is not None
        else None
    )
    restarted, restored = _restart_gui_bridge(previous_transport, previous_port)
    if restarted is not None and not restored:
        _show_gui_message(f"Bridge is listening on {restarted.endpoint}.")
    elif restored:
        _show_gui_message(
            f"Could not start {selected_transport}; restored the bridge on {restarted.endpoint}."
        )
    else:
        _show_gui_message(
            f"Could not start the bridge with {selected_transport}. "
            "See the Binary Ninja log for details."
        )


def _set_gui_port_command(_):  # pragma: no cover - GUI runtime
    previous_port = (
        int(_bridge.port)
        if _bridge is not None and _bridge.transport == "tcp" and _bridge.port is not None
        else _configured_tcp_port("gui")
    )
    get_int_input = getattr(bn, "get_int_input", None)
    if get_int_input is None:
        bn.log_error("Binary Ninja integer input API is unavailable")
        return
    port = get_int_input(
        f"Loopback TCP port (current: {previous_port})",
        "BN Agent Bridge Port",
    )
    if port is None:
        return
    port = int(port)
    if not 1 <= port <= 65535:
        _show_gui_message("Port must be between 1 and 65535.")
        return
    if not _set_gui_port_setting(port):
        _show_gui_message("Binary Ninja could not save the GUI port setting.")
        return

    selected_transport = _configured_transport("gui")
    if selected_transport != "tcp":
        _show_gui_message(f"Port {port} saved for Loopback TCP mode.")
        return

    previous_transport = _bridge.transport if _bridge is not None else "tcp"
    restarted, restored = _restart_gui_bridge(previous_transport, previous_port)
    if restarted is not None and not restored:
        _show_gui_message(f"Bridge is now listening on {restarted.endpoint}.")
    elif restored:
        _show_gui_message(
            f"Port {port} is unavailable; restored the bridge on {restarted.endpoint}."
        )
    else:
        _show_gui_message(
            f"Port {port} is unavailable and the previous listener could not be restored. "
            "See the Binary Ninja log for details."
        )


def start_bridge(mode: str = "gui"):  # pragma: no cover - exercised in real bridges
    global _bridge
    if mode == "gui" and ui is None:
        bn.log_warn("BN Agent Bridge GUI mode requires Binary Ninja GUI; refusing to start")
        return None
    if _bridge is not None:
        return _bridge
    try:
        candidate = BinaryNinjaBridge(mode=mode)
    except ValueError as exc:
        bn.log_error(f"BN Agent Bridge transport configuration is invalid: {exc}")
        return None
    if not candidate.start():
        return None
    _bridge = candidate
    return _bridge


def _stop_bridge():  # pragma: no cover - exercised in real bridges
    global _bridge
    if _bridge is not None:
        _bridge.stop()
        _bridge = None


def _run_headless(*, foreground: bool = True) -> int:  # pragma: no cover - requires BN headless license
    import signal

    bridge = start_bridge(mode="headless")
    if bridge is None:
        return 1

    if not foreground:
        return 0

    def _handle_signal(signum, _frame):
        bn.log_info(f"BN Agent Bridge received signal {signum}; shutting down")
        bridge.request_shutdown()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    try:
        bridge.shutdown_event.wait()
    finally:
        _stop_bridge()
    return 0


atexit.register(_stop_bridge)

if ui is not None:
    PluginCommand.register(
        "BN Agent Bridge\\Restart Bridge",
        "Restart the bn CLI bridge",
        _restart_bridge_command,
    )
    if os.name == "nt":
        _register_gui_settings()
        PluginCommand.register(
            "BN Agent Bridge\\Set GUI Port...",
            "Change the authenticated loopback TCP port and restart the bridge",
            _set_gui_port_command,
        )
