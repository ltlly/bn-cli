from __future__ import annotations

import contextlib
import errno
import json
import socket
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .paths import (
    DAEMON_MODES,
    bridge_registry_dir,
    bridge_registry_path,
    current_daemon_mode_path,
)


class BridgeError(RuntimeError):
    pass


_request_mode: ContextVar[str | None] = ContextVar("bn_request_mode", default=None)
_request_instance: ContextVar[BridgeInstance | None] = ContextVar("bn_request_instance", default=None)
_session_active: ContextVar[bool] = ContextVar("bn_session_active", default=False)


@contextlib.contextmanager
def request_session(mode: str | None = None):
    """Lazily pin one connection for a complete CLI invocation, including jobs."""
    mode_token = _request_mode.set(mode)
    instance_token = _request_instance.set(None)
    active_token = _session_active.set(True)
    try:
        yield
    finally:
        _session_active.reset(active_token)
        _request_instance.reset(instance_token)
        _request_mode.reset(mode_token)


TRANSIENT_SOCKET_ERRNOS = {
    errno.ECONNREFUSED,
    errno.ENOENT,
}

DENIED_SOCKET_ERRNOS = {
    errno.EACCES,
    errno.EPERM,
}


@dataclass(slots=True)
class BridgeInstance:
    pid: int
    socket_path: Path | None
    registry_path: Path
    plugin_name: str
    plugin_version: str
    started_at: str | None
    meta: dict[str, Any]
    mode: str = "gui"
    transport: str = "unix"
    host: str | None = None
    port: int | None = None
    auth_token: str | None = None

    @property
    def endpoint(self) -> str:
        if self.transport == "tcp":
            return f"tcp://{self.host}:{self.port}"
        return str(self.socket_path)


def _purge_stale_registry(registry_path: Path) -> None:
    with contextlib.suppress(OSError):
        registry_path.unlink()


def _socket_args(instance: BridgeInstance) -> tuple[int, str | tuple[str, int]]:
    if instance.transport == "tcp":
        if instance.host != "127.0.0.1" or instance.port is None:
            raise OSError(errno.EINVAL, "Invalid TCP bridge endpoint")
        return socket.AF_INET, (instance.host, instance.port)
    if instance.socket_path is None or not hasattr(socket, "AF_UNIX"):
        raise OSError(errno.EPROTONOSUPPORT, "Unix-domain sockets are unavailable")
    return socket.AF_UNIX, str(instance.socket_path)


def _socket_probe_error(instance: BridgeInstance, timeout: float = 0.2) -> OSError | None:
    try:
        family, address = _socket_args(instance)
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(address)
        return None
    except OSError as exc:
        return exc


def _mode_for_registry(payload: dict[str, Any], path: Path) -> str:
    mode = payload.get("mode")
    if isinstance(mode, str) and mode in DAEMON_MODES:
        return mode
    stem = path.stem
    if stem in DAEMON_MODES:
        return stem
    return "gui"


def _load_instance(path: Path) -> BridgeInstance | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        pid = int(payload["pid"])
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        return None

    transport = str(payload.get("transport", "unix"))
    if transport == "tcp":
        try:
            host = str(payload["host"])
            port = int(payload["port"])
            auth_token = payload["auth_token"]
        except (KeyError, TypeError, ValueError):
            _purge_stale_registry(path)
            return None
        if (
            host != "127.0.0.1"
            or not 1 <= port <= 65535
            or not isinstance(auth_token, str)
            or not auth_token
        ):
            _purge_stale_registry(path)
            return None
        socket_path = None
    elif transport == "unix":
        try:
            socket_path = Path(payload["socket_path"])
        except (KeyError, TypeError):
            _purge_stale_registry(path)
            return None
        host = None
        port = None
        auth_token = None
        if not socket_path.exists():
            _purge_stale_registry(path)
            return None
    else:
        _purge_stale_registry(path)
        return None

    instance = BridgeInstance(
        pid=pid,
        socket_path=socket_path,
        registry_path=path,
        plugin_name=str(payload.get("plugin_name", "bn_agent_bridge")),
        plugin_version=str(payload.get("plugin_version", "0")),
        started_at=payload.get("started_at"),
        meta=payload,
        mode=_mode_for_registry(payload, path),
        transport=transport,
        host=host,
        port=port,
        auth_token=auth_token,
    )

    probe_error = _socket_probe_error(instance)
    if probe_error is not None and probe_error.errno in DENIED_SOCKET_ERRNOS:
        payload["socket_probe_error"] = str(probe_error)
    elif probe_error is not None:
        _purge_stale_registry(path)
        return None

    return instance


def list_instances() -> list[BridgeInstance]:
    registry_dir = bridge_registry_dir()
    instances: list[BridgeInstance] = []
    seen: set[Path] = set()
    for mode in DAEMON_MODES:
        candidate = bridge_registry_path(mode)
        if not candidate.exists():
            continue
        seen.add(candidate)
        instance = _load_instance(candidate)
        if instance is not None:
            instances.append(instance)

    if registry_dir.is_dir():
        for candidate in sorted(registry_dir.glob("*.json")):
            if candidate in seen:
                continue
            instance = _load_instance(candidate)
            if instance is not None:
                instances.append(instance)
    return instances


def read_current_daemon_mode() -> str | None:
    path = current_daemon_mode_path()
    try:
        text = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if text in DAEMON_MODES:
        return text
    return None


def write_current_daemon_mode(mode: str | None) -> None:
    path = current_daemon_mode_path()
    if mode is None:
        with contextlib.suppress(OSError):
            path.unlink()
        return
    if mode not in DAEMON_MODES:
        raise ValueError(f"Unknown daemon mode: {mode!r} (expected one of {DAEMON_MODES})")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(mode, encoding="utf-8")


def _hint_for_multiple_instances(instances: list[BridgeInstance]) -> str:
    modes = sorted({instance.mode for instance in instances})
    options = ", ".join(modes)
    return (
        f"Multiple daemons are running ({options}). "
        "Pick one with `bn daemon use <mode>` or unset with `bn daemon use --clear`."
    )


def choose_instance() -> BridgeInstance:
    instances = list_instances()
    if not instances:
        raise BridgeError(
            "No running Binary Ninja bridge instances found. "
            "Start one with `bn daemon start` or open Binary Ninja."
        )

    explicit = _request_mode.get()
    if explicit is not None:
        for instance in instances:
            if instance.mode == explicit:
                return instance
        raise BridgeError(f"No {explicit!r} daemon is running; run `bn daemon start --mode {explicit}`")

    sticky = read_current_daemon_mode()
    if sticky is not None:
        for instance in instances:
            if instance.mode == sticky:
                return instance
        raise BridgeError(
            f"Sticky daemon mode is `{sticky}` but no `{sticky}` daemon is running. "
            "Run `bn daemon list` to see available daemons or `bn daemon use --clear` to drop the selection."
        )

    if len(instances) == 1:
        return instances[0]

    raise BridgeError(_hint_for_multiple_instances(instances))


def _send_request_to_instance(
    instance: BridgeInstance,
    op: str,
    *,
    params: dict[str, Any] | None = None,
    target: str | None = None,
    timeout: float | None = None,
    connect_retries: int = 4,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "op": op,
        "params": params or {},
    }
    if target is not None:
        payload["target"] = target
    if instance.auth_token is not None:
        payload["auth"] = instance.auth_token

    encoded = (json.dumps(payload) + "\n").encode("utf-8")

    chunks: list[bytes] = []
    last_error: OSError | None = None
    for attempt in range(connect_retries):
        try:
            family, address = _socket_args(instance)
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                if timeout is not None:
                    sock.settimeout(timeout)
                sock.connect(address)
                sock.sendall(encoded)
                with contextlib.suppress(OSError):
                    sock.shutdown(socket.SHUT_WR)
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
            break
        except OSError as exc:
            last_error = exc
            if exc.errno not in TRANSIENT_SOCKET_ERRNOS or attempt == connect_retries - 1:
                break
            time.sleep(0.05 * (attempt + 1))

    if last_error is not None and not chunks:
        if isinstance(last_error, TimeoutError):
            timeout_suffix = f" after {timeout:.1f}s" if timeout is not None else ""
            raise BridgeError(
                f"Timed out waiting for Binary Ninja bridge pid {instance.pid} at {instance.endpoint}"
                f"{timeout_suffix}"
            ) from last_error
        raise BridgeError(
            f"Failed to contact Binary Ninja bridge pid {instance.pid} at {instance.endpoint}: {last_error}"
        ) from last_error

    if not chunks:
        raise BridgeError("Binary Ninja bridge returned an empty response")

    try:
        response = json.loads(b"".join(chunks).decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise BridgeError("Binary Ninja bridge returned invalid JSON") from exc

    if not isinstance(response, dict):
        raise BridgeError("Binary Ninja bridge returned a malformed response")

    if response.get("ok"):
        return response

    error = response.get("error") or "Unknown Binary Ninja bridge error"
    raise BridgeError(str(error))


def send_request(
    op: str,
    *,
    params: dict[str, Any] | None = None,
    target: str | None = None,
    timeout: float | None = None,
    connect_retries: int = 4,
) -> dict[str, Any]:
    instance = _request_instance.get()
    if instance is None:
        instance = choose_instance()
        if _session_active.get():
            _request_instance.set(instance)
    return _send_request_to_instance(
        instance,
        op,
        params=params,
        target=target,
        timeout=timeout,
        connect_retries=connect_retries,
    )
