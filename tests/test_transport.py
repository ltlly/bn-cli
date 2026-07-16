from __future__ import annotations

import json
import os
import errno
import socket
import socketserver
import threading
import uuid
from pathlib import Path

import pytest

from bn.paths import bridge_registry_path, bridge_tcp_port, current_daemon_mode_path
from bn.transport import (
    BridgeError,
    BridgeInstance,
    _socket_args,
    choose_instance,
    list_instances,
    read_current_daemon_mode,
    send_request,
    write_current_daemon_mode,
)


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        raw = self.rfile.readline()
        if not raw:
            return
        payload = json.loads(raw.decode("utf-8"))
        response = {
            "ok": True,
            "result": {
                "op": payload["op"],
                "target": payload.get("target"),
                "params": payload.get("params"),
                "auth": payload.get("auth"),
            },
        }
        self.wfile.write(json.dumps(response).encode("utf-8"))


HAS_UNIX_SOCKETS = hasattr(socket, "AF_UNIX") and hasattr(socketserver, "UnixStreamServer")
requires_unix_sockets = pytest.mark.skipif(
    not HAS_UNIX_SOCKETS, reason="Unix-domain sockets are unavailable on this platform"
)


if HAS_UNIX_SOCKETS:
    class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True
else:
    _Server = None


class _TcpServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def test_bridge_tcp_ports_are_fixed_and_overridable(monkeypatch):
    monkeypatch.delenv("BN_BRIDGE_GUI_PORT", raising=False)
    monkeypatch.delenv("BN_BRIDGE_HEADLESS_PORT", raising=False)
    assert bridge_tcp_port("gui") == 26765
    assert bridge_tcp_port("headless") == 26766

    monkeypatch.setenv("BN_BRIDGE_GUI_PORT", "30001")
    assert bridge_tcp_port("gui") == 30001


def test_socket_args_rejects_non_loopback_tcp_endpoint(tmp_path):
    instance = BridgeInstance(
        pid=123,
        socket_path=None,
        registry_path=tmp_path / "gui.json",
        plugin_name="bn_agent_bridge",
        plugin_version="0.15.0",
        started_at=None,
        meta={},
        transport="tcp",
        host="0.0.0.0",
        port=26765,
        auth_token="secret",
    )

    with pytest.raises(OSError, match="Invalid TCP bridge endpoint"):
        _socket_args(instance)


def test_list_instances_purges_unix_registry_without_socket_path(tmp_path, monkeypatch):
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path))
    registry_path = bridge_registry_path("gui")
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_text(
        json.dumps({"pid": os.getpid(), "transport": "unix", "mode": "gui"}),
        encoding="utf-8",
    )

    assert list_instances() == []
    assert not registry_path.exists()


@requires_unix_sockets
def test_send_request_uses_registry_and_socket(tmp_path, monkeypatch):
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path))
    pid = os.getpid()
    socket_path = Path("/tmp") / f"bn-test-{os.getpid()}-{uuid.uuid4().hex[:8]}.sock"
    registry_path = bridge_registry_path("gui")
    registry_path.parent.mkdir(parents=True, exist_ok=True)

    server = _Server(str(socket_path), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    registry_path.write_text(
        json.dumps(
            {
                "pid": pid,
                "socket_path": str(socket_path),
                "plugin_name": "bn_agent_bridge",
                "plugin_version": "0.1.0",
            }
        ),
        encoding="utf-8",
    )

    try:
        instances = list_instances()
        assert len(instances) == 1
        instance = choose_instance()
        assert instance.pid == pid

        response = send_request("ping", params={"hello": "world"}, target=f"{pid}:1:999")
        assert response["result"]["op"] == "ping"
        assert response["result"]["params"] == {"hello": "world"}
    finally:
        server.shutdown()
        server.server_close()


@requires_unix_sockets
def test_list_instances_prunes_stale_registry_and_socket(tmp_path, monkeypatch):
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path))
    registry_path = bridge_registry_path("gui")
    registry_path.parent.mkdir(parents=True, exist_ok=True)

    stale_socket_path = Path("/tmp") / f"bn-stale-{os.getpid()}-{uuid.uuid4().hex[:8]}.sock"
    stale_server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale_server.bind(str(stale_socket_path))
    stale_server.listen(1)
    stale_server.close()

    registry_path.write_text(
        json.dumps(
            {
                "pid": os.getpid(),
                "socket_path": str(stale_socket_path),
                "plugin_name": "bn_agent_bridge",
                "plugin_version": "0.1.0",
            }
        ),
        encoding="utf-8",
    )

    assert stale_socket_path.exists()

    instances = list_instances()

    assert instances == []
    assert not registry_path.exists()
    assert stale_socket_path.exists()


@requires_unix_sockets
def test_list_instances_preserves_permission_denied_registry(tmp_path, monkeypatch):
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path))
    registry_path = bridge_registry_path("gui")
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    socket_path = tmp_path / "bridge.sock"
    socket_path.write_text("", encoding="utf-8")
    registry_path.write_text(
        json.dumps(
            {
                "pid": os.getpid(),
                "socket_path": str(socket_path),
                "plugin_name": "bn_agent_bridge",
                "plugin_version": "0.1.0",
            }
        ),
        encoding="utf-8",
    )

    class _DeniedSocket:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def settimeout(self, timeout):
            self.timeout = timeout

        def connect(self, path):
            raise PermissionError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr("bn.transport.socket.socket", lambda *args, **kwargs: _DeniedSocket())

    instances = list_instances()

    assert len(instances) == 1
    assert instances[0].socket_path == socket_path
    assert "Operation not permitted" in instances[0].meta["socket_probe_error"]
    assert registry_path.exists()


def test_send_request_uses_tcp_registry_and_auth(tmp_path, monkeypatch):
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path))
    server = _TcpServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    registry_path = bridge_registry_path("gui")
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_text(
        json.dumps(
            {
                "pid": os.getpid(),
                "transport": "tcp",
                "host": host,
                "port": port,
                "auth_token": "test-token",
                "plugin_name": "bn_agent_bridge",
                "plugin_version": "0.1.0",
            }
        ),
        encoding="utf-8",
    )

    try:
        instance = choose_instance()
        assert instance.transport == "tcp"
        assert instance.endpoint == f"tcp://127.0.0.1:{port}"
        response = send_request("ping", params={"hello": "world"})
        assert response["result"]["op"] == "ping"
        assert response["result"]["auth"] == "test-token"
    finally:
        server.shutdown()
        server.server_close()


def test_list_instances_prunes_stale_tcp_registry(tmp_path, monkeypatch):
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path))
    registry_path = bridge_registry_path("gui")
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_text(
        json.dumps(
            {
                "pid": os.getpid(),
                "transport": "tcp",
                "host": "127.0.0.1",
                "port": 1,
                "auth_token": "test-token",
            }
        ),
        encoding="utf-8",
    )

    assert list_instances() == []
    assert not registry_path.exists()


def test_send_request_wraps_socket_errors(tmp_path, monkeypatch):
    from bn.transport import BridgeError, BridgeInstance

    instance = BridgeInstance(
        pid=999,
        socket_path=tmp_path / "missing.sock",
        registry_path=tmp_path / "missing.json",
        plugin_name="bn_agent_bridge",
        plugin_version="0.1.0",
        started_at=None,
        meta={},
        transport="tcp",
        host="127.0.0.1",
        port=1,
    )
    monkeypatch.setattr("bn.transport.choose_instance", lambda: instance)

    with pytest.raises(BridgeError, match="Failed to contact Binary Ninja bridge pid 999"):
        send_request("doctor")


def test_send_request_retries_transient_connect_failures(tmp_path, monkeypatch):
    from bn.transport import BridgeInstance

    instance = BridgeInstance(
        pid=999,
        socket_path=tmp_path / "bridge.sock",
        registry_path=tmp_path / "bridge.json",
        plugin_name="bn_agent_bridge",
        plugin_version="0.1.0",
        started_at=None,
        meta={},
        transport="tcp",
        host="127.0.0.1",
        port=1,
    )
    monkeypatch.setattr("bn.transport.choose_instance", lambda: instance)

    class _FakeSocket:
        attempts = 0

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def settimeout(self, timeout):
            self.timeout = timeout

        def connect(self, path):
            type(self).attempts += 1
            if type(self).attempts == 1:
                raise ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused")

        def sendall(self, payload):
            self.payload = payload

        def shutdown(self, how):
            self.how = how

        def recv(self, size):
            if not hasattr(self, "_sent"):
                self._sent = True
                return json.dumps({"ok": True, "result": {"pong": True}}).encode("utf-8")
            return b""

    monkeypatch.setattr("bn.transport.socket.socket", lambda *args, **kwargs: _FakeSocket())

    response = send_request("ping")

    assert response["result"]["pong"] is True
    assert _FakeSocket.attempts == 2


def test_send_request_uses_blocking_socket_by_default(tmp_path, monkeypatch):
    from bn.transport import BridgeInstance

    instance = BridgeInstance(
        pid=999,
        socket_path=tmp_path / "bridge.sock",
        registry_path=tmp_path / "bridge.json",
        plugin_name="bn_agent_bridge",
        plugin_version="0.1.0",
        started_at=None,
        meta={},
        transport="tcp",
        host="127.0.0.1",
        port=1,
    )
    monkeypatch.setattr("bn.transport.choose_instance", lambda: instance)

    class _FakeSocket:
        timeout_calls = 0

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def settimeout(self, timeout):
            type(self).timeout_calls += 1
            self.timeout = timeout

        def connect(self, path):
            self.path = path

        def sendall(self, payload):
            self.payload = payload

        def shutdown(self, how):
            self.how = how

        def recv(self, size):
            if not hasattr(self, "_sent"):
                self._sent = True
                return json.dumps({"ok": True, "result": {"pong": True}}).encode("utf-8")
            return b""

    monkeypatch.setattr("bn.transport.socket.socket", lambda *args, **kwargs: _FakeSocket())

    response = send_request("ping")

    assert response["result"]["pong"] is True
    assert _FakeSocket.timeout_calls == 0


def test_send_request_reports_timeout_waiting_for_response(tmp_path, monkeypatch):
    from bn.transport import BridgeError, BridgeInstance

    instance = BridgeInstance(
        pid=999,
        socket_path=tmp_path / "bridge.sock",
        registry_path=tmp_path / "bridge.json",
        plugin_name="bn_agent_bridge",
        plugin_version="0.1.0",
        started_at=None,
        meta={},
        transport="tcp",
        host="127.0.0.1",
        port=1,
    )
    monkeypatch.setattr("bn.transport.choose_instance", lambda: instance)

    class _FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def settimeout(self, timeout):
            self.timeout = timeout

        def connect(self, path):
            self.path = path

        def sendall(self, payload):
            self.payload = payload

        def shutdown(self, how):
            self.how = how

        def recv(self, size):
            raise socket.timeout("timed out")

    monkeypatch.setattr("bn.transport.socket.socket", lambda *args, **kwargs: _FakeSocket())

    with pytest.raises(BridgeError, match="Timed out waiting for Binary Ninja bridge pid 999"):
        send_request("ping", timeout=12.5)


@requires_unix_sockets
def test_list_instances_trusts_live_socket_even_with_stale_pid(tmp_path, monkeypatch):
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path))
    registry_path = bridge_registry_path("gui")
    registry_path.parent.mkdir(parents=True, exist_ok=True)

    socket_path = Path("/tmp") / f"bn-live-{os.getpid()}-{uuid.uuid4().hex[:8]}.sock"
    server = _Server(str(socket_path), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    registry_path.write_text(
        json.dumps(
            {
                "pid": 111,
                "socket_path": str(socket_path),
                "plugin_name": "bn_agent_bridge",
                "plugin_version": "0.1.0",
            }
        ),
        encoding="utf-8",
    )

    try:
        instances = list_instances()

        assert len(instances) == 1
        assert instances[0].pid == 111
        assert registry_path.exists()
    finally:
        server.shutdown()
        server.server_close()


@requires_unix_sockets
def test_list_instances_reads_fixed_registry_path(tmp_path, monkeypatch):
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path))
    pid = os.getpid()
    socket_path = Path("/tmp") / f"bn-fixed-{pid}-{uuid.uuid4().hex[:8]}.sock"
    server = _Server(str(socket_path), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    registry_path = bridge_registry_path("gui")
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_text(
        json.dumps(
            {
                "pid": pid,
                "socket_path": str(socket_path),
                "plugin_name": "bn_agent_bridge",
                "plugin_version": "0.1.0",
            }
        ),
        encoding="utf-8",
    )

    try:
        instances = list_instances()

        assert len(instances) == 1
        assert instances[0].pid == pid
        assert instances[0].registry_path == registry_path
    finally:
        server.shutdown()
        server.server_close()


def _write_registry(mode: str, *, pid: int, socket_path: Path) -> Path:
    registry_path = bridge_registry_path(mode)
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_text(
        json.dumps(
            {
                "pid": pid,
                "socket_path": str(socket_path),
                "plugin_name": "bn_agent_bridge",
                "plugin_version": "0.1.0",
                "mode": mode,
            }
        ),
        encoding="utf-8",
    )
    return registry_path


@requires_unix_sockets
def test_list_instances_discovers_both_modes(tmp_path, monkeypatch):
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path))
    pid = os.getpid()

    gui_socket = Path("/tmp") / f"bn-gui-{pid}-{uuid.uuid4().hex[:8]}.sock"
    headless_socket = Path("/tmp") / f"bn-headless-{pid}-{uuid.uuid4().hex[:8]}.sock"
    gui_server = _Server(str(gui_socket), _Handler)
    headless_server = _Server(str(headless_socket), _Handler)
    threading.Thread(target=gui_server.serve_forever, daemon=True).start()
    threading.Thread(target=headless_server.serve_forever, daemon=True).start()

    try:
        _write_registry("gui", pid=pid, socket_path=gui_socket)
        _write_registry("headless", pid=pid, socket_path=headless_socket)

        instances = list_instances()

        assert {instance.mode for instance in instances} == {"gui", "headless"}
    finally:
        gui_server.shutdown()
        gui_server.server_close()
        headless_server.shutdown()
        headless_server.server_close()


@requires_unix_sockets
def test_choose_instance_uses_sticky_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path))
    pid = os.getpid()
    gui_socket = Path("/tmp") / f"bn-gui-{pid}-{uuid.uuid4().hex[:8]}.sock"
    headless_socket = Path("/tmp") / f"bn-headless-{pid}-{uuid.uuid4().hex[:8]}.sock"
    gui_server = _Server(str(gui_socket), _Handler)
    headless_server = _Server(str(headless_socket), _Handler)
    threading.Thread(target=gui_server.serve_forever, daemon=True).start()
    threading.Thread(target=headless_server.serve_forever, daemon=True).start()

    try:
        _write_registry("gui", pid=pid, socket_path=gui_socket)
        _write_registry("headless", pid=pid, socket_path=headless_socket)
        write_current_daemon_mode("headless")

        chosen = choose_instance()
        assert chosen.mode == "headless"
    finally:
        gui_server.shutdown()
        gui_server.server_close()
        headless_server.shutdown()
        headless_server.server_close()


@requires_unix_sockets
def test_choose_instance_errors_on_multiple_without_sticky(tmp_path, monkeypatch):
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path))
    pid = os.getpid()
    gui_socket = Path("/tmp") / f"bn-gui-{pid}-{uuid.uuid4().hex[:8]}.sock"
    headless_socket = Path("/tmp") / f"bn-headless-{pid}-{uuid.uuid4().hex[:8]}.sock"
    gui_server = _Server(str(gui_socket), _Handler)
    headless_server = _Server(str(headless_socket), _Handler)
    threading.Thread(target=gui_server.serve_forever, daemon=True).start()
    threading.Thread(target=headless_server.serve_forever, daemon=True).start()

    try:
        _write_registry("gui", pid=pid, socket_path=gui_socket)
        _write_registry("headless", pid=pid, socket_path=headless_socket)

        with pytest.raises(BridgeError, match="Multiple daemons"):
            choose_instance()
    finally:
        gui_server.shutdown()
        gui_server.server_close()
        headless_server.shutdown()
        headless_server.server_close()


@requires_unix_sockets
def test_choose_instance_errors_when_sticky_mode_not_running(tmp_path, monkeypatch):
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path))
    pid = os.getpid()
    gui_socket = Path("/tmp") / f"bn-gui-{pid}-{uuid.uuid4().hex[:8]}.sock"
    gui_server = _Server(str(gui_socket), _Handler)
    threading.Thread(target=gui_server.serve_forever, daemon=True).start()

    try:
        _write_registry("gui", pid=pid, socket_path=gui_socket)
        write_current_daemon_mode("headless")

        with pytest.raises(BridgeError, match="Sticky daemon mode is `headless`"):
            choose_instance()
    finally:
        gui_server.shutdown()
        gui_server.server_close()


def test_sticky_mode_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path))

    assert read_current_daemon_mode() is None
    write_current_daemon_mode("gui")
    assert read_current_daemon_mode() == "gui"
    write_current_daemon_mode(None)
    assert read_current_daemon_mode() is None
    assert not current_daemon_mode_path().exists()


def test_sticky_mode_ignores_invalid_value(tmp_path, monkeypatch):
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path))
    sticky = current_daemon_mode_path()
    sticky.parent.mkdir(parents=True, exist_ok=True)
    sticky.write_text("nonsense", encoding="utf-8")

    assert read_current_daemon_mode() is None
