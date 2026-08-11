from __future__ import annotations

import json
import os
import errno
import multiprocessing.connection
import socket
import socketserver
import threading
import uuid
from pathlib import Path

import pytest

from bn.paths import (
    bridge_pipe_name,
    bridge_registry_path,
    bridge_tcp_port,
    bridge_transport,
    current_daemon_mode_path,
)
from bn.transport import (
    BridgeError,
    BridgeInstance,
    _send_request_to_instance,
    _socket_args,
    _validate_pipe_name,
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


def test_bridge_transport_defaults_by_platform(monkeypatch):
    monkeypatch.delenv("BN_BRIDGE_TRANSPORT", raising=False)
    monkeypatch.setattr("bn.paths.platform.system", lambda: "Windows")
    assert bridge_transport() == "pipe"

    monkeypatch.setattr("bn.paths.platform.system", lambda: "Linux")
    assert bridge_transport() == "unix"


def test_bridge_pipe_names_are_fixed_per_mode():
    assert bridge_pipe_name("gui") == r"\\.\pipe\bn-agent-bridge-gui"
    assert bridge_pipe_name("headless") == r"\\.\pipe\bn-agent-bridge-headless"


def test_bridge_transport_validates_explicit_platform_choices(monkeypatch):
    monkeypatch.setattr("bn.paths.platform.system", lambda: "Windows")
    monkeypatch.setenv("BN_BRIDGE_TRANSPORT", "tcp")
    assert bridge_transport() == "tcp"

    monkeypatch.setenv("BN_BRIDGE_TRANSPORT", "unix")
    with pytest.raises(ValueError, match="not supported on Windows"):
        bridge_transport()

    monkeypatch.setenv("BN_BRIDGE_TRANSPORT", "bogus")
    with pytest.raises(ValueError, match="must be one of"):
        bridge_transport()


def test_pipe_name_validation_rejects_remote_and_nested_names():
    assert _validate_pipe_name(r"\\.\pipe\bn-agent-bridge-gui-1-token") == (
        r"\\.\pipe\bn-agent-bridge-gui-1-token"
    )
    with pytest.raises(OSError, match="Invalid local Named Pipe endpoint"):
        _validate_pipe_name(r"\\server\pipe\bn-agent-bridge")
    with pytest.raises(OSError, match="Invalid local Named Pipe endpoint"):
        _validate_pipe_name(r"\\.\pipe\nested\bn-agent-bridge")


def test_list_instances_reads_pipe_registry(monkeypatch, tmp_path):
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr("bn.transport._socket_probe_error", lambda _instance: None)
    registry_path = bridge_registry_path("gui")
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    pipe_name = r"\\.\pipe\bn-agent-bridge-gui-123-token"
    registry_path.write_text(
        json.dumps(
            {
                "pid": 123,
                "transport": "pipe",
                "pipe_name": pipe_name,
                "auth_token": "secret",
                "mode": "gui",
            }
        ),
        encoding="utf-8",
    )

    instances = list_instances()

    assert len(instances) == 1
    assert instances[0].pipe_name == pipe_name
    assert instances[0].endpoint == f"pipe://{pipe_name}"
    assert instances[0].auth_token == "secret"


@pytest.mark.skipif(os.name != "nt", reason="Windows Named Pipes are unavailable")
def test_send_request_over_real_windows_named_pipe(tmp_path):
    pipe_name = rf"\\.\pipe\bn-agent-bridge-test-{os.getpid()}-{uuid.uuid4().hex}"
    listener = multiprocessing.connection.Listener(
        pipe_name, family="AF_PIPE", backlog=4, authkey=None
    )

    def serve():
        connection = listener.accept()
        try:
            payload = json.loads(connection.recv_bytes().decode("utf-8"))
            connection.send_bytes(
                json.dumps(
                    {
                        "ok": True,
                        "result": {
                            "op": payload["op"],
                            "auth": payload["auth"],
                        },
                    }
                ).encode("utf-8")
            )
        finally:
            connection.close()
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    instance = BridgeInstance(
        pid=os.getpid(),
        socket_path=None,
        registry_path=tmp_path / "gui.json",
        plugin_name="bn_agent_bridge",
        plugin_version="0.15.0",
        started_at=None,
        meta={},
        transport="pipe",
        pipe_name=pipe_name,
        auth_token="test-token",
    )

    response = _send_request_to_instance(instance, "doctor", timeout=2.0)

    assert response["result"] == {"op": "doctor", "auth": "test-token"}
    thread.join(timeout=2)
    assert not thread.is_alive()


def _pipe_instance(tmp_path):
    return BridgeInstance(
        pid=999,
        socket_path=None,
        registry_path=tmp_path / "gui.json",
        plugin_name="bn_agent_bridge",
        plugin_version="0.15.0",
        started_at=None,
        meta={},
        transport="pipe",
        pipe_name=r"\\.\pipe\bn-agent-bridge-gui-999-test",
        auth_token="secret",
    )


def test_pipe_request_retries_busy_endpoint(monkeypatch, tmp_path):
    class _Connection:
        def send_bytes(self, payload):
            self.payload = json.loads(payload.decode("utf-8"))

        def recv_bytes(self):
            return json.dumps({"ok": True, "result": self.payload}).encode("utf-8")

        def close(self):
            pass

    attempts = []

    def connect(_pipe_name, _timeout):
        attempts.append(True)
        if len(attempts) == 1:
            error = OSError(231, "All pipe instances are busy")
            error.winerror = 231
            raise error
        return _Connection()

    monkeypatch.setattr("bn.transport._pipe_connect", connect)
    monkeypatch.setattr("bn.transport.time.sleep", lambda _delay: None)

    response = _send_request_to_instance(_pipe_instance(tmp_path), "doctor")

    assert len(attempts) == 2
    assert response["result"]["auth"] == "secret"


def test_pipe_request_reports_response_timeout(monkeypatch, tmp_path):
    class _Connection:
        def send_bytes(self, _payload):
            pass

        def poll(self, _timeout):
            return False

        def close(self):
            pass

    monkeypatch.setattr(
        "bn.transport._pipe_connect", lambda _pipe_name, _timeout: _Connection()
    )

    with pytest.raises(BridgeError, match="Timed out waiting for Binary Ninja bridge pid 999"):
        _send_request_to_instance(_pipe_instance(tmp_path), "doctor", timeout=0.01)


def test_pipe_request_wraps_early_eof(monkeypatch, tmp_path):
    class _Connection:
        def send_bytes(self, _payload):
            pass

        def recv_bytes(self):
            raise EOFError

        def close(self):
            pass

    monkeypatch.setattr(
        "bn.transport._pipe_connect", lambda _pipe_name, _timeout: _Connection()
    )

    with pytest.raises(BridgeError, match="Failed to contact Binary Ninja bridge pid 999"):
        _send_request_to_instance(_pipe_instance(tmp_path), "doctor")


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
