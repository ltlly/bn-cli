from __future__ import annotations

import os
import platform
import tempfile
from pathlib import Path


PLUGIN_NAME = "bn_agent_bridge"
SKILL_NAME = "bn"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def codex_home() -> Path:
    env = os.environ.get("CODEX_HOME")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".codex"


def claude_home() -> Path:
    env = os.environ.get("CLAUDE_CONFIG_DIR")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".claude"


def cache_home() -> Path:
    env = os.environ.get("BN_CACHE_DIR")
    if env:
        return Path(env).expanduser()

    system = platform.system()
    home = Path.home()
    if system == "Darwin":
        return home / "Library" / "Caches" / "bn"
    if system == "Windows":
        base = os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base) / "bn"
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "bn"
    return home / ".cache" / "bn"


DAEMON_MODES: tuple[str, ...] = ("gui", "headless")
BRIDGE_TRANSPORTS: tuple[str, ...] = ("auto", "pipe", "tcp", "unix")
DEFAULT_BRIDGE_TCP_PORTS = {
    "gui": 26765,
    "headless": 26766,
}


def bridge_transport() -> str:
    configured = os.environ.get("BN_BRIDGE_TRANSPORT", "auto").strip().lower()
    if configured not in BRIDGE_TRANSPORTS:
        expected = ", ".join(BRIDGE_TRANSPORTS)
        raise ValueError(
            f"BN_BRIDGE_TRANSPORT must be one of {expected}; got {configured!r}"
        )

    system = platform.system()
    selected = "pipe" if configured == "auto" and system == "Windows" else configured
    if selected == "auto":
        selected = "unix"
    if selected == "pipe" and system != "Windows":
        raise ValueError("BN_BRIDGE_TRANSPORT=pipe is only supported on Windows")
    if selected == "unix" and system == "Windows":
        raise ValueError("BN_BRIDGE_TRANSPORT=unix is not supported on Windows")
    return selected


def _validate_mode(mode: str) -> str:
    if mode not in DAEMON_MODES:
        raise ValueError(f"Unknown daemon mode: {mode!r} (expected one of {DAEMON_MODES})")
    return mode


def bridge_registry_dir() -> Path:
    return cache_home() / "daemons"


def bridge_registry_path(mode: str) -> Path:
    return bridge_registry_dir() / f"{_validate_mode(mode)}.json"


def bridge_socket_path(mode: str) -> Path:
    return cache_home() / f"{PLUGIN_NAME}.{_validate_mode(mode)}.sock"


def bridge_job_root(mode: str) -> Path:
    return cache_home() / "jobs" / _validate_mode(mode)


def bridge_tcp_port(mode: str) -> int:
    mode = _validate_mode(mode)
    env_name = f"BN_BRIDGE_{mode.upper()}_PORT"
    raw = os.environ.get(env_name)
    if raw is None:
        return DEFAULT_BRIDGE_TCP_PORTS[mode]
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError(f"{env_name} must be an integer TCP port") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"{env_name} must be between 1 and 65535")
    return port


def current_daemon_mode_path() -> Path:
    return cache_home() / "current_daemon"


def api_docs_index_path() -> Path:
    return cache_home() / "api_docs_index.json"


def spill_root() -> Path:
    root = Path(tempfile.gettempdir()) / "bn-spills"
    root.mkdir(parents=True, exist_ok=True)
    return root


def plugin_source_dir() -> Path:
    return repo_root() / "plugin" / PLUGIN_NAME


def binary_ninja_plugin_dir() -> Path:
    env = os.environ.get("BN_PLUGIN_DIR")
    if env:
        return Path(env).expanduser()

    system = platform.system()
    home = Path.home()
    if system == "Darwin":
        return home / "Library" / "Application Support" / "Binary Ninja" / "plugins"
    if system == "Windows":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "Binary Ninja" / "plugins"
    return home / ".binaryninja" / "plugins"


def plugin_install_dir() -> Path:
    return binary_ninja_plugin_dir() / PLUGIN_NAME


def codex_skills_dir() -> Path:
    return codex_home() / "skills"


def claude_skills_dir() -> Path:
    return claude_home() / "skills"


def skill_source_dir() -> Path:
    return repo_root() / "skills" / SKILL_NAME


def skill_install_dir() -> Path:
    return codex_skills_dir() / SKILL_NAME


def claude_skill_install_dir() -> Path:
    return claude_skills_dir() / SKILL_NAME


SKILL_CLIENTS: tuple[str, ...] = ("codex", "claude-code")


def skill_install_dir_for(client: str) -> Path:
    if client == "codex":
        return skill_install_dir()
    if client == "claude-code":
        return claude_skill_install_dir()
    raise ValueError(f"Unknown skill client: {client}")
