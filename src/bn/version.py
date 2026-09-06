from __future__ import annotations

import hashlib
from pathlib import Path


VERSION = "0.16.0"


def build_id_for_file(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    return hashlib.sha256(data).hexdigest()[:12]


def bridge_build_id(path: Path) -> str | None:
    """Include bridge helpers and shared symlinks, not just the dispatch module."""
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    try:
        for source in sorted(path.parent.glob("*.py")):
            digest.update(source.name.encode() + b"\0")
            digest.update(source.read_bytes())
    except OSError:
        return None
    return digest.hexdigest()[:12]
