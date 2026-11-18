"""Atomic artifact files and bounded local result inspection (no BN dependency)."""

from __future__ import annotations

import difflib
import itertools
import json
import os
import tempfile
from pathlib import Path


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def select_result(
    path: Path, *, key: str | None, offset: int, limit: int, fields: str | None
):
    if offset < 0 or limit < 0:
        raise ValueError("Result offset and limit must be nonnegative")
    if path.suffix == ".ndjson":
        if key:
            raise ValueError("--key applies to a JSON object, not NDJSON")
        with path.open(encoding="utf-8") as stream:
            rows = (json.loads(line) for line in stream if line.strip())
            value = list(itertools.islice(rows, offset, offset + limit + 1))
    elif path.suffix == ".json":
        value = json.loads(path.read_text(encoding="utf-8"))
        if key:
            for part in key.split("."):
                if not isinstance(value, dict) or part not in value:
                    raise ValueError(f"Result has no key {key!r}")
                value = value[part]
        if isinstance(value, list):
            value = value[offset : offset + limit + 1]
    else:
        if key or fields:
            raise ValueError("--key and --fields require structured JSON results")
        with path.open(encoding="utf-8") as stream:
            value = [
                line.rstrip("\n")
                for line in itertools.islice(stream, offset, offset + limit + 1)
            ]
    truncated = isinstance(value, list) and len(value) > limit
    if isinstance(value, list):
        value = value[:limit]
    if fields:
        names = fields.split(",")

        def project(row):
            if not isinstance(row, dict):
                raise TypeError("--fields requires objects")
            return {name: row.get(name) for name in names}

        value = (
            [project(row) for row in value]
            if isinstance(value, list)
            else project(value)
        )
    return {
        "artifact_path": str(path.resolve()),
        "result": value,
        "truncated": truncated,
        "next_offset": offset + limit if truncated else None,
    }


def diff_results(before: Path, after: Path) -> dict:
    def lines(path):
        text = path.read_text(encoding="utf-8")
        if path.suffix == ".json":
            text = json.dumps(json.loads(text), indent=2, sort_keys=True) + "\n"
        return text.splitlines(keepends=True)

    diff = "".join(
        difflib.unified_diff(
            lines(before), lines(after), fromfile=str(before), tofile=str(after)
        )
    )
    return {
        "changed": bool(diff),
        "diff": diff,
        "comparison": "text/JSON structure, not semantic equivalence",
    }
