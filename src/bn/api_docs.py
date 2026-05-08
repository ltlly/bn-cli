"""Local Binary Ninja API documentation queries.

Parses the Sphinx ``objects.inv`` shipped with Binary Ninja into a flat index of
fully-qualified names and reads individual symbols out of the HTML on demand.
No bridge call is involved — everything is done from the on-disk docs tree.
"""

from __future__ import annotations

import json
import os
import platform
import re
import sys
import zlib
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable, TypedDict

from .paths import api_docs_index_path


INDEX_VERSION = 1
DOCS_DIR_ENV = "BN_API_DOCS_DIR"


KNOWN_KINDS: tuple[str, ...] = (
    "module",
    "class",
    "method",
    "function",
    "attribute",
    "property",
    "exception",
    "data",
)


class IndexEntry(TypedDict):
    name: str
    kind: str
    uri: str
    display: str


@dataclass(frozen=True)
class SymbolDetail:
    name: str
    kind: str
    signature: str
    docstring: str
    source_url: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# docs-dir resolution
# ---------------------------------------------------------------------------


def _platform_default_dirs() -> list[Path]:
    system = platform.system()
    home = Path.home()
    if system == "Darwin":
        return [Path("/Applications/Binary Ninja.app/Contents/Resources/api-docs")]
    if system == "Windows":
        candidates: list[Path] = []
        local = os.environ.get("LOCALAPPDATA")
        if local:
            candidates.append(Path(local) / "Vector35" / "BinaryNinja" / "api-docs")
        program_files = os.environ.get("PROGRAMFILES", r"C:\Program Files")
        candidates.append(Path(program_files) / "Vector35" / "BinaryNinja" / "api-docs")
        return candidates
    return [
        home / "binaryninja" / "api-docs",
        Path("/opt/binaryninja/api-docs"),
    ]


def find_docs_dir(explicit: Path | None = None) -> Path:
    """Resolve the Binary Ninja api-docs directory.

    Order: explicit argument, ``BN_API_DOCS_DIR`` env var, platform defaults.
    Raises ``FileNotFoundError`` if no candidate has an ``objects.inv``.
    """

    tried: list[Path] = []

    def _check(candidate: Path) -> Path | None:
        tried.append(candidate)
        return candidate if (candidate / "objects.inv").is_file() else None

    if explicit is not None:
        result = _check(Path(explicit).expanduser())
        if result is None:
            raise FileNotFoundError(
                f"--docs-dir does not contain objects.inv: {explicit}"
            )
        return result

    env = os.environ.get(DOCS_DIR_ENV)
    if env:
        result = _check(Path(env).expanduser())
        if result is None:
            raise FileNotFoundError(
                f"{DOCS_DIR_ENV} does not contain objects.inv: {env}"
            )
        return result

    for candidate in _platform_default_dirs():
        result = _check(candidate)
        if result is not None:
            return result

    searched = "\n  ".join(str(p) for p in tried)
    raise FileNotFoundError(
        "Could not locate Binary Ninja api-docs. Set "
        f"{DOCS_DIR_ENV} or pass --docs-dir. Searched:\n  {searched}"
    )


# ---------------------------------------------------------------------------
# objects.inv parser
# ---------------------------------------------------------------------------


def parse_objects_inv(path: Path) -> list[IndexEntry]:
    """Parse a Sphinx ``objects.inv`` file into a flat list of entries."""

    with path.open("rb") as f:
        for _ in range(4):
            f.readline()
        compressed = f.read()

    body = zlib.decompress(compressed).decode("utf-8", "replace")

    entries: list[IndexEntry] = []
    for line in body.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        name, role, _priority, uri = parts[0], parts[1], parts[2], parts[3]
        display = parts[4] if len(parts) > 4 else "-"
        if display == "-":
            display = name
        # Sphinx shorthand: trailing "$" in URI = the name itself.
        uri = uri.replace("$", name)
        domain, sep, kind = role.partition(":")
        # Only keep Python API entries; Sphinx also emits page-level
        # `std:label` / `std:doc` anchors that would only add noise.
        if sep and domain != "py":
            continue
        entries.append({"name": name, "kind": kind or role, "uri": uri, "display": display})
    return entries


# ---------------------------------------------------------------------------
# Index cache
# ---------------------------------------------------------------------------


def _objects_inv_path(docs_dir: Path) -> Path:
    return docs_dir / "objects.inv"


def _read_cached_index(cache_path: Path) -> dict[str, Any] | None:
    if not cache_path.is_file():
        return None
    try:
        return json.loads(cache_path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def load_or_build_index(
    docs_dir: Path,
    *,
    refresh: bool = False,
    cache_path: Path | None = None,
) -> list[IndexEntry]:
    """Return the index for ``docs_dir``, building or refreshing the cache as needed."""

    cache_path = cache_path or api_docs_index_path()
    inv_path = _objects_inv_path(docs_dir)
    inv_mtime_ns = inv_path.stat().st_mtime_ns
    docs_dir_str = str(docs_dir.resolve())

    if not refresh:
        cached = _read_cached_index(cache_path)
        if (
            cached is not None
            and cached.get("version") == INDEX_VERSION
            and cached.get("docs_dir") == docs_dir_str
            and cached.get("objects_inv_mtime_ns") == inv_mtime_ns
            and isinstance(cached.get("entries"), list)
        ):
            return cached["entries"]

    entries = parse_objects_inv(inv_path)
    payload = {
        "version": INDEX_VERSION,
        "docs_dir": docs_dir_str,
        "objects_inv_mtime_ns": inv_mtime_ns,
        "entries": entries,
    }
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(payload), encoding="utf-8")
    return entries


# ---------------------------------------------------------------------------
# Search / list / show
# ---------------------------------------------------------------------------


def _filter_kind(entries: Iterable[IndexEntry], kind: str | None) -> list[IndexEntry]:
    if not kind:
        return list(entries)
    return [e for e in entries if e["kind"] == kind]


def search(
    entries: Iterable[IndexEntry],
    pattern: str,
    *,
    regex: bool = False,
    kind: str | None = None,
    limit: int | None = None,
) -> list[IndexEntry]:
    pool = _filter_kind(entries, kind)
    if regex:
        rx = re.compile(pattern, re.IGNORECASE)
        matches = [e for e in pool if rx.search(e["name"])]
    else:
        needle = pattern.lower()
        matches = [e for e in pool if needle in e["name"].lower()]
    matches.sort(key=lambda e: (len(e["name"]), e["name"]))
    if limit is not None and limit >= 0:
        matches = matches[:limit]
    return matches


def list_entries(
    entries: Iterable[IndexEntry],
    *,
    kind: str | None = None,
    module: str | None = None,
    limit: int | None = None,
) -> list[IndexEntry]:
    pool = _filter_kind(entries, kind)
    if module:
        prefix = module if module.endswith(".") else module + "."
        pool = [e for e in pool if e["name"] == module or e["name"].startswith(prefix)]
    pool.sort(key=lambda e: e["name"])
    if limit is not None and limit >= 0:
        pool = pool[:limit]
    return pool


def find_symbol(entries: Iterable[IndexEntry], name: str) -> list[IndexEntry]:
    """Resolve ``name`` against the index.

    Tries: exact qualified-name hit first, then exact bare-name match against
    the trailing component. Returns one entry on a unique hit, multiple on an
    ambiguous bare-name match, or an empty list if nothing matches.
    """

    pool = list(entries)
    by_name = {e["name"]: e for e in pool}
    if name in by_name:
        return [by_name[name]]

    bare_matches = [e for e in pool if e["name"].rsplit(".", 1)[-1] == name]
    if bare_matches:
        return sorted(bare_matches, key=lambda e: e["name"])
    return []


# ---------------------------------------------------------------------------
# HTML extraction for `show`
# ---------------------------------------------------------------------------


_BLOCK_TAGS = {"p", "li", "dt", "dd", "div", "section", "br", "tr", "pre"}
_HEADERLINK_CLASSES = {"headerlink", "viewcode-link", "viewcode-back"}


class _SignatureExtractor(HTMLParser):
    """Extract the signature line from a ``<dt id=target>...</dt>``."""

    def __init__(self, target: str) -> None:
        super().__init__(convert_charrefs=True)
        self._target = target
        self._depth = 0  # >0 while inside the matched <dt>
        self._skip_depth = 0  # >0 while inside a [source]/¶ child to skip
        self._parts: list[str] = []
        self.found = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = dict(attrs)
        if self._depth == 0:
            if tag != "dt":
                return
            if attr.get("id") == self._target:
                self.found = True
                self._depth = 1
            return
        # We are inside the target <dt>.
        classes = (attr.get("class") or "").split()
        if any(c in _HEADERLINK_CLASSES for c in classes):
            self._skip_depth = 1
            return
        if self._skip_depth:
            self._skip_depth += 1
            return
        if tag == "dt":
            self._depth += 1

    def handle_endtag(self, tag: str) -> None:
        if self._depth == 0:
            return
        if self._skip_depth:
            self._skip_depth -= 1
            return
        if tag == "dt":
            self._depth -= 1

    def handle_data(self, data: str) -> None:
        if self._depth and not self._skip_depth:
            self._parts.append(data)

    def signature(self) -> str:
        text = "".join(self._parts)
        text = text.replace("¶", "")  # stray ¶
        text = re.sub(r"\s+", " ", text).strip()
        return text


class _DocstringExtractor(HTMLParser):
    """Extract the docstring from the ``<dd>`` immediately following ``<dt id=target>``."""

    def __init__(self, target: str) -> None:
        super().__init__(convert_charrefs=True)
        self._target = target
        self._state = "search"  # search -> after_dt -> capturing -> done
        self._capture_depth = 0
        self._skip_depth = 0
        self._parts: list[str] = []
        self.found = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = dict(attrs)
        if self._state == "search":
            if tag == "dt" and attr.get("id") == self._target:
                self._state = "after_dt"
            return
        if self._state == "after_dt":
            if tag == "dd":
                self._state = "capturing"
                self._capture_depth = 1
                self.found = True
            return
        if self._state == "capturing":
            classes = (attr.get("class") or "").split()
            if any(c in _HEADERLINK_CLASSES for c in classes):
                self._skip_depth = 1
                return
            if self._skip_depth:
                self._skip_depth += 1
                return
            if tag == "dd":
                self._capture_depth += 1
            elif tag in _BLOCK_TAGS and self._parts and not self._parts[-1].endswith("\n\n"):
                self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if self._state != "capturing":
            return
        if self._skip_depth:
            self._skip_depth -= 1
            return
        if tag == "dd":
            self._capture_depth -= 1
            if self._capture_depth == 0:
                self._state = "done"
            return
        if tag in _BLOCK_TAGS and self._parts and not self._parts[-1].endswith("\n\n"):
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._state == "capturing" and not self._skip_depth:
            self._parts.append(data)

    def docstring(self) -> str:
        text = "".join(self._parts)
        text = text.replace("¶", "")
        # Collapse runs of blank lines and trim per-line whitespace.
        lines = [re.sub(r"[ \t]+", " ", line).strip() for line in text.splitlines()]
        out: list[str] = []
        prev_blank = False
        for line in lines:
            if line:
                out.append(line)
                prev_blank = False
            elif not prev_blank and out:
                out.append("")
                prev_blank = True
        return "\n".join(out).strip()


def _resolve_html_target(uri: str, entry: IndexEntry) -> tuple[str, str]:
    """Return (relative html path, anchor) for an index entry's URI.

    Sphinx URIs look like ``binaryninja.binaryview-module.html#binaryninja.binaryview.BinaryView.read``.
    """

    if "#" in uri:
        rel, _, anchor = uri.partition("#")
    else:
        rel, anchor = uri, entry["name"]
    if not anchor or anchor == "module-" + entry["name"]:
        anchor = entry["name"]
    return rel, anchor


def extract_symbol_detail(
    docs_dir: Path,
    entry: IndexEntry,
) -> SymbolDetail:
    rel, anchor = _resolve_html_target(entry["uri"], entry)
    html_path = docs_dir / rel
    if not html_path.is_file():
        raise FileNotFoundError(f"HTML file not found: {html_path}")
    html = html_path.read_text("utf-8", errors="replace")

    sig_parser = _SignatureExtractor(anchor)
    sig_parser.feed(html)
    signature = sig_parser.signature()

    doc_parser = _DocstringExtractor(anchor)
    doc_parser.feed(html)
    docstring = doc_parser.docstring()

    if not signature and entry["kind"] == "module":
        # Module pages do not have a signature; the page title serves instead.
        signature = entry["name"]

    source_url = f"{html_path}#{anchor}"
    return SymbolDetail(
        name=entry["name"],
        kind=entry["kind"],
        signature=signature,
        docstring=docstring,
        source_url=source_url,
    )


# ---------------------------------------------------------------------------
# Text renderers
# ---------------------------------------------------------------------------


def _format_entry_line(entry: IndexEntry) -> str:
    return f"{entry['kind']:<10} {entry['name']}"


def format_entries_text(entries: list[IndexEntry], *, empty: str = "no matches") -> str:
    if not entries:
        return empty
    return "\n".join(_format_entry_line(e) for e in entries)


def format_detail_text(detail: SymbolDetail) -> str:
    parts: list[str] = []
    if detail.signature:
        parts.append(detail.signature)
    if detail.docstring:
        parts.append(detail.docstring)
    parts.append(f"Source: {detail.source_url}")
    return "\n\n".join(parts)


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------


def supported_kind(value: str | None) -> str | None:
    if value is None:
        return None
    if value not in KNOWN_KINDS:
        raise ValueError(f"unknown kind: {value}")
    return value


def is_macos() -> bool:  # pragma: no cover - convenience for callers
    return sys.platform == "darwin"
