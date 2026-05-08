from __future__ import annotations

import json
from pathlib import Path

import pytest

import bn.api_docs as api_docs
import bn.cli


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "api_docs"


@pytest.fixture
def docs_dir(tmp_path: Path) -> Path:
    """Copy the fixture docs into a tmp dir so mtime-keyed cache tests are stable."""

    dest = tmp_path / "docs"
    dest.mkdir()
    (dest / "objects.inv").write_bytes((FIXTURE_DIR / "objects.inv").read_bytes())
    (dest / "fake-module.html").write_text(
        (FIXTURE_DIR / "fake-module.html").read_text()
    )
    return dest


@pytest.fixture
def cache_path(tmp_path: Path) -> Path:
    return tmp_path / "cache.json"


def test_parse_objects_inv(docs_dir: Path) -> None:
    entries = api_docs.parse_objects_inv(docs_dir / "objects.inv")
    names = {e["name"] for e in entries}
    assert names == {
        "fakelib",
        "fakelib.Widget",
        "fakelib.Widget.read",
        "fakelib.Other",
        "fakelib.Other.read",
        "fakelib.log_info",
    }
    by_name = {e["name"]: e for e in entries}
    assert by_name["fakelib.Widget.read"]["kind"] == "method"
    # The `$` shorthand is expanded to the full name.
    assert by_name["fakelib.Widget.read"]["uri"].endswith("#fakelib.Widget.read")


def test_load_or_build_index_caches(docs_dir: Path, cache_path: Path) -> None:
    import os

    first = api_docs.load_or_build_index(docs_dir, cache_path=cache_path)
    assert cache_path.exists()
    payload = json.loads(cache_path.read_text())
    assert payload["docs_dir"] == str(docs_dir.resolve())
    assert len(payload["entries"]) == len(first)

    # Corrupt the inventory while preserving its mtime — the cache must hit
    # without ever reading the file.
    inv = docs_dir / "objects.inv"
    original_mtime_ns = inv.stat().st_mtime_ns
    inv.write_bytes(b"garbage")
    os.utime(inv, ns=(original_mtime_ns, original_mtime_ns))

    second = api_docs.load_or_build_index(docs_dir, cache_path=cache_path)
    assert second == first


def test_load_or_build_index_refresh(docs_dir: Path, cache_path: Path) -> None:
    api_docs.load_or_build_index(docs_dir, cache_path=cache_path)
    # Replace the inventory with one that has a different mtime AND fewer entries.
    import zlib

    header = (
        b"# Sphinx inventory version 2\n"
        b"# Project: fakelib\n"
        b"# Version: 1.0\n"
        b"# The remainder of this file is compressed using zlib.\n"
    )
    body = b"fakelib py:module 0 fake-module.html#module-$ -\n"
    (docs_dir / "objects.inv").write_bytes(header + zlib.compress(body))

    refreshed = api_docs.load_or_build_index(docs_dir, refresh=True, cache_path=cache_path)
    assert [e["name"] for e in refreshed] == ["fakelib"]


def test_find_docs_dir_env_override(monkeypatch, docs_dir: Path) -> None:
    monkeypatch.setenv(api_docs.DOCS_DIR_ENV, str(docs_dir))
    assert api_docs.find_docs_dir(None) == docs_dir


def test_find_docs_dir_missing_dir(monkeypatch, tmp_path: Path) -> None:
    bogus = tmp_path / "nope"
    monkeypatch.setenv(api_docs.DOCS_DIR_ENV, str(bogus))
    with pytest.raises(FileNotFoundError):
        api_docs.find_docs_dir(None)


def test_search_substring_and_regex(docs_dir: Path, cache_path: Path) -> None:
    entries = api_docs.load_or_build_index(docs_dir, cache_path=cache_path)
    matches = api_docs.search(entries, "read")
    names = [e["name"] for e in matches]
    assert "fakelib.Widget.read" in names
    assert "fakelib.Other.read" in names

    methods = api_docs.search(entries, "read", kind="method")
    assert all(e["kind"] == "method" for e in methods)

    rx_matches = api_docs.search(entries, r"^fakelib\.log", regex=True)
    assert [e["name"] for e in rx_matches] == ["fakelib.log_info"]


def test_find_symbol_unique_and_ambiguous(docs_dir: Path, cache_path: Path) -> None:
    entries = api_docs.load_or_build_index(docs_dir, cache_path=cache_path)

    unique = api_docs.find_symbol(entries, "fakelib.Widget.read")
    assert len(unique) == 1
    assert unique[0]["name"] == "fakelib.Widget.read"

    ambiguous = api_docs.find_symbol(entries, "read")
    assert {e["name"] for e in ambiguous} == {
        "fakelib.Widget.read",
        "fakelib.Other.read",
    }

    assert api_docs.find_symbol(entries, "does.not.exist") == []


def test_extract_symbol_detail(docs_dir: Path, cache_path: Path) -> None:
    entries = api_docs.load_or_build_index(docs_dir, cache_path=cache_path)
    entry = next(e for e in entries if e["name"] == "fakelib.Widget.read")
    detail = api_docs.extract_symbol_detail(docs_dir, entry)

    assert detail.name == "fakelib.Widget.read"
    assert detail.kind == "method"
    assert detail.signature.startswith("read(")
    assert "bytes" in detail.signature
    assert "[source]" not in detail.signature
    assert "¶" not in detail.signature

    assert "Reads" in detail.docstring
    assert "Returns the bytes" in detail.docstring
    # Multi-paragraph: paragraphs preserved as blank lines.
    assert "\n\n" in detail.docstring


def test_format_entries_text(docs_dir: Path, cache_path: Path) -> None:
    entries = api_docs.load_or_build_index(docs_dir, cache_path=cache_path)
    lines = api_docs.format_entries_text(entries[:2]).splitlines()
    assert all(line[:10].rstrip() in api_docs.KNOWN_KINDS for line in lines)


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


def test_cli_search_text(monkeypatch, capsys, docs_dir: Path, tmp_path: Path) -> None:
    monkeypatch.setenv(api_docs.DOCS_DIR_ENV, str(docs_dir))
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path / "cache"))
    rc = bn.cli.main(["api-docs", "search", "read"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "fakelib.Widget.read" in captured.out
    assert "fakelib.Other.read" in captured.out


def test_cli_search_no_match_exit_one(monkeypatch, capsys, docs_dir: Path, tmp_path: Path) -> None:
    monkeypatch.setenv(api_docs.DOCS_DIR_ENV, str(docs_dir))
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path / "cache"))
    rc = bn.cli.main(["api-docs", "search", "zzzz"])
    assert rc == 1


def test_cli_show_unique(monkeypatch, capsys, docs_dir: Path, tmp_path: Path) -> None:
    monkeypatch.setenv(api_docs.DOCS_DIR_ENV, str(docs_dir))
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path / "cache"))
    rc = bn.cli.main(["api-docs", "show", "fakelib.Widget.read"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "read(" in out
    assert "Reads" in out
    assert "Source:" in out


def test_cli_show_ambiguous_exit_two(monkeypatch, capsys, docs_dir: Path, tmp_path: Path) -> None:
    monkeypatch.setenv(api_docs.DOCS_DIR_ENV, str(docs_dir))
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path / "cache"))
    rc = bn.cli.main(["api-docs", "show", "read"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "fakelib.Widget.read" in err
    assert "fakelib.Other.read" in err


def test_cli_show_missing_exit_one(monkeypatch, capsys, docs_dir: Path, tmp_path: Path) -> None:
    monkeypatch.setenv(api_docs.DOCS_DIR_ENV, str(docs_dir))
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path / "cache"))
    rc = bn.cli.main(["api-docs", "show", "nope"])
    assert rc == 1


def test_cli_list_module_filter(monkeypatch, capsys, docs_dir: Path, tmp_path: Path) -> None:
    monkeypatch.setenv(api_docs.DOCS_DIR_ENV, str(docs_dir))
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path / "cache"))
    rc = bn.cli.main(["api-docs", "list", "--module", "fakelib", "--kind", "method"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "fakelib.Widget.read" in out
    assert "fakelib.log_info" not in out


def test_cli_show_json(monkeypatch, capsys, docs_dir: Path, tmp_path: Path) -> None:
    monkeypatch.setenv(api_docs.DOCS_DIR_ENV, str(docs_dir))
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path / "cache"))
    rc = bn.cli.main(["api-docs", "show", "fakelib.Widget.read", "--format", "json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["name"] == "fakelib.Widget.read"
    assert payload["kind"] == "method"
    assert payload["signature"].startswith("read(")
    assert "Reads" in payload["docstring"]


def test_cli_refresh(monkeypatch, capsys, docs_dir: Path, tmp_path: Path) -> None:
    monkeypatch.setenv(api_docs.DOCS_DIR_ENV, str(docs_dir))
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path / "cache"))
    rc = bn.cli.main(["api-docs", "refresh"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["entries"] == 6
    assert Path(payload["docs_dir"]).name == "docs"


def test_cli_missing_docs_dir_returns_two(monkeypatch, capsys, tmp_path: Path) -> None:
    monkeypatch.setenv(api_docs.DOCS_DIR_ENV, str(tmp_path / "absent"))
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path / "cache"))
    rc = bn.cli.main(["api-docs", "search", "read"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "objects.inv" in err
