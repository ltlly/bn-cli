from __future__ import annotations

import hashlib
import json
import socket
import tempfile
from pathlib import Path

import pytest

import tiktoken

from bn import output
from bn.output import DEFAULT_SPILL_TOKEN_LIMIT
from bn.output import write_output


TOKENIZER = "o200k_base"


def _token_count(text: str) -> int:
    return len(tiktoken.get_encoding(TOKENIZER).encode(text, disallowed_special=()))


def test_default_spill_token_limit_is_10k():
    assert DEFAULT_SPILL_TOKEN_LIMIT == 10_000


def test_write_output_renders_small_payload_without_spill(tmp_path, monkeypatch):
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path))

    rendered = write_output({"ok": True}, fmt="json", out_path=None, stem="small")

    payload = json.loads(rendered)
    assert payload["ok"] is True


def test_write_output_spills_large_payload(tmp_path, monkeypatch):
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path))
    payload = {"data": [f"item-{index:04d}" for index in range(1000)]}

    rendered = write_output(
        payload,
        fmt="json",
        out_path=None,
        stem="large",
        spill_token_limit=256,
    )

    envelope = json.loads(rendered)
    artifact_root = tempfile.gettempdir()
    assert envelope["artifact_path"].startswith(artifact_root)
    artifact_text = Path(envelope["artifact_path"]).read_text()
    assert envelope["tokenizer"] == TOKENIZER
    assert envelope["tokens"] == _token_count(artifact_text)


def test_write_output_spills_text_payload_with_txt_suffix(tmp_path, monkeypatch):
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path))
    payload = "\n".join(f"line {index} with distinctive content" for index in range(1000))

    rendered = write_output(
        payload,
        fmt="text",
        out_path=None,
        stem="large-text",
        spill_token_limit=256,
    )

    envelope = json.loads(rendered)
    assert envelope["artifact_path"].endswith(".txt")


def test_write_output_uses_token_limit_not_byte_limit(tmp_path, monkeypatch):
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path))
    payload = "x" * 1000
    token_limit = _token_count(payload + "\n") + 1

    rendered = write_output(
        payload,
        fmt="text",
        out_path=None,
        stem="byte-heavy",
        spill_token_limit=token_limit,
    )

    assert rendered == payload + "\n"


def test_write_output_reports_exact_tokens_for_explicit_out_path(tmp_path, monkeypatch):
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path))

    out_path = tmp_path / "artifacts" / "payload.json"
    rendered = write_output(
        {"message": "token-aware output"},
        fmt="json",
        out_path=out_path,
        stem="explicit-out",
    )

    envelope = json.loads(rendered)
    artifact_text = out_path.read_text()
    assert envelope["artifact_path"] == str(out_path)
    assert envelope["tokenizer"] == TOKENIZER
    assert envelope["tokens"] == _token_count(artifact_text)


def test_embedded_tokenizer_data_matches_pinned_hash():
    data = output.tokenizer_data_path().read_bytes()

    assert hashlib.sha256(data).hexdigest() == output.TOKENIZER_DATA_SHA256


def test_tokenizer_status_reports_embedded_table():
    status = output.tokenizer_status()

    assert status["embedded_data_present"] is True


def test_embedded_tokenizer_matches_tiktoken_counts():
    try:
        reference = tiktoken.get_encoding(TOKENIZER)
    except Exception as exc:  # pragma: no cover - depends on a downloadable BPE cache
        pytest.skip(f"tiktoken reference encoding unavailable: {exc}")

    encoding = output._embedded_encoding()
    if encoding is None:  # pragma: no cover - the vendored table ships with the package
        pytest.skip("vendored tokenizer data unavailable")

    samples = [
        "",
        "hello world",
        '{"ok": true, "items": [1, 2, 3]}\n',
        "0x401000  mov rax, qword [rbp-0x8]\n" * 20,
        "中文测试 — emoji 🚀 mixed\n" * 5,
        "".join(chr(c) for c in range(32, 0x800)),
    ]
    for sample in samples:
        assert len(encoding.encode(sample, disallowed_special=())) == len(
            reference.encode(sample, disallowed_special=())
        )


def test_count_tokens_treats_literal_special_tokens_as_text():
    count, tokenizer = output.count_tokens("hello <|endoftext|> world")

    assert tokenizer == TOKENIZER
    assert count > 0


def test_small_payload_does_not_need_the_tokenizer(monkeypatch, tmp_path):
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path))

    def _explode():
        raise AssertionError("tokenizer must not load for payloads under the byte limit")

    monkeypatch.setattr(output, "_load_tokenizer", _explode)

    rendered = write_output({"ok": True}, fmt="json", out_path=None, stem="small")

    assert json.loads(rendered) == {"ok": True}


def test_spill_falls_back_to_estimate_without_tiktoken(monkeypatch, tmp_path):
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(output, "tiktoken", None)
    output._load_tokenizer.cache_clear()
    try:
        payload = {"data": [f"item-{index:04d}" for index in range(1000)]}
        rendered = write_output(
            payload,
            fmt="json",
            out_path=None,
            stem="large-fallback",
            spill_token_limit=256,
        )

        envelope = json.loads(rendered)
        artifact_text = Path(envelope["artifact_path"]).read_text()
        assert envelope["tokenizer"] == output.ESTIMATE_TOKENIZER
        assert envelope["tokens"] > 0
        assert len(artifact_text) == envelope["bytes"]
    finally:
        output._load_tokenizer.cache_clear()


def test_tokenizer_works_offline_with_embedded_table(monkeypatch, tmp_path):
    monkeypatch.setenv("TIKTOKEN_CACHE_DIR", str(tmp_path / "empty-tiktoken-cache"))
    monkeypatch.setenv("DATA_GYM_CACHE_DIR", str(tmp_path / "empty-data-gym-cache"))

    def _refuse(*args, **kwargs):
        raise OSError("network disabled")

    monkeypatch.setattr(socket, "socket", _refuse)
    monkeypatch.setattr(socket, "create_connection", _refuse)
    output._load_tokenizer.cache_clear()
    try:
        count, tokenizer = output.count_tokens("0x401000  mov rax, qword [rbp-0x8]\n" * 100)
        status = output.tokenizer_status()
    finally:
        output._load_tokenizer.cache_clear()

    assert tokenizer == TOKENIZER
    assert count > 0
    assert status["source"] == output.TOKENIZER_SOURCE_EMBEDDED


def test_tokenizer_status_reports_estimate_after_failure(monkeypatch, tmp_path):
    monkeypatch.setenv("BN_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(output, "tiktoken", None)
    monkeypatch.setattr(output, "tokenizer_data_path", lambda: tmp_path / "missing.tiktoken")
    output._load_tokenizer.cache_clear()
    try:
        status = output.tokenizer_status()
    finally:
        output._load_tokenizer.cache_clear()

    assert status["exact"] is False
    assert status["source"] == output.TOKENIZER_SOURCE_ESTIMATE
    assert status["tokenizer"] == output.ESTIMATE_TOKENIZER
