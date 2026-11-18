from __future__ import annotations

import functools
import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .artifacts import atomic_write
from .paths import spill_root, tokenizer_cache_dir

try:  # pragma: no cover - the fallback path is covered by tests that unload tiktoken
    import tiktoken
except Exception:  # pragma: no cover - tiktoken is optional at runtime
    tiktoken = None  # type: ignore[assignment]


DEFAULT_SPILL_TOKEN_LIMIT = 10_000
# `tiktoken` does not currently resolve the dotted `gpt-5.4` alias directly.
GPT_5_4_TOKENIZER = "o200k_base"
# sha256 of the upstream `o200k_base.tiktoken` BPE file. The vendored copy is checked
# against it so a truncated or tampered table can never silently skew token counts.
TOKENIZER_DATA_SHA256 = (
    "446a9538cb6c348e3516120d7c08b09f57c36495e2acfffe59a5bf8b0cfb1a2d"
)
# Mirrors `tiktoken_ext.openai_public.o200k_base` so the vendored ranks can be turned
# into an Encoding without contacting the network.
TOKENIZER_PAT_STR = "|".join(
    [
        r"""[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}]*[\p{Ll}\p{Lm}\p{Lo}\p{M}]+(?i:'s|'t|'re|'ve|'m|'ll|'d)?""",
        r"""[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}]+[\p{Ll}\p{Lm}\p{Lo}\p{M}]*(?i:'s|'t|'re|'ve|'m|'ll|'d)?""",
        r"""\p{N}{1,3}""",
        r""" ?[^\s\p{L}\p{N}]+[\r\n/]*""",
        r"""\s*[\r\n]+""",
        r"""\s+(?!\S)""",
        r"""\s+""",
    ]
)
TOKENIZER_SPECIAL_TOKENS = {"<|endoftext|>": 199999, "<|endofprompt|>": 200018}
# Reported instead of `GPT_5_4_TOKENIZER` when the real BPE table is unavailable and
# the byte-level estimate is used to keep the spill guard working offline.
ESTIMATE_TOKENIZER = f"{GPT_5_4_TOKENIZER}+estimate"

TOKENIZER_SOURCE_EMBEDDED = "embedded"
TOKENIZER_SOURCE_TIKTOKEN = "tiktoken"
TOKENIZER_SOURCE_ESTIMATE = "estimate"


@dataclass(frozen=True)
class OutputWriteResult:
    rendered: str
    artifact: dict[str, Any] | None = None
    spilled: bool = False


def _json_default(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    return repr(value)


def render_value(value: Any, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(value, indent=2, sort_keys=True, default=_json_default) + "\n"

    if fmt == "ndjson":
        if isinstance(value, list):
            lines = [
                json.dumps(item, sort_keys=True, default=_json_default) for item in value
            ]
            return "\n".join(lines) + ("\n" if lines else "")
        return json.dumps(value, sort_keys=True, default=_json_default) + "\n"

    if isinstance(value, str):
        return value if value.endswith("\n") else value + "\n"
    return json.dumps(value, indent=2, sort_keys=True, default=_json_default) + "\n"


def _summary(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return {"kind": "object", "keys": sorted(value.keys())[:10], "count": len(value)}
    if isinstance(value, list):
        return {"kind": "array", "count": len(value)}
    if isinstance(value, str):
        return {"kind": "string", "chars": len(value)}
    return {"kind": type(value).__name__}


def _spill_path(stem: str, suffix: str) -> Path:
    now = datetime.now(timezone.utc)
    directory = spill_root() / now.strftime("%Y%m%d")
    directory.mkdir(parents=True, exist_ok=True)
    return directory / f"{stem}-{now.strftime('%H%M%S')}-{uuid.uuid4().hex}{suffix}"


def tokenizer_data_path() -> Path:
    """Path of the BPE table shipped inside the package (offline token counting)."""
    return Path(__file__).with_name("_data") / f"{GPT_5_4_TOKENIZER}.tiktoken"


def _embedded_encoding() -> tiktoken.Encoding | None:
    if tiktoken is None:
        return None
    path = tokenizer_data_path()
    if not path.is_file():
        return None
    try:
        from tiktoken.load import load_tiktoken_bpe

        mergeable_ranks = load_tiktoken_bpe(
            str(path), expected_hash=TOKENIZER_DATA_SHA256
        )
        return tiktoken.Encoding(
            name=GPT_5_4_TOKENIZER,
            pat_str=TOKENIZER_PAT_STR,
            mergeable_ranks=mergeable_ranks,
            special_tokens=dict(TOKENIZER_SPECIAL_TOKENS),
        )
    except Exception:
        return None


def _downloaded_encoding() -> tiktoken.Encoding | None:
    if tiktoken is None:
        return None
    # Keep tiktoken's one-time BPE download inside bn's cache instead of the OS temp
    # directory, so a temp cleanup cannot silently degrade token counts later.
    os.environ.setdefault("TIKTOKEN_CACHE_DIR", str(tokenizer_cache_dir()))
    try:
        return tiktoken.get_encoding(GPT_5_4_TOKENIZER)
    except Exception:
        return None


@functools.cache
def _load_tokenizer() -> tuple[tiktoken.Encoding | None, str]:
    encoding = _embedded_encoding()
    if encoding is not None:
        return encoding, TOKENIZER_SOURCE_EMBEDDED
    encoding = _downloaded_encoding()
    if encoding is not None:
        return encoding, TOKENIZER_SOURCE_TIKTOKEN
    return None, TOKENIZER_SOURCE_ESTIMATE


def _token_encoding() -> tiktoken.Encoding | None:
    return _load_tokenizer()[0]


def tokenizer_status() -> dict[str, Any]:
    """Describe how token counts are produced (used by `bn doctor`)."""
    encoding, source = _load_tokenizer()
    path = tokenizer_data_path()
    return {
        "tokenizer": GPT_5_4_TOKENIZER if encoding is not None else ESTIMATE_TOKENIZER,
        "source": source,
        "exact": encoding is not None,
        "embedded_data_path": str(path),
        "embedded_data_present": path.is_file(),
    }


def _estimate_tokens(text: str) -> int:
    # ~4 bytes per token. Only used when no BPE table can be loaded; it keeps the spill
    # guard conservative instead of failing the whole command.
    return (len(text.encode("utf-8")) + 3) // 4


def count_tokens(text: str) -> tuple[int, str]:
    """Return `(token_count, tokenizer_name)` for a rendered payload."""
    encoding = _token_encoding()
    if encoding is not None:
        try:
            # `disallowed_special=()` keeps literal `<|endoftext|>`-style text (which can
            # easily show up in Binary Ninja output) from raising mid-render.
            return len(encoding.encode(text, disallowed_special=())), GPT_5_4_TOKENIZER
        except Exception:
            pass
    return _estimate_tokens(text), ESTIMATE_TOKENIZER


def _artifact_payload(
    *,
    artifact_path: Path,
    fmt: str,
    encoded: bytes,
    token_count: int,
    tokenizer: str,
    value: Any,
) -> dict[str, Any]:
    return {
        "ok": True,
        "artifact_path": str(artifact_path),
        "format": fmt,
        "bytes": len(encoded),
        "tokens": token_count,
        "tokenizer": tokenizer,
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "summary": _summary(value),
    }


def _artifact_envelope(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def write_output_result(
    value: Any,
    *,
    fmt: str,
    out_path: Path | None,
    stem: str,
    spill_token_limit: int = DEFAULT_SPILL_TOKEN_LIMIT,
) -> OutputWriteResult:
    rendered = render_value(value, fmt)
    encoded = rendered.encode("utf-8")

    if out_path is not None:
        token_count, tokenizer = count_tokens(rendered)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(out_path, encoded)
        artifact = _artifact_payload(
            artifact_path=out_path,
            fmt=fmt,
            encoded=encoded,
            token_count=token_count,
            tokenizer=tokenizer,
            value=value,
        )
        return OutputWriteResult(
            rendered=_artifact_envelope(artifact),
            artifact=artifact,
            spilled=False,
        )

    # A token never spans less than one byte, so a payload at or below the byte limit
    # cannot spill. Skipping the BPE table here keeps the common small-output path fast
    # and independent of the tokenizer being available.
    if len(encoded) <= spill_token_limit:
        return OutputWriteResult(rendered=rendered)

    token_count, tokenizer = count_tokens(rendered)
    if token_count <= spill_token_limit:
        return OutputWriteResult(rendered=rendered)

    suffix = ".ndjson" if fmt == "ndjson" else ".txt" if fmt == "text" else ".json"
    spill_path = _spill_path(stem, suffix)
    atomic_write(spill_path, encoded)
    artifact = _artifact_payload(
        artifact_path=spill_path,
        fmt=fmt,
        encoded=encoded,
        token_count=token_count,
        tokenizer=tokenizer,
        value=value,
    )
    return OutputWriteResult(
        rendered=_artifact_envelope(artifact),
        artifact=artifact,
        spilled=True,
    )


def write_output(
    value: Any,
    *,
    fmt: str,
    out_path: Path | None,
    stem: str,
    spill_token_limit: int = DEFAULT_SPILL_TOKEN_LIMIT,
) -> str:
    return write_output_result(
        value,
        fmt=fmt,
        out_path=out_path,
        stem=stem,
        spill_token_limit=spill_token_limit,
    ).rendered
