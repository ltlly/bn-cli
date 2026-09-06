"""Explicit address coordinates. No Binary Ninja import; all mappings are view-scoped.

Bare integers keep the CLI's historical decimal/0x-hex BN-VA semantics. External
addresses are never guessed, rebased, dereferenced, or stripped of pointer tags.
"""

from __future__ import annotations

import hashlib
import json
import re
from itertools import pairwise
from typing import Any


class AddressError(RuntimeError):
    pass


def number(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise TypeError("Expected an integer or decimal/0x hexadecimal string")
    if isinstance(value, int):
        return value
    text = value.strip()
    return int(text, 16 if text.lower().startswith(("0x", "-0x")) else 10)


def unsigned(value: Any) -> int:
    result = number(value)
    if not 0 <= result < 1 << 64:
        raise AddressError("Address must fit an unsigned 64-bit integer")
    return result


class AddressResolver:
    def __init__(self, bv, spaces: dict | None = None):
        self.bv = bv
        self.spaces = spaces if spaces is not None else {}

    @property
    def base(self) -> int:
        base = getattr(self.bv, "image_base", None)
        if base is None:
            raise AddressError(
                "BinaryView.image_base unavailable; cannot infer RVA origin from view.start"
            )
        return int(base)

    def segments(self) -> list[dict]:
        return sorted(
            (
                {
                    "start": int(s.start),
                    "end": int(s.end),
                    "file_offset": int(s.data_offset),
                    "file_length": int(s.data_length),
                }
                for s in getattr(self.bv, "segments", [])
            ),
            key=lambda s: (s["start"], s["end"], s["file_offset"]),
        )

    def layout_id(self) -> str:
        payload = {
            "base": getattr(self.bv, "image_base", None),
            "segments": self.segments(),
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

    def context(self) -> dict:
        base = getattr(self.bv, "image_base", None)
        original = getattr(self.bv, "original_image_base", None)
        layout = self.layout_id()
        return {
            "default_space": "bn_va",
            "image_base": hex(base) if base is not None else None,
            "original_image_base": hex(original) if original is not None else None,
            "view_start": hex(getattr(self.bv, "start", 0)),
            "view_end": hex(getattr(self.bv, "end", 0)),
            "layout_id": layout,
            "file_offset_domain": "BinaryView backing-data offsets; container/slice views may differ from outer-file offsets",
            "external_spaces": {
                name: {"source": space["source"], "stale": space["layout_id"] != layout}
                for name, space in self.spaces.items()
            },
            "syntax": [
                "va:0xADDRESS",
                "rva:0xOFFSET",
                "file:0xOFFSET",
                "map:NAME:0xADDRESS",
                "expr:SYMBOL+0xOFFSET",
            ],
        }

    def require_mapped(self, address: int, length: int = 1) -> None:
        if length <= 0 or address < 0 or address + length > 1 << 64:
            raise AddressError("Invalid address range")
        cursor = address
        for segment in self.segments():
            if segment["start"] <= cursor < segment["end"]:
                cursor = max(cursor, segment["end"])
                if cursor >= address + length:
                    return
        # Raw views can have no explicit segments.
        if (
            not self.segments()
            and getattr(self.bv, "view_type", None) == "Raw"
            and self.bv.start <= address
            and address + length <= self.bv.end
        ):
            return
        raise AddressError(
            f"Unmapped BN VA {hex(address)} (length {length}); use rva:, file:, or map:NAME: explicitly. Run `bn address context`."
        )

    def _file_candidates(self, offset: int, *, endpoint: bool = False) -> list[int]:
        candidates = {
            s["start"] + offset - s["file_offset"]
            for s in self.segments()
            if s["file_offset"]
            <= offset
            < s["file_offset"] + min(s["file_length"], s["end"] - s["start"])
        }
        api = getattr(self.bv, "get_address_for_data_offset", None)
        if endpoint:
            candidates.update(
                s["start"] + offset - s["file_offset"]
                for s in self.segments()
                if s["file_length"] > 0
                and offset
                == s["file_offset"] + min(s["file_length"], s["end"] - s["start"])
            )
        if api is not None:
            address = api(offset)
            if address is not None:
                candidates.add(int(address))
        if (
            not self.segments()
            and getattr(self.bv, "view_type", None) == "Raw"
            and 0 <= offset < self.bv.end - self.bv.start + int(endpoint)
        ):
            candidates.add(int(self.bv.start) + offset)
        return sorted(candidates)

    def resolve(self, value: Any, *, endpoint: bool = False) -> int:
        text = str(value).strip()
        kind, separator, rest = text.partition(":")
        if not separator or kind not in {"va", "rva", "file", "map", "expr"}:
            return unsigned(value)
        try:
            if kind == "va":
                return unsigned(rest)
            if kind == "rva":
                address = unsigned(self.base + unsigned(rest))
            elif kind == "file":
                candidates = self._file_candidates(unsigned(rest), endpoint=endpoint)
                if len(candidates) != 1:
                    raise AddressError(
                        f"File offset {rest} has {len(candidates)} BN mappings: {[hex(a) for a in candidates]}; choose an explicit va: address"
                    )
                address = candidates[0]
            elif kind == "expr":
                parse = getattr(self.bv, "parse_expression", None)
                if parse is None:
                    raise AddressError("BinaryView.parse_expression unavailable")
                address = unsigned(parse(rest))
            else:
                name, sep, external = rest.partition(":")
                if not sep:
                    raise AddressError("Expected map:NAME:0xADDRESS")
                space = self.get_space(name)
                value = unsigned(external)
                candidates = [
                    r["bn_start"] + value - r["external_start"]
                    for r in space["regions"]
                    if r["external_start"] <= value < r["external_start"] + r["length"]
                ]
                if endpoint:
                    candidates += [
                        r["bn_start"] + r["length"]
                        for r in space["regions"]
                        if value == r["external_start"] + r["length"]
                    ]
                candidates = sorted(set(candidates))
                if len(candidates) > 1:
                    raise AddressError(
                        f"Ambiguous map endpoint {external}: {[hex(a) for a in candidates]}; use va: explicitly"
                    )
                if not candidates:
                    raise AddressError(
                        f"Address {external} is outside map {name!r}; refresh the mapping for this process/emulator session"
                    )
                address = candidates[0]
            if not endpoint:
                self.require_mapped(address)
            return address
        except (ValueError, TypeError) as exc:
            raise AddressError(f"Invalid {kind} address {text!r}: {exc}") from exc

    def get_space(self, name: str) -> dict:
        if name not in self.spaces:
            raise AddressError(
                f"Unknown address map {name!r}; register it with `bn address map add` or `import`"
            )
        space = self.spaces[name]
        if space["layout_id"] != self.layout_id():
            raise AddressError(
                f"Address map {name!r} is stale after a BN layout change; remove and recreate it"
            )
        return space

    def add_space(
        self,
        name: str,
        regions: list[dict],
        source: str,
        *,
        layout_id: str | None = None,
    ) -> dict:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            raise AddressError("Map name must contain only letters, digits, _, . or -")
        if name in self.spaces:
            raise AddressError(
                f"Address map {name!r} already exists; remove it explicitly before replacing"
            )
        if layout_id is not None and layout_id != self.layout_id():
            raise AddressError("Imported mapping belongs to a different BN layout")
        if not regions or not source:
            raise AddressError(
                "A mapping requires nonempty regions and a process/emulator source label"
            )
        normalized = []
        for region in regions:
            row = {
                key: unsigned(region[key])
                for key in ("bn_start", "external_start", "length")
            }
            self.require_mapped(row["bn_start"], row["length"])
            if row["external_start"] + row["length"] > 1 << 64:
                raise AddressError("External range overflows 64 bits")
            normalized.append(row)
        for key in ("bn_start", "external_start"):
            ordered = sorted(normalized, key=lambda r: r[key])
            if any(a[key] + a["length"] > b[key] for a, b in pairwise(ordered)):
                raise AddressError(
                    f"Overlapping {key} ranges would make the mapping ambiguous"
                )
        space = {
            "name": name,
            "source": source,
            "layout_id": self.layout_id(),
            "regions": normalized,
            "verification": "user_declared; external process identity and bytes are not verified",
        }
        self.spaces[name] = space
        return self.export_space(name)

    def add_slide(
        self, name: str, external_base: Any, source: str, size: Any, bn_base: Any = None
    ) -> dict:
        anchor = self.base if bn_base is None else self.resolve(bn_base)
        external_base, size = unsigned(external_base), unsigned(size)
        if not size or anchor + size > 1 << 64 or external_base + size > 1 << 64:
            raise AddressError("Invalid module span")
        slide = external_base - anchor
        regions = []
        for segment in self.segments():
            start, end = (
                max(segment["start"], anchor),
                min(segment["end"], anchor + size),
            )
            if start < end:
                regions.append(
                    {
                        "bn_start": start,
                        "external_start": start + slide,
                        "length": end - start,
                    }
                )
        self.add_space(name, regions, source)
        self.spaces[name].update(
            {
                "kind": "module_slide",
                "bn_anchor": hex(anchor),
                "external_anchor": hex(external_base),
                "size": hex(size),
            }
        )
        return self.export_space(name)

    def export_space(self, name: str) -> dict:
        space = self.get_space(name)
        return {
            **space,
            "regions": [
                {key: hex(value) for key, value in row.items()}
                for row in space["regions"]
            ],
        }

    def describe(self, value: Any) -> dict:
        address = self.resolve(value)
        self.require_mapped(address)
        base = getattr(self.bv, "image_base", None)
        rva = address - base if base is not None and address >= base else None
        get_offset = getattr(self.bv, "get_data_offset_for_address", None)
        offset = get_offset(address) if get_offset is not None else None
        if (
            offset is None
            and not self.segments()
            and getattr(self.bv, "view_type", None) == "Raw"
        ):
            offset = address - self.bv.start
        external = {}
        for name in self.spaces:
            if self.spaces[name]["layout_id"] != self.layout_id():
                external[name] = {"stale": True}
                continue
            space = self.get_space(name)
            for row in space["regions"]:
                if row["bn_start"] <= address < row["bn_start"] + row["length"]:
                    translated = row["external_start"] + address - row["bn_start"]
                    external[name] = {
                        "address": hex(translated),
                        "input": f"map:{name}:{hex(translated)}",
                        "source": space["source"],
                    }
        return {
            "input": str(value),
            "bn_va": hex(address),
            "rva": hex(rva) if rva is not None else None,
            "file_offset": hex(offset) if offset is not None else None,
            "file_offset_unique": len(self._file_candidates(offset)) == 1
            if offset is not None
            else None,
            "external": external,
            "address_context": self.context(),
        }
