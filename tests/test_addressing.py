from __future__ import annotations

import types

import pytest
from test_bridge import _FakeFunction, _FakeHeadlessBV, _load_bridge


def segment(start, end, offset=0, size=0):
    return types.SimpleNamespace(
        start=start, end=end, data_offset=offset, data_length=size
    )


class MappedBV(_FakeHeadlessBV):
    def __init__(self, *, filename="/tmp/sample.so", session_id="address-test"):
        super().__init__(filename=filename, session_id=session_id)
        # The image origin intentionally differs from the lowest mapped address.
        self.image_base = 0x400000
        self.original_image_base = 0x10000
        self.start = 0x401000
        self.end = 0x409000
        self.segments = [
            segment(0x401000, 0x401100, 0x200, 0x80),
            segment(0x408000, 0x409000, 0x800, 0x1000),
        ]
        self.functions = [_FakeFunction(0x401010, "entry")]

    def get_data_offset_for_address(self, address):
        for s in self.segments:
            if s.start <= address < min(s.end, s.start + s.data_length):
                return address - s.start + s.data_offset
        return None

    def get_address_for_data_offset(self, offset):
        for s in self.segments:
            if (
                s.data_offset
                <= offset
                < s.data_offset + min(s.data_length, s.end - s.start)
            ):
                return s.start + offset - s.data_offset
        return None


@pytest.fixture
def setup(monkeypatch, tmp_path):
    module = _load_bridge(monkeypatch)
    instance = module.BinaryNinjaBridge(mode="headless")
    instance.jobs._root = tmp_path / "jobs"
    bv = MappedBV()
    record = instance.targets.register(bv)
    return module, instance, bv, record.target_id()


def test_rva_origin_is_image_base_and_file_offsets_use_segment_mapping(setup):
    _, bridge, bv, _ = setup
    resolver = bridge._address_resolver(bv)
    expected = 0x401010
    assert resolver.resolve("rva:0x1010") == expected
    assert resolver.resolve("file:0x210") == expected
    assert resolver.resolve("va:0x401010") == expected
    assert resolver.resolve(str(expected)) == expected
    result = resolver.describe(expected)
    assert result["rva"] == "0x1010"
    assert result["file_offset"] == "0x210"
    assert result["address_context"]["view_start"] == "0x401000"


def test_bss_has_no_file_offset_and_aliases_are_not_arbitrarily_resolved(setup):
    module, bridge, bv, _ = setup
    resolver = bridge._address_resolver(bv)
    assert resolver.describe(0x401090)["file_offset"] is None
    bv.segments.append(segment(0x500000, 0x500080, 0x200, 0x80))
    with pytest.raises(module.AddressError, match="2 BN mappings"):
        resolver.resolve("file:0x210")
    assert resolver.describe(0x401010)["file_offset_unique"] is False


def test_full_range_validation_rejects_gaps_and_accepts_adjacent_segments(setup):
    module, bridge, bv, _ = setup
    resolver = bridge._address_resolver(bv)
    with pytest.raises(module.AddressError, match="Unmapped"):
        resolver.require_mapped(0x4010F0, 0x20)
    bv.segments.append(segment(0x401100, 0x401200))
    resolver.require_mapped(0x4010F0, 0x20)


def test_module_map_is_bounded_and_works_in_existing_function_commands(setup):
    module, bridge, bv, target = setup
    result = bridge._address_operation(
        "address_map_add",
        {
            "name": "frida-123",
            "base": "0x7100000000",
            "size": "0x2000",
            "source": "pid:123/start:456",
        },
        target,
    )
    assert len(result["regions"]) == 1  # excludes the unrelated high segment
    assert result["bn_anchor"] == "0x400000"
    assert bridge._find_function(bv, "map:frida-123:0x7100001010").name == "entry"
    assert (
        bridge._memory_read(target, "map:frida-123:0x7100001010", 2)["address"]
        == "0x401010"
    )
    with pytest.raises(module.AddressError, match="outside map"):
        bridge._address(bv, "map:frida-123:0x7100008000")


def test_piecewise_emulator_map_roundtrips_and_stale_layout_fails(setup):
    module, bridge, bv, target = setup
    bridge._address_operation(
        "address_map_import",
        {
            "name": "uc-run1",
            "source": "unicorn:run1",
            "manifest": {
                "regions": [
                    {
                        "bn_start": "0x401000",
                        "external_start": "0x10000",
                        "length": "0x100",
                    },
                    {
                        "bn_start": "0x408000",
                        "external_start": "0x90000000",
                        "length": "0x1000",
                    },
                ]
            },
        },
        target,
    )
    resolver = bridge._address_resolver(bv)
    for bn_address, external in [(0x401010, 0x10010), (0x408050, 0x90000050)]:
        assert resolver.resolve(f"map:uc-run1:{hex(external)}") == bn_address
        assert resolver.describe(bn_address)["external"]["uc-run1"]["address"] == hex(
            external
        )
    bv.image_base += 0x10000
    with pytest.raises(module.AddressError, match="stale"):
        resolver.resolve("map:uc-run1:0x10010")
    assert resolver.describe(0x401010)["external"]["uc-run1"] == {"stale": True}


def test_maps_are_target_scoped_and_duplicates_do_not_replace(setup):
    module, bridge, _bv, target = setup
    params = {
        "name": "runtime",
        "base": "0x7100000000",
        "size": "0x2000",
        "source": "pid:123",
    }
    bridge._address_operation("address_map_add", params, target)
    with pytest.raises(module.AddressError, match="already exists"):
        bridge._address_operation(
            "address_map_add", {**params, "base": "0x7200000000"}, target
        )
    other = MappedBV(filename="/tmp/other.so", session_id="other")
    bridge.targets.register(other)
    with pytest.raises(module.AddressError, match="Unknown address map"):
        bridge._address(other, "map:runtime:0x7100001010")


@pytest.mark.parametrize(
    "regions,match",
    [
        (
            [{"bn_start": 0x401000, "external_start": 0x100, "length": 0}],
            "Invalid address range",
        ),
        (
            [{"bn_start": 0x401000, "external_start": (1 << 64) - 2, "length": 4}],
            "overflows",
        ),
        (
            [
                {"bn_start": 0x401000, "external_start": 0x100, "length": 0x20},
                {"bn_start": 0x401010, "external_start": 0x200, "length": 0x20},
            ],
            "Overlapping bn_start",
        ),
        (
            [
                {"bn_start": 0x401000, "external_start": 0x100, "length": 0x20},
                {"bn_start": 0x408000, "external_start": 0x110, "length": 0x20},
            ],
            "Overlapping external_start",
        ),
    ],
)
def test_invalid_regions_are_atomic(setup, regions, match):
    module, bridge, bv, _ = setup
    resolver = bridge._address_resolver(bv)
    with pytest.raises(module.AddressError, match=match):
        resolver.add_space("bad", regions, "test")
    assert not resolver.spaces


def test_expression_uses_native_parser_only_when_explicit(setup):
    module, bridge, bv, _ = setup
    calls = []
    bv.parse_expression = lambda value: calls.append(value) or 0x401010
    assert bridge._address(bv, "expr:entry+0x10") == 0x401010
    assert calls == ["entry+0x10"]
    assert bridge._address(bv, "10") == 10
    with pytest.raises(module.AddressError):
        bridge._address(bv, "rva:garbage")


def test_byte_verification_and_frida_snapshot_import(setup):
    _, bridge, _, target = setup
    result = bridge._address_operation(
        "address_map_import",
        {
            "name": "frida",
            "source": "pid:7",
            "kind": "frida-module",
            "bn_base": "va:0x400000",
            "manifest": {"name": "sample.so", "base": "0x7700000000", "size": 0x2000},
        },
        target,
    )
    assert result["external_anchor"] == "0x7700000000"
    ok = bridge._address_operation(
        "address_verify", {"address": "map:frida:0x7700001010", "bytes": "9090"}, target
    )
    mismatch = bridge._address_operation(
        "address_verify", {"address": "rva:0x1010", "bytes": "cccc"}, target
    )
    assert ok["matches"] is True
    assert mismatch["matches"] is False


def test_frida_module_requires_explicit_anchor_when_base_and_start_differ(setup):
    module, bridge, _, target = setup
    with pytest.raises(module.AddressError, match="specify --bn-base"):
        bridge._address_operation(
            "address_map_import",
            {
                "name": "frida",
                "source": "pid:7",
                "kind": "frida-module",
                "manifest": {"base": "0x7700000000", "size": 0x2000},
            },
            target,
        )


def test_job_results_carry_address_context_without_changing_result_shape(setup):
    _, bridge, _, target = setup
    response = bridge.dispatch(
        {
            "op": "memory_read",
            "target": target,
            "params": {"address": "rva:0x1010", "length": 2},
        }
    )
    assert response["ok"] is True
    assert response["result"]["data_hex"] == "9090"
    assert response["address_context"]["image_base"] == "0x400000"
    assert response["address_context"]["target_id"] == target


def test_pagination_applies_after_function_filtering(setup):
    _, bridge, bv, target = setup
    bv.functions = [
        _FakeFunction(0x401000 + n, name)
        for n, name in enumerate(["skip", "hit_a", "skip2", "hit_b", "hit_c"])
    ]
    assert [
        row["name"]
        for row in bridge._search_functions(target, "hit", offset=1, limit=1)
    ] == ["hit_b"]
    assert len(bridge._list_functions(target, offset=2, limit=2)) == 2
    assert bridge._list_functions(target, limit=0) == []


def test_rebase_replaces_target_preserves_active_and_drops_maps(setup):
    _, bridge, bv, target = setup
    bridge.targets.set_active(bridge.targets.view_id_for(bv))
    bridge._address_operation(
        "address_map_add",
        {"name": "old", "base": "0x7100000000", "size": "0x2000", "source": "old"},
        target,
    )
    new = MappedBV(session_id="rebase-new")
    new.start = new.image_base = 0x900000
    calls = []
    bv.rebase = lambda address, force=False: calls.append((address, force)) or new
    result = bridge._loader_rebase(target, "va:0x900000", force=True)
    assert calls == [(0x900000, True)]
    assert result["target_id"] != target and result["removed_address_maps"] == ["old"]
    assert bridge.targets.resolve("active") is new
    assert bridge.targets.target_id_for(bv) is None
    assert not bridge._address_resolver(new).spaces


def test_failed_rebase_does_not_claim_success_or_replace_target(setup):
    _, bridge, bv, target = setup
    bv.rebase = lambda *a, **k: None
    with pytest.raises(RuntimeError, match="rebase failed"):
        bridge._loader_rebase(target, "0x900000")
    assert bridge.targets.resolve(target) is bv


def test_file_and_piecewise_range_endpoints_do_not_jump_across_gaps(setup):
    module, bridge, bv, _ = setup
    resolver = bridge._address_resolver(bv)
    assert resolver.resolve("file:0x280", endpoint=True) == 0x401080
    resolver.add_space(
        "uc",
        [
            {"bn_start": 0x401000, "external_start": 0x1000, "length": 0x100},
            {"bn_start": 0x408000, "external_start": 0x1100, "length": 0x100},
        ],
        "test",
    )
    assert resolver.resolve("map:uc:0x1100") == 0x408000
    with pytest.raises(module.AddressError, match="Ambiguous map endpoint"):
        resolver.resolve("map:uc:0x1100", endpoint=True)
