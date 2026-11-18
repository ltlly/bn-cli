from __future__ import annotations

import json
import shlex
import types
from pathlib import Path

import pytest
from test_addressing import MappedBV
from test_bridge import (
    _bv_with_workflow,
    _FakeMutationBV,
    _FakeWorkflowMachine,
    _load_bridge,
)

import bn.cli
from bn import transport
from bn.artifacts import select_result
from bn.output import write_output_result


def test_cli_address_inputs_are_passed_unchanged_and_context_is_visible(
    monkeypatch, capsys
):
    calls = []
    context = {
        "target_id": "test",
        "image_base": "0x400000",
        "view_start": "0x401000",
        "external_spaces": {},
    }

    def send(op, *, params=None, target=None):
        calls.append((op, params))
        return {
            "ok": True,
            "result": {"address": "0x401010"},
            "address_context": context,
        }

    monkeypatch.setattr(bn.cli, "send_request", send)
    assert (
        bn.cli.main(
            [
                "memory",
                "read",
                "map:uc:0x1010",
                "--length",
                "4",
                "--target",
                "test",
                "--with-context",
                "--format",
                "json",
            ]
        )
        == 0
    )
    out, err = capsys.readouterr()
    assert calls[0][1]["address"] == "map:uc:0x1010"
    assert json.loads(out)["address_context"] == context
    assert "image_base=0x400000" in err


@pytest.mark.parametrize("command", ["decompile", "il"])
def test_il_commands_share_job_wait_and_context_output(monkeypatch, capsys, command):
    calls = []
    context = {"target_id": "test", "image_base": "0x400000"}

    def send(op, *, params=None, target=None):
        calls.append(op)
        if op == "job_submit":
            return {"ok": True, "result": {"job_id": "job", "wait_supported": True}}
        if op == "job_wait":
            return {"ok": True, "result": {"state": "succeeded"}}
        assert op == "job_result"
        return {
            "ok": True,
            "result": {
                "ready": True,
                "job": {"state": "succeeded", "address_context": context},
                "result": {"text": "return 1;"},
            },
        }

    monkeypatch.setattr(bn.cli, "send_request", send)
    monkeypatch.setattr(bn.cli, "_JOB_CAPABLE_SEND_REQUEST", send)
    assert (
        bn.cli.main(
            [command, "main", "--target", "test", "--with-context", "--format", "json"]
        )
        == 0
    )
    assert calls == ["job_submit", "job_wait", "job_result"]
    result = json.loads(capsys.readouterr().out)
    assert result == {"address_context": context, "result": {"text": "return 1;"}}


def test_cli_patch_assembly_and_nop_length_plumbing(monkeypatch):
    calls = []

    def send(op, *, params=None, target=None):
        calls.append((op, params))
        return {"ok": True, "result": {}}

    monkeypatch.setattr(bn.cli, "send_request", send)
    assert (
        bn.cli.main(["patch", "assemble", "rva:0x10", "nop", "--target", "test"]) == 0
    )
    assert calls[-1] == ("patch_assemble", {"address": "rva:0x10", "asm": "nop"})
    assert (
        bn.cli.main(["patch", "nop", "0x10", "--length", "12", "--target", "test"]) == 0
    )
    assert calls[-1][1]["length"] == 12


@pytest.mark.parametrize(
    "argv,expected",
    [
        (
            ["value", "reg", "entry", "0", "rax"],
            {"instruction_index": 0, "address": None, "register": "rax"},
        ),
        (
            ["value", "reg", "entry", "rax", "--address", "map:uc:0x1000"],
            {"instruction_index": None, "address": "map:uc:0x1000"},
        ),
        (["value", "stack", "entry", "-8", "--address", "rva:0x1010"], {"offset": -8}),
        (
            ["value", "possible", "entry", "0", "rax", "--after"],
            {"after": True, "kind": "possible"},
        ),
        (["value", "flags", "entry", "0", "zf"], {"flag": "zf"}),
        (
            ["memory", "reader", "0x401010", "--width", "8", "--endian", "big"],
            {"width": 8, "endian": "big"},
        ),
        (
            ["arch", "assemble", "nop", "--arch", "x86_64"],
            {"asm": "nop", "arch_name": "x86_64"},
        ),
        (["arch", "disasm-bytes", "9090", "--count", "1"], {"count": 1}),
        (["patch", "status", "0x401010"], {"address": "0x401010"}),
        (
            ["search", "constant", "0x42"],
            {"constant": "0x42", "start": None, "end": None},
        ),
    ],
)
def test_previously_disconnected_command_parameters(monkeypatch, argv, expected):
    calls = []

    def send(op, *, params=None, target=None):
        calls.append(params)
        return {"ok": True, "result": {}}

    monkeypatch.setattr(bn.cli, "send_request", send)
    assert bn.cli.main([*argv, "--target", "test"]) == 0
    assert all(calls[-1][key] == value for key, value in expected.items())


def test_value_query_uses_precise_native_instruction_api(monkeypatch):
    module = _load_bridge(monkeypatch)
    instance = module.BinaryNinjaBridge(mode="headless")
    bv = MappedBV()
    calls = []
    value = types.SimpleNamespace(type="ConstantValue", value=42)
    instruction = types.SimpleNamespace(
        address=0x401012,
        instr_index=7,
        get_possible_reg_values_after=lambda reg: calls.append(reg) or value,
    )
    fn = bv.functions[0]
    fn.get_low_level_il_at = lambda address: (
        instruction if address == 0x401010 else None
    )
    instance.targets.register(bv)
    result = instance._value_query(
        "active",
        {
            "function_start": "entry",
            "address": "rva:0x1010",
            "kind": "possible",
            "register": "rax",
            "after": True,
        },
    )
    assert calls == ["rax"]
    assert result["instruction_index"] == 7 and result["address"] == "0x401010"
    assert result["llil_address"] == "0x401012"


def test_preview_restore_rejection_is_not_reported_as_success(monkeypatch):
    module = _load_bridge(monkeypatch)
    instance = module.BinaryNinjaBridge(mode="headless")
    machine = _FakeWorkflowMachine()
    bv = _bv_with_workflow(machine)
    monkeypatch.setattr(instance, "_resolve_view", lambda _: bv)
    machine.override_clear = lambda activity: {"commandStatus": {"accepted": False}}
    result = instance._workflow_override_apply(
        None, action="set", activity="test", enable=True, function=None, preview=True
    )
    assert result["status"] == "verification_failed"
    assert not result["reverted"] and not result["success"]


def test_unknown_override_state_does_not_authorize_mutation(monkeypatch):
    module = _load_bridge(monkeypatch)
    instance = module.BinaryNinjaBridge(mode="headless")
    machine = _FakeWorkflowMachine()
    monkeypatch.setattr(instance, "_resolve_view", lambda _: _bv_with_workflow(machine))
    machine.override_query = lambda activity: {"commandStatus": {"accepted": False}}
    with pytest.raises(module.OperationFailure, match="state is unknown"):
        instance._workflow_override_apply(
            None,
            action="set",
            activity="test",
            enable=True,
            function=None,
            preview=True,
        )
    assert not machine._overrides


def test_function_page_reports_next_offset_without_changing_default(
    monkeypatch, capsys
):
    def send(op, *, params=None, target=None):
        assert params == {"offset": 2, "limit": 2}
        return {
            "ok": True,
            "result": [
                {"address": "0x10", "name": "a"},
                {"address": "0x20", "name": "b"},
            ],
        }

    monkeypatch.setattr(bn.cli, "send_request", send)
    assert (
        bn.cli.main(
            [
                "function",
                "list",
                "--offset",
                "2",
                "--limit",
                "1",
                "--target",
                "test",
                "--format",
                "json",
            ]
        )
        == 0
    )
    out, err = capsys.readouterr()
    assert len(json.loads(out)) == 1
    assert "--offset 3" in err


@pytest.mark.parametrize(
    "filename", ["README.md", "README_CN.md", "skills/bn/SKILL.md"]
)
def test_standalone_documented_commands_parse(filename):
    root = Path(__file__).resolve().parents[1]
    parser = bn.cli.build_parser()
    text = (root / filename).read_text(encoding="utf-8").replace("\\\n", " ")
    for line in text.splitlines():
        if not line.startswith("bn ") or any(
            char in line for char in ("|", ";", ">", "&", "<<")
        ):
            continue
        parser.parse_args(shlex.split(line, comments=True)[1:])


def test_cli_schema_tracks_real_parser_and_result_selection_is_bounded(
    tmp_path, capsys
):
    assert bn.cli.main(["schema", "address", "map", "add"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert {a["name"] for a in result["arguments"] if a["required"]} >= {
        "name",
        "base",
        "size",
        "source",
    }
    path = tmp_path / "items.ndjson"
    path.write_text(
        "".join(json.dumps({"n": n, "extra": True}) + "\n" for n in range(10))
    )
    assert (
        bn.cli.main(
            [
                "result",
                "show",
                str(path),
                "--offset",
                "3",
                "--limit",
                "2",
                "--fields",
                "n",
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["result"] == [{"n": 3}, {"n": 4}]
    assert result["truncated"] and result["next_offset"] == 5
    with pytest.raises(ValueError, match="nonnegative"):
        select_result(path, key=None, offset=-1, limit=10, fields=None)


def test_spills_with_same_stem_never_overwrite_each_other(tmp_path, monkeypatch):
    monkeypatch.setattr("bn.output.spill_root", lambda: tmp_path)
    results = [
        write_output_result(
            {"value": n}, fmt="json", out_path=None, stem="same", spill_token_limit=0
        )
        for n in range(20)
    ]
    paths = [Path(result.artifact["artifact_path"]) for result in results]
    assert len(set(paths)) == 20
    assert [json.loads(path.read_text())["value"] for path in paths] == list(range(20))
    assert not list(tmp_path.glob("*/.*"))


def test_request_session_pins_daemon_across_sticky_changes(monkeypatch):
    instances = [
        types.SimpleNamespace(mode="headless"),
        types.SimpleNamespace(mode="gui"),
    ]
    selections = iter(instances)
    monkeypatch.setattr(transport, "choose_instance", lambda: next(selections))
    monkeypatch.setattr(
        transport, "_send_request_to_instance", lambda instance, *a, **k: instance.mode
    )
    with transport.request_session():
        assert transport.send_request("job_submit") == "headless"
        assert transport.send_request("job_result") == "headless"
    with transport.request_session():
        assert transport.send_request("doctor") == "gui"


def test_explicit_daemon_takes_precedence_without_writing_sticky(monkeypatch):
    headless, gui = (
        types.SimpleNamespace(mode="headless"),
        types.SimpleNamespace(mode="gui"),
    )
    monkeypatch.setattr(transport, "list_instances", lambda: [headless, gui])
    monkeypatch.setattr(transport, "read_current_daemon_mode", lambda: "gui")
    with transport.request_session("headless"):
        assert transport.choose_instance() is headless


def test_cli_job_watch_prints_only_changes_and_returns_original_result(
    monkeypatch, capsys
):
    states = iter(
        [
            {"state": "running", "progress": "analysis"},
            {"state": "running", "progress": "analysis"},
            {"state": "succeeded"},
        ]
    )

    def send(op, *, params=None, target=None):
        if op == "job_wait":
            return {"ok": True, "result": next(states)}
        assert op == "job_result"
        return {
            "ok": True,
            "result": {
                "ready": True,
                "job": {"state": "succeeded"},
                "result": {"answer": 42},
            },
        }

    monkeypatch.setattr(bn.cli, "send_request", send)
    assert bn.cli.main(["job", "watch", "job-1"]) == 0
    out, err = capsys.readouterr()
    assert json.loads(out) == {"answer": 42}
    assert err.count("running: analysis") == 1


def test_job_completed_write_is_not_discarded_by_late_cancellation(
    monkeypatch, tmp_path
):
    module = _load_bridge(monkeypatch)
    instance = module.BinaryNinjaBridge(mode="headless")
    instance.jobs._root = tmp_path
    target = instance.targets.register(MappedBV()).target_id()

    def execute(op, params, selected):
        job = instance._job_local.record
        assert instance.jobs.cancel(job.job_id)[
            "accepted"
        ]  # operation has already committed
        return {"committed": True}

    monkeypatch.setattr(instance, "_execute_operation", execute)
    job_id = instance.jobs.submit("rename_symbol", {}, target)["job_id"]
    job = instance.jobs.get(job_id)
    assert job.done_event.wait(2)
    assert job.state == "succeeded"
    assert instance.jobs.result(job_id)["result"] == {"committed": True}


def test_mutation_unexpected_exception_reverts_before_propagating(monkeypatch):
    module = _load_bridge(monkeypatch)
    instance = module.BinaryNinjaBridge(mode="headless")
    bv = _FakeMutationBV()
    monkeypatch.setattr(instance, "_resolve_view", lambda _: bv)
    monkeypatch.setattr(instance, "_guess_affected_functions", lambda *a: [])
    monkeypatch.setattr(instance, "_capture_function_snapshots", lambda *a: {})
    monkeypatch.setattr(instance, "_capture_type_snapshots", lambda *a: {})

    def fail(*args):
        raise RuntimeError("unexpected apply failure")

    monkeypatch.setattr(instance, "_apply_operation", fail)
    with pytest.raises(RuntimeError, match="unexpected apply failure"):
        instance._mutation(None, False, [{"op": "rename_symbol"}])
    assert bv.events == ["begin", ("revert", "state")]


def test_byte_write_short_count_rolls_back_and_assembly_uses_block_arch(monkeypatch):
    module = _load_bridge(monkeypatch)
    instance = module.BinaryNinjaBridge(mode="headless")
    bv = MappedBV()
    memory = bytearray(b"\x90" * 0x100)
    events = []
    bv.read = lambda addr, length: bytes(
        memory[addr - 0x401000 : addr - 0x401000 + length]
    )
    bv.begin_undo_actions = lambda: bytes(memory)

    def revert(before):
        memory[:] = before
        events.append("revert")

    bv.revert_undo_actions = revert
    bv.commit_undo_actions = lambda state: events.append("commit")

    def short_write(address, data):
        memory[address - 0x401000] = data[0]
        return 1

    bv.write = short_write
    arch = types.SimpleNamespace(assemble=lambda text, addr: b"\xcc\xcc")
    bv.get_basic_blocks_at = lambda address: [types.SimpleNamespace(arch=arch)]
    monkeypatch.setattr(instance, "_resolve_view", lambda _: bv)
    with pytest.raises(RuntimeError, match="Write verification failed"):
        instance._patch_assemble(None, "rva:0x1010", "test")
    assert memory == b"\x90" * 0x100
    assert events == ["revert"]
