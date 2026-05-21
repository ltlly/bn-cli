from __future__ import annotations

import importlib
import importlib.util
import sys
import threading
import time
import types
from pathlib import Path

import pytest


def _load_bridge(monkeypatch):
    fake_bn = types.ModuleType("binaryninja")

    class SymbolType:
        FunctionSymbol = "SymbolType.FunctionSymbol"
        DataSymbol = "SymbolType.DataSymbol"
        ImportedFunctionSymbol = "SymbolType.ImportedFunctionSymbol"

    class Symbol:
        def __init__(self, symbol_type, address, name):
            self.type = symbol_type
            self.address = address
            self.name = name
            self.raw_name = name

    fake_bn.SymbolType = SymbolType
    fake_bn.Symbol = Symbol
    fake_bn.log_info = lambda *args, **kwargs: None
    fake_bn.log_warn = lambda *args, **kwargs: None
    fake_bn.log_error = lambda *args, **kwargs: None

    fake_mainthread = types.ModuleType("binaryninja.mainthread")
    fake_mainthread.execute_on_main_thread_and_wait = lambda func: func()
    fake_mainthread.is_main_thread = lambda: True

    fake_plugin = types.ModuleType("binaryninja.plugin")

    class PluginCommand:
        @staticmethod
        def register(*args, **kwargs):
            return None

    fake_plugin.PluginCommand = PluginCommand

    monkeypatch.setitem(sys.modules, "binaryninja", fake_bn)
    monkeypatch.setitem(sys.modules, "binaryninja.mainthread", fake_mainthread)
    monkeypatch.setitem(sys.modules, "binaryninja.plugin", fake_plugin)
    monkeypatch.delitem(sys.modules, "binaryninjaui", raising=False)
    package_name = "bn_test_bridge"
    module_name = f"{package_name}.bridge"
    monkeypatch.delitem(sys.modules, module_name, raising=False)
    monkeypatch.delitem(sys.modules, package_name, raising=False)

    bridge_path = Path(__file__).resolve().parents[1] / "plugin" / "bn_agent_bridge" / "bridge.py"
    package = types.ModuleType(package_name)
    package.__path__ = [str(bridge_path.parent)]
    monkeypatch.setitem(sys.modules, package_name, package)
    spec = importlib.util.spec_from_file_location(module_name, bridge_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)
    return module


class _FakeFunction:
    def __init__(self, start: int, name: str, type_text: str = "int32_t()"):
        self.start = start
        self.name = name
        self.raw_name = name
        self.type = type_text
        self.parameter_vars = []
        self.stack_layout = []
        self.calling_convention = "__cdecl"
        self.return_type = "int32_t"
        self.basic_blocks = []
        self.low_level_il = []


class _FakeBasicBlock:
    def __init__(self, start: int, end: int):
        self.start = start
        self.end = end


class _FakeInstructionInfo:
    def __init__(self, length: int):
        self.length = length


class _FakeArch:
    def __init__(self, lengths=None):
        self.max_instr_length = 16
        self.lengths = dict(lengths or {})

    def get_instruction_info(self, data, address):
        return _FakeInstructionInfo(self.lengths.get(int(address), 1))


class _FakeOperation:
    def __init__(self, name: str):
        self.name = name

    def __str__(self):
        return self.name


class _FakeConstPtr:
    def __init__(self, constant: int):
        self.operation = _FakeOperation("LLIL_CONST_PTR")
        self.constant = constant


class _FakeReg:
    def __init__(self, name: str):
        self.operation = _FakeOperation("LLIL_REG")
        self.name = name


class _FakeHLILInstructionNode:
    def __init__(self, text: str, *, condition=None, parent=None, expr_index: int = 0, instr_index: int = 0):
        self.text = text
        self.condition = condition
        self.parent = parent
        self.expr_index = expr_index
        self.instr_index = instr_index

    def __str__(self):
        return self.text


_FAKE_HLIL_TYPES: dict[str, type[_FakeHLILInstructionNode]] = {}


def _FakeHLILInstruction(
    text: str,
    *,
    class_name: str,
    condition=None,
    parent=None,
    expr_index: int = 0,
    instr_index: int = 0,
):
    cls = _FAKE_HLIL_TYPES.get(class_name)
    if cls is None:
        cls = type(class_name, (_FakeHLILInstructionNode,), {})
        _FAKE_HLIL_TYPES[class_name] = cls
    return cls(
        text,
        condition=condition,
        parent=parent,
        expr_index=expr_index,
        instr_index=instr_index,
    )


class _FakeLLILInstruction:
    def __init__(self, address: int, dest, *, operation: str = "LLIL_CALL", hlils=None):
        self.address = address
        self.dest = dest
        self.operation = _FakeOperation(operation)
        self.hlils = list(hlils or [])
        self.mlils = []
        self.mapped_medium_level_il = None


class _FakeVariable:
    def __init__(
        self,
        *,
        name: str,
        storage: int,
        var_type: str,
        identifier: int,
        index: int = 0,
        source_type: str = "StackVariableSourceType",
    ):
        self.name = name
        self.storage = storage
        self.type = var_type
        self.identifier = identifier
        self.index = index
        self.source_type = types.SimpleNamespace(name=source_type)


class _FakeBV:
    def __init__(self, *, functions=None, symbols=None, types_=None, arch=None, disassembly=None, instruction_lengths=None):
        self.functions = list(functions or [])
        self._symbols = list(symbols or [])
        self.types = dict(types_ or {})
        self.arch = arch or _FakeArch(instruction_lengths)
        self._disassembly = dict(disassembly or {})
        self._instruction_lengths = dict(instruction_lengths or {})

    def get_function_at(self, address: int):
        for fn in self.functions:
            if int(fn.start) == int(address):
                return fn
        return None

    def get_symbols_by_name(self, name: str):
        return [symbol for symbol in self._symbols if getattr(symbol, "name", None) == name]

    def get_symbol_by_raw_name(self, name: str):
        for symbol in self._symbols:
            if getattr(symbol, "raw_name", None) == name:
                return symbol
        return None

    def get_symbols(self):
        return list(self._symbols)

    def get_symbol_at(self, address: int):
        for symbol in self._symbols:
            if int(symbol.address) == int(address):
                return symbol
        return None

    def get_type_by_name(self, name: str):
        return self.types.get(str(name))

    def define_user_type(self, name: str, type_obj):
        self.types[str(name)] = type_obj

    def get_instruction_length(self, address: int):
        return self._instruction_lengths.get(int(address), 1)

    def get_disassembly(self, address: int):
        return self._disassembly.get(int(address), "")

    def read(self, address: int, length: int):
        return b"\x90" * length


class _FakeBVFile:
    def __init__(self, filename: str = "", session_id: str = ""):
        self.filename = filename
        self.session_id = session_id
        self.closed = False

    def close(self):
        self.closed = True


class _FakeAnalysisProgress:
    def __init__(self, state_name: str = "Idle", count: int = 0, total: int = 0):
        self.state = types.SimpleNamespace(name=state_name)
        self.count = count
        self.total = total


class _FakeHeadlessBV(_FakeBV):
    def __init__(self, *, filename: str = "", session_id: str = "", **kwargs):
        super().__init__(**kwargs)
        self.file = _FakeBVFile(filename=filename, session_id=session_id)
        self.analysis_progress = _FakeAnalysisProgress(state_name="Idle")
        self.analysis_calls = 0
        self.created_database_at: str | None = None
        self.snapshots_saved = 0

    def update_analysis_and_wait(self):
        self.analysis_calls += 1
        self.analysis_progress = _FakeAnalysisProgress(state_name="Idle")

    def create_database(self, path: str):
        self.created_database_at = str(path)
        Path(path).write_bytes(b"fake-bndb")
        self.file = _FakeBVFile(filename=str(path), session_id=self.file.session_id)
        return True

    def save_auto_snapshot(self):
        self.snapshots_saved += 1
        return True


class _FakeType:
    def __init__(self, decl: str, *, width: int = 0, members=None, type_class: str = "StructureTypeClass"):
        self._decl = decl
        self.width = width
        self.members = list(members) if members is not None else None
        self.type_class = type_class

    def __str__(self):
        return self._decl


class _FakeMember:
    def __init__(self, offset: int, name: str, type_text: str):
        self.offset = offset
        self.name = name
        self.type = type_text


class _FakeMutationBV(_FakeBV):
    def __init__(self):
        super().__init__()
        self.events: list[tuple[str, str] | str] = []

    def begin_undo_actions(self):
        self.events.append("begin")
        return "state"

    def update_analysis_and_wait(self):
        self.events.append("refresh")

    def revert_undo_actions(self, state):
        self.events.append(("revert", state))

    def commit_undo_actions(self, state):
        self.events.append(("commit", state))


class _ParseResult:
    def __init__(self, *, types=None, variables=None, functions=None):
        self.types = dict(types or {})
        self.variables = dict(variables or {})
        self.functions = dict(functions or {})


def test_resolve_rename_target_rejects_ambiguous_function_identifier(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    bv = _FakeBV(
        functions=[
            _FakeFunction(0x401000, "duplicate_name"),
            _FakeFunction(0x402000, "duplicate_name"),
        ]
    )

    with pytest.raises(bridge.OperationFailure, match="Ambiguous function identifier"):
        instance._resolve_rename_target(bv, "duplicate_name", "function")


def test_verify_rename_symbol_reports_noop(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    bv = _FakeBV(functions=[_FakeFunction(0x401000, "player_update")])

    result = instance._verify_operation(
        bv,
        {
            "op": "rename_symbol",
            "kind": "function",
            "address": "0x401000",
            "before_name": "player_update",
            "new_name": "player_update",
            "requested": {
                "op": "rename_symbol",
                "identifier": "player_update",
                "new_name": "player_update",
            },
        },
    )

    assert result["status"] == "noop"
    assert result["observed"]["name"] == "player_update"


def test_mutation_reverts_on_verification_failure(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    bv = _FakeMutationBV()

    monkeypatch.setattr(instance, "_resolve_view", lambda selector: bv)
    monkeypatch.setattr(instance, "_guess_affected_functions", lambda bv, operations: [])
    monkeypatch.setattr(instance, "_capture_function_snapshots", lambda bv, functions: {})
    monkeypatch.setattr(instance, "_capture_type_snapshots", lambda bv, operations: {})
    monkeypatch.setattr(instance, "_diff_snapshots", lambda before, after: [])
    monkeypatch.setattr(instance, "_diff_type_snapshots", lambda before, after: [])
    monkeypatch.setattr(
        instance,
        "_apply_operation",
        lambda bv, op: {
            "op": "rename_symbol",
            "kind": "function",
            "address": "0x401000",
            "new_name": "player_update",
            "requested": {"identifier": "sub_401000", "new_name": "player_update"},
        },
    )
    monkeypatch.setattr(
        instance,
        "_verify_operation",
        lambda bv, result: {
            **result,
            "status": "verification_failed",
            "message": "Live rename verification failed at 0x401000",
        },
    )

    result = instance._mutation("active", False, [{"op": "rename_symbol"}])

    assert result["success"] is False
    assert result["committed"] is False
    assert ("revert", "state") in bv.events
    assert ("commit", "state") not in bv.events


def test_refresh_updates_analysis_and_returns_target_info(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    bv = _FakeMutationBV()

    monkeypatch.setattr(instance, "_resolve_view", lambda selector: bv)
    monkeypatch.setattr(instance, "_target_info", lambda selector: {"selector": "SnailMail_unwrapped.exe.bndb"})

    result = instance._refresh("active")

    assert result["refreshed"] is True
    assert result["target"]["selector"] == "SnailMail_unwrapped.exe.bndb"
    assert "refresh" in bv.events


def test_parse_declaration_source_uses_platform_parser_with_source_path(monkeypatch, tmp_path):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    recorded = {}

    class _Platform:
        def parse_types_from_source(self, source, **kwargs):
            recorded["source"] = source
            recorded["kwargs"] = kwargs
            return _ParseResult(types={"Player": "struct Player"})

    class _SourceBV(_FakeBV):
        def __init__(self):
            super().__init__()
            self.platform = _Platform()

        def parse_types_from_string(self, declaration):
            raise AssertionError("string parser should not be used when source parsing succeeds")

    header_path = tmp_path / "win32_min.h"
    header_path.write_text("typedef struct Player { int hp; } Player;", encoding="utf-8")
    bv = _SourceBV()

    parsed = instance._parse_declaration_source(bv, header_path.read_text(encoding="utf-8"), source_path=str(header_path))

    assert [name for name, _ in parsed["types"]] == ["Player"]
    assert recorded["kwargs"]["filename"] == str(header_path)
    assert recorded["kwargs"]["include_dirs"] == [str(header_path.parent.resolve())]


def test_op_types_declare_accepts_source_without_named_types(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()

    class _Platform:
        def parse_types_from_source(self, source, **kwargs):
            return _ParseResult(
                functions={"DirectInput8Create": "int32_t(void)"},
                variables={"GUID_SysKeyboard": "GUID"},
            )

    class _SourceOnlyBV(_FakeBV):
        def __init__(self):
            super().__init__()
            self.platform = _Platform()
            self.defined: list[tuple[str, str]] = []

        def parse_types_from_string(self, declaration):
            raise AssertionError("string parser should not be used when source parsing succeeds")

        def get_type_by_name(self, name):
            return None

        def define_user_type(self, name, type_obj):
            self.defined.append((name, type_obj))

    bv = _SourceOnlyBV()

    result = instance._op_types_declare(
        bv,
        {
            "op": "types_declare",
            "declaration": "extern const GUID GUID_SysKeyboard;",
            "source_path": "/tmp/win32_min.h",
        },
    )

    assert result["count"] == 0
    assert result["defined_types"] == {}
    assert result["parsed_functions"] == ["DirectInput8Create"]
    assert result["parsed_variables"] == ["GUID_SysKeyboard"]
    assert bv.defined == []


def test_op_types_declare_uses_canonical_defined_type_text(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()

    raw_type = _FakeType(
        "struct",
        width=0x2C,
        members=[
            _FakeMember(0x0, "state", "uint32_t"),
            _FakeMember(0x10, "transition_progress", "float"),
        ],
    )

    class _Platform:
        def parse_types_from_source(self, source, **kwargs):
            return _ParseResult(types={"DamageGaugeController": raw_type})

    class _CanonicalizingBV(_FakeBV):
        def __init__(self):
            super().__init__()
            self.platform = _Platform()

        def parse_types_from_string(self, declaration):
            raise AssertionError("string parser should not be used when source parsing succeeds")

        def define_user_type(self, name, type_obj):
            canonical = _FakeType(
                f"struct {name}",
                width=type_obj.width,
                members=getattr(type_obj, "members", None),
            )
            super().define_user_type(name, canonical)

    bv = _CanonicalizingBV()

    result = instance._op_types_declare(
        bv,
        {
            "op": "types_declare",
            "declaration": "struct DamageGaugeController { int state; };",
            "source_path": "/tmp/controller.h",
        },
    )

    assert result["defined_types"] == {"DamageGaugeController": "struct DamageGaugeController"}
    verified = instance._verify_operation(bv, result)
    assert verified["status"] == "verified"
    assert verified["observed"]["defined_types"]["DamageGaugeController"] == "struct DamageGaugeController"


def test_op_set_prototype_uses_string_user_type_for_bn_compat(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()

    class _SetterFunction(_FakeFunction):
        def __init__(self):
            super().__init__(0x43F200, "update_garbage_hazard", "void* __fastcall(void* arg1)")
            self.user_type_calls = []

        def set_user_type(self, value):
            self.user_type_calls.append(value)
            if isinstance(value, str):
                self.type = value

    class _PrototypeBV(_FakeBV):
        def parse_type_string(self, declaration):
            return _FakeType("void* __thiscall(struct GarbageHazardRuntime* self)", type_class="FunctionTypeClass"), None

    fn = _SetterFunction()
    bv = _PrototypeBV(functions=[fn])

    result = instance._op_set_prototype(
        bv,
        {
            "op": "set_prototype",
            "identifier": "update_garbage_hazard",
            "prototype": "void* __thiscall update_garbage_hazard(struct GarbageHazardRuntime* self)",
        },
    )

    assert fn.user_type_calls == ["void* __thiscall(struct GarbageHazardRuntime* self)"]
    verified = instance._verify_operation(bv, result)
    assert verified["status"] == "verified"
    assert verified["observed"]["prototype"] == "void* __thiscall(struct GarbageHazardRuntime* self)"


def test_resolve_type_field_accepts_offset_and_suggests_near_match(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    bv = _FakeBV(
        types_={
            "Player": _FakeType(
                "struct Player",
                width=0x5000,
                members=[
                    _FakeMember(0x380, "player_slot", "uint32_t"),
                    _FakeMember(0x4340, "visible_life_stock", "uint32_t"),
                ],
            )
        }
    )

    by_offset = instance._resolve_type_field(bv, "Player.0x4340")
    assert by_offset["field_name"] == "visible_life_stock"
    assert by_offset["offset"] == 0x4340

    by_case = instance._resolve_type_field(bv, "Player.Visible_Life_Stock")
    assert by_case["field_name"] == "visible_life_stock"

    with pytest.raises(RuntimeError, match=r"Did you mean: visible_life_stock"):
        instance._resolve_type_field(bv, "Player.visible_life_stok")


def test_list_locals_returns_stable_ids(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    fn = _FakeFunction(0x401000, "player_update", "int32_t player_update(int32_t arg1)")
    fn.parameter_vars = [
        _FakeVariable(name="arg1", storage=4, var_type="int32_t", identifier=1001, index=0)
    ]
    fn.stack_layout = [
        _FakeVariable(name="var_4", storage=-4, var_type="float", identifier=2001, index=1)
    ]
    bv = _FakeBV(functions=[fn])
    monkeypatch.setattr(instance, "_resolve_view", lambda selector: bv)

    result = instance._list_locals_for_function("active", "player_update")

    assert result["function"]["name"] == "player_update"
    assert len(result["locals"]) == 2
    assert result["locals"][0]["local_id"].startswith("0x401000:param:")
    assert result["locals"][1]["local_id"].startswith("0x401000:local:")


def test_list_locals_skips_stack_aliases_for_parameters(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    fn = _FakeFunction(0x401000, "player_update")
    parameter = _FakeVariable(name="arg1", storage=4, var_type="int32_t", identifier=1001)
    alias = _FakeVariable(name="arg1", storage=4, var_type="int32_t", identifier=1001)
    local = _FakeVariable(name="var_4", storage=-4, var_type="float", identifier=2001)
    fn.parameter_vars = [parameter]
    fn.stack_layout = [alias, local]

    locals_list = instance._list_locals(fn)

    assert len(locals_list) == 2
    assert [item["local_id"] for item in locals_list] == [
        "0x401000:param:StackVariableSourceType:4:0:1001",
        "0x401000:local:StackVariableSourceType:-4:0:2001",
    ]


def test_find_variable_selector_prefers_local_id(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    fn = _FakeFunction(0x401000, "player_update")
    shared = _FakeVariable(name="tmp", storage=-4, var_type="int32_t", identifier=2001)
    duplicate = _FakeVariable(name="tmp", storage=-8, var_type="int32_t", identifier=2002)
    fn.stack_layout = [shared, duplicate]

    local_id = instance._local_id(fn, duplicate, is_parameter=False)
    found, is_parameter = instance._find_variable_selector(fn, local_id)

    assert found is duplicate
    assert is_parameter is False


def test_function_info_includes_metadata(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    fn = _FakeFunction(0x401000, "player_update", "int32_t player_update(int32_t arg1)")
    fn.parameter_vars = [
        _FakeVariable(name="arg1", storage=4, var_type="int32_t", identifier=1001, index=0)
    ]
    bv = _FakeBV(functions=[fn])
    monkeypatch.setattr(instance, "_resolve_view", lambda selector: bv)

    result = instance._function_info("active", "player_update")

    assert result["prototype"] == "int32_t player_update(int32_t arg1)"
    assert result["return_type"] == "int32_t"
    assert result["calling_convention"] == "__cdecl"
    assert result["size"] is None


def test_list_functions_is_sorted_by_address(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    bv = _FakeBV(
        functions=[
            _FakeFunction(0x402000, "sub_402000"),
            _FakeFunction(0x401000, "sub_401000"),
        ]
    )
    monkeypatch.setattr(instance, "_resolve_view", lambda selector: bv)

    result = instance._list_functions("active")

    assert [item["address"] for item in result] == ["0x401000", "0x402000"]


def test_list_functions_can_filter_by_address_range(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    bv = _FakeBV(
        functions=[
            _FakeFunction(0x401000, "sub_401000"),
            _FakeFunction(0x402000, "sub_402000"),
            _FakeFunction(0x403000, "sub_403000"),
        ]
    )
    monkeypatch.setattr(instance, "_resolve_view", lambda selector: bv)

    result = instance._list_functions("active", min_address="0x401800", max_address="0x402fff")

    assert [item["address"] for item in result] == ["0x402000"]


def test_search_functions_supports_regex(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    bv = _FakeBV(
        functions=[
            _FakeFunction(0x401000, "load_attachment"),
            _FakeFunction(0x402000, "detach_player"),
            _FakeFunction(0x403000, "update_camera"),
        ]
    )
    monkeypatch.setattr(instance, "_resolve_view", lambda selector: bv)

    result = instance._search_functions("active", "attach|detach", regex=True)

    assert [item["name"] for item in result] == ["load_attachment", "detach_player"]


def test_search_functions_rejects_invalid_regex(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    bv = _FakeBV(functions=[_FakeFunction(0x401000, "load_attachment")])
    monkeypatch.setattr(instance, "_resolve_view", lambda selector: bv)

    with pytest.raises(bridge.OperationFailure, match="Invalid function regex"):
        instance._search_functions("active", "(", regex=True)


def test_callsites_returns_local_hlil_assignment_and_pre_branch_condition(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    branch = _FakeHLILInstruction(
        "if (result == 2)",
        class_name="HighLevelILIf",
        condition="result == 2",
        expr_index=40,
        instr_index=40,
    )
    first_statement = _FakeHLILInstruction(
        "edx_1:eax_1 = sx.q(crt_rand())",
        class_name="HighLevelILVarInit",
        expr_index=32,
        instr_index=32,
    )
    first_sx = _FakeHLILInstruction(
        "sx.q(crt_rand())",
        class_name="HighLevelILSx",
        parent=first_statement,
        expr_index=31,
        instr_index=31,
    )
    first_call = _FakeHLILInstruction(
        "crt_rand()",
        class_name="HighLevelILCall",
        parent=first_sx,
        expr_index=30,
        instr_index=30,
    )
    second_statement = _FakeHLILInstruction(
        "eax_3, edx_2 = crt_rand()",
        class_name="HighLevelILVarInit",
        parent=branch,
        expr_index=42,
        instr_index=42,
    )
    second_call = _FakeHLILInstruction(
        "crt_rand()",
        class_name="HighLevelILCall",
        parent=second_statement,
        expr_index=41,
        instr_index=41,
    )
    callee = _FakeFunction(0x461746, "crt_rand")
    fn = _FakeFunction(0x412470, "bonus_pick_random_type")
    fn.basic_blocks = [_FakeBasicBlock(0x41249C, 0x4124D8)]
    fn.low_level_il = [
        [
            _FakeLLILInstruction(0x4124A0, _FakeConstPtr(0x461746), hlils=[first_call]),
            _FakeLLILInstruction(0x4124D1, _FakeConstPtr(0x461746), hlils=[second_call]),
        ]
    ]
    bv = _FakeBV(
        functions=[callee, fn],
        instruction_lengths={
            0x41249C: 2,
            0x41249E: 2,
            0x4124A0: 5,
            0x4124A5: 3,
            0x4124D1: 5,
            0x4124D6: 2,
        },
        disassembly={
            0x41249C: "mov eax, 0",
            0x41249E: "mov ebx, 0",
            0x4124A0: "call crt_rand",
            0x4124A5: "cmp eax, 0xd",
            0x4124D1: "call crt_rand",
            0x4124D6: "test al, 0x3f",
        },
    )
    monkeypatch.setattr(instance, "_resolve_view", lambda selector: bv)

    rows = instance._callsites(
        "active",
        "crt_rand",
        within_identifiers=["bonus_pick_random_type"],
        context=2,
    )

    assert [row["caller_static"] for row in rows] == ["0x4124a5", "0x4124d6"]
    assert rows[0]["call_addr"] == "0x4124a0"
    assert rows[0]["instruction_length"] == 5
    assert rows[0]["call_index"] == 0
    assert rows[0]["within_query"] == "bonus_pick_random_type"
    assert rows[0]["hlil_statement"] == "edx_1:eax_1 = sx.q(crt_rand())"
    assert rows[0]["pre_branch_condition"] is None
    assert rows[1]["call_index"] == 1
    assert rows[1]["hlil_statement"] == "eax_3, edx_2 = crt_rand()"
    assert rows[1]["pre_branch_condition"] == "result == 2"
    assert [item["address"] for item in rows[0]["previous_instructions"]] == ["0x41249c", "0x41249e"]
    assert rows[0]["call_instruction"]["text"] == "call crt_rand"
    assert [item["address"] for item in rows[0]["next_instructions"][:1]] == ["0x4124a5"]


def test_callsites_prefers_local_expression_over_broad_enclosing_hlil(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    branch = _FakeHLILInstruction(
        "if (config_fx_toggle != 0)",
        class_name="HighLevelILIf",
        condition="config_fx_toggle != 0",
        expr_index=100,
        instr_index=100,
    )
    broad_statement = _FakeHLILInstruction(
        "if (config_fx_toggle != 0)\nlong expression blob\nreturn",
        class_name="HighLevelILVarInit",
        parent=branch,
        expr_index=99,
        instr_index=99,
    )
    add_expr = _FakeHLILInstruction(
        "float.t(crt_rand() & 0xf) * 0.01 + 0.84",
        class_name="HighLevelILAdd",
        parent=broad_statement,
        expr_index=35,
        instr_index=9,
    )
    mul_expr = _FakeHLILInstruction(
        "float.t(crt_rand() & 0xf) * 0.01",
        class_name="HighLevelILMul",
        parent=add_expr,
        expr_index=34,
        instr_index=9,
    )
    cast_expr = _FakeHLILInstruction(
        "float.t(crt_rand() & 0xf)",
        class_name="HighLevelILIntToFloat",
        parent=mul_expr,
        expr_index=33,
        instr_index=9,
    )
    and_expr = _FakeHLILInstruction(
        "crt_rand() & 0xf",
        class_name="HighLevelILAnd",
        parent=cast_expr,
        expr_index=32,
        instr_index=9,
    )
    call_expr = _FakeHLILInstruction(
        "crt_rand()",
        class_name="HighLevelILCall",
        parent=and_expr,
        expr_index=31,
        instr_index=9,
    )
    callee = _FakeFunction(0x461746, "crt_rand")
    fn = _FakeFunction(0x427700, "fx_queue_add_random")
    fn.basic_blocks = [_FakeBasicBlock(0x427753, 0x427768)]
    fn.low_level_il = [[_FakeLLILInstruction(0x42775B, _FakeConstPtr(0x461746), hlils=[broad_statement, call_expr])]]
    bv = _FakeBV(
        functions=[callee, fn],
        instruction_lengths={
            0x427753: 5,
            0x427758: 3,
            0x42775B: 5,
            0x427760: 3,
        },
        disassembly={
            0x427753: "call helper",
            0x427758: "add esp, 0x4",
            0x42775B: "call crt_rand",
            0x427760: "and eax, 0xf",
        },
    )
    monkeypatch.setattr(instance, "_resolve_view", lambda selector: bv)

    rows = instance._callsites(
        "active",
        "crt_rand",
        within_identifiers=["fx_queue_add_random"],
        context=2,
    )

    assert len(rows) == 1
    assert rows[0]["hlil_statement"] == "float.t(crt_rand() & 0xf) * 0.01 + 0.84"
    assert rows[0]["pre_branch_condition"] == "config_fx_toggle != 0"
    assert rows[0]["call_index"] == 0
    assert rows[0]["within_query"] == "fx_queue_add_random"


def test_callsites_within_file_scope_preserves_file_order_and_dedupes(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    callee = _FakeFunction(0x461746, "crt_rand")
    alpha = _FakeFunction(0x401000, "alpha")
    alpha.basic_blocks = [_FakeBasicBlock(0x401010, 0x401016)]
    alpha.low_level_il = [[_FakeLLILInstruction(0x401010, _FakeConstPtr(0x461746))]]
    beta = _FakeFunction(0x402000, "beta")
    beta.basic_blocks = [_FakeBasicBlock(0x402020, 0x402026)]
    beta.low_level_il = [[_FakeLLILInstruction(0x402020, _FakeConstPtr(0x461746))]]
    bv = _FakeBV(
        functions=[callee, alpha, beta],
        instruction_lengths={0x401010: 5, 0x402020: 5},
        disassembly={0x401010: "call crt_rand", 0x402020: "call crt_rand"},
    )
    monkeypatch.setattr(instance, "_resolve_view", lambda selector: bv)

    rows = instance._callsites(
        "active",
        "crt_rand",
        within_identifiers=["beta", "alpha", "beta"],
        context=0,
    )

    assert [row["containing_function"]["name"] for row in rows] == ["beta", "alpha"]
    assert [row["caller_static"] for row in rows] == ["0x402025", "0x401015"]
    assert [row["within_query"] for row in rows] == ["beta", "alpha"]
    assert [row["call_index"] for row in rows] == [0, 0]


def test_callsites_ignores_indirect_calls_and_returns_null_context_when_unmapped(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    callee = _FakeFunction(0x461746, "crt_rand")
    fn = _FakeFunction(0x500000, "fx_queue_add_random")
    fn.basic_blocks = [_FakeBasicBlock(0x500010, 0x50001A)]
    fn.low_level_il = [
        [
            _FakeLLILInstruction(0x500010, _FakeReg("eax")),
            _FakeLLILInstruction(0x500015, _FakeConstPtr(0x461746)),
        ]
    ]
    bv = _FakeBV(
        functions=[callee, fn],
        instruction_lengths={0x500010: 5, 0x500015: 5},
        disassembly={0x500010: "call eax", 0x500015: "call crt_rand"},
    )
    monkeypatch.setattr(instance, "_resolve_view", lambda selector: bv)

    rows = instance._callsites(
        "active",
        "crt_rand",
        within_identifiers=["fx_queue_add_random"],
        context=1,
    )

    assert len(rows) == 1
    assert rows[0]["call_addr"] == "0x500015"
    assert rows[0]["hlil_statement"] is None
    assert rows[0]["pre_branch_condition"] is None


def test_callsites_returns_null_for_coarse_only_hlil(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    callee = _FakeFunction(0x461746, "crt_rand")
    broad_statement = _FakeHLILInstruction(
        "if (x)\nwhole function blob\nreturn",
        class_name="HighLevelILVarInit",
        expr_index=10,
        instr_index=10,
    )
    fn = _FakeFunction(0x600000, "coarse")
    fn.basic_blocks = [_FakeBasicBlock(0x600010, 0x600016)]
    fn.low_level_il = [[_FakeLLILInstruction(0x600010, _FakeConstPtr(0x461746), hlils=[broad_statement])]]
    bv = _FakeBV(
        functions=[callee, fn],
        instruction_lengths={0x600010: 5},
        disassembly={0x600010: "call crt_rand"},
    )
    monkeypatch.setattr(instance, "_resolve_view", lambda selector: bv)

    rows = instance._callsites(
        "active",
        "crt_rand",
        within_identifiers=["coarse"],
        context=1,
    )

    assert len(rows) == 1
    assert rows[0]["hlil_statement"] is None
    assert rows[0]["pre_branch_condition"] is None


def test_callsites_filters_placeholder_pre_branch_condition(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    branch = _FakeHLILInstruction(
        "do while (not(cond:0_1))",
        class_name="HighLevelILDoWhile",
        condition="not(cond:0_1)",
        expr_index=50,
        instr_index=50,
    )
    statement = _FakeHLILInstruction(
        "eax_1 = crt_rand()",
        class_name="HighLevelILVarInit",
        parent=branch,
        expr_index=51,
        instr_index=51,
    )
    call = _FakeHLILInstruction(
        "crt_rand()",
        class_name="HighLevelILCall",
        parent=statement,
        expr_index=52,
        instr_index=52,
    )
    callee = _FakeFunction(0x461746, "crt_rand")
    fn = _FakeFunction(0x700000, "placeholder_cond")
    fn.basic_blocks = [_FakeBasicBlock(0x700010, 0x700016)]
    fn.low_level_il = [[_FakeLLILInstruction(0x700010, _FakeConstPtr(0x461746), hlils=[call])]]
    bv = _FakeBV(
        functions=[callee, fn],
        instruction_lengths={0x700010: 5},
        disassembly={0x700010: "call crt_rand"},
    )
    monkeypatch.setattr(instance, "_resolve_view", lambda selector: bv)

    rows = instance._callsites(
        "active",
        "crt_rand",
        within_identifiers=["placeholder_cond"],
        context=1,
    )

    assert rows[0]["pre_branch_condition"] is None


def test_bridge_handler_swallows_broken_pipe(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    warnings = []

    class _BrokenWriter:
        def write(self, data):
            raise BrokenPipeError(32, "Broken pipe")

    handler = bridge.BridgeHandler.__new__(bridge.BridgeHandler)
    handler.wfile = _BrokenWriter()
    monkeypatch.setattr(bridge.bn, "log_warn", lambda message: warnings.append(message))

    handler._write_response(b"{}", op="xrefs", request_id="req-123")

    assert warnings == [
        "BN Agent Bridge client disconnected before response could be delivered (op=xrefs, id=req-123)"
    ]


def test_bridge_handler_reraises_unrelated_write_errors(monkeypatch):
    bridge = _load_bridge(monkeypatch)

    class _FailingWriter:
        def write(self, data):
            raise OSError(5, "Input/output error")

    handler = bridge.BridgeHandler.__new__(bridge.BridgeHandler)
    handler.wfile = _FailingWriter()

    with pytest.raises(OSError, match="Input/output error"):
        handler._write_response(b"{}", op="xrefs")


def test_py_exec_non_serializable_result_falls_back_to_repr(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    bv = _FakeBV()
    monkeypatch.setattr(instance, "_resolve_view", lambda selector: bv)

    result = instance._py_exec("active", "result = object()")

    assert isinstance(result["result"], str)
    assert result["warnings"]


def test_diff_snapshots_marks_name_only_changes(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()

    diffs = instance._diff_snapshots(
        {
            0x401000: {
                "name": "sub_401000",
                "address": "0x401000",
                "text": "return 7;",
            }
        },
        {
            0x401000: {
                "name": "player_update",
                "address": "0x401000",
                "text": "return 7;",
            }
        },
    )

    assert len(diffs) == 1
    assert diffs[0]["changed"] is True
    assert diffs[0]["before_name"] == "sub_401000"
    assert diffs[0]["after_name"] == "player_update"
    assert diffs[0]["diff"] == "--- before:sub_401000\n+++ after:player_update"
    assert "before_excerpt" not in diffs[0]


def test_read_write_lock_blocks_reader_until_writer_releases(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    lock = bridge._ReadWriteLock()
    writer_ready = threading.Event()
    writer_release = threading.Event()
    reader_entered = threading.Event()

    def writer():
        with lock.write():
            writer_ready.set()
            writer_release.wait(1)

    def reader():
        writer_ready.wait(1)
        with lock.read():
            reader_entered.set()

    writer_thread = threading.Thread(target=writer)
    reader_thread = threading.Thread(target=reader)
    writer_thread.start()
    reader_thread.start()

    assert writer_ready.wait(1)
    time.sleep(0.05)
    assert not reader_entered.is_set()

    writer_release.set()
    reader_thread.join(1)
    writer_thread.join(1)

    assert reader_entered.is_set()


def test_read_write_lock_allows_parallel_readers(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    lock = bridge._ReadWriteLock()
    entered: list[str] = []
    both_entered = threading.Event()
    release = threading.Event()

    def reader(name: str):
        with lock.read():
            entered.append(name)
            if len(entered) == 2:
                both_entered.set()
            release.wait(1)

    first = threading.Thread(target=reader, args=("first",))
    second = threading.Thread(target=reader, args=("second",))
    first.start()
    second.start()

    assert both_entered.wait(1)

    release.set()
    first.join(1)
    second.join(1)

    assert sorted(entered) == ["first", "second"]


class _FakeWorkflowMachine:
    def __init__(self, *, status=None, dump=None, overrides=None, set_accepted=True, clear_accepted=True, accept_machine_commands=True):
        self._status = status if status is not None else {"state": "idle"}
        self._dump = dump if dump is not None else {"trace": []}
        self._overrides = dict(overrides or {})
        self.calls: list[tuple[str, Any]] = []
        self._set_accepted = set_accepted
        self._clear_accepted = clear_accepted
        self._suppress_set = False
        self._breakpoints: list[str] = []
        self._accept_machine_commands = accept_machine_commands
        self._machine_state = {"activity": "undetermined", "state": "Idle"}

    def _envelope(self, command: str, *, accepted: bool | None = None, action: str | None = None, response: Any = None) -> dict[str, Any]:
        cs = {"command": command}
        if action is not None:
            cs["action"] = action
        cs["accepted"] = bool(self._accept_machine_commands if accepted is None else accepted)
        env = {
            "commandStatus": cs,
            "logStatus": {"global": False, "local": False},
            "machineState": dict(self._machine_state),
        }
        if response is not None:
            env["response"] = response
        return env

    def enable(self):
        self.calls.append(("enable", None))
        return self._envelope("enable")

    def disable(self):
        self.calls.append(("disable", None))
        return self._envelope("disable")

    def step(self):
        self.calls.append(("step", None))
        return self._envelope("step")

    def halt(self):
        self.calls.append(("halt", None))
        return self._envelope("halt")

    def reset(self):
        self.calls.append(("reset", None))
        return self._envelope("reset")

    def run(self, advanced: bool = True, incremental: bool = False):
        self.calls.append(("run", (bool(advanced), bool(incremental))))
        return self._envelope("run")

    def resume(self, advanced: bool = True, incremental: bool = False):
        self.calls.append(("resume", (bool(advanced), bool(incremental))))
        return self._envelope("resume")

    def breakpoint_set(self, activities):
        if isinstance(activities, str):
            activities = [activities]
        for name in activities:
            if name not in self._breakpoints:
                self._breakpoints.append(name)
        self.calls.append(("breakpoint_set", list(activities)))
        return self._envelope("breakpoint", action="set")

    def breakpoint_delete(self, activities):
        if isinstance(activities, str):
            activities = [activities]
        for name in activities:
            if name in self._breakpoints:
                self._breakpoints.remove(name)
        self.calls.append(("breakpoint_delete", list(activities)))
        return self._envelope("breakpoint", action="delete")

    def breakpoint_query(self):
        self.calls.append(("breakpoint_query", None))
        if self._breakpoints:
            return self._envelope(
                "breakpoint",
                action="query",
                response={"activities": list(self._breakpoints)},
            )
        return self._envelope("breakpoint", action="query")

    def status(self):
        self.calls.append(("status", None))
        return dict(self._status)

    def dump(self):
        self.calls.append(("dump", None))
        return dict(self._dump)

    def override_query(self, activity=""):
        self.calls.append(("override_query", activity))
        if activity:
            info: dict[str, Any] = {"activity": activity, "eligible": True}
            if activity in self._overrides:
                info["override"] = bool(self._overrides[activity])
            return {
                "commandStatus": {"accepted": True, "action": "query", "command": "override"},
                "response": {"activity": info},
            }
        listed = []
        for name, value in self._overrides.items():
            entry = {"activity": name, "eligible": True, "override": bool(value)}
            listed.append(entry)
        return {
            "commandStatus": {"accepted": True, "action": "query", "command": "override"},
            "response": {"activities": listed},
        }

    def override_set(self, activity, enable):
        self.calls.append(("override_set", (activity, bool(enable))))
        if self._set_accepted and not self._suppress_set:
            self._overrides[activity] = bool(enable)
        return {
            "commandStatus": {
                "accepted": bool(self._set_accepted),
                "action": "set",
                "command": "override",
            },
        }

    def override_clear(self, activity):
        self.calls.append(("override_clear", activity))
        if self._clear_accepted:
            self._overrides.pop(activity, None)
        return {
            "commandStatus": {
                "accepted": bool(self._clear_accepted),
                "action": "clear",
                "command": "override",
            },
        }


class _FakeWorkflow:
    def __init__(
        self,
        name: str,
        *,
        registered: bool = True,
        roots=None,
        activities=None,
        eligibility=None,
        configuration_text: str = "[]",
        machine: _FakeWorkflowMachine | None = ...,
    ):
        self.name = name
        self.registered = registered
        self._roots = list(roots or [])
        self._activities = list(activities or [])
        self._eligibility = list(eligibility or [])
        self._configuration_text = configuration_text
        if machine is ...:
            self._machine = _FakeWorkflowMachine()
        else:
            self._machine = machine

    def activity_roots(self, activity=""):
        if not activity:
            return list(self._roots)
        return [a for a in self._activities if a.startswith(activity + ".")][:1]

    def subactivities(self, activity="", immediate=False):
        if not activity:
            base = list(self._activities)
        else:
            base = [a for a in self._activities if a.startswith(activity)]
        if immediate:
            return [a for a in base if a.count(".") <= activity.count(".") + 1]
        return base

    def configuration(self, activity=""):
        return self._configuration_text

    def eligibility_settings(self):
        return list(self._eligibility)

    @property
    def machine(self):
        if self._machine is None:
            raise AttributeError("Machine does not exist.")
        return self._machine


def _install_fake_workflow(bridge_module, workflows: list[_FakeWorkflow]) -> dict[str, _FakeWorkflow]:
    by_name = {wf.name: wf for wf in workflows}

    class _WorkflowProxy:
        @classmethod
        @property
        def list(cls):
            return [by_name[name] for name in by_name]

    # python's classmethod-property combo varies across versions; use a simple namespace
    proxy = types.SimpleNamespace(list=[by_name[name] for name in by_name])
    bridge_module.bn.Workflow = proxy
    return by_name


def test_workflow_list_returns_sorted_with_registered_filter(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    _install_fake_workflow(
        bridge,
        [
            _FakeWorkflow("core.module.defaultAnalysis", registered=True),
            _FakeWorkflow("core.function.metaAnalysis", registered=True),
            _FakeWorkflow("plugins.scratch", registered=False),
        ],
    )

    rows = instance._workflow_list(None)
    assert [r["name"] for r in rows] == [
        "core.function.metaAnalysis",
        "core.module.defaultAnalysis",
        "plugins.scratch",
    ]
    assert {r["registered"] for r in rows} == {True, False}

    only_registered = instance._workflow_list(None, registered_only=True)
    assert all(r["registered"] for r in only_registered)
    assert {r["name"] for r in only_registered} == {
        "core.function.metaAnalysis",
        "core.module.defaultAnalysis",
    }


def test_workflow_show_returns_roots_and_activities(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    _install_fake_workflow(
        bridge,
        [
            _FakeWorkflow(
                "core.function.metaAnalysis",
                roots=["core.function.start"],
                activities=[
                    "core.function.start",
                    "core.function.start.firstPass",
                    "core.function.generateHighLevelIL",
                ],
                eligibility=["analysis.experimental"],
            ),
        ],
    )

    payload = instance._workflow_show(None, name="core.function.metaAnalysis")
    assert payload["registered"] is True
    assert payload["roots"] == ["core.function.start"]
    assert payload["activities"] == [
        "core.function.start",
        "core.function.start.firstPass",
        "core.function.generateHighLevelIL",
    ]
    assert payload["eligibility_settings"] == ["analysis.experimental"]
    assert payload["depth"] == "all"


def test_workflow_show_with_activity_and_config(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    _install_fake_workflow(
        bridge,
        [
            _FakeWorkflow(
                "core.module.defaultAnalysis",
                activities=[
                    "core.module.start",
                    "core.module.start.linearSweep",
                    "core.module.start.recurDescend",
                ],
                configuration_text='[{"name":"core.module.start"}]',
            ),
        ],
    )

    payload = instance._workflow_show(
        None,
        name="core.module.defaultAnalysis",
        activity="core.module.start",
        depth="immediate",
        with_config=True,
    )
    assert payload["scope_activity"] == "core.module.start"
    assert payload["depth"] == "immediate"
    assert payload["configuration"] == '[{"name":"core.module.start"}]'


def test_workflow_show_raises_for_unknown_workflow(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    _install_fake_workflow(bridge, [_FakeWorkflow("core.module.defaultAnalysis")])

    with pytest.raises(RuntimeError, match="Workflow not found"):
        instance._workflow_show(None, name="does.not.exist")


def test_workflow_active_for_binaryview_and_function(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()

    bv_workflow = _FakeWorkflow(
        "core.module.defaultAnalysis",
        roots=["core.module.start"],
        activities=["core.module.start", "core.module.start.linearSweep"],
    )
    fn_workflow = _FakeWorkflow(
        "core.function.metaAnalysis",
        roots=["core.function.start"],
        activities=["core.function.start", "core.function.generateHighLevelIL"],
    )

    fn = _FakeFunction(0x401000, "player_update")
    fn.workflow = fn_workflow

    class _BVWithWorkflow(_FakeBV):
        def __init__(self):
            super().__init__(functions=[fn])
            self.workflow = bv_workflow

    bv = _BVWithWorkflow()
    monkeypatch.setattr(instance, "_resolve_view", lambda selector: bv)

    bv_payload = instance._workflow_active(None)
    assert bv_payload["scope"] == "binaryview"
    assert bv_payload["workflow"]["name"] == "core.module.defaultAnalysis"
    assert bv_payload["workflow"]["activity_count"] == 2

    fn_payload = instance._workflow_active(None, function="player_update")
    assert fn_payload["scope"] == "function"
    assert fn_payload["workflow"]["name"] == "core.function.metaAnalysis"
    assert fn_payload["workflow"]["function"] == "0x401000"


def test_workflow_active_returns_none_when_no_workflow_bound(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()

    class _BareBV(_FakeBV):
        def __init__(self):
            super().__init__()
            self.workflow = None

    bv = _BareBV()
    monkeypatch.setattr(instance, "_resolve_view", lambda selector: bv)

    payload = instance._workflow_active(None)
    assert payload == {"workflow": None, "scope": "binaryview"}


def test_workflow_machine_status_and_overrides(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()

    machine = _FakeWorkflowMachine(
        status={"state": "halted", "current": "core.function.start"},
        overrides={"core.function.analyzeTailCalls": False},
    )
    workflow = _FakeWorkflow("core.module.defaultAnalysis", machine=machine)

    class _BVWithMachine(_FakeBV):
        def __init__(self):
            super().__init__()
            self.workflow = workflow

    bv = _BVWithMachine()
    monkeypatch.setattr(instance, "_resolve_view", lambda selector: bv)

    status_payload = instance._workflow_machine_call(None, "status", {})
    assert status_payload["available"] is True
    assert status_payload["scope"] == "binaryview"
    assert status_payload["status"]["state"] == "halted"

    overrides_payload = instance._workflow_machine_call(
        None,
        "overrides",
        {"activity": "core.function.analyzeTailCalls"},
    )
    assert overrides_payload["available"] is True
    activity_info = overrides_payload["overrides"]["response"]["activity"]
    assert activity_info["activity"] == "core.function.analyzeTailCalls"
    assert activity_info["override"] is False
    assert ("override_query", "core.function.analyzeTailCalls") in machine.calls


def _bv_with_workflow(machine: _FakeWorkflowMachine) -> _FakeBV:
    workflow = _FakeWorkflow("core.module.metaAnalysis", machine=machine)

    class _BV(_FakeBV):
        def __init__(self):
            super().__init__()
            self.workflow = workflow

    return _BV()


def test_workflow_override_set_persists_when_not_preview(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    machine = _FakeWorkflowMachine()
    bv = _bv_with_workflow(machine)
    monkeypatch.setattr(instance, "_resolve_view", lambda selector: bv)

    payload = instance._workflow_override_apply(
        None,
        action="set",
        activity="core.function.analyzeTailCalls",
        enable=False,
        function=None,
        preview=False,
    )

    assert payload["status"] == "verified"
    assert payload["success"] is True
    assert payload["committed"] is True
    assert payload["before"] is None
    assert payload["after"] is False
    assert payload["reverted"] is False
    assert machine._overrides["core.function.analyzeTailCalls"] is False


def test_workflow_override_set_preview_reverts_to_previous_state(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    machine = _FakeWorkflowMachine()
    bv = _bv_with_workflow(machine)
    monkeypatch.setattr(instance, "_resolve_view", lambda selector: bv)

    payload = instance._workflow_override_apply(
        None,
        action="set",
        activity="core.function.analyzeTailCalls",
        enable=True,
        function=None,
        preview=True,
    )

    assert payload["status"] == "previewed"
    assert payload["success"] is True
    assert payload["committed"] is False
    assert payload["after"] is True
    assert payload["reverted"] is True
    assert "core.function.analyzeTailCalls" not in machine._overrides


def test_workflow_override_set_preview_restores_pre_existing_override(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    machine = _FakeWorkflowMachine(overrides={"core.function.foo": True})
    bv = _bv_with_workflow(machine)
    monkeypatch.setattr(instance, "_resolve_view", lambda selector: bv)

    payload = instance._workflow_override_apply(
        None,
        action="set",
        activity="core.function.foo",
        enable=False,
        function=None,
        preview=True,
    )

    assert payload["before"] is True
    assert payload["after"] is False
    assert payload["status"] == "previewed"
    assert payload["reverted"] is True
    assert machine._overrides["core.function.foo"] is True


def test_workflow_override_clear_round_trip(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    machine = _FakeWorkflowMachine(overrides={"core.function.foo": False})
    bv = _bv_with_workflow(machine)
    monkeypatch.setattr(instance, "_resolve_view", lambda selector: bv)

    payload = instance._workflow_override_apply(
        None,
        action="clear",
        activity="core.function.foo",
        enable=None,
        function=None,
        preview=False,
    )

    assert payload["status"] == "verified"
    assert payload["before"] is False
    assert payload["after"] is None
    assert "core.function.foo" not in machine._overrides


def test_workflow_override_set_marks_verification_failed_when_state_unchanged(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    machine = _FakeWorkflowMachine()
    machine._suppress_set = True  # accept the command but never mutate
    bv = _bv_with_workflow(machine)
    monkeypatch.setattr(instance, "_resolve_view", lambda selector: bv)

    payload = instance._workflow_override_apply(
        None,
        action="set",
        activity="core.function.foo",
        enable=True,
        function=None,
        preview=False,
    )

    assert payload["status"] == "verification_failed"
    assert payload["success"] is False
    assert payload["committed"] is False
    assert payload["accepted"] is True
    assert payload["verified"] is False
    assert payload["reverted"] is True


def test_workflow_override_set_unsupported_when_command_not_accepted(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    machine = _FakeWorkflowMachine(set_accepted=False)
    bv = _bv_with_workflow(machine)
    monkeypatch.setattr(instance, "_resolve_view", lambda selector: bv)

    payload = instance._workflow_override_apply(
        None,
        action="set",
        activity="core.function.foo",
        enable=True,
        function=None,
        preview=False,
    )

    assert payload["status"] == "unsupported"
    assert payload["success"] is False


def test_workflow_override_apply_raises_when_no_machine(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    workflow = _FakeWorkflow("core.module.metaAnalysis", machine=None)

    class _BV(_FakeBV):
        def __init__(self):
            super().__init__()
            self.workflow = workflow

    bv = _BV()
    monkeypatch.setattr(instance, "_resolve_view", lambda selector: bv)

    with pytest.raises(bridge.OperationFailure, match="machine not enabled"):
        instance._workflow_override_apply(
            None,
            action="set",
            activity="core.function.foo",
            enable=True,
            function=None,
            preview=False,
        )


def test_workflow_machine_enable_returns_accepted_envelope(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    machine = _FakeWorkflowMachine()
    bv = _bv_with_workflow(machine)
    monkeypatch.setattr(instance, "_resolve_view", lambda selector: bv)

    payload = instance._workflow_machine_command(None, command="enable")
    assert payload["command"] == "enable"
    assert payload["accepted"] is True
    assert payload["scope"] == "binaryview"
    assert payload["machine_state"] == {"activity": "undetermined", "state": "Idle"}
    assert ("enable", None) in machine.calls


def test_workflow_machine_run_forwards_options(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    machine = _FakeWorkflowMachine()
    bv = _bv_with_workflow(machine)
    monkeypatch.setattr(instance, "_resolve_view", lambda selector: bv)

    payload = instance._workflow_machine_command(
        None,
        command="run",
        advanced=False,
        incremental=True,
    )
    assert payload["command"] == "run"
    assert payload["options"] == {"advanced": False, "incremental": True}
    assert ("run", (False, True)) in machine.calls


def test_workflow_machine_breakpoint_lifecycle(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    machine = _FakeWorkflowMachine()
    bv = _bv_with_workflow(machine)
    monkeypatch.setattr(instance, "_resolve_view", lambda selector: bv)

    set_payload = instance._workflow_machine_command(
        None,
        command="breakpoint_set",
        activities=["analysis.warp.fetcher", "analysis.warp.matcher"],
    )
    assert set_payload["accepted"] is True
    assert set_payload["requested_activities"] == [
        "analysis.warp.fetcher",
        "analysis.warp.matcher",
    ]

    list_payload = instance._workflow_machine_command(None, command="breakpoint_list")
    assert list_payload["activities"] == [
        "analysis.warp.fetcher",
        "analysis.warp.matcher",
    ]

    clear_payload = instance._workflow_machine_command(
        None,
        command="breakpoint_clear",
        activities=["analysis.warp.fetcher"],
    )
    assert clear_payload["accepted"] is True
    assert clear_payload["requested_activities"] == ["analysis.warp.fetcher"]

    final_list = instance._workflow_machine_command(None, command="breakpoint_list")
    assert final_list["activities"] == ["analysis.warp.matcher"]


def test_workflow_machine_breakpoint_set_requires_activities(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    machine = _FakeWorkflowMachine()
    bv = _bv_with_workflow(machine)
    monkeypatch.setattr(instance, "_resolve_view", lambda selector: bv)

    with pytest.raises(bridge.OperationFailure, match="at least one activity"):
        instance._workflow_machine_command(None, command="breakpoint_set", activities=[])


def test_workflow_machine_unavailable_when_no_machine(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()

    workflow = _FakeWorkflow("core.module.defaultAnalysis", machine=None)

    class _BVWithoutMachine(_FakeBV):
        def __init__(self):
            super().__init__()
            self.workflow = workflow

    bv = _BVWithoutMachine()
    monkeypatch.setattr(instance, "_resolve_view", lambda selector: bv)

    payload = instance._workflow_machine_call(None, "status", {})
    assert payload["available"] is False
    assert payload["reason"] == "machine not enabled"
    assert payload["status"] is None


def test_collect_open_views_uses_tabs_api(monkeypatch):
    bridge = _load_bridge(monkeypatch)

    class _View:
        def __init__(self, data):
            self._data = data

        def getData(self):
            return self._data

    class _Frame:
        def __init__(self, data):
            self._data = data

        def getCurrentBinaryView(self):
            return self._data

        def getCurrentView(self):
            return _View(self._data)

    view_a = object()
    view_b = object()
    view_c = object()

    class _Context:
        def getCurrentViewFrame(self):
            return _Frame(view_c)

        def getTabs(self):
            return ["tab-a", "tab-b", "tab-c"]

        def getViewFrameForTab(self, tab):
            mapping = {
                "tab-a": _Frame(view_a),
                "tab-b": _Frame(view_b),
                "tab-c": _Frame(view_c),
            }
            return mapping[tab]

        def getViewForTab(self, tab):
            mapping = {
                "tab-a": _View(view_a),
                "tab-b": _View(view_b),
                "tab-c": _View(view_c),
            }
            return mapping[tab]

    fake_ui = types.SimpleNamespace(
        UIContext=types.SimpleNamespace(
            allContexts=lambda: [_Context()],
            activeContext=lambda: None,
        )
    )
    monkeypatch.setattr(bridge, "ui", fake_ui)

    views = bridge._collect_open_views()

    assert len(views) == 3
    assert set(id(view) for view in views) == {id(view_a), id(view_b), id(view_c)}


def test_target_manager_explicit_register_unregister_most_recent(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    manager = bridge.TargetManager(mode="headless")

    bv_a = _FakeHeadlessBV(filename="/tmp/a.so", session_id="sess-a")
    bv_b = _FakeHeadlessBV(filename="/tmp/b.so", session_id="sess-b")

    record_a = manager.register(bv_a)
    record_b = manager.register(bv_b)

    assert manager.most_recent() is bv_b

    listed = manager.refresh()
    actives = [item for item in listed if item["active"]]
    assert len(actives) == 1
    assert actives[0]["target_id"] == record_b.target_id()

    removed = manager.unregister(record_b.view_id)
    assert removed is not None
    assert manager.most_recent() is bv_a
    assert all(item["target_id"] != record_b.target_id() for item in manager.refresh())
    assert manager.unregister(record_b.view_id) is None
    # `record_a` is still alive
    assert any(item["target_id"] == record_a.target_id() for item in manager.refresh())


def test_load_target_op_registers_target_and_runs_analysis(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge(mode="headless")
    bv = _FakeHeadlessBV(filename="/tmp/app.so", session_id="sess-app")
    monkeypatch.setattr(bridge.bn, "load", lambda path, **kwargs: bv, raising=False)

    result = instance._load_target(path="/tmp/app.so", analysis="wait", options=None)

    assert bv.analysis_calls == 1
    assert result["filename"] == "/tmp/app.so"
    assert any(item["target_id"] == result["target_id"] for item in instance.targets.refresh())


def test_load_target_op_respects_no_update_analysis(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge(mode="headless")
    bv = _FakeHeadlessBV(filename="/tmp/app.so", session_id="sess-app")
    monkeypatch.setattr(bridge.bn, "load", lambda path, **kwargs: bv, raising=False)

    instance._load_target(path="/tmp/app.so", analysis="skip", options=None)

    assert bv.analysis_calls == 0


def test_load_target_op_async_returns_queued_immediately_and_loads_in_thread(monkeypatch):
    import time

    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge(mode="headless")
    bv = _FakeHeadlessBV(filename="/tmp/app.so", session_id="sess-app")
    load_calls: list[tuple[str, dict]] = []

    def fake_load(path, **kwargs):
        load_calls.append((path, kwargs))
        return bv

    monkeypatch.setattr(bridge.bn, "load", fake_load, raising=False)

    result = instance._load_target(path="/tmp/app.so", analysis="async", options=None)

    assert result["queued"] is True
    assert result["path"] == "/tmp/app.so"
    assert "load_id" in result

    deadline = time.time() + 1.0
    while (not load_calls or bv.analysis_calls < 1) and time.time() < deadline:
        time.sleep(0.01)
    assert len(load_calls) == 1
    assert bv.analysis_calls == 1
    assert any(item["target_id"] for item in instance.targets.refresh())

    deadline = time.time() + 1.0
    attempts = []
    while time.time() < deadline:
        attempts = instance._list_loads()
        if attempts and attempts[-1]["status"] == "succeeded":
            break
        time.sleep(0.01)
    assert attempts[-1]["status"] == "succeeded"
    assert attempts[-1]["load_id"] == result["load_id"]
    assert attempts[-1]["target_id"] is not None
    assert attempts[-1]["error"] is None


def test_load_target_op_async_records_load_failure(monkeypatch):
    import time

    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge(mode="headless")

    def fake_load(path, **kwargs):
        raise RuntimeError("simulated load failure")

    monkeypatch.setattr(bridge.bn, "load", fake_load, raising=False)

    result = instance._load_target(path="/tmp/bad.so", analysis="async", options=None)
    assert result["queued"] is True

    deadline = time.time() + 1.0
    attempts = []
    while time.time() < deadline:
        attempts = instance._list_loads()
        if attempts and attempts[-1]["status"] == "failed":
            break
        time.sleep(0.01)
    assert attempts[-1]["status"] == "failed"
    assert "simulated load failure" in (attempts[-1]["error"] or "")
    assert attempts[-1]["target_id"] is None
    tb_text = attempts[-1]["traceback"] or ""
    assert "Traceback" in tb_text
    assert "simulated load failure" in tb_text
    assert "fake_load" in tb_text
    assert instance.targets.refresh() == []


def test_load_target_op_async_success_has_no_traceback(monkeypatch):
    import time

    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge(mode="headless")
    bv = _FakeHeadlessBV(filename="/tmp/ok.so", session_id="sess-ok")
    monkeypatch.setattr(bridge.bn, "load", lambda path, **kwargs: bv, raising=False)
    instance._load_target(path="/tmp/ok.so", analysis="async", options=None)

    deadline = time.time() + 1.0
    attempts = []
    while time.time() < deadline:
        attempts = instance._list_loads()
        if attempts and attempts[-1]["status"] == "succeeded":
            break
        time.sleep(0.01)
    assert attempts[-1]["status"] == "succeeded"
    assert attempts[-1]["traceback"] is None
    assert attempts[-1]["error"] is None


def test_list_loads_bounded_to_limit(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge(mode="headless")
    for i in range(bridge.LOAD_ATTEMPTS_LIMIT + 5):
        instance._record_load_start(f"/tmp/x{i}.so")
    attempts = instance._list_loads()
    assert len(attempts) == bridge.LOAD_ATTEMPTS_LIMIT
    # Oldest dropped (path x0..x4); newest preserved
    assert attempts[0]["path"] == "/tmp/x5.so"
    assert attempts[-1]["path"] == f"/tmp/x{bridge.LOAD_ATTEMPTS_LIMIT + 4}.so"


def test_per_target_locks_allow_concurrent_reads_on_distinct_targets(monkeypatch):
    import threading
    import time

    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge(mode="headless")
    bv_a = _FakeHeadlessBV(filename="/tmp/a.so", session_id="sess-a")
    bv_b = _FakeHeadlessBV(filename="/tmp/b.so", session_id="sess-b")
    record_a = instance.targets.register(bv_a)
    record_b = instance.targets.register(bv_b)
    lock_a = instance._get_target_lock(record_a.view_id)
    lock_b = instance._get_target_lock(record_b.view_id)
    # Distinct locks — different view_ids must get different lock instances.
    assert lock_a is not lock_b

    # Hold A's write lock; B's read lock should still be acquirable without blocking.
    barrier = threading.Event()
    grabbed_b = threading.Event()

    def hold_a():
        with lock_a.write():
            barrier.wait()

    def grab_b():
        with lock_b.read():
            grabbed_b.set()

    holder = threading.Thread(target=hold_a)
    grabber = threading.Thread(target=grab_b)
    holder.start()
    grabber.start()
    assert grabbed_b.wait(timeout=1.0), "per-target locks should not block across targets"
    barrier.set()
    holder.join(timeout=1.0)
    grabber.join(timeout=1.0)


def test_concurrent_loads_serialize_on_load_lock(monkeypatch):
    import threading
    import time

    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge(mode="headless")

    active = [0]
    peak = [0]
    state_lock = threading.Lock()
    block = threading.Event()
    entered = threading.Event()

    def slow_load(path, **kwargs):
        with state_lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        entered.set()
        block.wait(timeout=2.0)
        with state_lock:
            active[0] -= 1
        return _FakeHeadlessBV(filename=path, session_id=f"sess-{path}")

    monkeypatch.setattr(bridge.bn, "load", slow_load, raising=False)

    threads = [
        threading.Thread(
            target=instance._load_target,
            kwargs={"path": f"/tmp/{i}.so", "analysis": "skip", "options": None},
        )
        for i in range(3)
    ]
    for t in threads:
        t.start()
    entered.wait(timeout=1.0)
    # First load is inside slow_load; the other two should be queued behind _load_lock.
    time.sleep(0.05)
    with state_lock:
        assert active[0] == 1
    block.set()
    for t in threads:
        t.join(timeout=2.0)
    # Peak parallelism inside bn.load must never exceed 1.
    assert peak[0] == 1
    # All three loads registered their BVs.
    assert len(instance.targets.refresh()) == 3


def test_close_target_waits_for_in_flight_op_on_same_target(monkeypatch):
    import threading
    import time

    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge(mode="headless")
    bv = _FakeHeadlessBV(filename="/tmp/x.so", session_id="sess-x")
    monkeypatch.setattr(bridge.bn, "load", lambda path, **kwargs: bv, raising=False)
    instance._load_target(path="/tmp/x.so", analysis="skip", options=None)
    view_id = instance.targets.view_id_for(bv)
    assert view_id is not None
    target_lock = instance._get_target_lock(view_id)

    in_flight = threading.Event()
    proceed = threading.Event()

    def in_flight_read():
        with target_lock.read():
            in_flight.set()
            proceed.wait()

    reader = threading.Thread(target=in_flight_read)
    reader.start()
    in_flight.wait(timeout=1.0)

    close_done = threading.Event()

    def close_after_release():
        instance._close_target(view_id)
        close_done.set()

    closer = threading.Thread(target=close_after_release)
    closer.start()
    # The closer must NOT finish while the read lock is held.
    assert not close_done.wait(timeout=0.2)
    proceed.set()
    assert close_done.wait(timeout=1.0)

    reader.join(timeout=1.0)
    closer.join(timeout=1.0)
    # After close, lock entry must be gone too.
    with instance._target_locks_lock:
        assert view_id not in instance._target_locks


def test_load_target_op_rejects_unknown_analysis_value(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge(mode="headless")
    monkeypatch.setattr(bridge.bn, "load", lambda path, **kwargs: _FakeHeadlessBV(), raising=False)
    with pytest.raises(RuntimeError, match="analysis must be one of"):
        instance._load_target(path="/tmp/x.so", analysis="nonsense", options=None)


def test_load_target_op_rejected_in_gui_mode(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge(mode="gui")
    monkeypatch.setattr(bridge.bn, "load", lambda path, **kwargs: _FakeHeadlessBV(), raising=False)

    with pytest.raises(RuntimeError, match="headless mode"):
        instance._load_target(path="/tmp/app.so", analysis="skip", options=None)


def test_close_target_op_unregisters_and_closes_file(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge(mode="headless")
    bv = _FakeHeadlessBV(filename="/tmp/app.so", session_id="sess-app")
    monkeypatch.setattr(bridge.bn, "load", lambda path, **kwargs: bv, raising=False)
    instance._load_target(path="/tmp/app.so", analysis="skip", options=None)

    result = instance._close_target("active")

    assert result["closed"] is True
    assert bv.file.closed is True
    assert instance.targets.refresh() == []


def test_save_target_op_creates_new_database(monkeypatch, tmp_path):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge(mode="headless")
    bv = _FakeHeadlessBV(filename="/tmp/raw.bin", session_id="sess-raw")
    monkeypatch.setattr(bridge.bn, "load", lambda path, **kwargs: bv, raising=False)
    instance._load_target(path="/tmp/raw.bin", analysis="skip", options=None)

    out = tmp_path / "raw.bndb"
    result = instance._save_target("active", path=str(out))

    assert result["saved_to"] == str(out)
    assert result["is_new_database"] is True
    assert out.exists()


def test_save_target_op_rejects_raw_binary_without_path(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge(mode="headless")
    bv = _FakeHeadlessBV(filename="/tmp/raw.bin", session_id="sess-raw")
    monkeypatch.setattr(bridge.bn, "load", lambda path, **kwargs: bv, raising=False)
    instance._load_target(path="/tmp/raw.bin", analysis="skip", options=None)

    with pytest.raises(RuntimeError, match="No .bndb path"):
        instance._save_target("active", path=None)


def test_save_target_op_overwrites_existing_bndb(monkeypatch, tmp_path):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge(mode="headless")
    existing = tmp_path / "existing.bndb"
    existing.write_bytes(b"old")
    bv = _FakeHeadlessBV(filename=str(existing), session_id="sess-existing")
    monkeypatch.setattr(bridge.bn, "load", lambda path, **kwargs: bv, raising=False)
    instance._load_target(path=str(existing), analysis="skip", options=None)

    result = instance._save_target("active", path=None)

    assert result["saved_to"] == str(existing)
    assert result["is_new_database"] is False
    assert bv.snapshots_saved == 1


def test_analysis_status_op_returns_progress(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge(mode="headless")
    bv = _FakeHeadlessBV(filename="/tmp/app.so", session_id="sess-app")
    bv.analysis_progress = _FakeAnalysisProgress(state_name="Analyzing", count=3, total=10)
    monkeypatch.setattr(bridge.bn, "load", lambda path, **kwargs: bv, raising=False)
    instance._load_target(path="/tmp/app.so", analysis="skip", options=None)

    status = instance._analysis_status("active")

    assert status["state"] == "Analyzing"
    assert status["count"] == 3
    assert status["total"] == 10
    assert status["done"] is False


def test_active_resolves_to_most_recent_in_headless(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge(mode="headless")
    bv_a = _FakeHeadlessBV(filename="/tmp/a.so", session_id="sess-a")
    bv_b = _FakeHeadlessBV(filename="/tmp/b.so", session_id="sess-b")

    loads = iter([bv_a, bv_b])
    monkeypatch.setattr(bridge.bn, "load", lambda path, **kwargs: next(loads), raising=False)
    instance._load_target(path="/tmp/a.so", analysis="skip", options=None)
    instance._load_target(path="/tmp/b.so", analysis="skip", options=None)

    assert instance._resolve_view("active") is bv_b
    assert instance._resolve_view(None) is bv_b
