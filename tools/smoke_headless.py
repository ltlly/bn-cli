"""Opt-in real BN/CLI smoke; uses isolated state and never saves the input binary.

PYTHONPATH=/path/to/binaryninja/python BN_DISABLE_USER_PLUGINS=1 \
    uv run python tools/smoke_headless.py --sample /bin/true

Add --external with `uv run --with unicorn --with frida python ...` to exercise
real Unicorn memory and a Frida-spawned local /bin/sleep process (Linux).
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import types
from pathlib import Path

import binaryninja as bn

ROOT = Path(__file__).resolve().parents[1]


def load_bridge():
    package = types.ModuleType("bn_smoke_bridge")
    package.__path__ = [str(ROOT / "plugin/bn_agent_bridge")]
    sys.modules[package.__name__] = package
    spec = importlib.util.spec_from_file_location(
        f"{package.__name__}.bridge", Path(package.__path__[0]) / "bridge.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", default="/bin/true")
    parser.add_argument("--external", action="store_true")
    args = parser.parse_args()
    report = {"binaryninja": bn.core_version(), "sample": args.sample, "checks": []}
    with tempfile.TemporaryDirectory(prefix="bn-headless-smoke-") as directory:
        os.environ["BN_CACHE_DIR"] = directory
        module = load_bridge()
        bridge = module.BinaryNinjaBridge(mode="headless")
        bridge.start()
        env = {
            **os.environ,
            "PYTHONPATH": str(ROOT / "src")
            + os.pathsep
            + os.environ.get("PYTHONPATH", ""),
        }

        def cli(*argv, expected=0, error=None):
            result = subprocess.run(
                [sys.executable, "-m", "bn", "--daemon", "headless", *argv],
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            assert result.returncode == expected, (
                argv,
                result.returncode,
                result.stdout,
                result.stderr,
            )
            if error is not None:
                assert error in result.stderr, result.stderr
            return json.loads(result.stdout) if result.stdout.strip() else None

        try:
            target = cli("target", "load", args.sample, "--format", "json")
            selector = target["target_id"]
            rows = cli("query", "functions", "--fields", "address,name", "--sort=-address",
                       "--filter", "address>=0", "--limit", "2", "--target", selector)
            assert rows and set(rows[0]) == {"address", "name"}
            assert cli("query", "functions", "--count", "--target", selector)["count"] >= len(rows)
            report["checks"].append("targeted function query and count")
            context = cli("address", "context", "--target", selector)
            entry = int(target["entry_point"], 16)
            rva = entry - int(context["image_base"], 16)
            bn_data = cli(
                "memory",
                "read",
                f"rva:{hex(rva)}",
                "--length",
                "8",
                "--format",
                "json",
                "--target",
                selector,
            )
            assert bn_data["address"] == hex(entry)
            location = cli("address", "resolve", hex(entry), "--target", selector)[
                "addresses"
            ][0]
            if location["file_offset"] and location["file_offset_unique"]:
                file_data = cli(
                    "memory",
                    "read",
                    f"file:{location['file_offset']}",
                    "--length",
                    "8",
                    "--format",
                    "json",
                    "--target",
                    selector,
                )
                assert file_data == bn_data
            cli(
                "address",
                "map",
                "add",
                "runtime",
                "--base",
                "0x7100000000",
                "--size",
                hex(int(context["view_end"], 16) - int(context["image_base"], 16)),
                "--source",
                "smoke:synthetic",
                "--target",
                selector,
            )
            runtime_address = f"map:runtime:{hex(0x7100000000 + rva)}"
            mapped = cli("inspect", runtime_address, "--target", selector)
            assert mapped["location"]["bn_va"] == hex(entry)
            assert mapped["decompile"]
            decompiled = cli(
                "decompile",
                runtime_address,
                "--target",
                selector,
                "--with-context",
                "--format",
                "json",
            )
            assert decompiled["address_context"]["target_id"] == selector
            assert decompiled["result"]["text"]
            assert cli(
                "address",
                "verify",
                runtime_address,
                "--bytes",
                bn_data["data_hex"],
                "--target",
                selector,
            )["matches"]
            assert not cli(
                "address",
                "verify",
                runtime_address,
                "--bytes",
                "00" * 8,
                "--target",
                selector,
                expected=3,
            )["matches"]
            job = cli(
                "memory",
                "read",
                runtime_address,
                "--length",
                "8",
                "--async",
                "--format",
                "json",
                "--target",
                selector,
            )
            outcome = cli("job", "wait", job["job_id"])
            assert outcome == bn_data
            artifact = Path(directory) / "function.json"
            cli(
                "function",
                "info",
                hex(entry),
                "--format",
                "json",
                "--with-context",
                "--out",
                str(artifact),
                "--target",
                selector,
            )
            stored = json.loads(artifact.read_text())
            assert stored["address_context"]["image_base"] == context["image_base"]
            report["checks"].append(
                "CLI socket: load, RVA/file/runtime, inspect, verify/mismatch, job wait, context artifact"
            )
            if target["arch"] == "x86_64":
                for kind, operand in (
                    ("reg", "rax"),
                    ("possible", "rax"),
                    ("flags", "z"),
                    ("stack", "-8"),
                ):
                    value = cli(
                        "value",
                        kind,
                        hex(entry),
                        "0",
                        operand,
                        "--format",
                        "json",
                        "--target",
                        selector,
                    )
                    assert value["instruction_index"] == 0 and value["level"] == "llil"
                value = cli(
                    "value",
                    "reg",
                    hex(entry),
                    "rax",
                    "--address",
                    runtime_address,
                    "--after",
                    "--format",
                    "json",
                    "--target",
                    selector,
                )
                assert value["address"] == hex(entry)
            cli(
                "search",
                "constant",
                "0x2",
                "--limit",
                "1",
                "--format",
                "json",
                "--target",
                selector,
            )
            literal = cli(
                "search",
                "text",
                "return",
                "--il-type",
                "mlil",
                "--limit",
                "1",
                "--format",
                "json",
                "--target",
                selector,
            )
            regex = cli(
                "search",
                "text",
                ".*",
                "--regex",
                "--il-type",
                "llil",
                "--limit",
                "1",
                "--format",
                "json",
                "--target",
                selector,
            )
            assert literal["il_type"] == "mlil" and regex["count"] == 1
            report["checks"].append(
                "Native LLIL register/possible/flag/stack queries; machine address distinct from IL index; searches"
            )

            with bn.BinaryView.new(
                b"\xb8\x2a\x00\x00\x00\x90\xc3" + b"\x90" * 57
            ) as scratch:
                scratch.arch = bn.Architecture["x86_64"]
                raw_id = bridge.targets.register(scratch).target_id()
                patched = cli(
                    "patch", "assemble", "0x0", "mov eax, 7", "--target", raw_id
                )
                assert patched["bytes_hex"] == "b807000000"
                cli("patch", "nop", "0x0", "--length", "5", "--target", raw_id)
                assert scratch.read(0, 5) == b"\x90" * 5
                assert (
                    cli(
                        "arch",
                        "assemble",
                        "nop",
                        "--arch",
                        "x86_64",
                        "--format",
                        "json",
                        "--target",
                        raw_id,
                    )["bytes_hex"]
                    == "90"
                )
                assert (
                    cli(
                        "arch",
                        "disasm-bytes",
                        "9090",
                        "--count",
                        "1",
                        "--format",
                        "json",
                        "--target",
                        raw_id,
                    )["count"]
                    == 1
                )
                cli(
                    "memory",
                    "writer",
                    "0x0",
                    "0x11223344",
                    "--width",
                    "4",
                    "--target",
                    raw_id,
                )
                assert (
                    cli(
                        "memory",
                        "reader",
                        "0x0",
                        "--width",
                        "4",
                        "--format",
                        "json",
                        "--target",
                        raw_id,
                    )["value"]
                    == 0x11223344
                )
                cli(
                    "memory",
                    "writer",
                    "0x1000",
                    "7",
                    "--width",
                    "1",
                    "--target",
                    raw_id,
                    expected=2,
                    error="Unmapped",
                )
                bridge.targets.unregister(bridge.targets.view_id_for(scratch))
            report["checks"].append(
                "Real architecture assemble, exact NOP range, unmapped writer rejection; scratch BV only"
            )

            if args.external:
                import frida
                import unicorn

                uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
                uc.mem_map(0x100000, 0x1000)
                uc.mem_write(0x100080, bytes.fromhex(bn_data["data_hex"]))
                manifest = Path(directory) / "unicorn.json"
                manifest.write_text(
                    json.dumps(
                        {
                            "regions": [
                                {
                                    "bn_start": hex(entry),
                                    "external_start": "0x100080",
                                    "length": "0x8",
                                }
                            ]
                        }
                    )
                )
                cli(
                    "address",
                    "map",
                    "import",
                    "uc",
                    str(manifest),
                    "--source",
                    "unicorn:smoke",
                    "--target",
                    selector,
                )
                assert cli(
                    "address",
                    "verify",
                    "map:uc:0x100080",
                    "--bytes",
                    bytes(uc.mem_read(0x100080, 8)).hex(),
                    "--target",
                    selector,
                )["matches"]
                report["checks"].append(
                    f"Unicorn {unicorn.__version__}: actual memory at independent address"
                )

                device = frida.get_local_device()
                pid = device.spawn(["/bin/sleep", "60"])
                session = None
                try:
                    session = device.attach(pid)
                    script = session.create_script("""
                        rpc.exports = {
                            module() { const m = Process.enumerateModules()[0]; return {name:m.name, path:m.path, base:m.base.toString(), size:m.size}; },
                            bytes(offset) { const m = Process.enumerateModules()[0]; return Array.from(new Uint8Array(m.base.add(offset).readByteArray(8))).map(x => x.toString(16).padStart(2,'0')).join(''); }
                        };
                    """)
                    script.load()
                    snapshot = script.exports_sync.module()
                    loaded = cli("target", "load", snapshot["path"], "--format", "json")
                    frida_id = loaded["target_id"]
                    frida_rva = int(loaded["entry_point"], 16) - int(
                        loaded["address_context"]["image_base"], 16
                    )
                    manifest = Path(directory) / "frida.json"
                    manifest.write_text(json.dumps(snapshot))
                    cli(
                        "address",
                        "map",
                        "import",
                        "frida",
                        str(manifest),
                        "--kind",
                        "frida-module",
                        "--source",
                        f"pid:{pid}/spawn:smoke",
                        "--target",
                        frida_id,
                    )
                    runtime = int(snapshot["base"], 16) + frida_rva
                    assert cli(
                        "address",
                        "verify",
                        f"map:frida:{hex(runtime)}",
                        "--bytes",
                        script.exports_sync.bytes(hex(frida_rva)),
                        "--target",
                        frida_id,
                    )["matches"]
                    report["checks"].append(
                        f"Frida {frida.__version__}: spawned /bin/sleep, actual module snapshot + entry bytes under ASLR"
                    )
                finally:
                    if session is not None:
                        session.detach()
                    device.kill(pid)
            rebased = cli("loader", "rebase", "0x900000", "--target", selector)
            assert (
                rebased["target_id"] != selector and rebased["new_start"] == "0x900000"
            )
            assert "runtime" in rebased["removed_address_maps"]
            relocated = cli(
                "address",
                "resolve",
                f"rva:{hex(rva)}",
                "--target",
                rebased["target_id"],
            )
            assert relocated["addresses"][0]["bn_va"] == hex(0x900000 + rva)
            report["checks"].append(
                "Native rebase replaces target with returned BinaryView and drops old external maps"
            )
        finally:
            for target in bridge.targets.refresh():
                bridge._close_target(target["target_id"])
            bridge.stop()
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
