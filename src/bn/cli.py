from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Callable

from . import api_docs
from .output import write_output_result
from .paths import (
    DAEMON_MODES,
    SKILL_CLIENTS,
    bridge_registry_path,
    bridge_socket_path,
    current_daemon_mode_path,
    plugin_install_dir,
    plugin_source_dir,
    skill_install_dir_for,
    skill_source_dir,
)
from .transport import (
    BridgeError,
    BridgeInstance,
    _send_request_to_instance,
    list_instances,
    read_current_daemon_mode,
    send_request,
    write_current_daemon_mode,
)
from .version import VERSION, build_id_for_file

FAILED_MUTATION_STATUSES = {"unsupported", "verification_failed"}


class _HelpFullAction(argparse.Action):
    def __init__(
        self,
        option_strings: list[str],
        dest: str = argparse.SUPPRESS,
        default: str = argparse.SUPPRESS,
        help: str | None = None,
    ) -> None:
        super().__init__(
            option_strings=option_strings,
            dest=dest,
            default=default,
            nargs=0,
            help=help,
        )

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str | list[str] | None,
        option_string: str | None = None,
    ) -> None:
        if isinstance(parser, BnArgumentParser):
            parser.print_full_help()
        else:
            parser.print_help()
        parser.exit()


class BnArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.set_defaults(_parser=self)
        self.add_argument(
            "--help-full",
            action=_HelpFullAction,
            help="Show help for this command and all subcommands",
        )

    def _iter_full_help_parsers(self) -> list[argparse.ArgumentParser]:
        parsers: list[argparse.ArgumentParser] = [self]
        for action in self._actions:
            if isinstance(action, argparse._SubParsersAction):
                for parser in action.choices.values():
                    if isinstance(parser, BnArgumentParser):
                        parsers.extend(parser._iter_full_help_parsers())
                    else:
                        parsers.append(parser)
        return parsers

    def _full_help_actions(self) -> tuple[type[argparse.Action], ...]:
        return (argparse._HelpAction, _HelpFullAction)

    def format_help_for_full(self) -> str:
        formatter = self._get_formatter()
        help_action_types = self._full_help_actions()
        actions = [action for action in self._actions if not isinstance(action, help_action_types)]

        formatter.add_usage(self.usage, actions, self._mutually_exclusive_groups)
        formatter.add_text(self.description)

        for action_group in self._action_groups:
            group_actions = [
                action
                for action in action_group._group_actions
                if not isinstance(action, help_action_types)
            ]
            if not group_actions:
                continue
            formatter.start_section(action_group.title)
            formatter.add_text(action_group.description)
            formatter.add_arguments(group_actions)
            formatter.end_section()

        formatter.add_text(self.epilog)
        return formatter.format_help()

    def format_full_help(self) -> str:
        sections: list[str] = []
        seen: set[int] = set()
        for parser in self._iter_full_help_parsers():
            parser_id = id(parser)
            if parser_id in seen:
                continue
            seen.add(parser_id)
            if isinstance(parser, BnArgumentParser):
                sections.append(parser.format_help_for_full().rstrip())
            else:
                sections.append(parser.format_help().rstrip())
        return "\n\n".join(sections) + "\n"

    def print_full_help(self, file: Any = None) -> None:
        if file is None:
            file = sys.stdout
        self._print_message(self.format_full_help(), file)


def _package_version() -> str:
    return VERSION


def _common_io_options(
    parser: argparse.ArgumentParser,
    *,
    default_format: str = "text",
) -> None:
    parser.add_argument(
        "--format",
        choices=("json", "text", "ndjson"),
        default=default_format,
        help="Output format",
    )
    parser.add_argument("--out", type=Path, help="Write output to a file instead of stdout")


def _target_option(
    parser: argparse.ArgumentParser,
    *,
    required: bool,
) -> None:
    kwargs: dict[str, Any] = {
        "help": (
            "Target selector from `bn target list` (`selector`, `target_id`, basename, filename, or view id); "
            "omit only when exactly one target is open, or use `active` to follow the GUI-selected target explicitly"
        ),
        "required": required,
    }
    parser.add_argument("--target", **kwargs)


def _render_result(
    value: Any,
    *,
    fmt: str,
    out_path: Path | None,
    stem: str,
    spill_label: str | None = None,
    spill_context: Any = None,
) -> None:
    result = write_output_result(value, fmt=fmt, out_path=out_path, stem=stem)
    if result.spilled and result.artifact:
        label = spill_label or stem.replace("_", " ")
        artifact = result.artifact
        lines = [
            f"warning: {label} output spilled",
            f"path: {artifact['artifact_path']}",
            f"format: {artifact['format']}",
            f"bytes: {artifact['bytes']}",
            f"tokens: {artifact['tokens']}",
            f"tokenizer: {artifact['tokenizer']}",
        ]
        if isinstance(artifact.get("sha256"), str):
            lines.append(f"sha256: {artifact['sha256']}")
        summary = artifact.get("summary")
        if isinstance(summary, dict):
            summary_parts = []
            kind = summary.get("kind")
            if kind is not None:
                summary_parts.append(f"kind={kind}")
            for key in sorted(summary):
                if key == "kind":
                    continue
                summary_parts.append(
                    f"{key}={json.dumps(summary[key], sort_keys=True, default=str)}"
                )
            if summary_parts:
                lines.append(f"summary: {', '.join(summary_parts)}")
        if isinstance(spill_context, list):
            lines.append(f"items: {len(spill_context)}")
        if isinstance(value, str):
            lines.append(f"lines: {len(value.splitlines())}")
        print("\n".join(lines), file=sys.stderr)
        return
    sys.stdout.write(result.rendered)


def _render_and_output(
    args: argparse.Namespace,
    result: Any,
    *,
    text_renderer: Callable[[Any], str] | None = None,
    stem: str,
) -> int:
    """Render result and write output (mini version of _call's tail for direct-request handlers)."""
    spill_context = result
    if text_renderer is not None and args.format == "text":
        result = text_renderer(result)
    _render_result(
        result,
        fmt=args.format,
        out_path=args.out,
        stem=stem,
        spill_label=stem.replace("-", " "),
        spill_context=spill_context,
    )
    return 0


def _render_target_choice(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)

    label = str(value.get("selector") or value.get("target_id") or "<unknown>")
    if value.get("active"):
        label += " [active]"

    target_id = value.get("target_id")
    if target_id not in (None, "", value.get("selector")):
        label += f" (target_id: {target_id})"
    return label


def _render_target_choices(value: Any) -> str:
    if not isinstance(value, list):
        return _render_fallback_text(value)
    if not value:
        return "none"
    return "\n".join(f"- {_render_target_choice(item)}" for item in value)


def _implicit_target(args: argparse.Namespace) -> str:
    response = send_request(
        "list_targets",
        params={},
        target=None,
    )
    targets = list(response["result"])
    if not targets:
        raise BridgeError(
            "No BinaryView targets are loaded. "
            "Load one with `bn target load <path>` (headless) or open it in Binary Ninja."
        )
    if len(targets) == 1:
        return "active"
    active_count = sum(1 for item in targets if isinstance(item, dict) and item.get("active"))
    if active_count == 1:
        return "active"
    raise BridgeError(
        "This command requires --target when multiple targets are open.\n"
        f"Open targets:\n{_render_target_choices(targets)}"
    )


def _resolve_target(
    args: argparse.Namespace,
    *,
    require_target: bool,
    allow_implicit_target: bool = False,
) -> str | None:
    target = getattr(args, "target", None)
    if require_target and not target:
        if allow_implicit_target:
            return _implicit_target(args)
        raise BridgeError("This command requires --target")
    return target


def _mutation_exit_code(result: Any) -> int:
    if not isinstance(result, dict):
        return 0
    results = list(result.get("results") or [])
    if any(isinstance(item, dict) and item.get("status") in FAILED_MUTATION_STATUSES for item in results):
        return 3
    if result.get("success") is False:
        return 3
    return 0


def _call(
    args: argparse.Namespace,
    op: str,
    params: dict[str, Any] | None = None,
    *,
    require_target: bool,
    allow_implicit_target: bool = False,
    text_renderer: Callable[[Any], str] | None = None,
    page_limit: int | None = None,
    page_offset: int = 0,
    page_label: str | None = None,
    stem: str,
    result_exit_code: Callable[[Any], int] | None = None,
    bridge_writes_output: bool = False,
) -> int:
    request_params = dict(params or {})
    effective_page_limit = None
    if page_limit is not None and page_limit >= 0:
        effective_page_limit = page_limit
        request_params["limit"] = page_limit + 1

    target = _resolve_target(
        args,
        require_target=require_target,
        allow_implicit_target=allow_implicit_target,
    )
    response = send_request(
        op,
        params=request_params,
        target=target,
    )
    result = response["result"]
    exit_code = result_exit_code(result) if result_exit_code is not None else 0
    if effective_page_limit is not None and isinstance(result, list) and len(result) > effective_page_limit:
        result = result[:effective_page_limit]
        label = page_label or op
        next_offset = page_offset + effective_page_limit
        print(
            f"warning: {label} output truncated to {effective_page_limit} items; rerun with --offset {next_offset} or a larger --limit",
            file=sys.stderr,
        )
    spill_context = result
    if text_renderer is not None and args.format == "text":
        result = text_renderer(result)
    _render_result(
        result,
        fmt=args.format,
        out_path=None if bridge_writes_output else args.out,
        stem=stem,
        spill_label=page_label or op.replace("_", " "),
        spill_context=spill_context,
    )
    return exit_code


def _render_fallback_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, indent=2, sort_keys=True)


def _format_local_entry(item: dict[str, Any]) -> str:
    role = "param" if item.get("is_parameter") else "local"
    details = [f"storage={item.get('storage', '?')}"]
    if item.get("source_type"):
        details.append(f"source={item['source_type']}")
    if item.get("index") is not None:
        details.append(f"index={item['index']}")
    if item.get("identifier") is not None:
        details.append(f"identifier={item['identifier']}")
    if item.get("local_id"):
        details.append(f"id={item['local_id']}")
    return (
        f"- {item.get('type', '<unknown>')} {item.get('name', '<unknown>')} "
        f"[{role}; {'; '.join(details)}]"
    )


def _text_field(field: str) -> Callable[[Any], str]:
    def render(value: Any) -> str:
        if isinstance(value, dict):
            text = value.get(field)
            if isinstance(text, str):
                return text
        return _render_fallback_text(value)

    return render


def _render_function_info_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)

    function = value.get("function") or {}
    lines = [
        f"{function.get('name', '<unknown>')} @ {function.get('address', '<unknown>')}",
        str(value.get("prototype", "")),
        f"return: {value.get('return_type', '<unknown>')}",
        f"calling convention: {value.get('calling_convention', '<unknown>')}",
        f"size: {value.get('size', '<unknown>')}",
        "",
        "parameters:",
    ]
    parameters = list(value.get("parameters") or [])
    if parameters:
        for item in parameters:
            lines.append(_format_local_entry(item))
    else:
        lines.append("- none")

    lines.extend(["", "locals:"])
    locals_only = list(value.get("locals") or [])
    if locals_only:
        for item in locals_only:
            lines.append(_format_local_entry(item))
    else:
        lines.append("- none")
    return "\n".join(lines)


def _render_proto_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    prototype = value.get("prototype")
    if isinstance(prototype, str):
        return prototype
    return _render_fallback_text(value)


def _render_local_list_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    function = value.get("function") or {}
    lines = [f"{function.get('name', '<unknown>')} @ {function.get('address', '<unknown>')}", ""]
    locals_only = list(value.get("locals") or [])
    if not locals_only:
        lines.append("locals: none")
        return "\n".join(lines)
    lines.append("locals:")
    for item in locals_only:
        lines.append(_format_local_entry(item))
    return "\n".join(lines)


def _render_type_info_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    layout = value.get("layout")
    if isinstance(layout, str) and layout:
        return layout
    decl = value.get("decl")
    if isinstance(decl, str) and decl:
        return decl
    return _render_fallback_text(value)


def _render_field_xrefs_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)

    field = value.get("field") or {}
    lines = [
        f"{field.get('type_name', '<unknown>')}.{field.get('field_name', '<unknown>')} @ +0x{int(field.get('offset', 0)):x}",
        f"type: {field.get('field_type', '<unknown>')}",
        "",
        "code refs:",
    ]
    code_refs = list(value.get("code_refs") or [])
    if code_refs:
        for ref in code_refs:
            details = [ref.get("address", "<unknown>")]
            if ref.get("function"):
                details.append(ref["function"])
            if ref.get("incoming_type"):
                details.append(f"type={ref['incoming_type']}")
            if ref.get("disasm"):
                details.append(ref["disasm"])
            lines.append("- " + " | ".join(details))
    else:
        lines.append("- none")

    lines.extend(["", "data refs:"])
    data_refs = list(value.get("data_refs") or [])
    if data_refs:
        for ref in data_refs:
            details = [ref.get("address", "<unknown>")]
            if ref.get("symbol"):
                details.append(ref["symbol"])
            if ref.get("type"):
                details.append(f"type={ref['type']}")
            lines.append("- " + " | ".join(details))
    else:
        lines.append("- none")

    return "\n".join(lines)


def _render_comment_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    comment = value.get("comment")
    if isinstance(comment, str):
        return comment
    return _render_fallback_text(value)


def _render_refresh_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    target = value.get("target")
    if isinstance(target, dict):
        return f"refreshed: true\n\n{_render_target_summary(target)}"
    return _render_fallback_text(value)


def _render_workflow_list_text(value: Any) -> str:
    if not isinstance(value, list):
        return _render_fallback_text(value)
    if not value:
        return "no workflows"
    lines = []
    for item in value:
        if not isinstance(item, dict):
            lines.append(_render_fallback_text(item))
            continue
        flag = "registered" if item.get("registered") else "unregistered"
        lines.append(f"{item.get('name', '<unknown>')}  [{flag}]")
    return "\n".join(lines)


def _render_workflow_show_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    name = value.get("name", "<unknown>")
    flag = "registered" if value.get("registered") else "unregistered"
    lines = [f"{name}  [{flag}]"]
    if value.get("scope_activity"):
        lines.append(f"scope: {value['scope_activity']}")
    if value.get("depth"):
        lines.append(f"depth: {value['depth']}")
    roots = list(value.get("roots") or [])
    lines.append("")
    lines.append("roots:")
    if roots:
        lines.extend(f"- {r}" for r in roots)
    else:
        lines.append("- none")
    activities = list(value.get("activities") or [])
    lines.append("")
    lines.append(f"activities ({len(activities)}):")
    if activities:
        lines.extend(f"- {a}" for a in activities)
    else:
        lines.append("- none")
    eligibility = list(value.get("eligibility_settings") or [])
    if eligibility:
        lines.append("")
        lines.append("eligibility:")
        lines.extend(f"- {e}" for e in eligibility)
    if "configuration" in value:
        lines.append("")
        lines.append("configuration:")
        lines.append(str(value.get("configuration") or ""))
    elif "configuration_error" in value:
        lines.append("")
        lines.append(f"configuration error: {value['configuration_error']}")
    return "\n".join(lines)


def _render_workflow_active_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    scope = value.get("scope") or "binaryview"
    wf = value.get("workflow")
    if wf is None:
        return f"no workflow bound ({scope})"
    name = wf.get("name", "<unknown>")
    flag = "registered" if wf.get("registered") else "unregistered"
    lines = [f"{name}  [{flag}]  ({scope})"]
    if "function" in wf:
        lines.append(f"function: {wf['function']}")
    lines.append(f"activities: {wf.get('activity_count', 0)}")
    roots = list(wf.get("roots") or [])
    if roots:
        lines.append("roots:")
        lines.extend(f"- {r}" for r in roots)
    return "\n".join(lines)


def _render_workflow_machine_text(verb: str) -> Callable[[Any], str]:
    def render(value: Any) -> str:
        if not isinstance(value, dict):
            return _render_fallback_text(value)
        if not value.get("available"):
            reason = value.get("reason") or "unavailable"
            return f"machine {verb}: unavailable ({reason})"
        scope = value.get("scope") or "binaryview"
        body = value.get(verb)
        head = f"machine {verb} ({scope})"
        if "function" in value:
            head += f" function={value['function']}"
        return f"{head}\n{_render_fallback_text(body)}"

    return render


def _render_target_summary(value: dict[str, Any]) -> str:
    label = value.get("selector") or value.get("target_id") or "<unknown>"
    lines = [str(label)]
    if value.get("active"):
        lines[0] += " [active]"

    details = [
        ("target", value.get("target_id")),
        ("view", value.get("view_id")),
        ("kind", value.get("view_name")),
        ("file", value.get("filename")),
        ("arch", value.get("arch")),
        ("platform", value.get("platform")),
        ("entry", value.get("entry_point")),
    ]
    for key, item in details:
        if item not in (None, ""):
            lines.append(f"{key}: {item}")
    return "\n".join(lines)


def _render_target_list_text(value: Any) -> str:
    if not isinstance(value, list):
        return _render_fallback_text(value)
    if not value:
        return "no targets"
    return "\n\n".join(
        _render_target_summary(item) if isinstance(item, dict) else _render_fallback_text(item)
        for item in value
    )


def _render_target_info_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    return _render_target_summary(value)


def _render_name_address_list_text(value: Any) -> str:
    if not isinstance(value, list):
        return _render_fallback_text(value)
    if not value:
        return "none"

    lines = []
    for item in value:
        if not isinstance(item, dict):
            lines.append(_render_fallback_text(item))
            continue
        address = item.get("address", "<unknown>")
        name = item.get("name") or item.get("function") or "<unknown>"
        line = f"{address}  {name}"
        library = item.get("library")
        if library:
            line += f" [{library}]"
        raw_name = item.get("raw_name")
        if raw_name and raw_name != name:
            line += f" (raw: {raw_name})"
        lines.append(line)
    return "\n".join(lines)


def _render_xrefs_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)

    lines = [
        f"xrefs to {value.get('address', '<unknown>')}",
        "",
        "code refs:",
    ]
    code_refs = list(value.get("code_refs") or [])
    if code_refs:
        for ref in code_refs:
            if not isinstance(ref, dict):
                lines.append("- " + _render_fallback_text(ref))
                continue
            details = [str(ref.get("address", "<unknown>"))]
            if ref.get("function"):
                details.append(str(ref["function"]))
            lines.append("- " + " | ".join(details))
    else:
        lines.append("- none")

    lines.extend(["", "data refs:"])
    data_refs = list(value.get("data_refs") or [])
    if data_refs:
        for ref in data_refs:
            if not isinstance(ref, dict):
                lines.append("- " + _render_fallback_text(ref))
                continue
            details = [str(ref.get("address", "<unknown>"))]
            if ref.get("function"):
                details.append(str(ref["function"]))
            lines.append("- " + " | ".join(details))
    else:
        lines.append("- none")
    return "\n".join(lines)


def _render_callsites_text(value: Any, *, prefer_caller_static: bool = False) -> str:
    if not isinstance(value, list):
        return _render_fallback_text(value)
    if not value:
        return "none"

    blocks = []
    for row in value:
        if not isinstance(row, dict):
            blocks.append(_render_fallback_text(row))
            continue

        callee = row.get("callee") if isinstance(row.get("callee"), dict) else {}
        containing = row.get("containing_function") if isinstance(row.get("containing_function"), dict) else {}
        call_addr = row.get("call_addr", "<unknown>")
        caller_static = row.get("caller_static", "<unknown>")
        call_index = row.get("call_index")
        primary = (
            f"caller_static {caller_static} | call {call_addr}"
            if prefer_caller_static
            else f"call {call_addr} | caller_static {caller_static}"
        )
        lines = [
            primary,
            (
                f"within: {containing.get('name', '<unknown>')} @ "
                f"{containing.get('address', '<unknown>')}"
            ),
            f"callee: {callee.get('name', '<unknown>')} @ {callee.get('address', '<unknown>')}",
        ]
        if call_index is not None:
            lines.append(f"call-index: {call_index}")
        if row.get("within_query"):
            lines.append(f"within-query: {row['within_query']}")
        if row.get("hlil_statement"):
            lines.append(f"hlil: {row['hlil_statement']}")
        if row.get("pre_branch_condition"):
            lines.append(f"pre-branch: {row['pre_branch_condition']}")

        call_instruction = row.get("call_instruction") if isinstance(row.get("call_instruction"), dict) else {}
        previous = list(row.get("previous_instructions") or [])
        next_instructions = list(row.get("next_instructions") or [])
        lines.append("context:")
        for item in previous:
            if isinstance(item, dict):
                lines.append(f"  {item.get('address', '<unknown>')}  {item.get('text', '')}".rstrip())
        lines.append(
            f"> {call_instruction.get('address', '<unknown>')}  {call_instruction.get('text', '')}".rstrip()
        )
        for item in next_instructions:
            if isinstance(item, dict):
                lines.append(f"  {item.get('address', '<unknown>')}  {item.get('text', '')}".rstrip())
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def _render_type_list_text(value: Any) -> str:
    if not isinstance(value, list):
        return _render_fallback_text(value)
    if not value:
        return "none"

    lines = []
    for item in value:
        if not isinstance(item, dict):
            lines.append(_render_fallback_text(item))
            continue
        name = item.get("name", "<unknown>")
        kind = item.get("kind", "<unknown>")
        decl = item.get("decl")
        line = f"{name} | {kind}"
        if decl:
            line += f" | {decl}"
        lines.append(line)
    return "\n".join(lines)


def _render_strings_text(value: Any) -> str:
    if not isinstance(value, list):
        return _render_fallback_text(value)
    if not value:
        return "none"

    lines = []
    for item in value:
        if not isinstance(item, dict):
            lines.append(_render_fallback_text(item))
            continue
        address = item.get("address", "<unknown>")
        length = item.get("length", "?")
        string_type = item.get("type", "")
        rendered = json.dumps(item.get("value", ""), ensure_ascii=True)
        lines.append(f"{address}  len={length}  {string_type}  {rendered}".rstrip())
    return "\n".join(lines)


def _render_doctor_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)

    lines = [
        f"cli version: {value.get('cli_version', '<unknown>')}",
        f"plugin source: {value.get('plugin_source_dir', '<unknown>')}",
        f"plugin install: {value.get('plugin_install_dir', '<unknown>')}",
        f"plugin source build: {value.get('plugin_source_build_id', '<unknown>')}",
        f"plugin install build: {value.get('plugin_install_build_id', '<unknown>')}",
        "",
        "instances:",
    ]
    instances = list(value.get("instances") or [])
    if not instances:
        lines.append("- none")
        return "\n".join(lines)

    for item in instances:
        if not isinstance(item, dict):
            lines.append("- " + _render_fallback_text(item))
            continue
        doctor = item.get("doctor") if isinstance(item.get("doctor"), dict) else {}
        status = "ok" if doctor and not doctor.get("error") else "error"
        lines.append(
            "- "
            + f"pid={item.get('pid', '<unknown>')} plugin={item.get('plugin_version', '<unknown>')} status={status}"
        )
        build_id = item.get("plugin_build_id")
        if build_id:
            lines.append(f"  build: {build_id}")
        if item.get("stale_plugin_version"):
            lines.append("  stale: loaded plugin version differs from CLI version")
        if item.get("stale_plugin_code"):
            lines.append("  stale: loaded plugin code does not match installed plugin file")
        if item.get("started_at"):
            lines.append(f"  started: {item['started_at']}")
        if item.get("socket_path"):
            lines.append(f"  socket: {item['socket_path']}")
        error = doctor.get("error")
        if error:
            lines.append(f"  error: {error}")
        sandbox_hint = item.get("sandbox_hint")
        if sandbox_hint:
            lines.append(f"  hint: {sandbox_hint}")
    return "\n".join(lines)


def _sandbox_socket_hint(instance: Any, error: str) -> str | None:
    if not os.environ.get("CODEX_SANDBOX"):
        return None
    lowered = error.lower()
    if "operation not permitted" not in lowered and "permission denied" not in lowered:
        return None
    return (
        "Codex sandbox blocked the Binary Ninja bridge socket at "
        f"{instance.socket_path}. `bn` must run outside the Codex sandbox to reach the "
        "live Binary Ninja GUI bridge. Add `prefix_rule(pattern=[\"bn\"], decision=\"allow\")` "
        "to `~/.codex/rules/default.rules`, then restart Codex or reload rules."
    )


def _format_operation_result(item: dict[str, Any]) -> str:
    op = item.get("op", "<unknown>")
    if op == "rename_symbol":
        return f"rename_symbol {item.get('kind', 'auto')} {item.get('address', '<unknown>')} -> {item.get('new_name', '<unknown>')}"
    if op == "set_comment":
        target = item.get("function") or item.get("address", "<unknown>")
        return f"set_comment {target}"
    if op == "delete_comment":
        target = item.get("function") or item.get("address", "<unknown>")
        return f"delete_comment {target}"
    if op == "set_prototype":
        return f"set_prototype {item.get('function', '<unknown>')} @ {item.get('address', '<unknown>')}"
    if op in {"local_rename", "local_retype"}:
        target = item.get("local_id") or item.get("variable", "<unknown>")
        return f"{op} {item.get('function', '<unknown>')}::{target}"
    if op == "struct_field_set":
        return (
            f"struct_field_set {item.get('struct_name', '<unknown>')} "
            f"{item.get('offset', '<unknown>')} {item.get('field_name', '<unknown>')} {item.get('field_type', '<unknown>')}"
        )
    if op == "struct_field_rename":
        return (
            f"struct_field_rename {item.get('struct_name', '<unknown>')} "
            f"{item.get('old_name', '<unknown>')} -> {item.get('new_name', '<unknown>')}"
        )
    if op == "struct_field_delete":
        return f"struct_field_delete {item.get('struct_name', '<unknown>')}::{item.get('field_name', '<unknown>')}"
    if op == "types_declare":
        return (
            f"types_declare {item.get('count', 0)} types"
            f" (parsed functions={item.get('parsed_function_count', len(item.get('parsed_functions') or []))},"
            f" variables={item.get('parsed_variable_count', len(item.get('parsed_variables') or []))})"
        )
    return _render_fallback_text(item)


def _render_mutation_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)

    lines = [
        f"preview: {bool(value.get('preview'))}",
        f"success: {bool(value.get('success', True))}",
        f"committed: {bool(value.get('committed', False))}",
    ]
    if value.get("message"):
        lines.append(f"message: {value['message']}")
    lines.extend(["", "results:"])
    results = list(value.get("results") or [])
    if results:
        for item in results:
            if isinstance(item, dict):
                summary = _format_operation_result(item)
                if item.get("status"):
                    summary += f" [status={item['status']}]"
                if "changed" in item:
                    summary += f" [changed={bool(item['changed'])}]"
                if item.get("message"):
                    summary += f" ({item['message']})"
                lines.append("- " + summary)
                if item.get("requested"):
                    lines.append("  requested: " + json.dumps(item["requested"], sort_keys=True))
                if item.get("observed"):
                    lines.append("  observed: " + json.dumps(item["observed"], sort_keys=True))
            else:
                lines.append("- " + _render_fallback_text(item))
    else:
        lines.append("- none")

    lines.extend(["", "affected functions:"])
    affected_functions = list(value.get("affected_functions") or [])
    if affected_functions:
        for item in affected_functions:
            if not isinstance(item, dict):
                lines.append("- " + _render_fallback_text(item))
                continue
            before_name = item.get("before_name") or item.get("after_name") or "<unknown>"
            after_name = item.get("after_name") or before_name
            summary = f"{item.get('address', '<unknown>')} {before_name}"
            if after_name != before_name:
                summary += f" -> {after_name}"
            summary += f" [changed={bool(item.get('changed'))}]"
            lines.append("- " + summary)
            if item.get("diff"):
                lines.append(str(item["diff"]))
    else:
        lines.append("- none")

    lines.extend(["", "affected types:"])
    affected_types = list(value.get("affected_types") or [])
    if affected_types:
        for item in affected_types:
            if not isinstance(item, dict):
                lines.append("- " + _render_fallback_text(item))
                continue
            summary = f"{item.get('type_name', '<unknown>')} [changed={bool(item.get('changed'))}]"
            if item.get("message"):
                summary += f" ({item['message']})"
            lines.append("- " + summary)
            if item.get("layout_diff"):
                lines.append(str(item["layout_diff"]))
    else:
        lines.append("- none")
    return "\n".join(lines)


def _render_py_exec_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)

    parts: list[str] = []
    stdout = value.get("stdout")
    if isinstance(stdout, str) and stdout:
        parts.append(stdout.rstrip("\n"))

    result = value.get("result")
    if result is not None:
        body = result if isinstance(result, str) else json.dumps(result, indent=2, sort_keys=True)
        prefix = "result:\n" if parts else "result:\n"
        parts.append(prefix + body)

    warnings = list(value.get("warnings") or [])
    if warnings:
        parts.append("warnings:\n" + "\n".join(f"- {warning}" for warning in warnings))

    artifact = value.get("artifact")
    if isinstance(artifact, dict) and artifact.get("artifact_path"):
        parts.append(f"artifact: {artifact['artifact_path']}")

    if not parts:
        return ""
    return "\n\n".join(parts)


def _doctor(args: argparse.Namespace) -> int:
    install_dir = plugin_install_dir()
    source_dir = plugin_source_dir()
    install_bridge = install_dir / "bridge.py"
    source_bridge = source_dir / "bridge.py"
    install_build_id = build_id_for_file(install_bridge)
    source_build_id = build_id_for_file(source_bridge)
    instances = []
    for instance in list_instances():
        ping: dict[str, Any]
        try:
            response = _send_request_to_instance(
                instance,
                "doctor",
                params={},
                target=None,
            )
            ping = response["result"]
        except Exception as exc:
            ping = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        sandbox_hint = _sandbox_socket_hint(instance, str(ping.get("error", "")))

        loaded_version = ping.get("plugin_version") if isinstance(ping, dict) else None
        loaded_build_id = ping.get("plugin_build_id") if isinstance(ping, dict) else None
        instance_info = {
            "pid": instance.pid,
            "socket_path": str(instance.socket_path),
            "plugin_version": instance.plugin_version,
            "plugin_build_id": loaded_build_id,
            "installed_plugin_build_id": install_build_id,
            "source_plugin_build_id": source_build_id,
            "stale_plugin_version": (
                bool(loaded_version)
                and str(loaded_version) != _package_version()
            ),
            "stale_plugin_code": (
                bool(loaded_build_id)
                and install_build_id is not None
                and loaded_build_id != install_build_id
            ),
            "started_at": instance.started_at,
            "doctor": ping,
        }
        if sandbox_hint:
            instance_info["sandbox_hint"] = sandbox_hint
        instances.append(instance_info)

    result = {
        "cli_version": _package_version(),
        "plugin_source_dir": str(source_dir),
        "plugin_install_dir": str(install_dir),
        "plugin_source_build_id": source_build_id,
        "plugin_install_build_id": install_build_id,
        "instances": instances,
    }
    if args.format == "text":
        result = _render_doctor_text(result)
    _render_result(result, fmt=args.format, out_path=args.out, stem="doctor")
    return 0


def _plugin_install(args: argparse.Namespace) -> int:
    source = plugin_source_dir()
    dest = args.dest or plugin_install_dir()
    _install_tree(source, dest, mode=args.mode, force=args.force)

    _render_result(
        {
            "installed": True,
            "mode": args.mode,
            "source": str(source),
            "destination": str(dest),
        },
        fmt=args.format,
        out_path=args.out,
        stem="plugin-install",
    )
    return 0


def _install_tree(source: Path, dest: Path, *, mode: str, force: bool) -> None:
    if not source.exists():
        raise BridgeError(f"Source directory is missing: {source}")

    dest.parent.mkdir(parents=True, exist_ok=True)

    if dest.exists() or dest.is_symlink():
        if not force:
            raise BridgeError(f"Destination already exists: {dest}")
        if dest.is_symlink() or dest.is_file():
            dest.unlink()
        else:
            shutil.rmtree(dest)

    if mode == "copy":
        shutil.copytree(source, dest)
    else:
        os.symlink(source, dest, target_is_directory=True)


def _skill_install(args: argparse.Namespace) -> int:
    source = skill_source_dir()
    if args.client == "both":
        clients = list(SKILL_CLIENTS)
    else:
        clients = [args.client]

    if args.dest is not None and len(clients) > 1:
        raise BridgeError("--dest cannot be combined with --client both; pick a single client")

    installations = []
    for client in clients:
        dest = args.dest or skill_install_dir_for(client)
        _install_tree(source, dest, mode=args.mode, force=args.force)
        installations.append({"client": client, "destination": str(dest)})

    _render_result(
        {
            "installed": True,
            "mode": args.mode,
            "skill": source.name,
            "source": str(source),
            "installations": installations,
        },
        fmt=args.format,
        out_path=args.out,
        stem="skill-install",
    )
    return 0


def _resolve_daemon_mode_for_action(args: argparse.Namespace) -> str:
    explicit = getattr(args, "mode", None)
    if explicit:
        return explicit
    sticky = read_current_daemon_mode()
    if sticky:
        return sticky
    instances = list_instances()
    if len(instances) == 1:
        return instances[0].mode
    if not instances:
        raise BridgeError(
            "No running daemon to act on. Start one with `bn daemon start` or pass `--mode <mode>`."
        )
    modes = sorted({instance.mode for instance in instances})
    raise BridgeError(
        f"Multiple daemons are running ({', '.join(modes)}); pass `--mode <mode>` or run `bn daemon use <mode>`."
    )


def _find_instance(mode: str) -> BridgeInstance | None:
    for instance in list_instances():
        if instance.mode == mode:
            return instance
    return None


def _render_daemon_list_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    instances = list(value.get("instances") or [])
    sticky = value.get("sticky_mode")
    if not instances:
        suffix = f"\nsticky mode: {sticky}" if sticky else ""
        return "no running daemons" + suffix
    lines = []
    if sticky:
        lines.append(f"sticky mode: {sticky}")
    else:
        lines.append("sticky mode: <unset>")
    lines.append("")
    for item in instances:
        flag = " [current]" if sticky and item.get("mode") == sticky else ""
        lines.append(
            f"- mode={item.get('mode', '<unknown>')}  pid={item.get('pid', '?')}  "
            f"socket={item.get('socket_path', '<unknown>')}  targets={item.get('target_count', '?')}{flag}"
        )
    return "\n".join(lines)


def _render_daemon_status_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    if not value.get("running"):
        return f"daemon mode={value.get('mode', '<unknown>')} is not running"
    lines = [
        f"mode: {value.get('mode')}",
        f"pid: {value.get('pid')}",
        f"socket: {value.get('socket_path')}",
        f"registry: {value.get('registry_path')}",
        f"plugin_version: {value.get('plugin_version')}",
        f"target_count: {value.get('target_count')}",
    ]
    if value.get("started_at"):
        lines.append(f"started_at: {value['started_at']}")
    return "\n".join(lines)


def _render_daemon_use_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    mode = value.get("mode")
    if mode is None:
        return "sticky daemon mode cleared"
    return f"sticky daemon mode set to: {mode}"


def _instance_summary(instance: BridgeInstance) -> dict[str, Any]:
    return {
        "mode": instance.mode,
        "pid": instance.pid,
        "socket_path": str(instance.socket_path),
        "registry_path": str(instance.registry_path),
        "plugin_version": instance.plugin_version,
        "started_at": instance.started_at,
    }


def _query_target_count(instance: BridgeInstance) -> int | None:
    try:
        response = _send_request_to_instance(
            instance, "list_targets", params={}, target=None, timeout=2.0
        )
    except Exception:
        return None
    result = response.get("result")
    if isinstance(result, list):
        return len(result)
    return None


def _default_daemon_log_path(mode: str) -> Path:
    from .paths import cache_home

    return cache_home() / "logs" / f"daemon-{mode}.log"


def _spawn_detached_daemon(mode: str, *, log_path: Path) -> int:
    import subprocess

    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_fh = log_path.open("ab", buffering=0)
    try:
        bn_exe = shutil.which("bn")
        if bn_exe is not None:
            cmd = [bn_exe, "daemon", "start", "--mode", mode, "--foreground"]
        else:
            cmd = [
                sys.executable,
                "-m",
                "bn",
                "daemon",
                "start",
                "--mode",
                mode,
                "--foreground",
            ]
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=log_fh,
            stderr=log_fh,
            start_new_session=True,
            env=os.environ.copy(),
        )
    finally:
        log_fh.close()
    return proc.pid


def _wait_for_registry(mode: str, *, timeout: float) -> bool:
    import time

    deadline = time.time() + timeout
    registry = bridge_registry_path(mode)
    while time.time() < deadline:
        if registry.exists():
            return True
        time.sleep(0.05)
    return False


def _daemon_start(args: argparse.Namespace) -> int:
    mode = args.mode or "headless"
    if mode == "gui":
        raise BridgeError(
            "GUI bridge is started automatically by the Binary Ninja plugin; use Binary Ninja itself."
        )
    existing = _find_instance(mode)
    if existing is not None:
        raise BridgeError(
            f"Daemon mode `{mode}` is already running (pid {existing.pid}). "
            "Stop it first with `bn daemon stop`."
        )

    if args.foreground:
        plugin_root = plugin_source_dir().parent
        if str(plugin_root) not in sys.path:
            sys.path.insert(0, str(plugin_root))
        try:
            from bn_agent_bridge import bridge as headless_bridge  # noqa: WPS433
        except ImportError as exc:
            raise BridgeError(
                f"Failed to import Binary Ninja headless bridge ({exc}). "
                "Ensure Binary Ninja is installed and `binaryninja` is on PYTHONPATH."
            ) from exc
        return headless_bridge._run_headless(foreground=True)

    log_path = Path(args.log).expanduser() if args.log else _default_daemon_log_path(mode)
    child_pid = _spawn_detached_daemon(mode, log_path=log_path)
    ready = _wait_for_registry(mode, timeout=10.0)
    if not ready:
        raise BridgeError(
            f"Daemon spawned (pid {child_pid}) but did not register within 10s. "
            f"Check the log at {log_path}."
        )
    instance = _find_instance(mode)
    daemon_pid = instance.pid if instance is not None else child_pid
    _render_result(
        {
            "started": True,
            "mode": mode,
            "pid": daemon_pid,
            "spawned_pid": child_pid,
            "log": str(log_path),
            "message": f"Daemon running in background. Logs at {log_path}.",
        },
        fmt=args.format,
        out_path=args.out,
        stem="daemon-start",
    )
    return 0


def _daemon_stop(args: argparse.Namespace) -> int:
    import signal

    mode = _resolve_daemon_mode_for_action(args)
    instance = _find_instance(mode)
    if instance is None:
        raise BridgeError(f"No `{mode}` daemon is running")
    if mode == "gui":
        raise BridgeError(
            "Refusing to stop the GUI bridge from the CLI; quit Binary Ninja itself."
        )
    try:
        os.kill(instance.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass

    _render_result(
        {
            "stopped": True,
            "mode": mode,
            "pid": instance.pid,
            "warning": "Any unsaved analysis on running targets has been discarded.",
        },
        fmt=args.format,
        out_path=args.out,
        stem="daemon-stop",
    )
    return 0


def _daemon_status(args: argparse.Namespace) -> int:
    mode = args.mode or read_current_daemon_mode()
    if mode is None:
        instances = list_instances()
        if len(instances) == 1:
            mode = instances[0].mode
        elif not instances:
            raise BridgeError("No running daemon. Pass --mode to ask about a specific mode.")
        else:
            modes = sorted({i.mode for i in instances})
            raise BridgeError(
                f"Multiple daemons running ({', '.join(modes)}); pass --mode <mode>."
            )

    instance = _find_instance(mode)
    if instance is None:
        payload: dict[str, Any] = {"mode": mode, "running": False}
    else:
        payload = {"mode": mode, "running": True, **_instance_summary(instance)}
        target_count = _query_target_count(instance)
        if target_count is not None:
            payload["target_count"] = target_count

    if args.format == "text":
        result = _render_daemon_status_text(payload)
    else:
        result = payload
    _render_result(result, fmt=args.format, out_path=args.out, stem="daemon-status")
    return 0


def _daemon_list(args: argparse.Namespace) -> int:
    instances = list_instances()
    sticky = read_current_daemon_mode()
    items: list[dict[str, Any]] = []
    for instance in instances:
        item = _instance_summary(instance)
        count = _query_target_count(instance)
        if count is not None:
            item["target_count"] = count
        items.append(item)
    payload = {"sticky_mode": sticky, "instances": items}
    if args.format == "text":
        result = _render_daemon_list_text(payload)
    else:
        result = payload
    _render_result(result, fmt=args.format, out_path=args.out, stem="daemon-list")
    return 0


def _daemon_use(args: argparse.Namespace) -> int:
    if args.clear:
        if args.mode_value is not None:
            raise BridgeError("Pass either <mode> or --clear, not both")
        write_current_daemon_mode(None)
        result: dict[str, Any] = {"mode": None}
    else:
        if args.mode_value is None:
            raise BridgeError("Pass a daemon mode (gui|headless) or --clear")
        if args.mode_value not in DAEMON_MODES:
            raise BridgeError(
                f"Unknown daemon mode: {args.mode_value!r} (expected one of {DAEMON_MODES})"
            )
        write_current_daemon_mode(args.mode_value)
        result = {"mode": args.mode_value}

    if args.format == "text":
        rendered = _render_daemon_use_text(result)
    else:
        rendered = result
    _render_result(rendered, fmt=args.format, out_path=args.out, stem="daemon-use")
    return 0


def _target_list(args: argparse.Namespace) -> int:
    return _call(
        args,
        "list_targets",
        {},
        require_target=False,
        text_renderer=_render_target_list_text,
        stem="targets",
    )


def _target_info(args: argparse.Namespace) -> int:
    return _call(
        args,
        "target_info",
        {"selector": args.target},
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_target_info_text,
        stem="target-info",
    )


def _refresh(args: argparse.Namespace) -> int:
    return _call(
        args,
        "refresh",
        {},
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_refresh_text,
        stem="refresh",
    )


def _parse_option_kv(entry: str) -> tuple[str, Any]:
    if "=" not in entry:
        raise BridgeError(f"--option expects KEY=VALUE, got: {entry!r}")
    key, _, raw = entry.partition("=")
    key = key.strip()
    if not key:
        raise BridgeError(f"--option key is empty in: {entry!r}")
    raw = raw.strip()
    try:
        value: Any = json.loads(raw)
    except json.JSONDecodeError:
        value = raw
    return key, value


def _collect_load_options(args: argparse.Namespace) -> dict[str, Any] | None:
    merged: dict[str, Any] = {}
    if args.options_json:
        try:
            parsed = json.loads(args.options_json)
        except json.JSONDecodeError as exc:
            raise BridgeError(f"--options-json is not valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise BridgeError("--options-json must encode a JSON object")
        merged.update(parsed)
    for entry in args.options or []:
        key, value = _parse_option_kv(entry)
        merged[key] = value
    return merged or None


def _target_load(args: argparse.Namespace) -> int:
    if not args.update_analysis:
        analysis = "skip"
    elif args.async_load:
        analysis = "async"
    else:
        analysis = "wait"
    params: dict[str, Any] = {
        "path": str(Path(args.path).expanduser().resolve()),
        "analysis": analysis,
    }
    options = _collect_load_options(args)
    if options is not None:
        params["options"] = options
    response = send_request("load_target", params=params, target=None)
    _render_result(
        response["result"],
        fmt=args.format,
        out_path=args.out,
        stem="target-load",
    )
    return 0


def _target_close(args: argparse.Namespace) -> int:
    return _call(
        args,
        "close_target",
        {"target": args.target or "active"},
        require_target=False,
        stem="target-close",
    )


def _target_save(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {}
    if args.path is not None:
        params["path"] = str(Path(args.path).expanduser().resolve())
    return _call(
        args,
        "save_target",
        params,
        require_target=True,
        allow_implicit_target=True,
        stem="target-save",
    )


def _render_analysis_status_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    state = value.get("state") or "<unknown>"
    count = value.get("count")
    total = value.get("total")
    done = value.get("done")
    pieces = [f"state: {state}"]
    if count is not None and total is not None:
        pieces.append(f"progress: {count}/{total}")
    pieces.append(f"done: {bool(done)}")
    return "\n".join(pieces)


def _target_status(args: argparse.Namespace) -> int:
    return _call(
        args,
        "analysis_status",
        {},
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_analysis_status_text,
        stem="target-status",
    )


def _render_target_loads_text(value: Any) -> str:
    if not isinstance(value, list):
        return _render_fallback_text(value)
    if not value:
        return "no recent load attempts"
    lines = []
    for item in value:
        if not isinstance(item, dict):
            lines.append(_render_fallback_text(item))
            continue
        load_id = item.get("load_id", "?")
        status = item.get("status", "?")
        path = item.get("path", "?")
        lines.append(f"- {load_id}  {status:<10}  {path}")
        if item.get("started_at"):
            lines.append(f"    started:   {item['started_at']}")
        if item.get("completed_at"):
            lines.append(f"    completed: {item['completed_at']}")
        if item.get("target_id"):
            lines.append(f"    target_id: {item['target_id']}")
        if item.get("error"):
            lines.append(f"    error:     {item['error']}")
        if item.get("traceback"):
            lines.append("    traceback:")
            for tb_line in item["traceback"].rstrip().splitlines():
                lines.append(f"      {tb_line}")
    return "\n".join(lines)


def _target_loads(args: argparse.Namespace) -> int:
    return _call(
        args,
        "list_loads",
        {},
        require_target=False,
        text_renderer=_render_target_loads_text,
        stem="target-loads",
    )


def _workflow_list(args: argparse.Namespace) -> int:
    return _call(
        args,
        "workflow_list",
        {"registered_only": bool(args.registered_only)},
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_workflow_list_text,
        stem="workflows",
    )


def _workflow_show(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {
        "name": args.name,
        "depth": args.depth,
        "with_config": bool(args.with_config),
    }
    if args.activity is not None:
        params["activity"] = args.activity
    return _call(
        args,
        "workflow_show",
        params,
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_workflow_show_text,
        stem="workflow-show",
    )


def _workflow_active(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {}
    if args.function is not None:
        params["function"] = args.function
    return _call(
        args,
        "workflow_active",
        params,
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_workflow_active_text,
        stem="workflow-active",
    )


def _workflow_machine_status(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {}
    if args.function is not None:
        params["function"] = args.function
    return _call(
        args,
        "workflow_machine_status",
        params,
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_workflow_machine_text("status"),
        stem="workflow-machine-status",
    )


def _workflow_machine_dump(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {}
    if args.function is not None:
        params["function"] = args.function
    return _call(
        args,
        "workflow_machine_dump",
        params,
        require_target=True,
        allow_implicit_target=True,
        stem="workflow-machine-dump",
    )


def _render_workflow_override_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    activity = value.get("activity", "<unknown>")
    scope = value.get("scope") or "binaryview"
    status = value.get("status") or ("previewed" if value.get("preview") else "")
    head = f"override {value.get('applied', '?')} {activity} ({scope})"
    if value.get("function"):
        head += f" function={value['function']}"
    lines = [head, f"status: {status}"]

    def _fmt(v: Any) -> str:
        if v is None:
            return "(none)"
        return str(v).lower() if isinstance(v, bool) else str(v)

    lines.append(f"before: {_fmt(value.get('before'))}")
    lines.append(f"after: {_fmt(value.get('after'))}")
    if value.get("preview"):
        lines.append(f"reverted: {bool(value.get('reverted'))}")
    if not value.get("verified", True):
        lines.append(f"verified: false")
    return "\n".join(lines)


def _workflow_override_set(args: argparse.Namespace) -> int:
    enable = args.enable
    if enable is None:
        print("error: must pass --enable or --disable", file=sys.stderr)
        return 2
    params: dict[str, Any] = {
        "activity": args.activity,
        "enable": bool(enable),
        "preview": bool(args.preview),
    }
    if args.function is not None:
        params["function"] = args.function
    return _call(
        args,
        "workflow_override_set",
        params,
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_workflow_override_text,
        result_exit_code=_mutation_exit_code,
        stem="workflow-override-set",
    )


def _workflow_override_clear(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {
        "activity": args.activity,
        "preview": bool(args.preview),
    }
    if args.function is not None:
        params["function"] = args.function
    return _call(
        args,
        "workflow_override_clear",
        params,
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_workflow_override_text,
        result_exit_code=_mutation_exit_code,
        stem="workflow-override-clear",
    )


def _render_workflow_machine_command_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    command = value.get("command", "?")
    scope = value.get("scope") or "binaryview"
    head = f"machine {command} ({scope})"
    if value.get("function"):
        head += f" function={value['function']}"
    accepted = bool(value.get("accepted"))
    lines = [head, f"accepted: {str(accepted).lower()}"]
    state = value.get("machine_state")
    if isinstance(state, dict):
        activity = state.get("activity", "<unknown>")
        s = state.get("state", "<unknown>")
        lines.append(f"machine state: {s} (activity={activity})")
    if command == "breakpoint_list":
        activities = list(value.get("activities") or [])
        lines.append(f"breakpoints ({len(activities)}):")
        if activities:
            lines.extend(f"- {a}" for a in activities)
        else:
            lines.append("- none")
    elif command in ("breakpoint_set", "breakpoint_clear"):
        requested = list(value.get("requested_activities") or [])
        if requested:
            lines.append("activities:")
            lines.extend(f"- {a}" for a in requested)
    return "\n".join(lines)


def _workflow_machine_command_handler(
    op: str, *, options: bool = False, activities: bool = False
) -> Callable[[argparse.Namespace], int]:
    def handler(args: argparse.Namespace) -> int:
        params: dict[str, Any] = {}
        if args.function is not None:
            params["function"] = args.function
        if options:
            params["advanced"] = bool(getattr(args, "advanced", True))
            params["incremental"] = bool(getattr(args, "incremental", False))
        if activities:
            params["activities"] = list(getattr(args, "activities", []) or [])
        return _call(
            args,
            op,
            params,
            require_target=True,
            allow_implicit_target=True,
            text_renderer=_render_workflow_machine_command_text,
            stem=op.replace("_", "-"),
        )

    return handler


def _workflow_machine_overrides(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {}
    if args.function is not None:
        params["function"] = args.function
    if args.activity is not None:
        params["activity"] = args.activity
    return _call(
        args,
        "workflow_machine_overrides",
        params,
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_workflow_machine_text("overrides"),
        stem="workflow-machine-overrides",
    )


def _function_list(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {}
    if args.min_address is not None:
        params["min_address"] = args.min_address
    if args.max_address is not None:
        params["max_address"] = args.max_address
    return _call(
        args,
        "list_functions",
        params,
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_name_address_list_text,
        page_label="function list",
        stem="functions",
    )


def _function_search(args: argparse.Namespace) -> int:
    params = {
        "query": args.query,
        "regex": bool(args.regex),
    }
    if args.min_address is not None:
        params["min_address"] = args.min_address
    if args.max_address is not None:
        params["max_address"] = args.max_address
    return _call(
        args,
        "search_functions",
        params,
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_name_address_list_text,
        page_label="function search",
        stem="function-search",
    )


def _function_info(args: argparse.Namespace) -> int:
    return _call(
        args,
        "function_info",
        {"identifier": args.identifier},
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_function_info_text,
        stem="function-info",
    )


def _handle_il_unavailable(result: dict[str, Any]) -> int:
    """Print IL unavailable info to stderr and return exit code 4."""
    func_info = result.get("function", {})
    name = func_info.get("name", "?")
    address = func_info.get("address", "?")
    reason = result.get("reason", "IL not available")
    hint = result.get("hint", "")
    status = result.get("status", "unknown")

    msg = f"error: cannot obtain IL for {name} ({address}): {reason}"
    if status == "analyzing":
        msg = f"info: {name} ({address}): {reason}"
    print(msg, file=sys.stderr)
    if hint:
        print(f"hint: {hint}", file=sys.stderr)
    return 4


def _decompile(args: argparse.Namespace) -> int:
    target = _resolve_target(args, require_target=True, allow_implicit_target=True)
    response = send_request("decompile", params={"identifier": args.identifier}, target=target)
    result = response["result"]
    if result.get("il_unavailable"):
        return _handle_il_unavailable(result)
    return _render_and_output(args, result, text_renderer=_text_field("text"), stem="decompile")


def _il(args: argparse.Namespace) -> int:
    target = _resolve_target(args, require_target=True, allow_implicit_target=True)
    response = send_request(
        "il",
        params={"identifier": args.identifier, "view": args.view, "ssa": bool(args.ssa)},
        target=target,
    )
    result = response["result"]
    if result.get("il_unavailable"):
        return _handle_il_unavailable(result)
    return _render_and_output(args, result, text_renderer=_text_field("text"), stem="il")


def _disasm(args: argparse.Namespace) -> int:
    return _call(
        args,
        "disasm",
        {"identifier": args.identifier},
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_text_field("text"),
        stem="disasm",
    )


def _disasm_linear(args: argparse.Namespace) -> int:
    return _call(
        args,
        "disasm_linear",
        {"address": args.address, "count": args.count},
        require_target=True,
        allow_implicit_target=True,
        stem="disasm-linear",
    )


def _disasm_range(args: argparse.Namespace) -> int:
    return _call(
        args,
        "disasm_range",
        {"start": args.start, "end": args.end},
        require_target=True,
        allow_implicit_target=True,
        stem="disasm-range",
    )


# =========================================================================
# Patch handlers
# =========================================================================


def _patch_status(args: argparse.Namespace) -> int:
    return _call(
        args,
        "patch_status",
        {"address": args.address},
        require_target=True,
        allow_implicit_target=True,
        stem="patch-status",
    )


def _patch_assemble(args: argparse.Namespace) -> int:
    return _call(
        args,
        "patch_assemble",
        {"address": args.address, "asm": args.asm},
        require_target=True,
        allow_implicit_target=True,
        stem="patch-assemble",
    )


def _patch_nop(args: argparse.Namespace) -> int:
    return _call(
        args,
        "patch_nop",
        {"address": args.address},
        require_target=True,
        allow_implicit_target=True,
        stem="patch-nop",
    )


def _patch_always_branch(args: argparse.Namespace) -> int:
    return _call(
        args,
        "patch_always_branch",
        {"address": args.address},
        require_target=True,
        allow_implicit_target=True,
        stem="patch-always-branch",
    )


def _patch_invert_branch(args: argparse.Namespace) -> int:
    return _call(
        args,
        "patch_invert_branch",
        {"address": args.address},
        require_target=True,
        allow_implicit_target=True,
        stem="patch-invert-branch",
    )


def _patch_never_branch(args: argparse.Namespace) -> int:
    return _call(
        args,
        "patch_never_branch",
        {"address": args.address},
        require_target=True,
        allow_implicit_target=True,
        stem="patch-never-branch",
    )


def _patch_skip_and_return(args: argparse.Namespace) -> int:
    return _call(
        args,
        "patch_skip_and_return",
        {"address": args.address, "value": args.return_value},
        require_target=True,
        allow_implicit_target=True,
        stem="patch-skip-return",
    )


# =========================================================================
# Memory handlers
# =========================================================================


def _memory_read(args: argparse.Namespace) -> int:
    return _call(
        args,
        "memory_read",
        {"address": args.address, "length": args.length},
        require_target=True,
        allow_implicit_target=True,
        stem="memory-read",
    )


def _memory_write(args: argparse.Namespace) -> int:
    return _call(
        args,
        "memory_write",
        {"address": args.address, "data_hex": args.hex_data},
        require_target=True,
        allow_implicit_target=True,
        stem="memory-write",
    )


def _memory_insert(args: argparse.Namespace) -> int:
    return _call(
        args,
        "memory_insert",
        {"address": args.address, "data_hex": args.hex_data},
        require_target=True,
        allow_implicit_target=True,
        stem="memory-insert",
    )


def _memory_remove(args: argparse.Namespace) -> int:
    return _call(
        args,
        "memory_remove",
        {"address": args.address, "length": args.length},
        require_target=True,
        allow_implicit_target=True,
        stem="memory-remove",
    )


def _memory_reader(args: argparse.Namespace) -> int:
    return _call(
        args,
        "memory_reader_read",
        {"address": args.address, "width": args.width, "endian": args.endian},
        require_target=True,
        allow_implicit_target=True,
        stem="memory-reader",
    )


def _memory_writer(args: argparse.Namespace) -> int:
    return _call(
        args,
        "memory_writer_write",
        {"address": args.address, "width": args.width, "value": args.value, "endian": args.endian},
        require_target=True,
        allow_implicit_target=True,
        stem="memory-writer",
    )


# =========================================================================
# Value handlers
# =========================================================================


def _value_reg(args: argparse.Namespace) -> int:
    return _call(
        args,
        "value_reg",
        {
            "function_start": args.function,
            "address": args.address,
            "register": args.register,
            "after": args.after,
        },
        require_target=True,
        allow_implicit_target=True,
        stem="value-reg",
    )


def _value_stack(args: argparse.Namespace) -> int:
    return _call(
        args,
        "value_stack",
        {
            "function_start": args.function,
            "address": args.address,
            "stack_offset": args.offset,
            "size": args.size,
            "after": args.after,
        },
        require_target=True,
        allow_implicit_target=True,
        stem="value-stack",
    )


def _value_possible(args: argparse.Namespace) -> int:
    return _call(
        args,
        "value_possible",
        {
            "function_start": args.function,
            "address": args.address,
            "level": args.level,
            "ssa": args.ssa,
        },
        require_target=True,
        allow_implicit_target=True,
        stem="value-possible",
    )


def _value_flags(args: argparse.Namespace) -> int:
    return _call(
        args,
        "value_flags_at",
        {
            "function_start": args.function,
            "address": args.address,
        },
        require_target=True,
        allow_implicit_target=True,
        stem="value-flags",
    )


# =========================================================================
# Search handlers
# =========================================================================


def _search_bytes(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"data_hex": args.pattern}
    if args.start:
        params["start"] = args.start
    if args.end:
        params["end"] = args.end
    if args.limit:
        params["limit"] = args.limit
    return _call(
        args,
        "search_bytes",
        params,
        require_target=True,
        allow_implicit_target=True,
        stem="search-bytes",
    )


def _search_constant(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"constant": args.value}
    if args.limit:
        params["limit"] = args.limit
    return _call(
        args,
        "search_constant",
        params,
        require_target=True,
        allow_implicit_target=True,
        stem="search-constant",
    )


def _search_text_handler(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"query": args.pattern}
    if args.regex:
        params["regex"] = True
    if args.il_type:
        params["il_type"] = args.il_type
    if args.limit:
        params["limit"] = args.limit
    return _call(
        args,
        "search_text",
        params,
        require_target=True,
        allow_implicit_target=True,
        stem="search-text",
    )


# =========================================================================
# Arch handlers
# =========================================================================


def _arch_info(args: argparse.Namespace) -> int:
    return _call(
        args,
        "arch_info",
        {},
        require_target=True,
        allow_implicit_target=True,
        stem="arch-info",
    )


def _arch_assemble(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"asm": args.asm}
    if args.address:
        params["address"] = args.address
    if hasattr(args, "arch_name") and args.arch_name:
        params["arch_name"] = args.arch_name
    return _call(
        args,
        "arch_assemble",
        params,
        require_target=True,
        allow_implicit_target=True,
        stem="arch-assemble",
    )


def _arch_disasm_bytes(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"data_hex": args.hex_bytes}
    if args.address:
        params["address"] = args.address
    if hasattr(args, "arch_name") and args.arch_name:
        params["arch_name"] = args.arch_name
    return _call(
        args,
        "arch_disasm_bytes",
        params,
        require_target=True,
        allow_implicit_target=True,
        stem="arch-disasm",
    )


# =========================================================================
# Segments/Sections/DataVars handlers
# =========================================================================


def _list_segments(args: argparse.Namespace) -> int:
    return _call(
        args,
        "list_segments",
        {},
        require_target=True,
        allow_implicit_target=True,
        stem="segments",
    )


def _list_sections(args: argparse.Namespace) -> int:
    return _call(
        args,
        "list_sections",
        {},
        require_target=True,
        allow_implicit_target=True,
        stem="sections",
    )


def _list_data_vars(args: argparse.Namespace) -> int:
    return _call(
        args,
        "list_data_vars",
        {"offset": args.offset, "limit": args.limit},
        require_target=True,
        allow_implicit_target=True,
        stem="data-vars",
    )


# =========================================================================
# Function extended handlers
# =========================================================================


def _function_basic_blocks(args: argparse.Namespace) -> int:
    return _call(
        args,
        "function_basic_blocks",
        {"identifier": args.identifier},
        require_target=True,
        allow_implicit_target=True,
        stem="function-bbs",
    )


def _function_callers(args: argparse.Namespace) -> int:
    return _call(
        args,
        "function_callers",
        {"identifier": args.identifier},
        require_target=True,
        allow_implicit_target=True,
        stem="function-callers",
    )


def _function_callees(args: argparse.Namespace) -> int:
    return _call(
        args,
        "function_callees",
        {"identifier": args.identifier},
        require_target=True,
        allow_implicit_target=True,
        stem="function-callees",
    )


def _render_force_analysis(value: Any) -> str:
    if not isinstance(value, dict):
        return _render_fallback_text(value)
    name = value.get("function", "?")
    addr = value.get("address", "?")
    il_ok = value.get("il_available", False)
    lines = [f"{name} ({addr}): reanalyzed"]
    if value.get("prior_skip_reason"):
        lines.append(f"  prior skip reason: {value['prior_skip_reason']}")
    lines.append(f"  IL available: {il_ok}")
    if not il_ok:
        il_status = value.get("il_status")
        if il_status:
            lines.append(f"  status: {il_status.get('reason', 'unknown')}")
            hint = il_status.get("hint")
            if hint:
                lines.append(f"  hint: {hint}")
    return "\n".join(lines)


def _function_force_analysis(args: argparse.Namespace) -> int:
    return _call(
        args,
        "function_force_analysis",
        {"identifier": args.identifier},
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_force_analysis,
        stem="function-force-analysis",
    )


def _xrefs(args: argparse.Namespace) -> int:
    if args.identifier == "field":
        if len(args.extra) != 1:
            raise BridgeError("Usage: bn xrefs field <Struct.field>")
        return _call(
            args,
            "field_xrefs",
            {"field": args.extra[0]},
            require_target=True,
            allow_implicit_target=True,
            text_renderer=_render_field_xrefs_text,
            stem="field-xrefs",
        )
    if not args.identifier:
        raise BridgeError("xrefs requires an identifier")
    return _call(
        args,
        "xrefs",
        {"identifier": args.identifier},
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_xrefs_text,
        stem="xrefs",
    )


def _load_within_identifiers(path: Path) -> list[str]:
    identifiers = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        identifiers.append(line)
    return identifiers


def _callsites(args: argparse.Namespace) -> int:
    if args.within is not None:
        within_identifiers = [args.within]
    else:
        if args.within_file is None or not args.within_file.exists():
            raise BridgeError(f"Scope file not found: {args.within_file}")
        within_identifiers = _load_within_identifiers(args.within_file)
        if not within_identifiers:
            raise BridgeError(f"Scope file did not contain any function identifiers: {args.within_file}")

    return _call(
        args,
        "callsites",
        {
            "callee": args.callee,
            "within_identifiers": within_identifiers,
            "context": args.context,
            "caller_static": bool(args.caller_static),
        },
        require_target=True,
        allow_implicit_target=True,
        text_renderer=lambda value: _render_callsites_text(
            value,
            prefer_caller_static=bool(args.caller_static),
        ),
        stem="callsites",
    )


def _types(args: argparse.Namespace) -> int:
    return _call(
        args,
        "types",
        {"query": args.query, "offset": args.offset, "limit": args.limit},
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_type_list_text,
        page_limit=args.limit,
        page_offset=args.offset,
        page_label="types",
        stem="types",
    )


def _types_show(args: argparse.Namespace) -> int:
    return _call(
        args,
        "type_info",
        {
            "type_name": args.type_name,
            "require_struct": bool(getattr(args, "require_struct", False)),
        },
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_type_info_text,
        stem="type-show",
    )


def _types_declare(args: argparse.Namespace) -> int:
    source_path = None
    if args.file is not None:
        if not args.file.exists():
            raise BridgeError(f"Declaration file not found: {args.file}")
        declaration = args.file.read_text(encoding="utf-8")
        source_path = str(args.file)
    elif args.stdin:
        declaration = sys.stdin.read()
    elif args.declaration:
        declaration = args.declaration
    else:
        raise BridgeError("Provide a declaration string, --file, or --stdin")

    return _call(
        args,
        "types_declare",
        {
            "declaration": declaration,
            "source_path": source_path,
            "preview": bool(args.preview),
        },
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_mutation_text,
        stem="types-declare",
        result_exit_code=_mutation_exit_code,
    )


def _strings(args: argparse.Namespace) -> int:
    return _call(
        args,
        "strings",
        {"query": args.query, "offset": args.offset, "limit": args.limit},
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_strings_text,
        page_limit=args.limit,
        page_offset=args.offset,
        page_label="strings",
        stem="strings",
    )


def _imports(args: argparse.Namespace) -> int:
    return _call(
        args,
        "imports",
        {},
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_name_address_list_text,
        stem="imports",
    )


def _bundle_function(args: argparse.Namespace) -> int:
    return _call(
        args,
        "bundle_function",
        {"identifier": args.identifier, "out_path": str(args.out) if args.out else None},
        require_target=True,
        allow_implicit_target=True,
        stem="function-bundle",
        bridge_writes_output=bool(args.out),
    )


def _py_exec(args: argparse.Namespace) -> int:
    if getattr(args, "code", None) is not None:
        script = args.code
    elif args.script:
        if not args.script.exists():
            raise BridgeError(f"Script file not found: {args.script}. Use --code for inline Python.")
        script = args.script.read_text(encoding="utf-8")
    else:
        script = sys.stdin.read()

    return _call(
        args,
        "py_exec",
        {"script": script},
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_py_exec_text,
        stem="py-exec",
    )


def _symbol_rename(args: argparse.Namespace) -> int:
    return _call(
        args,
        "rename_symbol",
        {
            "kind": args.kind,
            "identifier": args.identifier,
            "new_name": args.new_name,
            "preview": bool(args.preview),
        },
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_mutation_text,
        stem="symbol-rename",
        result_exit_code=_mutation_exit_code,
    )


def _comment_set(args: argparse.Namespace) -> int:
    return _call(
        args,
        "set_comment",
        {
            "address": args.address,
            "function": args.function,
            "comment": args.comment,
            "preview": bool(args.preview),
        },
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_mutation_text,
        stem="comment-set",
        result_exit_code=_mutation_exit_code,
    )


def _comment_get(args: argparse.Namespace) -> int:
    return _call(
        args,
        "get_comment",
        {
            "address": args.address,
            "function": args.function,
        },
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_comment_text,
        stem="comment-get",
    )


def _comment_delete(args: argparse.Namespace) -> int:
    return _call(
        args,
        "delete_comment",
        {
            "address": args.address,
            "function": args.function,
            "preview": bool(args.preview),
        },
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_mutation_text,
        stem="comment-delete",
        result_exit_code=_mutation_exit_code,
    )


def _proto_set(args: argparse.Namespace) -> int:
    return _call(
        args,
        "set_prototype",
        {
            "identifier": args.identifier,
            "prototype": args.prototype,
            "preview": bool(args.preview),
        },
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_mutation_text,
        stem="prototype-set",
        result_exit_code=_mutation_exit_code,
    )


def _proto_get(args: argparse.Namespace) -> int:
    return _call(
        args,
        "get_prototype",
        {"identifier": args.identifier},
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_proto_text,
        stem="prototype-get",
    )


def _local_list(args: argparse.Namespace) -> int:
    return _call(
        args,
        "list_locals",
        {"identifier": args.function},
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_local_list_text,
        stem="local-list",
    )


def _local_rename(args: argparse.Namespace) -> int:
    return _call(
        args,
        "local_rename",
        {
            "function": args.function,
            "variable": args.variable,
            "new_name": args.new_name,
            "preview": bool(args.preview),
        },
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_mutation_text,
        stem="local-rename",
        result_exit_code=_mutation_exit_code,
    )


def _local_retype(args: argparse.Namespace) -> int:
    return _call(
        args,
        "local_retype",
        {
            "function": args.function,
            "variable": args.variable,
            "new_type": args.new_type,
            "preview": bool(args.preview),
        },
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_mutation_text,
        stem="local-retype",
        result_exit_code=_mutation_exit_code,
    )


def _struct_field_set(args: argparse.Namespace) -> int:
    return _call(
        args,
        "struct_field_set",
        {
            "struct_name": args.struct_name,
            "offset": args.offset,
            "field_name": args.field_name,
            "field_type": args.field_type,
            "overwrite_existing": not args.no_overwrite,
            "preview": bool(args.preview),
        },
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_mutation_text,
        stem="struct-field-set",
        result_exit_code=_mutation_exit_code,
    )


def _struct_show(args: argparse.Namespace) -> int:
    return _call(
        args,
        "type_info",
        {
            "type_name": args.struct_name,
            "require_struct": True,
        },
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_type_info_text,
        stem="struct-show",
    )


def _struct_field_rename(args: argparse.Namespace) -> int:
    return _call(
        args,
        "struct_field_rename",
        {
            "struct_name": args.struct_name,
            "old_name": args.old_name,
            "new_name": args.new_name,
            "preview": bool(args.preview),
        },
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_mutation_text,
        stem="struct-field-rename",
        result_exit_code=_mutation_exit_code,
    )


def _struct_field_delete(args: argparse.Namespace) -> int:
    return _call(
        args,
        "struct_field_delete",
        {
            "struct_name": args.struct_name,
            "field_name": args.field_name,
            "preview": bool(args.preview),
        },
        require_target=True,
        allow_implicit_target=True,
        text_renderer=_render_mutation_text,
        stem="struct-field-delete",
        result_exit_code=_mutation_exit_code,
    )


def _batch_apply(args: argparse.Namespace) -> int:
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    if args.preview:
        manifest["preview"] = True
    return _call(
        args,
        "batch_apply",
        manifest,
        require_target=False,
        text_renderer=_render_mutation_text,
        stem="batch-apply",
        result_exit_code=_mutation_exit_code,
    )


def _add_paged_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--limit", type=int, default=100)


def _add_function_address_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--min-address",
        help="Only include functions whose start address is at or above this address",
    )
    parser.add_argument(
        "--max-address",
        help="Only include functions whose start address is at or below this address",
    )


def _api_docs_resolve_dir(args: argparse.Namespace) -> Path:
    try:
        return api_docs.find_docs_dir(getattr(args, "docs_dir", None))
    except FileNotFoundError as exc:
        raise BridgeError(str(exc)) from exc


def _api_docs_search(args: argparse.Namespace) -> int:
    docs_dir = _api_docs_resolve_dir(args)
    entries = api_docs.load_or_build_index(docs_dir)
    matches = api_docs.search(
        entries,
        args.pattern,
        regex=args.regex,
        kind=args.kind,
        limit=args.limit,
    )
    result: Any = matches
    if args.format == "text":
        result = api_docs.format_entries_text(matches)
    _render_result(result, fmt=args.format, out_path=args.out, stem="api-docs-search")
    return 0 if matches else 1


def _api_docs_list(args: argparse.Namespace) -> int:
    docs_dir = _api_docs_resolve_dir(args)
    entries = api_docs.load_or_build_index(docs_dir)
    matches = api_docs.list_entries(
        entries,
        kind=args.kind,
        module=args.module,
        limit=args.limit,
    )
    result: Any = matches
    if args.format == "text":
        result = api_docs.format_entries_text(matches)
    _render_result(result, fmt=args.format, out_path=args.out, stem="api-docs-list")
    return 0 if matches else 1


def _api_docs_show(args: argparse.Namespace) -> int:
    docs_dir = _api_docs_resolve_dir(args)
    entries = api_docs.load_or_build_index(docs_dir)
    matches = api_docs.find_symbol(entries, args.name)
    if not matches:
        print(f"no symbol matching {args.name!r}", file=sys.stderr)
        return 1
    if len(matches) > 1:
        names = "\n".join(e["name"] for e in matches)
        print(
            f"multiple symbols match {args.name!r}; pass a fully qualified name:\n{names}",
            file=sys.stderr,
        )
        return 2
    detail = api_docs.extract_symbol_detail(docs_dir, matches[0])
    result: Any = detail.to_dict()
    if args.format == "text":
        result = api_docs.format_detail_text(detail)
    _render_result(result, fmt=args.format, out_path=args.out, stem="api-docs-show")
    return 0


def _api_docs_refresh(args: argparse.Namespace) -> int:
    docs_dir = _api_docs_resolve_dir(args)
    entries = api_docs.load_or_build_index(docs_dir, refresh=True)
    result: Any = {
        "docs_dir": str(docs_dir),
        "entries": len(entries),
    }
    if args.format == "text":
        result = f"refreshed {len(entries)} entries from {docs_dir}"
    _render_result(result, fmt=args.format, out_path=args.out, stem="api-docs-refresh")
    return 0


# =========================================================================
# Database handlers
# =========================================================================


def _database_info(args: argparse.Namespace) -> int:
    return _call(args, "database_info", {}, require_target=True, allow_implicit_target=True, stem="database-info")


def _database_read_global(args: argparse.Namespace) -> int:
    return _call(args, "database_read_global", {"key": args.key}, require_target=True, allow_implicit_target=True, stem="database-read-global")


def _database_write_global(args: argparse.Namespace) -> int:
    return _call(args, "database_write_global", {"key": args.key, "value": args.value}, require_target=True, allow_implicit_target=True, stem="database-write-global")


def _database_snapshots(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {}
    if hasattr(args, "offset") and args.offset:
        params["offset"] = args.offset
    if hasattr(args, "limit") and args.limit:
        params["limit"] = args.limit
    return _call(args, "database_snapshots", params, require_target=True, allow_implicit_target=True, stem="database-snapshots")


def _database_save_auto_snapshot(args: argparse.Namespace) -> int:
    return _call(args, "database_save_auto_snapshot", {}, require_target=True, allow_implicit_target=True, stem="database-save")


def _database_create_bndb(args: argparse.Namespace) -> int:
    return _call(args, "database_create_bndb", {"path": args.path}, require_target=True, allow_implicit_target=True, stem="database-create-bndb")


# =========================================================================
# Type extended handlers
# =========================================================================


def _type_rename(args: argparse.Namespace) -> int:
    return _call(args, "type_rename", {"old_name": args.old_name, "new_name": args.new_name}, require_target=True, allow_implicit_target=True, stem="type-rename")


def _type_undefine(args: argparse.Namespace) -> int:
    return _call(args, "type_undefine_user", {"name": args.name}, require_target=True, allow_implicit_target=True, stem="type-undefine")


def _type_parse(args: argparse.Namespace) -> int:
    return _call(args, "type_parse_string", {"type_source": args.source}, require_target=True, allow_implicit_target=True, stem="type-parse")


def _type_import(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"name": args.name}
    if hasattr(args, "library") and args.library:
        params["type_library_id"] = args.library
    op = "type_import_library_type" if args.kind == "type" else "type_import_library_object"
    return _call(args, op, params, require_target=True, allow_implicit_target=True, stem="type-import")


def _type_export(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"type_library_id": args.library, "type_source": args.source}
    if hasattr(args, "name") and args.name:
        params["name"] = args.name
    return _call(args, "type_export_to_library", params, require_target=True, allow_implicit_target=True, stem="type-export")


def _type_library_list(args: argparse.Namespace) -> int:
    return _call(args, "type_library_list", {}, require_target=True, allow_implicit_target=True, stem="type-library-list")


def _type_library_get(args: argparse.Namespace) -> int:
    return _call(args, "type_library_get", {"type_library_id": args.id}, require_target=True, allow_implicit_target=True, stem="type-library-get")


def _type_library_create(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"name": args.name}
    if hasattr(args, "path") and args.path:
        params["path"] = args.path
    if hasattr(args, "add_to_view") and args.add_to_view:
        params["add_to_view"] = True
    return _call(args, "type_library_create", params, require_target=True, allow_implicit_target=True, stem="type-library-create")


def _type_library_load(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"path": args.path}
    if hasattr(args, "no_add") and args.no_add:
        params["add_to_view"] = False
    return _call(args, "type_library_load", params, require_target=True, allow_implicit_target=True, stem="type-library-load")


def _type_archive_list(args: argparse.Namespace) -> int:
    return _call(args, "type_archive_list", {}, require_target=True, allow_implicit_target=True, stem="type-archive-list")


def _type_archive_get(args: argparse.Namespace) -> int:
    return _call(args, "type_archive_get", {"type_archive_id": args.id}, require_target=True, allow_implicit_target=True, stem="type-archive-get")


def _type_archive_create(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"path": args.path}
    if hasattr(args, "attach") and args.attach:
        params["attach"] = True
    return _call(args, "type_archive_create", params, require_target=True, allow_implicit_target=True, stem="type-archive-create")


def _type_archive_open(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"path": args.path}
    if hasattr(args, "attach") and args.attach:
        params["attach"] = True
    return _call(args, "type_archive_open", params, require_target=True, allow_implicit_target=True, stem="type-archive-open")


def _type_archive_pull(args: argparse.Namespace) -> int:
    return _call(args, "type_archive_pull", {"type_archive_id": args.id, "names": args.names}, require_target=True, allow_implicit_target=True, stem="type-archive-pull")


def _type_archive_push(args: argparse.Namespace) -> int:
    return _call(args, "type_archive_push", {"type_archive_id": args.id, "names": args.names}, require_target=True, allow_implicit_target=True, stem="type-archive-push")


# =========================================================================
# Annotation handlers
# =========================================================================


def _annotation_add_tag(args: argparse.Namespace) -> int:
    return _call(args, "annotation_add_tag", {"address": args.address, "tag_type": args.tag_type, "data": args.data}, require_target=True, allow_implicit_target=True, stem="annotation-add-tag")


def _annotation_get_tags(args: argparse.Namespace) -> int:
    return _call(args, "annotation_get_tags", {"address": args.address}, require_target=True, allow_implicit_target=True, stem="annotation-get-tags")


def _annotation_define_data_var(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"address": args.address}
    if hasattr(args, "type_name") and args.type_name:
        params["type_name"] = args.type_name
    if hasattr(args, "name") and args.name:
        params["name"] = args.name
    if hasattr(args, "width") and args.width:
        params["width"] = args.width
    return _call(args, "annotation_define_data_var", params, require_target=True, allow_implicit_target=True, stem="annotation-define-data-var")


def _annotation_undefine_data_var(args: argparse.Namespace) -> int:
    return _call(args, "annotation_undefine_data_var", {"address": args.address}, require_target=True, allow_implicit_target=True, stem="annotation-undefine-data-var")


def _annotation_define_symbol(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"address": args.address, "name": args.name}
    if hasattr(args, "symbol_type") and args.symbol_type:
        params["symbol_type"] = args.symbol_type
    return _call(args, "annotation_define_symbol", params, require_target=True, allow_implicit_target=True, stem="annotation-define-symbol")


def _annotation_undefine_symbol(args: argparse.Namespace) -> int:
    return _call(args, "annotation_undefine_symbol", {"address": args.address}, require_target=True, allow_implicit_target=True, stem="annotation-undefine-symbol")


def _annotation_rename_data_var(args: argparse.Namespace) -> int:
    return _call(args, "annotation_rename_data_var", {"address": args.address, "new_name": args.new_name}, require_target=True, allow_implicit_target=True, stem="annotation-rename-data-var")


# =========================================================================
# Undo handlers
# =========================================================================


def _undo_begin(args: argparse.Namespace) -> int:
    return _call(args, "undo_begin", {}, require_target=True, allow_implicit_target=True, stem="undo-begin")


def _undo_commit(args: argparse.Namespace) -> int:
    return _call(args, "undo_commit", {}, require_target=True, allow_implicit_target=True, stem="undo-commit")


def _undo_revert(args: argparse.Namespace) -> int:
    return _call(args, "undo_revert", {}, require_target=True, allow_implicit_target=True, stem="undo-revert")


def _undo_undo(args: argparse.Namespace) -> int:
    return _call(args, "undo_undo", {}, require_target=True, allow_implicit_target=True, stem="undo-undo")


def _undo_redo(args: argparse.Namespace) -> int:
    return _call(args, "undo_redo", {}, require_target=True, allow_implicit_target=True, stem="undo-redo")


# =========================================================================
# UIDF handlers
# =========================================================================


def _uidf_set(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {
        "function_start": args.function_start,
        "address": args.address,
        "var_name": args.var_name,
        "value": args.value,
    }
    if hasattr(args, "def_site_address") and args.def_site_address:
        params["def_site_address"] = args.def_site_address
    if hasattr(args, "state") and args.state:
        params["state"] = args.state
    return _call(args, "uidf_set_user_var_value", params, require_target=True, allow_implicit_target=True, stem="uidf-set")


def _uidf_clear(args: argparse.Namespace) -> int:
    return _call(args, "uidf_clear_user_var_value", {"function_start": args.function_start, "address": args.address, "var_name": args.var_name}, require_target=True, allow_implicit_target=True, stem="uidf-clear")


def _uidf_list(args: argparse.Namespace) -> int:
    return _call(args, "uidf_list_user_var_values", {"function_start": args.function_start}, require_target=True, allow_implicit_target=True, stem="uidf-list")


def _uidf_parse(args: argparse.Namespace) -> int:
    return _call(args, "uidf_parse_possible_value", {"value": args.value, "state": args.state}, require_target=True, allow_implicit_target=True, stem="uidf-parse")


# =========================================================================
# Loader handlers
# =========================================================================


def _loader_settings_get(args: argparse.Namespace) -> int:
    return _call(args, "loader_load_settings_get", {"type_name": args.type_name}, require_target=True, allow_implicit_target=True, stem="loader-settings-get")


def _loader_settings_set(args: argparse.Namespace) -> int:
    return _call(args, "loader_load_settings_set", {"type_name": args.type_name, "key": args.key, "value": args.value}, require_target=True, allow_implicit_target=True, stem="loader-settings-set")


def _loader_settings_types(args: argparse.Namespace) -> int:
    return _call(args, "loader_load_settings_types", {}, require_target=True, allow_implicit_target=True, stem="loader-settings-types")


def _loader_rebase(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"address": args.address}
    if hasattr(args, "force") and args.force:
        params["force"] = True
    return _call(args, "loader_rebase", params, require_target=True, allow_implicit_target=True, stem="loader-rebase")


# =========================================================================
# External library handlers
# =========================================================================


def _external_library_add(args: argparse.Namespace) -> int:
    return _call(args, "external_library_add", {"name": args.name}, require_target=True, allow_implicit_target=True, stem="external-library-add")


def _external_library_list(args: argparse.Namespace) -> int:
    return _call(args, "external_library_list", {}, require_target=True, allow_implicit_target=True, stem="external-library-list")


def _external_library_remove(args: argparse.Namespace) -> int:
    return _call(args, "external_library_remove", {"name": args.name}, require_target=True, allow_implicit_target=True, stem="external-library-remove")


def _external_location_add(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"source_address": args.source_address}
    if hasattr(args, "library_name") and args.library_name:
        params["library_name"] = args.library_name
    if hasattr(args, "target_symbol") and args.target_symbol:
        params["target_symbol"] = args.target_symbol
    if hasattr(args, "target_address") and args.target_address:
        params["target_address"] = args.target_address
    return _call(args, "external_location_add", params, require_target=True, allow_implicit_target=True, stem="external-location-add")


def _external_location_get(args: argparse.Namespace) -> int:
    return _call(args, "external_location_get", {"source_address": args.source_address}, require_target=True, allow_implicit_target=True, stem="external-location-get")


def _external_location_remove(args: argparse.Namespace) -> int:
    return _call(args, "external_location_remove", {"source_address": args.source_address}, require_target=True, allow_implicit_target=True, stem="external-location-remove")


# =========================================================================
# Analysis handlers
# =========================================================================


def _analysis_status(args: argparse.Namespace) -> int:
    return _call(args, "analysis_status", {}, require_target=True, allow_implicit_target=True, stem="analysis-status")


def _analysis_progress(args: argparse.Namespace) -> int:
    return _call(args, "analysis_progress", {}, require_target=True, allow_implicit_target=True, stem="analysis-progress")


def _analysis_abort(args: argparse.Namespace) -> int:
    return _call(args, "analysis_abort", {}, require_target=True, allow_implicit_target=True, stem="analysis-abort")


def _analysis_set_hold(args: argparse.Namespace) -> int:
    return _call(args, "analysis_set_hold", {"hold": args.hold}, require_target=True, allow_implicit_target=True, stem="analysis-hold")


def _analysis_update(args: argparse.Namespace) -> int:
    return _call(args, "analysis_update", {}, require_target=True, allow_implicit_target=True, stem="analysis-update")


def _analysis_update_and_wait(args: argparse.Namespace) -> int:
    return _call(args, "analysis_update_and_wait", {}, require_target=True, allow_implicit_target=True, stem="analysis-update-wait")


# =========================================================================
# Metadata handlers
# =========================================================================


def _metadata_query(args: argparse.Namespace) -> int:
    return _call(args, "metadata_query", {"key": args.key}, require_target=True, allow_implicit_target=True, stem="metadata-query")


def _metadata_store(args: argparse.Namespace) -> int:
    return _call(args, "metadata_store", {"key": args.key, "value": args.value}, require_target=True, allow_implicit_target=True, stem="metadata-store")


def _metadata_remove(args: argparse.Namespace) -> int:
    return _call(args, "metadata_remove", {"key": args.key}, require_target=True, allow_implicit_target=True, stem="metadata-remove")


# =========================================================================
# Data handlers
# =========================================================================


def _data_typed_at(args: argparse.Namespace) -> int:
    return _call(args, "data_typed_at", {"address": args.address}, require_target=True, allow_implicit_target=True, stem="data-typed-at")


# =========================================================================
# Xref extended handlers
# =========================================================================


def _xref_code_refs_from(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"address": args.address}
    if hasattr(args, "length") and args.length:
        params["length"] = args.length
    return _call(args, "xref_code_refs_from", params, require_target=True, allow_implicit_target=True, stem="xref-code-refs-from")


def _xref_code_refs_to(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"address": args.address}
    if hasattr(args, "limit") and args.limit:
        params["limit"] = args.limit
    return _call(args, "xref_code_refs_to", params, require_target=True, allow_implicit_target=True, stem="xref-code-refs-to")


def _xref_data_refs_from(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"address": args.address}
    if hasattr(args, "length") and args.length:
        params["length"] = args.length
    return _call(args, "xref_data_refs_from", params, require_target=True, allow_implicit_target=True, stem="xref-data-refs-from")


def _xref_data_refs_to(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"address": args.address}
    if hasattr(args, "limit") and args.limit:
        params["limit"] = args.limit
    return _call(args, "xref_data_refs_to", params, require_target=True, allow_implicit_target=True, stem="xref-data-refs-to")


# =========================================================================
# IL extended handlers
# =========================================================================


def _il_address_to_index(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"function_start": args.function_start, "address": args.address}
    if hasattr(args, "level") and args.level:
        params["level"] = args.level
    return _call(args, "il_address_to_index", params, require_target=True, allow_implicit_target=True, stem="il-addr-to-index")


def _il_index_to_address(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"function_start": args.function_start, "index": args.index}
    if hasattr(args, "level") and args.level:
        params["level"] = args.level
    return _call(args, "il_index_to_address", params, require_target=True, allow_implicit_target=True, stem="il-index-to-addr")


def _il_instruction_by_addr(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"function_start": args.function_start, "address": args.address}
    if hasattr(args, "level") and args.level:
        params["level"] = args.level
    return _call(args, "il_instruction_by_addr", params, require_target=True, allow_implicit_target=True, stem="il-instr-at")


# =========================================================================
# Section/Segment user handlers
# =========================================================================


def _section_add_user(args: argparse.Namespace) -> int:
    return _call(args, "section_add_user", {"name": args.name, "start": args.start, "length": args.length}, require_target=True, allow_implicit_target=True, stem="section-add")


def _section_remove_user(args: argparse.Namespace) -> int:
    return _call(args, "section_remove_user", {"name": args.name}, require_target=True, allow_implicit_target=True, stem="section-remove")


def _segment_add_user(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"start": args.start, "length": args.length}
    if hasattr(args, "data_offset") and args.data_offset is not None:
        params["data_offset"] = args.data_offset
    if hasattr(args, "data_length") and args.data_length is not None:
        params["data_length"] = args.data_length
    if hasattr(args, "flags") and args.flags is not None:
        params["flags"] = args.flags
    return _call(args, "segment_add_user", params, require_target=True, allow_implicit_target=True, stem="segment-add")


def _segment_remove_user(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"start": args.start}
    if hasattr(args, "length") and args.length:
        params["length"] = args.length
    return _call(args, "segment_remove_user", params, require_target=True, allow_implicit_target=True, stem="segment-remove")


# =========================================================================
# Debug handlers
# =========================================================================


def _debug_parsers(args: argparse.Namespace) -> int:
    return _call(args, "debug_parsers", {}, require_target=True, allow_implicit_target=True, stem="debug-parsers")


def _debug_parse_and_apply(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {}
    if hasattr(args, "parser_name") and args.parser_name:
        params["parser_name"] = args.parser_name
    if hasattr(args, "debug_path") and args.debug_path:
        params["debug_path"] = args.debug_path
    return _call(args, "debug_parse_and_apply", params, require_target=True, allow_implicit_target=True, stem="debug-apply")


# =========================================================================
# Plugin handlers
# =========================================================================


def _plugin_valid_commands(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {}
    if hasattr(args, "address") and args.address:
        params["address"] = args.address
    return _call(args, "plugin_valid_commands", params, require_target=True, allow_implicit_target=True, stem="plugin-commands")


def _plugin_execute(args: argparse.Namespace) -> int:
    params: dict[str, Any] = {"name": args.name}
    if hasattr(args, "address") and args.address:
        params["address"] = args.address
    return _call(args, "plugin_execute", params, require_target=True, allow_implicit_target=True, stem="plugin-execute")


# =========================================================================
# Binary extended handlers
# =========================================================================


def _binary_basic_blocks_at(args: argparse.Namespace) -> int:
    return _call(args, "binary_basic_blocks_at", {"address": args.address}, require_target=True, allow_implicit_target=True, stem="binary-bbs-at")


def build_parser() -> argparse.ArgumentParser:
    parser = BnArgumentParser(prog="bn", description="Agent-friendly Binary Ninja CLI")
    parser.set_defaults(handler=None)

    subparsers = parser.add_subparsers(dest="command")

    setup = subparsers.add_parser(
        "setup",
        help="One-command setup: install the BN plugin and agent skill into all clients",
    )
    setup.add_argument("--force", action="store_true", help="Overwrite existing installations")
    _common_io_options(setup, default_format="json")
    setup.set_defaults(handler=_setup)

    doctor = subparsers.add_parser("doctor", help="Validate bridge discovery and installation")
    _common_io_options(doctor)
    doctor.set_defaults(handler=_doctor)

    plugin = subparsers.add_parser("plugin", help="Install the Binary Ninja companion plugin")
    plugin_sub = plugin.add_subparsers(dest="plugin_command")
    plugin_install = plugin_sub.add_parser("install", help="Install the GUI plugin")
    plugin_install.add_argument("--dest", type=Path, help="Custom install destination")
    plugin_install.add_argument("--mode", choices=("symlink", "copy"), default="symlink")
    plugin_install.add_argument("--force", action="store_true")
    _common_io_options(plugin_install, default_format="json")
    plugin_install.set_defaults(handler=_plugin_install)

    skill = subparsers.add_parser("skill", help="Install the bundled skill into Codex and/or Claude Code")
    skill_sub = skill.add_subparsers(dest="skill_command")
    skill_install = skill_sub.add_parser("install", help="Install the bundled skill")
    skill_install.add_argument("--dest", type=Path, help="Custom install destination (requires a single --client)")
    skill_install.add_argument("--mode", choices=("symlink", "copy"), default="symlink")
    skill_install.add_argument("--force", action="store_true")
    skill_install.add_argument(
        "--client",
        choices=(*SKILL_CLIENTS, "both"),
        default="both",
        help="Which agent harness to install the skill into",
    )
    _common_io_options(skill_install, default_format="json")
    skill_install.set_defaults(handler=_skill_install)

    daemon = subparsers.add_parser(
        "daemon",
        help="Manage bn bridge daemons (GUI bridge and headless daemon)",
    )
    daemon_sub = daemon.add_subparsers(dest="daemon_command")

    daemon_start = daemon_sub.add_parser(
        "start",
        help="Start a headless bridge daemon (GUI bridge is auto-started by Binary Ninja itself)",
    )
    daemon_start.add_argument(
        "--mode",
        choices=DAEMON_MODES,
        default="headless",
        help="Daemon mode to start (default: headless)",
    )
    daemon_start.add_argument(
        "--foreground",
        action="store_true",
        help="Block on the daemon process (for Docker PID 1 / systemd usage). "
        "Without this flag, the CLI spawns a detached background process and returns.",
    )
    daemon_start.add_argument(
        "--log",
        type=Path,
        help="Log file for background daemon stdout/stderr (default: cache_home()/logs/daemon-<mode>.log)",
    )
    _common_io_options(daemon_start, default_format="json")
    daemon_start.set_defaults(handler=_daemon_start)

    daemon_stop = daemon_sub.add_parser("stop", help="Stop a running daemon")
    daemon_stop.add_argument(
        "--mode",
        choices=DAEMON_MODES,
        help="Mode of the daemon to stop; defaults to the sticky mode or the only running daemon",
    )
    _common_io_options(daemon_stop, default_format="json")
    daemon_stop.set_defaults(handler=_daemon_stop)

    daemon_status = daemon_sub.add_parser(
        "status",
        help="Show one daemon's pid, socket, and target count",
    )
    daemon_status.add_argument("--mode", choices=DAEMON_MODES)
    _common_io_options(daemon_status)
    daemon_status.set_defaults(handler=_daemon_status)

    daemon_list = daemon_sub.add_parser(
        "list",
        help="List all running daemons and which one is sticky",
    )
    _common_io_options(daemon_list)
    daemon_list.set_defaults(handler=_daemon_list)

    daemon_use = daemon_sub.add_parser(
        "use",
        help="Pin the current daemon mode; subsequent commands route to it",
    )
    daemon_use.add_argument(
        "mode_value",
        nargs="?",
        metavar="MODE",
        help=f"Daemon mode to make sticky ({'/'.join(DAEMON_MODES)}); omit when using --clear",
    )
    daemon_use.add_argument(
        "--clear",
        action="store_true",
        help="Remove the sticky daemon selection",
    )
    _common_io_options(daemon_use, default_format="json")
    daemon_use.set_defaults(handler=_daemon_use)

    target = subparsers.add_parser("target", help="Inspect Binary Ninja targets")
    target_sub = target.add_subparsers(dest="target_command")
    target_list = target_sub.add_parser("list", help="List open BinaryView targets")
    _common_io_options(target_list)
    target_list.set_defaults(handler=_target_list)
    target_info = target_sub.add_parser("info", help="Show one target")
    _common_io_options(target_info)
    _target_option(target_info, required=False)
    target_info.set_defaults(handler=_target_info)

    target_load = target_sub.add_parser(
        "load",
        help="Load a binary into the headless daemon",
    )
    target_load.add_argument("path", help="Filesystem path to a binary or .bndb")
    analysis_group = target_load.add_mutually_exclusive_group()
    analysis_group.add_argument(
        "--async",
        dest="async_load",
        action="store_true",
        help="Kick off analysis in the background and return immediately (GUI-style); "
        "subsequent commands see analysis-in-progress state. Poll `bn target status` for completion.",
    )
    analysis_group.add_argument(
        "--no-update-analysis",
        dest="update_analysis",
        action="store_false",
        default=True,
        help="Load the BinaryView without starting analysis at all. Run `bn refresh` later when you need it.",
    )
    target_load.add_argument(
        "--option",
        dest="options",
        action="append",
        metavar="KEY=VALUE",
        help=(
            "Binary Ninja load option (repeatable). Value is parsed as JSON when possible, "
            "otherwise passed as a string. Examples: "
            "--option loader.imageBase=0 --option analysis.mode=full "
            "--option analysis.linearSweep.autorun=true"
        ),
    )
    target_load.add_argument(
        "--options-json",
        dest="options_json",
        help="Raw JSON object of load options; merged with --option entries (--option wins on conflict)",
    )
    _common_io_options(target_load, default_format="json")
    target_load.set_defaults(handler=_target_load)

    target_close = target_sub.add_parser(
        "close",
        help="Close a loaded target (headless daemon only)",
    )
    _common_io_options(target_close, default_format="json")
    _target_option(target_close, required=False)
    target_close.set_defaults(handler=_target_close)

    target_save = target_sub.add_parser(
        "save",
        help="Save the target's analysis database (.bndb)",
    )
    target_save.add_argument(
        "--path",
        type=Path,
        help="Write a new .bndb at this path (required the first time)",
    )
    _common_io_options(target_save, default_format="json")
    _target_option(target_save, required=False)
    target_save.set_defaults(handler=_target_save)

    target_status = target_sub.add_parser(
        "status",
        help="Show analysis progress for a target (use after `bn target load --async`)",
    )
    _common_io_options(target_status)
    _target_option(target_status, required=False)
    target_status.set_defaults(handler=_target_status)

    target_loads = target_sub.add_parser(
        "loads",
        help="List recent `--async` load attempts (status + errors)",
    )
    _common_io_options(target_loads)
    target_loads.set_defaults(handler=_target_loads)

    refresh = subparsers.add_parser("refresh", help="Refresh analysis for the selected target")
    _common_io_options(refresh)
    _target_option(refresh, required=False)
    refresh.set_defaults(handler=_refresh)

    workflow = subparsers.add_parser("workflow", help="Inspect Binary Ninja analysis workflows")
    workflow_sub = workflow.add_subparsers(dest="workflow_command")

    wf_list = workflow_sub.add_parser("list", help="List known workflows")
    _common_io_options(wf_list)
    _target_option(wf_list, required=False)
    wf_list.add_argument(
        "--registered-only",
        action="store_true",
        help="Only show workflows that have been registered",
    )
    wf_list.set_defaults(handler=_workflow_list)

    wf_show = workflow_sub.add_parser("show", help="Show a workflow's activity DAG")
    _common_io_options(wf_show)
    _target_option(wf_show, required=False)
    wf_show.add_argument("name", help="Workflow name (e.g. core.function.metaAnalysis)")
    wf_show.add_argument(
        "--activity",
        help="Scope roots and subactivities to this activity",
    )
    wf_show.add_argument(
        "--depth",
        choices=("all", "immediate"),
        default="all",
        help="Whether to recurse into subactivities (default: all)",
    )
    wf_show.add_argument(
        "--with-config",
        action="store_true",
        help="Include the JSON adjacency-list configuration",
    )
    wf_show.set_defaults(handler=_workflow_show)

    wf_active = workflow_sub.add_parser(
        "active",
        help="Show the workflow currently bound to the BinaryView or function",
    )
    _common_io_options(wf_active)
    _target_option(wf_active, required=False)
    wf_active.add_argument(
        "--function",
        help="Inspect the function-level workflow (accepts the same identifier shape as `bn function info`)",
    )
    wf_active.set_defaults(handler=_workflow_active)

    wf_override = workflow_sub.add_parser(
        "override",
        help="Toggle activity overrides on the WorkflowMachine",
    )
    wf_override_sub = wf_override.add_subparsers(dest="override_command")

    wf_override_set = wf_override_sub.add_parser(
        "set",
        help="Enable or disable a specific activity",
    )
    _common_io_options(wf_override_set, default_format="json")
    _target_option(wf_override_set, required=False)
    wf_override_set.add_argument("--preview", action="store_true")
    wf_override_set.add_argument("--function")
    enable_group = wf_override_set.add_mutually_exclusive_group(required=True)
    enable_group.add_argument(
        "--enable",
        dest="enable",
        action="store_true",
        default=None,
        help="Force the activity to run",
    )
    enable_group.add_argument(
        "--disable",
        dest="enable",
        action="store_false",
        help="Skip the activity",
    )
    wf_override_set.add_argument("activity")
    wf_override_set.set_defaults(handler=_workflow_override_set)

    wf_override_clear = wf_override_sub.add_parser(
        "clear",
        help="Remove an existing activity override",
    )
    _common_io_options(wf_override_clear, default_format="json")
    _target_option(wf_override_clear, required=False)
    wf_override_clear.add_argument("--preview", action="store_true")
    wf_override_clear.add_argument("--function")
    wf_override_clear.add_argument("activity")
    wf_override_clear.set_defaults(handler=_workflow_override_clear)

    wf_machine = workflow_sub.add_parser("machine", help="Inspect WorkflowMachine state")
    wf_machine_sub = wf_machine.add_subparsers(dest="machine_command")

    wf_machine_status = wf_machine_sub.add_parser("status", help="Current machine status")
    _common_io_options(wf_machine_status)
    _target_option(wf_machine_status, required=False)
    wf_machine_status.add_argument("--function")
    wf_machine_status.set_defaults(handler=_workflow_machine_status)

    wf_machine_dump = wf_machine_sub.add_parser("dump", help="Full machine state dump")
    _common_io_options(wf_machine_dump, default_format="json")
    _target_option(wf_machine_dump, required=False)
    wf_machine_dump.add_argument("--function")
    wf_machine_dump.set_defaults(handler=_workflow_machine_dump)

    wf_machine_overrides = wf_machine_sub.add_parser(
        "overrides",
        help="Active activity overrides",
    )
    _common_io_options(wf_machine_overrides)
    _target_option(wf_machine_overrides, required=False)
    wf_machine_overrides.add_argument("--function")
    wf_machine_overrides.add_argument("--activity")
    wf_machine_overrides.set_defaults(handler=_workflow_machine_overrides)

    for verb, helper, op_name in (
        ("enable", "Enable the WorkflowMachine", "workflow_machine_enable"),
        ("disable", "Disable the WorkflowMachine", "workflow_machine_disable"),
        ("step", "Advance the machine by one activity", "workflow_machine_step"),
        ("halt", "Halt the running machine", "workflow_machine_halt"),
        ("reset", "Reset the machine to its initial state", "workflow_machine_reset"),
    ):
        p = wf_machine_sub.add_parser(verb, help=helper)
        _common_io_options(p, default_format="json")
        _target_option(p, required=False)
        p.add_argument("--function")
        p.set_defaults(handler=_workflow_machine_command_handler(op_name))

    for verb, helper, op_name in (
        ("run", "Run the machine until the next breakpoint", "workflow_machine_run"),
        ("resume", "Resume after a halt or breakpoint", "workflow_machine_resume"),
    ):
        p = wf_machine_sub.add_parser(verb, help=helper)
        _common_io_options(p, default_format="json")
        _target_option(p, required=False)
        p.add_argument("--function")
        p.add_argument(
            "--no-advanced",
            dest="advanced",
            action="store_false",
            default=True,
            help="Disable advanced analysis mode",
        )
        p.add_argument("--incremental", action="store_true")
        p.set_defaults(handler=_workflow_machine_command_handler(op_name, options=True))

    wf_machine_bp = wf_machine_sub.add_parser(
        "breakpoint",
        help="Manage activity breakpoints",
    )
    wf_machine_bp_sub = wf_machine_bp.add_subparsers(dest="breakpoint_command")

    wf_machine_bp_list = wf_machine_bp_sub.add_parser("list", help="List active breakpoints")
    _common_io_options(wf_machine_bp_list)
    _target_option(wf_machine_bp_list, required=False)
    wf_machine_bp_list.add_argument("--function")
    wf_machine_bp_list.set_defaults(
        handler=_workflow_machine_command_handler("workflow_machine_breakpoint_list")
    )

    for verb, helper, op_name in (
        ("set", "Set breakpoints on activities", "workflow_machine_breakpoint_set"),
        ("clear", "Remove breakpoints from activities", "workflow_machine_breakpoint_clear"),
    ):
        p = wf_machine_bp_sub.add_parser(verb, help=helper)
        _common_io_options(p, default_format="json")
        _target_option(p, required=False)
        p.add_argument("--function")
        p.add_argument("activities", nargs="+", help="One or more activity names")
        p.set_defaults(
            handler=_workflow_machine_command_handler(op_name, activities=True)
        )

    function = subparsers.add_parser("function", help="Function discovery helpers")
    function_sub = function.add_subparsers(dest="function_command")
    function_list = function_sub.add_parser("list", help="List functions")
    _common_io_options(function_list)
    _target_option(function_list, required=False)
    _add_function_address_args(function_list)
    function_list.set_defaults(handler=_function_list)
    function_search = function_sub.add_parser("search", help="Search functions by substring or regex")
    _common_io_options(function_search)
    _target_option(function_search, required=False)
    _add_function_address_args(function_search)
    function_search.add_argument(
        "--regex",
        action="store_true",
        help="Interpret query as a case-insensitive regular expression",
    )
    function_search.add_argument("query")
    function_search.set_defaults(handler=_function_search)
    function_info = function_sub.add_parser("info", help="Show function prototype and variables")
    _common_io_options(function_info)
    _target_option(function_info, required=False)
    function_info.add_argument("identifier")
    function_info.set_defaults(handler=_function_info)
    function_bb = function_sub.add_parser("basic-blocks", help="List basic blocks for a function")
    _common_io_options(function_bb)
    _target_option(function_bb, required=False)
    function_bb.add_argument("identifier")
    function_bb.set_defaults(handler=_function_basic_blocks)
    function_callers_p = function_sub.add_parser("callers", help="List callers of a function")
    _common_io_options(function_callers_p)
    _target_option(function_callers_p, required=False)
    function_callers_p.add_argument("identifier")
    function_callers_p.set_defaults(handler=_function_callers)
    function_callees_p = function_sub.add_parser("callees", help="List callees from a function")
    _common_io_options(function_callees_p)
    _target_option(function_callees_p, required=False)
    function_callees_p.add_argument("identifier")
    function_callees_p.set_defaults(handler=_function_callees)
    function_force = function_sub.add_parser("force-analysis", help="Force re-analysis of a function")
    _common_io_options(function_force, default_format="json")
    _target_option(function_force, required=False)
    function_force.add_argument("identifier")
    function_force.set_defaults(handler=_function_force_analysis)

    decompile = subparsers.add_parser("decompile", help="Render HLIL-style decompile text for a function")
    _common_io_options(decompile)
    _target_option(decompile, required=False)
    decompile.add_argument("identifier")
    decompile.set_defaults(handler=_decompile)

    il = subparsers.add_parser("il", help="Dump IL for a function")
    _common_io_options(il)
    _target_option(il, required=False)
    il.add_argument("identifier")
    il.add_argument("--view", choices=("hlil", "mlil", "llil"), default="hlil")
    il.add_argument("--ssa", action="store_true")
    il.set_defaults(handler=_il)

    disasm = subparsers.add_parser("disasm", help="Disassemble a function")
    _common_io_options(disasm)
    _target_option(disasm, required=False)
    disasm.add_argument("identifier")
    disasm.set_defaults(handler=_disasm)

    disasm_linear = subparsers.add_parser("disasm-linear", help="Disassemble linearly from an address")
    _common_io_options(disasm_linear)
    _target_option(disasm_linear, required=False)
    disasm_linear.add_argument("address")
    disasm_linear.add_argument("--count", type=int, default=50, help="Number of instructions")
    disasm_linear.set_defaults(handler=_disasm_linear)

    disasm_range = subparsers.add_parser("disasm-range", help="Disassemble an address range")
    _common_io_options(disasm_range)
    _target_option(disasm_range, required=False)
    disasm_range.add_argument("start")
    disasm_range.add_argument("end")
    disasm_range.set_defaults(handler=_disasm_range)

    xrefs = subparsers.add_parser("xrefs", help="List xrefs to an address or function, or `field <Struct.field>`")
    _common_io_options(xrefs)
    _target_option(xrefs, required=False)
    xrefs.add_argument("identifier", nargs="?")
    xrefs.add_argument("extra", nargs="*")
    xrefs.set_defaults(handler=_xrefs)

    callsites = subparsers.add_parser("callsites", help="Find direct native callsites and exact caller_static addresses")
    _common_io_options(callsites)
    _target_option(callsites, required=False)
    callsites.add_argument("callee")
    scope = callsites.add_mutually_exclusive_group(required=True)
    scope.add_argument("--within", help="Containing function to search for callsites")
    scope.add_argument("--within-file", type=Path, help="Text file with one containing-function identifier per line")
    callsites.add_argument(
        "--context",
        type=int,
        default=3,
        help="Number of previous and next instructions to include around each callsite",
    )
    callsites.add_argument(
        "--caller-static",
        action="store_true",
        help="Prefer caller_static-first text output for return-address mapping workflows",
    )
    callsites.set_defaults(handler=_callsites)

    types = subparsers.add_parser("types", help="List or search types")
    _common_io_options(types)
    _target_option(types, required=False)
    _add_paged_args(types)
    types.add_argument("--query")
    types.set_defaults(handler=_types)
    types_sub = types.add_subparsers(dest="types_command")
    types_show = types_sub.add_parser("show", help="Show one type")
    _common_io_options(types_show)
    _target_option(types_show, required=False)
    types_show.add_argument("type_name")
    types_show.set_defaults(handler=_types_show)
    types_declare = types_sub.add_parser("declare", help="Import C declarations as user types")
    _common_io_options(types_declare, default_format="json")
    _target_option(types_declare, required=False)
    types_declare.add_argument("--preview", action="store_true")
    types_declare.add_argument("--file", type=Path, help="Read declarations from a file")
    types_declare.add_argument("--stdin", action="store_true", help="Read declarations from stdin")
    types_declare.add_argument("declaration", nargs="?")
    types_declare.set_defaults(handler=_types_declare)

    strings = subparsers.add_parser("strings", help="List or search strings")
    _common_io_options(strings)
    _target_option(strings, required=False)
    _add_paged_args(strings)
    strings.add_argument("--query")
    strings.set_defaults(handler=_strings)

    imports = subparsers.add_parser("imports", help="List imports")
    _common_io_options(imports)
    _target_option(imports, required=False)
    imports.set_defaults(handler=_imports)

    bundle = subparsers.add_parser("bundle", help="Export reusable bundles")
    bundle_sub = bundle.add_subparsers(dest="bundle_command")
    bundle_function = bundle_sub.add_parser("function", help="Export a function bundle")
    _common_io_options(bundle_function, default_format="json")
    _target_option(bundle_function, required=False)
    bundle_function.add_argument("identifier")
    bundle_function.set_defaults(handler=_bundle_function)

    py = subparsers.add_parser("py", help="Execute Python inside Binary Ninja")
    py_sub = py.add_subparsers(dest="py_command")
    py_exec = py_sub.add_parser("exec", help="Execute a Python snippet")
    _common_io_options(py_exec)
    _target_option(py_exec, required=False)
    source = py_exec.add_mutually_exclusive_group(required=True)
    source.add_argument("--script", type=Path, help="Read Python code from a file")
    source.add_argument("--code", help="Inline Python code")
    source.add_argument("--stdin", action="store_true")
    py_exec.set_defaults(handler=_py_exec)

    symbol = subparsers.add_parser("symbol", help="Rename functions or data")
    symbol_sub = symbol.add_subparsers(dest="symbol_command")
    symbol_rename = symbol_sub.add_parser("rename", help="Rename a symbol")
    _common_io_options(symbol_rename, default_format="json")
    _target_option(symbol_rename, required=False)
    symbol_rename.add_argument("--kind", choices=("auto", "function", "data"), default="auto")
    symbol_rename.add_argument("--preview", action="store_true")
    symbol_rename.add_argument("identifier")
    symbol_rename.add_argument("new_name")
    symbol_rename.set_defaults(handler=_symbol_rename)

    comment = subparsers.add_parser("comment", help="Set or delete comments")
    comment_sub = comment.add_subparsers(dest="comment_command")
    comment_get = comment_sub.add_parser("get", help="Get a comment")
    _common_io_options(comment_get)
    _target_option(comment_get, required=False)
    comment_get.add_argument("--address")
    comment_get.add_argument("--function")
    comment_get.set_defaults(handler=_comment_get)
    comment_set = comment_sub.add_parser("set", help="Set a comment")
    _common_io_options(comment_set, default_format="json")
    _target_option(comment_set, required=False)
    comment_set.add_argument("--preview", action="store_true")
    comment_set.add_argument("--address")
    comment_set.add_argument("--function")
    comment_set.add_argument("comment")
    comment_set.set_defaults(handler=_comment_set)
    comment_delete = comment_sub.add_parser("delete", help="Delete a comment")
    _common_io_options(comment_delete, default_format="json")
    _target_option(comment_delete, required=False)
    comment_delete.add_argument("--preview", action="store_true")
    comment_delete.add_argument("--address")
    comment_delete.add_argument("--function")
    comment_delete.set_defaults(handler=_comment_delete)

    proto = subparsers.add_parser("proto", help="Inspect or set a user prototype")
    proto_sub = proto.add_subparsers(dest="proto_command")
    proto_get = proto_sub.add_parser("get", help="Show the current prototype")
    _common_io_options(proto_get)
    _target_option(proto_get, required=False)
    proto_get.add_argument("identifier")
    proto_get.set_defaults(handler=_proto_get)
    proto_set = proto_sub.add_parser("set", help="Set a prototype")
    _common_io_options(proto_set, default_format="json")
    _target_option(proto_set, required=False)
    proto_set.add_argument("--preview", action="store_true")
    proto_set.add_argument("identifier")
    proto_set.add_argument("prototype")
    proto_set.set_defaults(handler=_proto_set)

    local = subparsers.add_parser("local", help="Inspect, rename, or retype locals")
    local_sub = local.add_subparsers(dest="local_command")
    local_list = local_sub.add_parser("list", help="List locals with stable IDs")
    _common_io_options(local_list)
    _target_option(local_list, required=False)
    local_list.add_argument("function")
    local_list.set_defaults(handler=_local_list)
    local_rename = local_sub.add_parser("rename", help="Rename a local")
    _common_io_options(local_rename, default_format="json")
    _target_option(local_rename, required=False)
    local_rename.add_argument("--preview", action="store_true")
    local_rename.add_argument("function")
    local_rename.add_argument("variable", help="Stable local_id or legacy variable name")
    local_rename.add_argument("new_name")
    local_rename.set_defaults(handler=_local_rename)
    local_retype = local_sub.add_parser("retype", help="Retype a local")
    _common_io_options(local_retype, default_format="json")
    _target_option(local_retype, required=False)
    local_retype.add_argument("--preview", action="store_true")
    local_retype.add_argument("function")
    local_retype.add_argument("variable", help="Stable local_id or legacy variable name")
    local_retype.add_argument("new_type")
    local_retype.set_defaults(handler=_local_retype)

    struct = subparsers.add_parser("struct", help="Field-first structure editing")
    struct_sub = struct.add_subparsers(dest="struct_command")
    struct_show = struct_sub.add_parser("show", help="Show one struct layout")
    _common_io_options(struct_show)
    _target_option(struct_show, required=False)
    struct_show.add_argument("struct_name")
    struct_show.set_defaults(handler=_struct_show)
    field = struct_sub.add_parser("field", help="Operate on struct fields")
    field_sub = field.add_subparsers(dest="struct_field_command")
    field_set = field_sub.add_parser("set", help="Set or replace a field")
    _common_io_options(field_set, default_format="json")
    _target_option(field_set, required=False)
    field_set.add_argument("--preview", action="store_true")
    field_set.add_argument("--no-overwrite", action="store_true")
    field_set.add_argument("struct_name")
    field_set.add_argument("offset")
    field_set.add_argument("field_name")
    field_set.add_argument("field_type")
    field_set.set_defaults(handler=_struct_field_set)
    field_rename = field_sub.add_parser("rename", help="Rename a field")
    _common_io_options(field_rename, default_format="json")
    _target_option(field_rename, required=False)
    field_rename.add_argument("--preview", action="store_true")
    field_rename.add_argument("struct_name")
    field_rename.add_argument("old_name")
    field_rename.add_argument("new_name")
    field_rename.set_defaults(handler=_struct_field_rename)
    field_delete = field_sub.add_parser("delete", help="Delete a field")
    _common_io_options(field_delete, default_format="json")
    _target_option(field_delete, required=False)
    field_delete.add_argument("--preview", action="store_true")
    field_delete.add_argument("struct_name")
    field_delete.add_argument("field_name")
    field_delete.set_defaults(handler=_struct_field_delete)
    batch = subparsers.add_parser("batch", help="Apply a batch manifest")
    batch_sub = batch.add_subparsers(dest="batch_command")
    batch_apply = batch_sub.add_parser("apply", help="Apply a JSON manifest")
    _common_io_options(batch_apply, default_format="json")
    batch_apply.add_argument("--preview", action="store_true")
    batch_apply.add_argument("manifest", type=Path)
    batch_apply.set_defaults(handler=_batch_apply)

    # --- patch ---
    patch = subparsers.add_parser("patch", help="Binary patching operations")
    patch_sub = patch.add_subparsers(dest="patch_command")
    patch_status_p = patch_sub.add_parser("status", help="Show current patch status")
    _common_io_options(patch_status_p)
    _target_option(patch_status_p, required=False)
    patch_status_p.set_defaults(handler=_patch_status)
    patch_assemble_p = patch_sub.add_parser("assemble", help="Assemble and patch at address")
    _common_io_options(patch_assemble_p, default_format="json")
    _target_option(patch_assemble_p, required=False)
    patch_assemble_p.add_argument("address")
    patch_assemble_p.add_argument("assembly")
    patch_assemble_p.set_defaults(handler=_patch_assemble)
    patch_nop_p = patch_sub.add_parser("nop", help="NOP out an address range")
    _common_io_options(patch_nop_p, default_format="json")
    _target_option(patch_nop_p, required=False)
    patch_nop_p.add_argument("address")
    patch_nop_p.add_argument("--length", type=int, default=4)
    patch_nop_p.set_defaults(handler=_patch_nop)
    patch_always_p = patch_sub.add_parser("always-branch", help="Force branch to always be taken")
    _common_io_options(patch_always_p, default_format="json")
    _target_option(patch_always_p, required=False)
    patch_always_p.add_argument("address")
    patch_always_p.set_defaults(handler=_patch_always_branch)
    patch_invert_p = patch_sub.add_parser("invert-branch", help="Invert branch condition")
    _common_io_options(patch_invert_p, default_format="json")
    _target_option(patch_invert_p, required=False)
    patch_invert_p.add_argument("address")
    patch_invert_p.set_defaults(handler=_patch_invert_branch)
    patch_never_p = patch_sub.add_parser("never-branch", help="Force branch to never be taken")
    _common_io_options(patch_never_p, default_format="json")
    _target_option(patch_never_p, required=False)
    patch_never_p.add_argument("address")
    patch_never_p.set_defaults(handler=_patch_never_branch)
    patch_skip_p = patch_sub.add_parser("skip-and-return", help="Skip function call and return value")
    _common_io_options(patch_skip_p, default_format="json")
    _target_option(patch_skip_p, required=False)
    patch_skip_p.add_argument("address")
    patch_skip_p.add_argument("--return-value", type=int, default=0)
    patch_skip_p.set_defaults(handler=_patch_skip_and_return)

    # --- memory ---
    memory = subparsers.add_parser("memory", help="Raw memory read/write operations")
    memory_sub = memory.add_subparsers(dest="memory_command")
    memory_read_p = memory_sub.add_parser("read", help="Read raw bytes from address")
    _common_io_options(memory_read_p)
    _target_option(memory_read_p, required=False)
    memory_read_p.add_argument("address")
    memory_read_p.add_argument("--length", type=int, default=256)
    memory_read_p.set_defaults(handler=_memory_read)
    memory_write_p = memory_sub.add_parser("write", help="Write raw bytes at address")
    _common_io_options(memory_write_p, default_format="json")
    _target_option(memory_write_p, required=False)
    memory_write_p.add_argument("address")
    memory_write_p.add_argument("hex_data", help="Hex string of bytes to write")
    memory_write_p.set_defaults(handler=_memory_write)
    memory_insert_p = memory_sub.add_parser("insert", help="Insert bytes at address")
    _common_io_options(memory_insert_p, default_format="json")
    _target_option(memory_insert_p, required=False)
    memory_insert_p.add_argument("address")
    memory_insert_p.add_argument("hex_data", help="Hex string of bytes to insert")
    memory_insert_p.set_defaults(handler=_memory_insert)
    memory_remove_p = memory_sub.add_parser("remove", help="Remove bytes at address")
    _common_io_options(memory_remove_p, default_format="json")
    _target_option(memory_remove_p, required=False)
    memory_remove_p.add_argument("address")
    memory_remove_p.add_argument("--length", type=int, required=True)
    memory_remove_p.set_defaults(handler=_memory_remove)
    memory_reader_p = memory_sub.add_parser("reader", help="Read using BinaryReader at address")
    _common_io_options(memory_reader_p)
    _target_option(memory_reader_p, required=False)
    memory_reader_p.add_argument("address")
    memory_reader_p.add_argument("--length", type=int, default=256)
    memory_reader_p.set_defaults(handler=_memory_reader)
    memory_writer_p = memory_sub.add_parser("writer", help="Write typed value using BinaryWriter")
    _common_io_options(memory_writer_p, default_format="json")
    _target_option(memory_writer_p, required=False)
    memory_writer_p.add_argument("address")
    memory_writer_p.add_argument("value", help="Integer value to write")
    memory_writer_p.add_argument("--width", type=int, choices=(1, 2, 4, 8), default=4, help="Width in bytes")
    memory_writer_p.add_argument("--endian", choices=("little", "big"), default="little")
    memory_writer_p.set_defaults(handler=_memory_writer)

    # --- value ---
    value = subparsers.add_parser("value", help="Register/stack value analysis at IL instructions")
    value_sub = value.add_subparsers(dest="value_command")
    value_reg_p = value_sub.add_parser("reg", help="Get register value at an instruction")
    _common_io_options(value_reg_p)
    _target_option(value_reg_p, required=False)
    value_reg_p.add_argument("function", help="Function identifier")
    value_reg_p.add_argument("instr_index", type=int, help="IL instruction index")
    value_reg_p.add_argument("register", help="Register name")
    value_reg_p.set_defaults(handler=_value_reg)
    value_stack_p = value_sub.add_parser("stack", help="Get stack value at an instruction")
    _common_io_options(value_stack_p)
    _target_option(value_stack_p, required=False)
    value_stack_p.add_argument("function", help="Function identifier")
    value_stack_p.add_argument("instr_index", type=int, help="IL instruction index")
    value_stack_p.add_argument("offset", type=int, help="Stack offset")
    value_stack_p.add_argument("--size", type=int, default=8)
    value_stack_p.set_defaults(handler=_value_stack)
    value_possible_p = value_sub.add_parser("possible", help="Get possible values at an instruction")
    _common_io_options(value_possible_p)
    _target_option(value_possible_p, required=False)
    value_possible_p.add_argument("function", help="Function identifier")
    value_possible_p.add_argument("instr_index", type=int, help="IL instruction index")
    value_possible_p.add_argument("register", help="Register name")
    value_possible_p.set_defaults(handler=_value_possible)
    value_flags_p = value_sub.add_parser("flags", help="Get flag values at an instruction")
    _common_io_options(value_flags_p)
    _target_option(value_flags_p, required=False)
    value_flags_p.add_argument("function", help="Function identifier")
    value_flags_p.add_argument("instr_index", type=int, help="IL instruction index")
    value_flags_p.add_argument("flag", help="Flag name")
    value_flags_p.set_defaults(handler=_value_flags)

    # --- search ---
    search = subparsers.add_parser("search", help="Search binary content")
    search_sub = search.add_subparsers(dest="search_command")
    search_bytes_p = search_sub.add_parser("bytes", help="Search for byte pattern")
    _common_io_options(search_bytes_p)
    _target_option(search_bytes_p, required=False)
    search_bytes_p.add_argument("pattern", help="Hex byte pattern (e.g. '48 8b 05 ?? ?? ?? ??')")
    search_bytes_p.add_argument("--start", help="Start address")
    search_bytes_p.add_argument("--end", help="End address")
    search_bytes_p.add_argument("--limit", type=int, default=100)
    search_bytes_p.set_defaults(handler=_search_bytes)
    search_constant_p = search_sub.add_parser("constant", help="Search for numeric constant in IL")
    _common_io_options(search_constant_p)
    _target_option(search_constant_p, required=False)
    search_constant_p.add_argument("value", help="Constant value (hex or decimal)")
    search_constant_p.add_argument("--limit", type=int, default=100)
    search_constant_p.set_defaults(handler=_search_constant)
    search_text_p = search_sub.add_parser("text", help="Search for text/regex in decompiled output")
    _common_io_options(search_text_p)
    _target_option(search_text_p, required=False)
    search_text_p.add_argument("pattern", help="Text or regex pattern")
    search_text_p.add_argument("--regex", action="store_true", help="Interpret pattern as regex")
    search_text_p.add_argument("--il-type", choices=("hlil", "mlil", "llil", "disasm"), default="hlil")
    search_text_p.add_argument("--limit", type=int, default=50)
    search_text_p.set_defaults(handler=_search_text_handler)

    # --- arch ---
    arch = subparsers.add_parser("arch", help="Architecture information and utilities")
    arch_sub = arch.add_subparsers(dest="arch_command")
    arch_info_p = arch_sub.add_parser("info", help="Show architecture info for target")
    _common_io_options(arch_info_p)
    _target_option(arch_info_p, required=False)
    arch_info_p.set_defaults(handler=_arch_info)
    arch_assemble_p = arch_sub.add_parser("assemble", help="Assemble instructions")
    _common_io_options(arch_assemble_p)
    _target_option(arch_assemble_p, required=False)
    arch_assemble_p.add_argument("assembly", help="Assembly code to assemble")
    arch_assemble_p.add_argument("--address", default="0x0", help="Address context for assembly")
    arch_assemble_p.set_defaults(handler=_arch_assemble)
    arch_disasm_p = arch_sub.add_parser("disasm-bytes", help="Disassemble raw bytes")
    _common_io_options(arch_disasm_p)
    _target_option(arch_disasm_p, required=False)
    arch_disasm_p.add_argument("hex_bytes", help="Hex string of bytes to disassemble")
    arch_disasm_p.add_argument("--address", default="0x0", help="Address context")
    arch_disasm_p.add_argument("--count", type=int, help="Max instructions to decode")
    arch_disasm_p.set_defaults(handler=_arch_disasm_bytes)

    # --- segments / sections / data-vars ---
    segments_p = subparsers.add_parser("segments", help="List binary segments")
    _common_io_options(segments_p)
    _target_option(segments_p, required=False)
    segments_p.set_defaults(handler=_list_segments)

    sections_p = subparsers.add_parser("sections", help="List binary sections")
    _common_io_options(sections_p)
    _target_option(sections_p, required=False)
    sections_p.set_defaults(handler=_list_sections)

    data_vars_p = subparsers.add_parser("data-vars", help="List data variables")
    _common_io_options(data_vars_p)
    _target_option(data_vars_p, required=False)
    _add_paged_args(data_vars_p)
    data_vars_p.add_argument("--query", help="Filter by name/address substring")
    data_vars_p.set_defaults(handler=_list_data_vars)

    api_docs_parser = subparsers.add_parser(
        "api-docs",
        help="Query Binary Ninja's local Python API docs (no target needed)",
    )
    api_docs_sub = api_docs_parser.add_subparsers(dest="api_docs_command")

    def _docs_dir_arg(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--docs-dir",
            type=Path,
            help=(
                "Path to the api-docs directory. Defaults to BN_API_DOCS_DIR or the "
                "Binary Ninja install location for this platform."
            ),
        )

    api_docs_search = api_docs_sub.add_parser("search", help="Search API symbols by name")
    _common_io_options(api_docs_search)
    _docs_dir_arg(api_docs_search)
    api_docs_search.add_argument("pattern")
    api_docs_search.add_argument(
        "--regex",
        action="store_true",
        help="Interpret the pattern as a case-insensitive regular expression",
    )
    api_docs_search.add_argument(
        "--kind",
        choices=api_docs.KNOWN_KINDS,
        help="Restrict matches to one symbol kind",
    )
    api_docs_search.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum number of matches to return (default: 50, use -1 for no limit)",
    )
    api_docs_search.set_defaults(handler=_api_docs_search)

    api_docs_show = api_docs_sub.add_parser(
        "show",
        help="Show signature and docstring for one symbol",
    )
    _common_io_options(api_docs_show)
    _docs_dir_arg(api_docs_show)
    api_docs_show.add_argument("name", help="Qualified name (e.g. binaryninja.BinaryView.read)")
    api_docs_show.set_defaults(handler=_api_docs_show)

    api_docs_list = api_docs_sub.add_parser("list", help="List symbols, optionally filtered")
    _common_io_options(api_docs_list)
    _docs_dir_arg(api_docs_list)
    api_docs_list.add_argument(
        "--kind",
        choices=api_docs.KNOWN_KINDS,
        help="Restrict to one symbol kind",
    )
    api_docs_list.add_argument(
        "--module",
        help="Restrict to entries inside a module prefix (e.g. binaryninja.highlevelil)",
    )
    api_docs_list.add_argument(
        "--limit",
        type=int,
        default=200,
        help="Maximum entries to return (default: 200, use -1 for no limit)",
    )
    api_docs_list.set_defaults(handler=_api_docs_list)

    api_docs_refresh = api_docs_sub.add_parser(
        "refresh",
        help="Rebuild the cached API docs index",
    )
    _common_io_options(api_docs_refresh, default_format="json")
    _docs_dir_arg(api_docs_refresh)
    api_docs_refresh.set_defaults(handler=_api_docs_refresh)

    # -----------------------------------------------------------------
    # database
    # -----------------------------------------------------------------
    database_p = subparsers.add_parser("database", help="Database operations (bndb)")
    database_sub = database_p.add_subparsers(dest="database_command")

    db_info = database_sub.add_parser("info", help="Show database info")
    _common_io_options(db_info)
    _target_option(db_info, required=False)
    db_info.set_defaults(handler=_database_info)

    db_read = database_sub.add_parser("read-global", help="Read a global database key")
    _common_io_options(db_read)
    _target_option(db_read, required=False)
    db_read.add_argument("key", help="Key to read")
    db_read.set_defaults(handler=_database_read_global)

    db_write = database_sub.add_parser("write-global", help="Write a global database key")
    _common_io_options(db_write, default_format="json")
    _target_option(db_write, required=False)
    db_write.add_argument("key", help="Key to write")
    db_write.add_argument("value", help="Value to write")
    db_write.set_defaults(handler=_database_write_global)

    db_snaps = database_sub.add_parser("snapshots", help="List database snapshots")
    _common_io_options(db_snaps)
    _target_option(db_snaps, required=False)
    _add_paged_args(db_snaps)
    db_snaps.set_defaults(handler=_database_snapshots)

    db_save = database_sub.add_parser("save", help="Save auto snapshot")
    _common_io_options(db_save, default_format="json")
    _target_option(db_save, required=False)
    db_save.set_defaults(handler=_database_save_auto_snapshot)

    db_create = database_sub.add_parser("create-bndb", help="Create a new .bndb file")
    _common_io_options(db_create, default_format="json")
    _target_option(db_create, required=False)
    db_create.add_argument("path", help="Path for new .bndb")
    db_create.set_defaults(handler=_database_create_bndb)

    # -----------------------------------------------------------------
    # type (extended) - add subcommands to existing type parser if needed
    # -----------------------------------------------------------------
    type_ext_p = subparsers.add_parser("type-ext", help="Extended type operations")
    type_ext_sub = type_ext_p.add_subparsers(dest="type_ext_command")

    te_rename = type_ext_sub.add_parser("rename", help="Rename a user type")
    _common_io_options(te_rename, default_format="json")
    _target_option(te_rename, required=False)
    te_rename.add_argument("old_name")
    te_rename.add_argument("new_name")
    te_rename.set_defaults(handler=_type_rename)

    te_undef = type_ext_sub.add_parser("undefine", help="Undefine a user type")
    _common_io_options(te_undef, default_format="json")
    _target_option(te_undef, required=False)
    te_undef.add_argument("name")
    te_undef.set_defaults(handler=_type_undefine)

    te_parse = type_ext_sub.add_parser("parse", help="Parse a type string")
    _common_io_options(te_parse)
    _target_option(te_parse, required=False)
    te_parse.add_argument("source", help="C type string to parse")
    te_parse.set_defaults(handler=_type_parse)

    te_import = type_ext_sub.add_parser("import", help="Import type/object from library")
    _common_io_options(te_import, default_format="json")
    _target_option(te_import, required=False)
    te_import.add_argument("name", help="Name to import")
    te_import.add_argument("--kind", choices=["type", "object"], default="type")
    te_import.add_argument("--library", help="Specific type library to search")
    te_import.set_defaults(handler=_type_import)

    te_export = type_ext_sub.add_parser("export", help="Export type to library")
    _common_io_options(te_export, default_format="json")
    _target_option(te_export, required=False)
    te_export.add_argument("library", help="Target type library ID/name")
    te_export.add_argument("source", help="C type definition")
    te_export.add_argument("--name", help="Override name")
    te_export.set_defaults(handler=_type_export)

    te_lib_list = type_ext_sub.add_parser("library-list", help="List type libraries")
    _common_io_options(te_lib_list)
    _target_option(te_lib_list, required=False)
    te_lib_list.set_defaults(handler=_type_library_list)

    te_lib_get = type_ext_sub.add_parser("library-get", help="Get type library detail")
    _common_io_options(te_lib_get)
    _target_option(te_lib_get, required=False)
    te_lib_get.add_argument("id", help="Library name or GUID")
    te_lib_get.set_defaults(handler=_type_library_get)

    te_lib_create = type_ext_sub.add_parser("library-create", help="Create type library")
    _common_io_options(te_lib_create, default_format="json")
    _target_option(te_lib_create, required=False)
    te_lib_create.add_argument("name")
    te_lib_create.add_argument("--path", help="Save to file path")
    te_lib_create.add_argument("--add-to-view", action="store_true")
    te_lib_create.set_defaults(handler=_type_library_create)

    te_lib_load = type_ext_sub.add_parser("library-load", help="Load type library from file")
    _common_io_options(te_lib_load, default_format="json")
    _target_option(te_lib_load, required=False)
    te_lib_load.add_argument("path")
    te_lib_load.add_argument("--no-add", action="store_true", help="Don't add to view")
    te_lib_load.set_defaults(handler=_type_library_load)

    te_arc_list = type_ext_sub.add_parser("archive-list", help="List type archives")
    _common_io_options(te_arc_list)
    _target_option(te_arc_list, required=False)
    te_arc_list.set_defaults(handler=_type_archive_list)

    te_arc_get = type_ext_sub.add_parser("archive-get", help="Get type archive detail")
    _common_io_options(te_arc_get)
    _target_option(te_arc_get, required=False)
    te_arc_get.add_argument("id", help="Archive ID")
    te_arc_get.set_defaults(handler=_type_archive_get)

    te_arc_create = type_ext_sub.add_parser("archive-create", help="Create type archive")
    _common_io_options(te_arc_create, default_format="json")
    _target_option(te_arc_create, required=False)
    te_arc_create.add_argument("path")
    te_arc_create.add_argument("--attach", action="store_true")
    te_arc_create.set_defaults(handler=_type_archive_create)

    te_arc_open = type_ext_sub.add_parser("archive-open", help="Open type archive from file")
    _common_io_options(te_arc_open, default_format="json")
    _target_option(te_arc_open, required=False)
    te_arc_open.add_argument("path")
    te_arc_open.add_argument("--attach", action="store_true")
    te_arc_open.set_defaults(handler=_type_archive_open)

    te_arc_pull = type_ext_sub.add_parser("archive-pull", help="Pull types from archive")
    _common_io_options(te_arc_pull, default_format="json")
    _target_option(te_arc_pull, required=False)
    te_arc_pull.add_argument("id", help="Archive ID")
    te_arc_pull.add_argument("names", nargs="+", help="Type names to pull")
    te_arc_pull.set_defaults(handler=_type_archive_pull)

    te_arc_push = type_ext_sub.add_parser("archive-push", help="Push types to archive")
    _common_io_options(te_arc_push, default_format="json")
    _target_option(te_arc_push, required=False)
    te_arc_push.add_argument("id", help="Archive ID")
    te_arc_push.add_argument("names", nargs="+", help="Type names to push")
    te_arc_push.set_defaults(handler=_type_archive_push)

    # -----------------------------------------------------------------
    # annotation
    # -----------------------------------------------------------------
    annot_p = subparsers.add_parser("annotation", help="Annotation operations (tags, data vars, symbols)")
    annot_sub = annot_p.add_subparsers(dest="annotation_command")

    annot_add_tag = annot_sub.add_parser("add-tag", help="Add tag at address")
    _common_io_options(annot_add_tag, default_format="json")
    _target_option(annot_add_tag, required=False)
    annot_add_tag.add_argument("address")
    annot_add_tag.add_argument("tag_type")
    annot_add_tag.add_argument("data")
    annot_add_tag.set_defaults(handler=_annotation_add_tag)

    annot_get_tags = annot_sub.add_parser("get-tags", help="Get tags at address")
    _common_io_options(annot_get_tags)
    _target_option(annot_get_tags, required=False)
    annot_get_tags.add_argument("address")
    annot_get_tags.set_defaults(handler=_annotation_get_tags)

    annot_def_dv = annot_sub.add_parser("define-data-var", help="Define data variable at address")
    _common_io_options(annot_def_dv, default_format="json")
    _target_option(annot_def_dv, required=False)
    annot_def_dv.add_argument("address")
    annot_def_dv.add_argument("--type-name", help="C type string")
    annot_def_dv.add_argument("--name", help="Symbol name")
    annot_def_dv.add_argument("--width", type=int, help="Width in bytes (if no type)")
    annot_def_dv.set_defaults(handler=_annotation_define_data_var)

    annot_undef_dv = annot_sub.add_parser("undefine-data-var", help="Undefine data variable")
    _common_io_options(annot_undef_dv, default_format="json")
    _target_option(annot_undef_dv, required=False)
    annot_undef_dv.add_argument("address")
    annot_undef_dv.set_defaults(handler=_annotation_undefine_data_var)

    annot_def_sym = annot_sub.add_parser("define-symbol", help="Define user symbol at address")
    _common_io_options(annot_def_sym, default_format="json")
    _target_option(annot_def_sym, required=False)
    annot_def_sym.add_argument("address")
    annot_def_sym.add_argument("name")
    annot_def_sym.add_argument("--symbol-type", choices=["function", "data", "import", "external"])
    annot_def_sym.set_defaults(handler=_annotation_define_symbol)

    annot_undef_sym = annot_sub.add_parser("undefine-symbol", help="Undefine user symbol")
    _common_io_options(annot_undef_sym, default_format="json")
    _target_option(annot_undef_sym, required=False)
    annot_undef_sym.add_argument("address")
    annot_undef_sym.set_defaults(handler=_annotation_undefine_symbol)

    annot_rename_dv = annot_sub.add_parser("rename-data-var", help="Rename data variable")
    _common_io_options(annot_rename_dv, default_format="json")
    _target_option(annot_rename_dv, required=False)
    annot_rename_dv.add_argument("address")
    annot_rename_dv.add_argument("new_name")
    annot_rename_dv.set_defaults(handler=_annotation_rename_data_var)

    # -----------------------------------------------------------------
    # undo
    # -----------------------------------------------------------------
    undo_p = subparsers.add_parser("undo", help="Undo/redo operations")
    undo_sub = undo_p.add_subparsers(dest="undo_command")

    undo_begin_p = undo_sub.add_parser("begin", help="Begin undo group")
    _common_io_options(undo_begin_p, default_format="json")
    _target_option(undo_begin_p, required=False)
    undo_begin_p.set_defaults(handler=_undo_begin)

    undo_commit_p = undo_sub.add_parser("commit", help="Commit undo group")
    _common_io_options(undo_commit_p, default_format="json")
    _target_option(undo_commit_p, required=False)
    undo_commit_p.set_defaults(handler=_undo_commit)

    undo_revert_p = undo_sub.add_parser("revert", help="Revert undo group")
    _common_io_options(undo_revert_p, default_format="json")
    _target_option(undo_revert_p, required=False)
    undo_revert_p.set_defaults(handler=_undo_revert)

    undo_undo_p = undo_sub.add_parser("undo", help="Undo last action")
    _common_io_options(undo_undo_p, default_format="json")
    _target_option(undo_undo_p, required=False)
    undo_undo_p.set_defaults(handler=_undo_undo)

    undo_redo_p = undo_sub.add_parser("redo", help="Redo last undone action")
    _common_io_options(undo_redo_p, default_format="json")
    _target_option(undo_redo_p, required=False)
    undo_redo_p.set_defaults(handler=_undo_redo)

    # -----------------------------------------------------------------
    # uidf (User IL Data Flow)
    # -----------------------------------------------------------------
    uidf_p = subparsers.add_parser("uidf", help="User IL Data Flow operations")
    uidf_sub = uidf_p.add_subparsers(dest="uidf_command")

    uidf_set_p = uidf_sub.add_parser("set", help="Set user variable value")
    _common_io_options(uidf_set_p, default_format="json")
    _target_option(uidf_set_p, required=False)
    uidf_set_p.add_argument("function_start", help="Function start address")
    uidf_set_p.add_argument("address", help="Instruction address")
    uidf_set_p.add_argument("var_name", help="Variable name")
    uidf_set_p.add_argument("value", help="Constant value")
    uidf_set_p.add_argument("--def-site-address", help="Definition site address")
    uidf_set_p.add_argument("--state", default="ConstantValue", help="Value state type")
    uidf_set_p.set_defaults(handler=_uidf_set)

    uidf_clear_p = uidf_sub.add_parser("clear", help="Clear user variable value")
    _common_io_options(uidf_clear_p, default_format="json")
    _target_option(uidf_clear_p, required=False)
    uidf_clear_p.add_argument("function_start")
    uidf_clear_p.add_argument("address")
    uidf_clear_p.add_argument("var_name")
    uidf_clear_p.set_defaults(handler=_uidf_clear)

    uidf_list_p = uidf_sub.add_parser("list", help="List user variable values for function")
    _common_io_options(uidf_list_p)
    _target_option(uidf_list_p, required=False)
    uidf_list_p.add_argument("function_start")
    uidf_list_p.set_defaults(handler=_uidf_list)

    uidf_parse_p = uidf_sub.add_parser("parse", help="Parse possible value")
    _common_io_options(uidf_parse_p)
    _target_option(uidf_parse_p, required=False)
    uidf_parse_p.add_argument("value")
    uidf_parse_p.add_argument("state")
    uidf_parse_p.set_defaults(handler=_uidf_parse)

    # -----------------------------------------------------------------
    # loader
    # -----------------------------------------------------------------
    loader_p = subparsers.add_parser("loader", help="Loader settings and rebase")
    loader_sub = loader_p.add_subparsers(dest="loader_command")

    loader_get = loader_sub.add_parser("settings-get", help="Get loader settings")
    _common_io_options(loader_get)
    _target_option(loader_get, required=False)
    loader_get.add_argument("type_name", help="View type name (e.g. ELF)")
    loader_get.set_defaults(handler=_loader_settings_get)

    loader_set = loader_sub.add_parser("settings-set", help="Set a loader setting")
    _common_io_options(loader_set, default_format="json")
    _target_option(loader_set, required=False)
    loader_set.add_argument("type_name")
    loader_set.add_argument("key")
    loader_set.add_argument("value")
    loader_set.set_defaults(handler=_loader_settings_set)

    loader_types = loader_sub.add_parser("settings-types", help="List available view types")
    _common_io_options(loader_types)
    _target_option(loader_types, required=False)
    loader_types.set_defaults(handler=_loader_settings_types)

    loader_rebase_p = loader_sub.add_parser("rebase", help="Rebase binary to new address")
    _common_io_options(loader_rebase_p, default_format="json")
    _target_option(loader_rebase_p, required=False)
    loader_rebase_p.add_argument("address", help="New base address")
    loader_rebase_p.add_argument("--force", action="store_true")
    loader_rebase_p.set_defaults(handler=_loader_rebase)

    # -----------------------------------------------------------------
    # external
    # -----------------------------------------------------------------
    ext_p = subparsers.add_parser("external", help="External library/location operations")
    ext_sub = ext_p.add_subparsers(dest="external_command")

    ext_lib_add = ext_sub.add_parser("library-add", help="Add external library")
    _common_io_options(ext_lib_add, default_format="json")
    _target_option(ext_lib_add, required=False)
    ext_lib_add.add_argument("name")
    ext_lib_add.set_defaults(handler=_external_library_add)

    ext_lib_list = ext_sub.add_parser("library-list", help="List external libraries")
    _common_io_options(ext_lib_list)
    _target_option(ext_lib_list, required=False)
    ext_lib_list.set_defaults(handler=_external_library_list)

    ext_lib_rm = ext_sub.add_parser("library-remove", help="Remove external library")
    _common_io_options(ext_lib_rm, default_format="json")
    _target_option(ext_lib_rm, required=False)
    ext_lib_rm.add_argument("name")
    ext_lib_rm.set_defaults(handler=_external_library_remove)

    ext_loc_add = ext_sub.add_parser("location-add", help="Add external location")
    _common_io_options(ext_loc_add, default_format="json")
    _target_option(ext_loc_add, required=False)
    ext_loc_add.add_argument("source_address")
    ext_loc_add.add_argument("--library-name")
    ext_loc_add.add_argument("--target-symbol")
    ext_loc_add.add_argument("--target-address")
    ext_loc_add.set_defaults(handler=_external_location_add)

    ext_loc_get = ext_sub.add_parser("location-get", help="Get external location")
    _common_io_options(ext_loc_get)
    _target_option(ext_loc_get, required=False)
    ext_loc_get.add_argument("source_address")
    ext_loc_get.set_defaults(handler=_external_location_get)

    ext_loc_rm = ext_sub.add_parser("location-remove", help="Remove external location")
    _common_io_options(ext_loc_rm, default_format="json")
    _target_option(ext_loc_rm, required=False)
    ext_loc_rm.add_argument("source_address")
    ext_loc_rm.set_defaults(handler=_external_location_remove)

    # -----------------------------------------------------------------
    # analysis
    # -----------------------------------------------------------------
    analysis_p = subparsers.add_parser("analysis", help="Analysis control")
    analysis_sub = analysis_p.add_subparsers(dest="analysis_command")

    analysis_stat = analysis_sub.add_parser("status", help="Get analysis status")
    _common_io_options(analysis_stat)
    _target_option(analysis_stat, required=False)
    analysis_stat.set_defaults(handler=_analysis_status)

    analysis_prog = analysis_sub.add_parser("progress", help="Get analysis progress")
    _common_io_options(analysis_prog)
    _target_option(analysis_prog, required=False)
    analysis_prog.set_defaults(handler=_analysis_progress)

    analysis_abort_p = analysis_sub.add_parser("abort", help="Abort analysis")
    _common_io_options(analysis_abort_p, default_format="json")
    _target_option(analysis_abort_p, required=False)
    analysis_abort_p.set_defaults(handler=_analysis_abort)

    analysis_hold_p = analysis_sub.add_parser("hold", help="Hold/resume analysis")
    _common_io_options(analysis_hold_p, default_format="json")
    _target_option(analysis_hold_p, required=False)
    analysis_hold_p.add_argument("hold", type=lambda x: x.lower() in ("true", "1", "yes"), help="true to hold, false to release")
    analysis_hold_p.set_defaults(handler=_analysis_set_hold)

    analysis_upd = analysis_sub.add_parser("update", help="Trigger analysis update (async)")
    _common_io_options(analysis_upd, default_format="json")
    _target_option(analysis_upd, required=False)
    analysis_upd.set_defaults(handler=_analysis_update)

    analysis_upd_wait = analysis_sub.add_parser("update-wait", help="Trigger and wait for analysis")
    _common_io_options(analysis_upd_wait, default_format="json")
    _target_option(analysis_upd_wait, required=False)
    analysis_upd_wait.set_defaults(handler=_analysis_update_and_wait)

    # -----------------------------------------------------------------
    # metadata (view-level)
    # -----------------------------------------------------------------
    meta_p = subparsers.add_parser("metadata", help="View-level metadata operations")
    meta_sub = meta_p.add_subparsers(dest="metadata_command")

    meta_query = meta_sub.add_parser("query", help="Query metadata key")
    _common_io_options(meta_query)
    _target_option(meta_query, required=False)
    meta_query.add_argument("key")
    meta_query.set_defaults(handler=_metadata_query)

    meta_store = meta_sub.add_parser("store", help="Store metadata key-value")
    _common_io_options(meta_store, default_format="json")
    _target_option(meta_store, required=False)
    meta_store.add_argument("key")
    meta_store.add_argument("value")
    meta_store.set_defaults(handler=_metadata_store)

    meta_rm = meta_sub.add_parser("remove", help="Remove metadata key")
    _common_io_options(meta_rm, default_format="json")
    _target_option(meta_rm, required=False)
    meta_rm.add_argument("key")
    meta_rm.set_defaults(handler=_metadata_remove)

    # -----------------------------------------------------------------
    # data
    # -----------------------------------------------------------------
    data_typed_p = subparsers.add_parser("data-typed-at", help="Get typed data variable at address")
    _common_io_options(data_typed_p)
    _target_option(data_typed_p, required=False)
    data_typed_p.add_argument("address")
    data_typed_p.set_defaults(handler=_data_typed_at)

    # -----------------------------------------------------------------
    # xref extended
    # -----------------------------------------------------------------
    xref_ext_p = subparsers.add_parser("xref-ext", help="Extended cross-reference operations")
    xref_ext_sub = xref_ext_p.add_subparsers(dest="xref_ext_command")

    xref_cf = xref_ext_sub.add_parser("code-refs-from", help="Code references from address")
    _common_io_options(xref_cf)
    _target_option(xref_cf, required=False)
    xref_cf.add_argument("address")
    xref_cf.add_argument("--length", type=int)
    xref_cf.set_defaults(handler=_xref_code_refs_from)

    xref_ct = xref_ext_sub.add_parser("code-refs-to", help="Code references to address")
    _common_io_options(xref_ct)
    _target_option(xref_ct, required=False)
    xref_ct.add_argument("address")
    xref_ct.add_argument("--limit", type=int, default=100)
    xref_ct.set_defaults(handler=_xref_code_refs_to)

    xref_df = xref_ext_sub.add_parser("data-refs-from", help="Data references from address")
    _common_io_options(xref_df)
    _target_option(xref_df, required=False)
    xref_df.add_argument("address")
    xref_df.add_argument("--length", type=int)
    xref_df.set_defaults(handler=_xref_data_refs_from)

    xref_dt = xref_ext_sub.add_parser("data-refs-to", help="Data references to address")
    _common_io_options(xref_dt)
    _target_option(xref_dt, required=False)
    xref_dt.add_argument("address")
    xref_dt.add_argument("--limit", type=int, default=100)
    xref_dt.set_defaults(handler=_xref_data_refs_to)

    # -----------------------------------------------------------------
    # il (extended)
    # -----------------------------------------------------------------
    il_p = subparsers.add_parser("il-nav", help="IL navigation operations")
    il_sub = il_p.add_subparsers(dest="il_command")

    il_a2i = il_sub.add_parser("addr-to-index", help="Address to IL instruction index")
    _common_io_options(il_a2i)
    _target_option(il_a2i, required=False)
    il_a2i.add_argument("function_start")
    il_a2i.add_argument("address")
    il_a2i.add_argument("--level", choices=["hlil", "mlil", "llil"], default="hlil")
    il_a2i.set_defaults(handler=_il_address_to_index)

    il_i2a = il_sub.add_parser("index-to-addr", help="IL instruction index to address")
    _common_io_options(il_i2a)
    _target_option(il_i2a, required=False)
    il_i2a.add_argument("function_start")
    il_i2a.add_argument("index", type=int)
    il_i2a.add_argument("--level", choices=["hlil", "mlil", "llil"], default="hlil")
    il_i2a.set_defaults(handler=_il_index_to_address)

    il_instr = il_sub.add_parser("instr-at", help="Get IL instruction at address")
    _common_io_options(il_instr)
    _target_option(il_instr, required=False)
    il_instr.add_argument("function_start")
    il_instr.add_argument("address")
    il_instr.add_argument("--level", choices=["hlil", "mlil", "llil"], default="hlil")
    il_instr.set_defaults(handler=_il_instruction_by_addr)

    # -----------------------------------------------------------------
    # section/segment user
    # -----------------------------------------------------------------
    sec_user_p = subparsers.add_parser("section-user", help="User section operations")
    sec_user_sub = sec_user_p.add_subparsers(dest="section_user_command")

    sec_add = sec_user_sub.add_parser("add", help="Add user section")
    _common_io_options(sec_add, default_format="json")
    _target_option(sec_add, required=False)
    sec_add.add_argument("name")
    sec_add.add_argument("start")
    sec_add.add_argument("length", type=int)
    sec_add.set_defaults(handler=_section_add_user)

    sec_rm = sec_user_sub.add_parser("remove", help="Remove user section")
    _common_io_options(sec_rm, default_format="json")
    _target_option(sec_rm, required=False)
    sec_rm.add_argument("name")
    sec_rm.set_defaults(handler=_section_remove_user)

    seg_user_p = subparsers.add_parser("segment-user", help="User segment operations")
    seg_user_sub = seg_user_p.add_subparsers(dest="segment_user_command")

    seg_add = seg_user_sub.add_parser("add", help="Add user segment")
    _common_io_options(seg_add, default_format="json")
    _target_option(seg_add, required=False)
    seg_add.add_argument("start")
    seg_add.add_argument("length", type=int)
    seg_add.add_argument("--data-offset", type=int)
    seg_add.add_argument("--data-length", type=int)
    seg_add.add_argument("--flags", type=int, default=0)
    seg_add.set_defaults(handler=_segment_add_user)

    seg_rm = seg_user_sub.add_parser("remove", help="Remove user segment")
    _common_io_options(seg_rm, default_format="json")
    _target_option(seg_rm, required=False)
    seg_rm.add_argument("start")
    seg_rm.add_argument("--length", type=int)
    seg_rm.set_defaults(handler=_segment_remove_user)

    # -----------------------------------------------------------------
    # debug
    # -----------------------------------------------------------------
    debug_p = subparsers.add_parser("debug-info", help="Debug info operations")
    debug_sub = debug_p.add_subparsers(dest="debug_command")

    debug_parsers_p = debug_sub.add_parser("parsers", help="List debug info parsers")
    _common_io_options(debug_parsers_p)
    _target_option(debug_parsers_p, required=False)
    debug_parsers_p.set_defaults(handler=_debug_parsers)

    debug_apply_p = debug_sub.add_parser("apply", help="Parse and apply debug info")
    _common_io_options(debug_apply_p, default_format="json")
    _target_option(debug_apply_p, required=False)
    debug_apply_p.add_argument("--parser-name", help="Specific parser to use")
    debug_apply_p.add_argument("--debug-path", help="Path to debug file")
    debug_apply_p.set_defaults(handler=_debug_parse_and_apply)

    # -----------------------------------------------------------------
    # plugin
    # -----------------------------------------------------------------
    plugin_cmd_p = subparsers.add_parser("plugin-cmd", help="Plugin command operations")
    plugin_cmd_sub = plugin_cmd_p.add_subparsers(dest="plugin_cmd_command")

    plugin_list_p = plugin_cmd_sub.add_parser("list", help="List valid plugin commands")
    _common_io_options(plugin_list_p)
    _target_option(plugin_list_p, required=False)
    plugin_list_p.add_argument("--address")
    plugin_list_p.set_defaults(handler=_plugin_valid_commands)

    plugin_exec_p = plugin_cmd_sub.add_parser("execute", help="Execute plugin command")
    _common_io_options(plugin_exec_p, default_format="json")
    _target_option(plugin_exec_p, required=False)
    plugin_exec_p.add_argument("name", help="Plugin command name")
    plugin_exec_p.add_argument("--address")
    plugin_exec_p.set_defaults(handler=_plugin_execute)

    # -----------------------------------------------------------------
    # binary extended
    # -----------------------------------------------------------------
    bin_bbs_p = subparsers.add_parser("binary-bbs-at", help="Get basic blocks at address (binary-wide)")
    _common_io_options(bin_bbs_p)
    _target_option(bin_bbs_p, required=False)
    bin_bbs_p.add_argument("address")
    bin_bbs_p.set_defaults(handler=_binary_basic_blocks_at)

    return parser


def _setup(args: argparse.Namespace) -> int:
    """One-command setup: install plugin + skill into all supported clients."""
    source_plugin = plugin_source_dir()
    dest_plugin = plugin_install_dir()
    plugin_ok = False
    try:
        _install_tree(source_plugin, dest_plugin, mode="symlink", force=args.force)
        plugin_ok = True
    except BridgeError as exc:
        plugin_err = str(exc)

    source_skill = skill_source_dir()
    skill_installations = []
    for client in SKILL_CLIENTS:
        dest = skill_install_dir_for(client)
        try:
            _install_tree(source_skill, dest, mode="symlink", force=args.force)
            skill_installations.append({"client": client, "destination": str(dest), "ok": True})
        except BridgeError as exc:
            skill_installations.append({"client": client, "destination": str(dest), "ok": False, "error": str(exc)})

    result = {
        "plugin": {"installed": plugin_ok, "source": str(source_plugin), "destination": str(dest_plugin)},
        "skill": {"source": str(source_skill), "installations": skill_installations},
    }
    if not plugin_ok:
        result["plugin"]["error"] = plugin_err

    _render_result(result, fmt=args.format, out_path=args.out, stem="setup")
    all_ok = plugin_ok and all(i["ok"] for i in skill_installations)
    return 0 if all_ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler: Callable[[argparse.Namespace], int] | None = getattr(args, "handler", None)
    if handler is None:
        selected_parser = getattr(args, "_parser", parser)
        selected_parser.print_help()
        return 1

    try:
        return handler(args)
    except BridgeError as exc:
        print(str(exc), file=sys.stderr)
        return 2
