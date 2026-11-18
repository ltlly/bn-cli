"""Machine-readable help derived from the actual argparse tree."""

from __future__ import annotations

import argparse


def command_schema(parser: argparse.ArgumentParser, path: list[str]) -> dict:
    for part in path:
        children = next(
            (
                a.choices
                for a in parser._actions
                if isinstance(a, argparse._SubParsersAction)
            ),
            {},
        )
        if part not in children:
            raise ValueError(
                f"Unknown command {part!r} under {parser.prog}; choices: {', '.join(children)}"
            )
        parser = children[part]

    def describe(node):
        arguments, commands = [], {}
        for action in node._actions:
            if isinstance(action, argparse._SubParsersAction):
                commands = {
                    name: describe(child) for name, child in action.choices.items()
                }
                continue
            if action.help == argparse.SUPPRESS:
                continue
            item = {
                "name": action.dest,
                "flags": action.option_strings,
                "required": action.required,
                "help": action.help,
                "nargs": action.nargs,
                "type": getattr(action.type, "__name__", "string")
                if action.nargs != 0
                else "flag",
            }
            if action.choices is not None:
                item["choices"] = list(action.choices)
            if action.default != argparse.SUPPRESS:
                item["default"] = action.default
            arguments.append(item)
        return {
            "command": node.prog,
            "description": node.description,
            "arguments": arguments,
            "mutually_exclusive": [
                {
                    "required": group.required,
                    "arguments": [a.dest for a in group._group_actions],
                }
                for group in node._mutually_exclusive_groups
            ],
            "commands": commands,
        }

    return {"schema_version": 1, **describe(parser)}
