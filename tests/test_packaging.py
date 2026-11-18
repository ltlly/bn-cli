from __future__ import annotations

import json
from pathlib import Path

import bn.paths
from bn.paths import plugin_source_dir, skill_source_dir
from bn.version import VERSION


def test_packaged_plugin_assets_are_complete():
    source = plugin_source_dir()

    assert (source / "__init__.py").is_file()
    assert (source / "bridge.py").is_file()
    assert (source / "addressing.py").is_file()
    assert (source / "query.py").is_file()
    for helper in ("artifacts.py", "paths.py", "version.py"):
        assert (source / helper).read_bytes() == Path(bn.paths.__file__).with_name(helper).read_bytes()
    metadata = json.loads((source / "plugin.json").read_text(encoding="utf-8"))
    assert metadata["version"] == VERSION


def test_packaged_skill_assets_are_complete():
    source = skill_source_dir()

    assert (source / "SKILL.md").is_file()
    assert (source / "agents" / "openai.yaml").is_file()
