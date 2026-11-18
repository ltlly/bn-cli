from pathlib import Path
from shutil import copyfile
from tempfile import TemporaryDirectory

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CompanionBuildHook(BuildHookInterface):
    """Embed regular Python files for the plugin's shared module symlinks."""

    def initialize(self, version, build_data):
        if version == "editable":
            return
        self._copies = TemporaryDirectory()
        for module in ("artifacts.py", "paths.py", "version.py"):
            source = Path(self.root, "src", "bn", module)
            copy = Path(self._copies.name, module)
            copyfile(source, copy)
            build_data["force_include"][str(copy)] = f"plugin/bn_agent_bridge/{module}"

    def finalize(self, version, build_data, artifact_path):
        if version != "editable":
            self._copies.cleanup()
