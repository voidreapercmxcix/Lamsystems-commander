"""Smoke check: the whole server imports and every tool registers.
Run with the venv active (or `uv run python3 check_import.py`)."""
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "src"))
from lamsystems_commander.server import mcp
from lamsystems_commander import shell
tools = mcp._tool_manager._tools
print(len(tools), "tools loaded:", ", ".join(sorted(tools)))
print("uv on whitelist:", "uv" in shell.WHITELIST, "| pytest:", "pytest" in shell.WHITELIST, "| rail:", "rail" in shell.WHITELIST)
