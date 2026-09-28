"""Entry point — `python -m lamsystems_commander` and the console script."""

from lamsystems_commander.server import mcp


def main() -> None:
    """Run the MCP server over stdio (default transport for local clients)."""
    mcp.run()


if __name__ == "__main__":
    main()
