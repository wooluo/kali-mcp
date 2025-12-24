"""
Main entry point for running the Kali MCP server

Usage:
    python -m kali_mcp
"""

from .server import main
import asyncio

if __name__ == "__main__":
    asyncio.run(main())
