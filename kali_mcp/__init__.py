"""
Kali MCP Server - Exposing Kali Linux tools to Claude AI via MCP

This package provides a Model Context Protocol server that bridges
Claude AI with Kali Linux security tools for authorized penetration testing.

Author: Security Research Team
Version: 1.0.0
"""

__version__ = "1.0.0"
__author__ = "Security Research Team"

from .security import SecurityManager, Authorizer

__all__ = [
    "SecurityManager",
    "Authorizer",
    "__version__",
]
