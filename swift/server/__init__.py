"""MCP (Model Context Protocol) server for SWIFT.

Provides defensive tools for controlled security scanning:
- semgrep_tool - Safe code vulnerability scanning
- nmap_tool - Controlled network reconnaissance
- cuckoo_tool - Safe malware analysis API wrapper
- sandbox_tool - Docker-based code execution isolation
- git_integrity_tool - Repository integrity verification

All tools enforce permissions, forensic logging, and input validation.
"""

from server.mcp_server import MCPServer

__all__ = ["MCPServer"]
