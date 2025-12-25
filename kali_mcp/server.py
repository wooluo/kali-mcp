#!/usr/bin/env python3
"""
Kali MCP Server

A Model Context Protocol server that exposes Kali Linux security tools to Claude AI.
This server uses stdio for communication and provides tools for authorized security testing.

Usage:
    python -m kali_mcp.server

Configuration:
    See config.yaml for configuration options
"""

import asyncio
import os
import sys
import logging
from pathlib import Path
from typing import Any

# Add parent directory to path to import from package
sys.path.insert(0, str(Path(__file__).parent.parent))

from mcp.server.models import InitializationOptions
from mcp.server import NotificationOptions, Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Resource,
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
)

from .tools import ReconTools, ScanTools, ExploitTools, PostTools, Utils
from .security import get_security_manager, Authorizer, OperationType
from .assistant import KaliAssistant


# Configure logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("kali_mcp")

# Initialize tool modules
recon_tools = ReconTools()
scan_tools = ScanTools()
exploit_tools = ExploitTools()
post_tools = PostTools()
utils = Utils()
assistant = KaliAssistant()

# Initialize security
security_manager = get_security_manager()
authorizer = Authorizer(security_manager)

# Create MCP server instance
server = Server("kali-mcp")

# Pending authorizations storage
pending_authorizations = {}


def format_tool_result(result: dict) -> list[TextContent]:
    """Format tool result for MCP response"""
    return [TextContent(
        type="text",
        text=str(result)
    )]


def get_safe_value(params: dict, key: str, default: Any = None) -> Any:
    """Safely get value from params dictionary"""
    return params.get(key) if params else default


# ==================== UTILITY TOOLS ====================

@server.list_resources()
async def handle_list_resources() -> list[Resource]:
    """List available resources"""
    return [
        Resource(
            uri="config://security",
            name="Security Configuration",
            description="Current security and authorization configuration",
            mimeType="application/json"
        ),
        Resource(
            uri="config://tools",
            name="Tool Configuration",
            description="Available tools and their status",
            mimeType="application/json"
        )
    ]


@server.read_resource()
async def handle_read_resource(uri: str) -> str:
    """Read a resource"""
    if uri == "config://security":
        import json
        return json.dumps({
            "authorization": {
                "require_auth_for_exploitation": True,
                "audit_log_enabled": True
            },
            "blocked_ranges": security_manager.config.get("authorization", {}).get("blocked_ranges", [])
        }, indent=2)
    elif uri == "config://tools":
        import json
        return json.dumps({
            "reconnaissance": {"enabled": True},
            "scanning": {"enabled": True},
            "exploitation": {"enabled": True, "requires_auth": True},
            "post_exploitation": {"enabled": True, "requires_auth": True},
            "utilities": {"enabled": True}
        }, indent=2)
    else:
        raise ValueError(f"Unknown resource: {uri}")


@server.list_tools()
async def handle_list_tools() -> list[Tool]:
    """List available tools"""

    tools = [
        # ============ AI ASSISTANT ============
        Tool(
            name="kali_assistant",
            description="Natural language interface to Kali tools - just describe what you want to do in plain English or Chinese! (中文也可以)",
            inputSchema={
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "Natural language command (e.g., 'scan 192.168.1.1', 'generate webshell password:123', 'whois example.com')"
                    }
                },
                "required": ["message"]
            }
        ),

        # ============ UTILITY TOOLS ============
        Tool(
            name="base64_encode",
            description="Encode data to Base64",
            inputSchema={
                "type": "object",
                "properties": {
                    "data": {
                        "type": "string",
                        "description": "String data to encode"
                    }
                },
                "required": ["data"]
            }
        ),
        Tool(
            name="base64_decode",
            description="Decode Base64 data",
            inputSchema={
                "type": "object",
                "properties": {
                    "data": {
                        "type": "string",
                        "description": "Base64 encoded string"
                    }
                },
                "required": ["data"]
            }
        ),
        Tool(
            name="url_encode",
            description="URL encode data",
            inputSchema={
                "type": "object",
                "properties": {
                    "data": {
                        "type": "string",
                        "description": "String to encode"
                    }
                },
                "required": ["data"]
            }
        ),
        Tool(
            name="url_decode",
            description="URL decode data",
            inputSchema={
                "type": "object",
                "properties": {
                    "data": {
                        "type": "string",
                        "description": "URL encoded string"
                    }
                },
                "required": ["data"]
            }
        ),
        Tool(
            name="hex_encode",
            description="Encode data to hexadecimal",
            inputSchema={
                "type": "object",
                "properties": {
                    "data": {
                        "type": "string",
                        "description": "String to encode"
                    }
                },
                "required": ["data"]
            }
        ),
        Tool(
            name="hex_decode",
            description="Decode hexadecimal data",
            inputSchema={
                "type": "object",
                "properties": {
                    "data": {
                        "type": "string",
                        "description": "Hexadecimal string"
                    }
                },
                "required": ["data"]
            }
        ),
        Tool(
            name="hash_data",
            description="Hash data with specified algorithm",
            inputSchema={
                "type": "object",
                "properties": {
                    "data": {
                        "type": "string",
                        "description": "String to hash"
                    },
                    "algorithm": {
                        "type": "string",
                        "enum": ["md5", "sha1", "sha256", "sha512"],
                        "default": "sha256",
                        "description": "Hash algorithm"
                    }
                },
                "required": ["data"]
            }
        ),
        Tool(
            name="identify_hash",
            description="Identify the type of hash based on length and format",
            inputSchema={
                "type": "object",
                "properties": {
                    "hash_value": {
                        "type": "string",
                        "description": "Hash string to identify"
                    }
                },
                "required": ["hash_value"]
            }
        ),
        Tool(
            name="rot13",
            description="Apply ROT13 cipher",
            inputSchema={
                "type": "object",
                "properties": {
                    "data": {
                        "type": "string",
                        "description": "String to encode/decode"
                    }
                },
                "required": ["data"]
            }
        ),
        Tool(
            name="xor_data",
            description="XOR encode/decode data with a key",
            inputSchema={
                "type": "object",
                "properties": {
                    "data": {
                        "type": "string",
                        "description": "String to encode/decode"
                    },
                    "key": {
                        "type": "string",
                        "description": "XOR key"
                    }
                },
                "required": ["data", "key"]
            }
        ),
        Tool(
            name="generate_random_string",
            description="Generate a random string",
            inputSchema={
                "type": "object",
                "properties": {
                    "length": {
                        "type": "integer",
                        "default": 16,
                        "description": "Length of string to generate"
                    },
                    "charset": {
                        "type": "string",
                        "enum": ["alphanumeric", "alpha", "numeric", "hex"],
                        "default": "alphanumeric",
                        "description": "Character set"
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="system_health_check",
            description="Check system health and installed tools availability",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),

        # ============ RECONNAISSANCE TOOLS ============
        Tool(
            name="nmap_scan",
            description="Perform an Nmap scan on a target",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address, hostname, or CIDR range"
                    },
                    "ports": {
                        "type": "string",
                        "default": "1-1024",
                        "description": "Port range (e.g., '1-1024', '22,80,443')"
                    },
                    "scan_type": {
                        "type": "string",
                        "enum": ["-sS", "-sT", "-sU", "-sA"],
                        "default": "-sS",
                        "description": "Nmap scan type"
                    },
                    "timing": {
                        "type": "string",
                        "enum": ["T0", "T1", "T2", "T3", "T4", "T5"],
                        "default": "T3",
                        "description": "Timing template (T0 paranoid - T5 insane)"
                    },
                    "service_detection": {
                        "type": "boolean",
                        "default": True,
                        "description": "Enable service version detection"
                    },
                    "os_detection": {
                        "type": "boolean",
                        "default": False,
                        "description": "Enable OS detection"
                    }
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="ping_sweep",
            description="Perform a ping sweep to find live hosts",
            inputSchema={
                "type": "object",
                "properties": {
                    "network": {
                        "type": "string",
                        "description": "Network CIDR (e.g., '192.168.1.0/24')"
                    }
                },
                "required": ["network"]
            }
        ),
        Tool(
            name="whois_lookup",
            description="Perform WHOIS lookup",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Domain name or IP address"
                    }
                },
                "required": ["domain"]
            }
        ),
        Tool(
            name="dns_enumerate",
            description="Enumerate DNS records for a domain",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Domain name"
                    },
                    "record_types": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of record types (default: A, AAAA, MX, NS, TXT, CNAME, SOA)"
                    }
                },
                "required": ["domain"]
            }
        ),
        Tool(
            name="dns_brute_force",
            description="Brute force DNS subdomains",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain"
                    },
                    "subdomains": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of subdomains to check (optional, uses default list if not provided)"
                    }
                },
                "required": ["domain"]
            }
        ),
        Tool(
            name="http_headers",
            description="Get HTTP headers from a URL",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL (e.g., 'https://example.com')"
                    }
                },
                "required": ["url"]
            }
        ),
        Tool(
            name="ssl_cert_info",
            description="Get SSL/TLS certificate information",
            inputSchema={
                "type": "object",
                "properties": {
                    "hostname": {
                        "type": "string",
                        "description": "Target hostname"
                    },
                    "port": {
                        "type": "integer",
                        "default": 443,
                        "description": "Port number"
                    }
                },
                "required": ["hostname"]
            }
        ),

        # ============ SCANNING TOOLS ============
        Tool(
            name="nikto_scan",
            description="Run Nikto web server scanner",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target hostname or IP"
                    },
                    "port": {
                        "type": "integer",
                        "default": 80,
                        "description": "Port number"
                    },
                    "use_https": {
                        "type": "boolean",
                        "default": False,
                        "description": "Use HTTPS instead of HTTP"
                    }
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="ssl_scan",
            description="Scan SSL/TLS configuration",
            inputSchema={
                "type": "object",
                "properties": {
                    "hostname": {
                        "type": "string",
                        "description": "Target hostname"
                    },
                    "port": {
                        "type": "integer",
                        "default": 443,
                        "description": "Port number"
                    }
                },
                "required": ["hostname"]
            }
        ),
        Tool(
            name="dir_brute_force",
            description="Brute force directories and files",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target hostname or IP"
                    },
                    "port": {
                        "type": "integer",
                        "default": 80,
                        "description": "Port number"
                    },
                    "use_https": {
                        "type": "boolean",
                        "default": False,
                        "description": "Use HTTPS"
                    },
                    "extensions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "File extensions to check"
                    }
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="smb_enum",
            description="Enumerate SMB shares and information",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or hostname"
                    }
                },
                "required": ["target"]
            }
        ),

        # ============ EXPLOITATION TOOLS ============
        Tool(
            name="searchsploit",
            description="Search exploit-db for exploits",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search term (software name, version, CVE, etc.)"
                    }
                },
                "required": ["query"]
            }
        ),
        Tool(
            name="hydra_crack",
            description="Password cracking with Hydra (REQUIRES AUTHORIZATION)",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or hostname"
                    },
                    "service": {
                        "type": "string",
                        "description": "Service to attack (ssh, ftp, http-post, etc.)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username to test"
                    },
                    "port": {
                        "type": "integer",
                        "description": "Port number"
                    }
                },
                "required": ["target", "service", "username"]
            }
        ),
        Tool(
            name="generate_payload",
            description="Generate a payload using msfvenom",
            inputSchema={
                "type": "object",
                "properties": {
                    "payload_type": {
                        "type": "string",
                        "description": "Payload type (e.g., windows/meterpreter/reverse_tcp)"
                    },
                    "lhost": {
                        "type": "string",
                        "description": "Local host for reverse connection"
                    },
                    "lport": {
                        "type": "integer",
                        "description": "Local port for reverse connection"
                    },
                    "format": {
                        "type": "string",
                        "default": "raw",
                        "description": "Output format (raw, exe, python, bash, etc.)"
                    }
                },
                "required": ["payload_type", "lhost", "lport"]
            }
        ),
        Tool(
            name="sqlmap_scan",
            description="SQL injection testing with sqlmap (REQUIRES AUTHORIZATION)",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target URL to test for SQL injection"
                    },
                    "scan_type": {
                        "type": "string",
                        "enum": ["basic", "extensive", "all_dbs", "dump_table"],
                        "default": "basic",
                        "description": "Type of scan"
                    },
                    "parameters": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Specific parameters to test (default: all)"
                    },
                    "level": {
                        "type": "integer",
                        "default": 1,
                        "minimum": 1,
                        "maximum": 5,
                        "description": "Test level (1-5, higher = more tests)"
                    },
                    "risk": {
                        "type": "integer",
                        "default": 1,
                        "minimum": 1,
                        "maximum": 3,
                        "description": "Risk level (1-3, higher = more risky tests)"
                    },
                    "dbms": {
                        "type": "string",
                        "description": "Force specific DBMS (e.g., MySQL, PostgreSQL)"
                    }
                },
                "required": ["url"]
            }
        ),
        Tool(
            name="msf_exploit",
            description="Execute a Metasploit exploit module (REQUIRES AUTHORIZATION)",
            inputSchema={
                "type": "object",
                "properties": {
                    "exploit_path": {
                        "type": "string",
                        "description": "Exploit module path (e.g., exploit/windows/smb/ms17_010_eternalblue)"
                    },
                    "options": {
                        "type": "object",
                        "description": "Exploit options (RHOSTS, RPORT, LHOST, LPORT, etc.)"
                    },
                    "payload": {
                        "type": "string",
                        "description": "Payload to use (optional)"
                    }
                },
                "required": ["exploit_path", "options"]
            }
        ),
        Tool(
            name="msf_auxiliary",
            description="Execute a Metasploit auxiliary module",
            inputSchema={
                "type": "object",
                "properties": {
                    "module_path": {
                        "type": "string",
                        "description": "Auxiliary module path"
                    },
                    "options": {
                        "type": "object",
                        "description": "Module options"
                    }
                },
                "required": ["module_path", "options"]
            }
        ),
        Tool(
            name="john_crack",
            description="Password cracking with John the Ripper (REQUIRES AUTHORIZATION)",
            inputSchema={
                "type": "object",
                "properties": {
                    "hash_file": {
                        "type": "string",
                        "description": "Path to file containing hashes"
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Path to password wordlist (default: rockyou.txt)"
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["wordlist", "single", "incremental"],
                        "default": "wordlist",
                        "description": "Cracking mode"
                    }
                },
                "required": ["hash_file"]
            }
        ),
        Tool(
            name="wpscan_scan",
            description="Scan WordPress installations using WPScan",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Target WordPress URL"
                    },
                    "enumerate_type": {
                        "type": "string",
                        "default": "vp",
                        "description": "What to enumerate (vulnerabilities, plugins, themes, vp)"
                    },
                    "additional_args": {
                        "type": "string",
                        "description": "Additional WPScan arguments"
                    }
                },
                "required": ["url"]
            }
        ),
        Tool(
            name="enum4linux_scan",
            description="Enumerate Windows/Samba servers using enum4linux",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP or hostname"
                    },
                    "enumerate_all": {
                        "type": "boolean",
                        "default": True,
                        "description": "Run all enumeration options"
                    }
                },
                "required": ["target"]
            }
        ),

        # ============ POST-EXPLOITATION TOOLS ============
        Tool(
            name="suggest_privilege_escalation",
            description="Suggest privilege escalation vectors",
            inputSchema={
                "type": "object",
                "properties": {
                    "os_type": {
                        "type": "string",
                        "enum": ["linux", "windows"],
                        "default": "linux",
                        "description": "Operating system type"
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="suggest_persistence",
            description="Suggest persistence mechanisms",
            inputSchema={
                "type": "object",
                "properties": {
                    "os_type": {
                        "type": "string",
                        "enum": ["linux", "windows"],
                        "default": "linux",
                        "description": "Operating system type"
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="webshell_execute",
            description="Execute command through webshell using weevely (REQUIRES AUTHORIZATION)",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Webshell URL"
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to execute"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for the webshell (REQUIRED)"
                    }
                },
                "required": ["url", "command", "password"]
            }
        ),
        Tool(
            name="generate_webshell",
            description="Generate a webshell using weevely (REQUIRES AUTHORIZATION)",
            inputSchema={
                "type": "object",
                "properties": {
                    "password": {
                        "type": "string",
                        "description": "Password for the webshell (REQUIRED)"
                    },
                    "filename": {
                        "type": "string",
                        "default": "shell.php",
                        "description": "Output filename"
                    },
                    "obfuscate": {
                        "type": "boolean",
                        "default": False,
                        "description": "Obfuscate the webshell code"
                    }
                },
                "required": ["password"]
            }
        ),
        Tool(
            name="webshell_upload",
            description="Attempt to upload a webshell to a target (REQUIRES AUTHORIZATION)",
            inputSchema={
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "Target URL for upload"
                    },
                    "shell_code": {
                        "type": "string",
                        "description": "Webshell code to upload"
                    },
                    "upload_path": {
                        "type": "string",
                        "description": "Path where webshell will be uploaded"
                    },
                    "method": {
                        "type": "string",
                        "enum": ["form", "put", "mv"],
                        "default": "form",
                        "description": "Upload method"
                    }
                },
                "required": ["target_url", "shell_code", "upload_path"]
            }
        ),
    ]

    return tools


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Handle tool execution"""

    try:
        # ============ AI ASSISTANT ============
        if name == "kali_assistant":
            result = assistant.chat(arguments["message"])

        # ============ UTILITY TOOLS ============
        elif name == "base64_encode":
            result = utils.base64_encode(arguments["data"])
        elif name == "base64_decode":
            result = utils.base64_decode(arguments["data"])
        elif name == "url_encode":
            result = utils.url_encode(arguments["data"])
        elif name == "url_decode":
            result = utils.url_decode(arguments["data"])
        elif name == "hex_encode":
            result = utils.hex_encode(arguments["data"])
        elif name == "hex_decode":
            result = utils.hex_decode(arguments["data"])
        elif name == "hash_data":
            result = utils.hash_data(
                arguments["data"],
                arguments.get("algorithm", "sha256")
            )
        elif name == "identify_hash":
            result = utils.identify_hash(arguments["hash_value"])
        elif name == "rot13":
            result = utils.rot13(arguments["data"])
        elif name == "xor_data":
            result = utils.xor_data(arguments["data"], arguments["key"])
        elif name == "generate_random_string":
            result = utils.generate_random_string(
                arguments.get("length", 16),
                arguments.get("charset", "alphanumeric")
            )
        elif name == "system_health_check":
            result = utils.system_health_check()

        # ============ RECONNAISSANCE TOOLS ============
        elif name == "nmap_scan":
            result = recon_tools.nmap_scan(
                target=arguments["target"],
                ports=arguments.get("ports", "1-1024"),
                scan_type=arguments.get("scan_type", "-sS"),
                timing=arguments.get("timing", "T3"),
                service_detection=arguments.get("service_detection", True),
                os_detection=arguments.get("os_detection", False)
            )
        elif name == "ping_sweep":
            result = recon_tools.ping_sweep(arguments["network"])
        elif name == "whois_lookup":
            result = recon_tools.whois_lookup(arguments["domain"])
        elif name == "dns_enumerate":
            result = recon_tools.dns_enumerate(
                arguments["domain"],
                arguments.get("record_types")
            )
        elif name == "dns_brute_force":
            result = recon_tools.dns_brute_force(
                arguments["domain"],
                subdomains=arguments.get("subdomains")
            )
        elif name == "http_headers":
            result = recon_tools.http_headers(arguments["url"])
        elif name == "ssl_cert_info":
            result = recon_tools.ssl_cert_info(
                arguments["hostname"],
                arguments.get("port", 443)
            )

        # ============ SCANNING TOOLS ============
        elif name == "nikto_scan":
            result = scan_tools.nikto_scan(
                target=arguments["target"],
                port=arguments.get("port", 80),
                use_https=arguments.get("use_https", False)
            )
        elif name == "ssl_scan":
            result = scan_tools.ssl_scan(
                arguments["hostname"],
                arguments.get("port", 443)
            )
        elif name == "dir_brute_force":
            result = scan_tools.dir_brute_force(
                target=arguments["target"],
                port=arguments.get("port", 80),
                use_https=arguments.get("use_https", False),
                extensions=arguments.get("extensions")
            )
        elif name == "smb_enum":
            result = scan_tools.smb_enum(arguments["target"])

        # ============ EXPLOITATION TOOLS ============
        elif name == "searchsploit":
            result = exploit_tools.searchsploit_search(arguments["query"])
        elif name == "hydra_crack":
            result = exploit_tools.hydra_crack(
                target=arguments["target"],
                service=arguments["service"],
                username=arguments["username"],
                port=arguments.get("port")
            )
        elif name == "generate_payload":
            result = exploit_tools.generate_payload(
                payload_type=arguments["payload_type"],
                lhost=arguments["lhost"],
                lport=arguments["lport"],
                format=arguments.get("format", "raw")
            )
        elif name == "sqlmap_scan":
            result = exploit_tools.sqlmap_scan(
                url=arguments["url"],
                scan_type=arguments.get("scan_type", "basic"),
                parameters=arguments.get("parameters"),
                level=arguments.get("level", 1),
                risk=arguments.get("risk", 1),
                dbms=arguments.get("dbms")
            )
        elif name == "msf_exploit":
            result = exploit_tools.msf_exploit(
                exploit_path=arguments["exploit_path"],
                options=arguments["options"],
                payload=arguments.get("payload")
            )
        elif name == "msf_auxiliary":
            result = exploit_tools.msf_auxiliary(
                module_path=arguments["module_path"],
                options=arguments["options"]
            )
        elif name == "john_crack":
            result = exploit_tools.john_crack(
                hash_file=arguments["hash_file"],
                wordlist=arguments.get("wordlist"),
                mode=arguments.get("mode", "wordlist")
            )
        elif name == "wpscan_scan":
            result = exploit_tools.wpscan_scan(
                url=arguments["url"],
                enumerate_type=arguments.get("enumerate_type", "vp"),
                additional_args=arguments.get("additional_args", "")
            )
        elif name == "enum4linux_scan":
            result = exploit_tools.enum4linux_scan(
                target=arguments["target"],
                enumerate_all=arguments.get("enumerate_all", True)
            )

        # ============ POST-EXPLOITATION TOOLS ============
        elif name == "suggest_privilege_escalation":
            result = post_tools.suggest_privilege_escalation(
                arguments.get("os_type", "linux")
            )
        elif name == "suggest_persistence":
            result = post_tools.suggest_persistence(
                arguments.get("os_type", "linux")
            )
        elif name == "webshell_execute":
            result = post_tools.webshell_execute(
                url=arguments["url"],
                command=arguments["command"],
                password=arguments["password"]
            )
        elif name == "generate_webshell":
            result = post_tools.generate_webshell(
                password=arguments["password"],
                filename=arguments.get("filename", "shell.php"),
                obfuscate=arguments.get("obfuscate", False)
            )
        elif name == "webshell_upload":
            result = post_tools.webshell_upload(
                target_url=arguments["target_url"],
                shell_code=arguments["shell_code"],
                upload_path=arguments["upload_path"],
                method=arguments.get("method", "form")
            )

        else:
            result = {
                "success": False,
                "error": f"Unknown tool: {name}"
            }

        # Format result
        import json
        return format_tool_result(result)

    except Exception as e:
        logger.error(f"Error executing tool {name}: {e}", exc_info=True)
        return format_tool_result({
            "success": False,
            "error": str(e)
        })


async def main():
    """Main entry point"""
    logger.info("Starting Kali MCP Server")

    # Log configuration
    logger.info(f"Security manager initialized with config: {security_manager.config.get('authorization', {})}")

    # Run server
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="kali-mcp",
                server_version="1.0.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={}
                )
            )
        )


if __name__ == "__main__":
    asyncio.run(main())
