# Kali MCP Server

A Model Context Protocol (MCP) server that exposes Kali Linux security tools to Claude AI for authorized security testing and penetration testing.

## 🌟 Features

### Natural Language Interface
- **AI-Powered Assistant**: Use plain English or Chinese to interact with Kali tools
- Just say: *"scan 192.168.1.1"* or *"生成webshell 密码123"*

### Comprehensive Toolset
- **Reconnaissance**: Network scanning, DNS enumeration, WHOIS lookups, HTTP headers
- **Vulnerability Scanning**: Nmap, Nikto, SSL/TLS scanning, directory brute forcing
- **Exploitation**: Metasploit framework, Hydra, sqlmap, weevely webshells
- **Post-Exploitation**: Webshell generation/management, privilege escalation, persistence
- **Utilities**: Base64, Hex, URL encoding, hashing, ROT13, XOR

### Security First
- Built-in authorization checks for dangerous operations
- Comprehensive audit logging
- Network range restrictions (allow/block lists)
- Rate limiting to prevent abuse

## 📋 Prerequisites

- **Kali Linux** (or compatible Debian-based system)
- **Python 3.11+**
- **SSH access** (for remote deployment)
- Common Kali tools: `nmap`, `metasploit-framework`, `hydra`, `nikto`, `weevely`, `sqlmap`

## 🚀 Quick Start

### Option 1: Automated Installation on Kali

```bash
# Clone the repository
git clone https://github.com/yourusername/kali-mcp.git
cd kali-mcp

# Run the installation script
chmod +x install_on_kali.sh
./install_on_kali.sh
```

### Option 2: Manual Installation

```bash
# 1. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Install additional Python packages for weevely
pip install mako prettytable pyyaml jinja2 requests paramiko cryptography pillow

# 4. Start the server
python -m kali_mcp.server
```

## ⚙️ Configuration

### Security Configuration (`config.yaml`)

```yaml
authorization:
  allowed_ranges: []          # Leave empty to allow all, or specify networks
  blocked_ranges: []          # Networks to block (e.g., ["127.0.0.0/8"])
  require_auth_for_exploitation: true

security:
  rate_limit:
    enabled: true
    max_requests_per_minute: 60

logging:
  file: /var/log/kali_mcp.log
  level: INFO
```

### Claude Desktop / CherryStudio Configuration

Add to your MCP configuration:

**For Local Connection:**
```json
{
  "mcpServers": {
    "kali": {
      "command": "python",
      "args": ["/path/to/kali-mcp/kali_mcp/server.py"],
      "env": {
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

**For Remote SSH Connection:**
```json
{
  "mcpServers": {
    "kali": {
      "command": "ssh",
      "args": [
        "user@your-kali-ip",
        "cd /path/to/kali-mcp && source venv/bin/activate && python -m kali_mcp.server"
      ],
      "env": {
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

## 💡 Usage Examples

### Using the Natural Language Assistant

Just describe what you want in plain English or Chinese:

**English Examples:**
```
"Scan 192.168.1.1 for open ports"
"Generate a webshell with password: mypass123"
"Whois lookup for example.com"
"Search for vsftpd exploits"
"Brute force directories on http://example.com"
"Test SQL injection on http://example.com/page?id=1"
```

**中文 Examples:**
```
"扫描 192.168.1.1 的开放端口"
"生成webshell 密码123"
"查询 example.com 的whois信息"
"搜索 vsftpd 漏洞"
"爆破目录 http://example.com"
```

### Direct Tool Usage

Or call specific tools directly:

```python
# Port scanning
nmap_scan(target="192.168.1.1", ports="1-1000", scan_type="-sS")

# Webshell generation
generate_webshell(password="mypass123", filename="shell.php")

# WHOIS lookup
whois_lookup(domain="example.com")

# Exploit search
searchsploit(query="apache 2.4.49")

# SQL injection testing
sqlmap_scan(url="http://example.com/page?id=1")
```

## 🛠️ Available Tools

### Reconnaissance
- `nmap_scan` - Port and service scanning with Nmap
- `ping_sweep` - Discover live hosts on network
- `whois_lookup` - Domain/IP WHOIS information
- `dns_enumerate` - DNS record enumeration (A, AAAA, MX, NS, TXT, etc.)
- `dns_brute_force` - Subdomain brute forcing
- `http_headers` - Get HTTP headers from URL
- `ssl_cert_info` - SSL/TLS certificate information

### Vulnerability Scanning
- `nikto_scan` - Web server vulnerability scanner
- `ssl_scan` - SSL/TLS configuration scanning
- `dir_brute_force` - Directory and file brute forcing
- `smb_enum` - SMB shares enumeration

### Exploitation (Requires Authorization)
- `searchsploit` - Search Exploit-DB
- `hydra_crack` - Password brute forcing with Hydra
- `generate_payload` - Generate payloads with msfvenom
- `sqlmap_scan` - SQL injection testing with sqlmap
- `msf_exploit` - Execute Metasploit exploits
- `msf_auxiliary` - Run Metasploit auxiliary modules

### Post-Exploitation (Requires Authorization)
- `generate_webshell` - Generate webshells with weevely
- `webshell_execute` - Execute commands through webshell
- `webshell_upload` - Upload webshell to target
- `suggest_privilege_escalation` - Suggest privesc vectors
- `suggest_persistence` - Suggest persistence mechanisms

### Utilities
- `base64_encode/decode` - Base64 encoding/decoding
- `url_encode/decode` - URL encoding/decoding
- `hex_encode/decode` - Hexadecimal encoding/decoding
- `hash_data` - Hash data (MD5, SHA1, SHA256, SHA512)
- `identify_hash` - Identify hash type
- `rot13` - ROT13 cipher
- `xor_data` - XOR encoding/decoding
- `generate_random_string` - Generate random strings

## 🔒 Security Features

### Authorization System
- Dangerous operations (exploitation, post-exploitation) require explicit authorization
- Configurable danger levels for different operation types
- User confirmation prompts before critical actions

### Audit Logging
All operations logged with:
- Timestamp
- Operation type
- Target
- Parameters
- Results
- User identification

### Network Restrictions
- Allowed ranges whitelist (optional)
- Blocked ranges blacklist
- CIDR notation supported
- Hostname bypass (when IP cannot be determined)

### Rate Limiting
- Configurable requests per minute
- Prevents automated abuse
- Protects both your systems and targets

## ⚠️ Legal and Ethical Use

**IMPORTANT**: This tool is designed for **authorized security testing only**.

### Requirements:
- ✅ Written permission from system owners
- ✅ Only test systems you own or are authorized to test
- ✅ Follow responsible disclosure practices
- ✅ Comply with all applicable laws and regulations
- ✅ Use appropriate rate limiting

### Prohibited:
- ❌ Unauthorized scanning of networks you don't own
- ❌ Testing systems without explicit permission
- ❌ Using for malicious purposes
- ❌ Violating any local or international laws

**The developers are not responsible for misuse of this tool.**

## 📁 Project Structure

```
kali-mcp/
├── kali_mcp/
│   ├── __init__.py
│   ├── __main__.py
│   ├── server.py              # Main MCP server
│   ├── assistant.py           # Natural language AI assistant
│   ├── security.py            # Security & authorization
│   └── tools/
│       ├── __init__.py
│       ├── recon.py           # Reconnaissance tools
│       ├── scan.py            # Scanning tools
│       ├── exploit.py         # Exploitation tools
│       ├── post.py            # Post-exploitation tools
│       └── utils.py           # Utility functions
├── config.yaml                # Configuration file
├── requirements.txt           # Python dependencies
├── install_on_kali.sh         # Installation script
├── setup.py                   # Package setup
├── claude_config_example.json # Example MCP config
└── README.md                  # This file
```

## 🤝 Contributing

Contributions are welcome! Please ensure:

1. **Authorization Checks** - All dangerous tools require authorization
2. **Documentation** - Comprehensive docstrings and comments
3. **Error Handling** - Graceful failure with helpful messages
4. **Audit Logging** - Log all operations
5. **Testing** - Test in safe environments first

### Adding New Tools

1. Create function in appropriate `tools/` module
2. Add security validation if needed
3. Register in `server.py` tool list
4. Add handler in `handle_call_tool()`
5. Update documentation

## 🐛 Troubleshooting

### Common Issues

**Tool not found:**
```bash
sudo apt install nmap metasploit-framework hydra nikto weevely sqlmap
```

**Permission denied:**
- Run with appropriate privileges
- Configure sudoers for specific commands

**SSH connection fails:**
- Setup SSH key authentication
- Test: `ssh user@kali-ip`

**weevely not working:**
```bash
pip install mako prettytable pyyaml jinja2 requests
```

### Debug Mode

Enable debug logging:
```bash
LOG_LEVEL=DEBUG python -m kali_mcp.server
```

## 📄 License

This project is provided as-is for authorized security testing purposes.

Use responsibly and legally.

## 🙏 Acknowledgments

- MCP (Model Context Protocol) by Anthropic
- Kali Linux team
- All open-source security tools integrated

## 📞 Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Check existing documentation
- Review tool-specific help text

---

**Remember**: With great power comes great responsibility. Use this tool ethically and legally!
