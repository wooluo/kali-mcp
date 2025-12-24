# Kali MCP 服务器

**中文** | [English](README.md)

一个模型上下文协议(MCP)服务器，将 Kali Linux 安全工具暴露给 Claude AI，用于授权的安全测试和渗透测试。

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Kali Linux](https://img.shields.io/badge/Kali%20Linux-Supported-red.svg)](https://www.kali.org/)

## 🌟 特性

### 自然语言界面
- **AI驱动的助手**：使用简单的英语或中文与 Kali 工具交互
- 只需说：*"扫描 192.168.1.1"* 或 *"generate webshell password:123"*

### 全面的工具集
- **信息收集**：网络扫描、DNS枚举、WHOIS查询、HTTP头分析
- **漏洞扫描**：Nmap、Nikto、SSL/TLS扫描、目录暴力破解
- **渗透利用**：Metasploit框架、Hydra、sqlmap、weevely webshell
- **后渗透**：Webshell生成/管理、权限提升、持久化
- **实用工具**：Base64、Hex、URL编码、哈希、ROT13、XOR

### 安全优先
- 对危险操作进行内置授权检查
- 全面的审计日志记录
- 网络范围限制（允许/阻止列表）
- 速率限制以防止滥用

## 📋 系统要求

- **Kali Linux**（或兼容的基于Debian的系统）
- **Python 3.11+**
- **SSH访问**（用于远程部署）
- 常见的Kali工具：`nmap`、`metasploit-framework`、`hydra`、`nikto`、`weevely`、`sqlmap`

## 🚀 快速开始

### 方式1：Kali上自动安装

```bash
# 克隆仓库
git clone https://github.com/wooluo/kali-mcp.git
cd kali-mcp

# 运行安装脚本
chmod +x install_on_kali.sh
./install_on_kali.sh
```

### 方式2：手动安装

```bash
# 1. 创建虚拟环境
python3 -m venv venv
source venv/bin/activate

# 2. 安装依赖
pip install -r requirements.txt

# 3. 安装weevely所需的额外Python包
pip install mako prettytable pyyaml jinja2 requests paramiko cryptography pillow

# 4. 启动服务器
python -m kali_mcp.server
```

## ⚙️ 配置

### 安全配置 (`config.yaml`)

```yaml
authorization:
  allowed_ranges: []          # 留空以允许所有，或指定网络
  blocked_ranges: []          # 要阻止的网络（例如 ["127.0.0.0/8"]）
  require_auth_for_exploitation: true

security:
  rate_limit:
    enabled: true
    max_requests_per_minute: 60

logging:
  file: /var/log/kali_mcp.log
  level: INFO
```

### Claude Desktop / CherryStudio 配置

添加到你的MCP配置中：

**本地连接：**
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

**远程SSH连接：**
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

## 💡 使用示例

### 使用自然语言助手

只需用简单的中文或英语描述你想要什么：

**中文示例：**
```
"扫描 192.168.1.1 的开放端口"
"生成一个密码为123的webshell"
"查询 example.com 的whois信息"
"搜索 vsftpd 漏洞"
"暴力破解 http://example.com 的目录"
"对 http://example.com/page?id=1 进行SQL注入测试"
```

**英文示例：**
```
"Scan 192.168.1.1 for open ports"
"Generate a webshell with password: mypass123"
"Whois lookup for example.com"
"Search for vsftpd exploits"
"Brute force directories on http://example.com"
"Test SQL injection on http://example.com/page?id=1"
```

### 直接调用工具

或直接调用特定工具：

```python
# 端口扫描
nmap_scan(target="192.168.1.1", ports="1-1000", scan_type="-sS")

# Webshell生成
generate_webshell(password="mypass123", filename="shell.php")

# WHOIS查询
whois_lookup(domain="example.com")

# 漏洞搜索
searchsploit(query="apache 2.4.49")

# SQL注入测试
sqlmap_scan(url="http://example.com/page?id=1")
```

## 🛠️ 可用工具

### 信息收集 (Reconnaissance)
- `nmap_scan` - 使用Nmap进行端口和服务扫描
- `ping_sweep` - 发现网络中的存活主机
- `whois_lookup` - 域名/IP的WHOIS信息
- `dns_enumerate` - DNS记录枚举（A、AAAA、MX、NS、TXT等）
- `dns_brute_force` - 子域名暴力破解
- `http_headers` - 从URL获取HTTP头
- `ssl_cert_info` - SSL/TLS证书信息

### 漏洞扫描 (Vulnerability Scanning)
- `nikto_scan` - Web服务器漏洞扫描器
- `ssl_scan` - SSL/TLS配置扫描
- `dir_brute_force` - 目录和文件暴力破解
- `smb_enum` - SMB共享枚举

### 渗透利用（需要授权）
- `searchsploit` - 搜索Exploit-DB
- `hydra_crack` - 使用Hydra进行密码暴力破解
- `generate_payload` - 使用msfvenom生成载荷
- `sqlmap_scan` - 使用sqlmap进行SQL注入测试
- `msf_exploit` - 执行Metasploit漏洞利用
- `msf_auxiliary` - 运行Metasploit辅助模块

### 后渗透（需要授权）
- `generate_webshell` - 使用weevely生成webshell
- `webshell_execute` - 通过webshell执行命令
- `webshell_upload` - 上传webshell到目标
- `suggest_privilege_escalation` - 提权向量建议
- `suggest_persistence` - 持久化机制建议

### 实用工具 (Utilities)
- `base64_encode/decode` - Base64编码/解码
- `url_encode/decode` - URL编码/解码
- `hex_encode/decode` - 十六进制编码/解码
- `hash_data` - 哈希数据（MD5、SHA1、SHA256、SHA512）
- `identify_hash` - 识别哈希类型
- `rot13` - ROT13密码
- `xor_data` - XOR编码/解码
- `generate_random_string` - 生成随机字符串

## 🔒 安全特性

### 授权系统
- 危险操作（渗透利用、后渗透）需要明确授权
- 为不同操作类型配置危险级别
- 在关键操作前提示用户确认

### 审计日志
所有操作都记录以下信息：
- 时间戳
- 操作类型
- 目标
- 参数
- 结果
- 用户身份

### 网络限制
- 允许范围白名单（可选）
- 阻止范围黑名单
- 支持CIDR表示法
- 主名旁路（当无法确定IP时）

### 速率限制
- 可配置的每分钟请求数
- 防止自动化滥用
- 保护你的系统和目标

## ⚠️ 法律和道德使用

**重要提示**：此工具仅用于**授权安全测试**。

### 要求：
- ✅ 获得系统所有者的书面许可
- ✅ 仅测试你拥有或获得授权测试的系统
- ✅ 遵循负责任的披露实践
- ✅ 遵守所有适用的法律法规
- ✅ 使用适当的速率限制

### 禁止：
- ❌ 未经授权扫描你不拥有的网络
- ❌ 在没有明确许可的情况下测试系统
- ❌ 用于恶意目的
- ❌ 违反任何地方法律或国际法

**开发者不对本工具的误用负责。**

## 📁 项目结构

```
kali-mcp/
├── kali_mcp/
│   ├── __init__.py
│   ├── __main__.py
│   ├── server.py              # 主MCP服务器
│   ├── assistant.py           # 自然语言AI助手
│   ├── security.py            # 安全和授权
│   └── tools/
│       ├── __init__.py
│       ├── recon.py           # 信息收集工具
│       ├── scan.py            # 扫描工具
│       ├── exploit.py         # 渗透利用工具
│       ├── post.py            # 后渗透工具
│       └── utils.py           # 实用函数
├── config.yaml                # 配置文件
├── requirements.txt           # Python依赖
├── install_on_kali.sh         # 安装脚本
├── setup.py                   # 包设置
├── claude_config_example.json # MCP配置示例
└── README.md                  # 本文件
```

## 🤝 贡献

欢迎贡献！请确保：

1. **授权检查** - 所有危险工具都需要授权
2. **文档** - 全面的文档字符串和注释
3. **错误处理** - 优雅的失败和有用的消息
4. **审计日志** - 记录所有操作
5. **测试** - 首先在安全环境中测试

### 添加新工具

1. 在适当的`tools/`模块中创建函数
2. 如需要，添加安全验证
3. 在`server.py`工具列表中注册
4. 在`handle_call_tool()`中添加处理器
5. 更新文档

## 🐛 故障排除

### 常见问题

**工具未找到：**
```bash
sudo apt install nmap metasploit-framework hydra nikto weevely sqlmap
```

**权限被拒绝：**
- 使用适当的权限运行
- 为特定命令配置sudoers

**SSH连接失败：**
- 设置SSH密钥认证
- 测试：`ssh user@kali-ip`

**weevely不工作：**
```bash
pip install mako prettytable pyyaml jinja2 requests
```

### 调试模式

启用调试日志：
```bash
LOG_LEVEL=DEBUG python -m kali_mcp.server
```

## 📄 许可证

本项目按原样提供，用于授权安全测试目的。

请负责任且合法地使用。

## 🙏 致谢

- Anthropic的MCP（模型上下文协议）
- Kali Linux团队
- 所有集成的开源安全工具

## 📞 支持

如有问题、疑问或贡献：
- 在GitHub上提出issue
- 查看现有文档
- 查看工具特定的帮助文本

## 🌟 Star历史

[![Star History Chart](https://api.star-history.com/svg?repos=wooluo/kali-mcp&type=Date)](https://star-history.com/#wooluo/kali-mcp&Date)

---

**记住**：能力越大，责任越大。请合乎道德且合法地使用此工具！

## 📷 截图和演示

### 自然语言助手示例

```
用户: "帮我扫描一下本地网络的开放端口"
助手: 正在执行nmap扫描...
     发现5个开放端口：22, 80, 443, 3306, 8080

用户: "生成一个密码为admin888的webshell"
助手: ✓ 已生成webshell
     文件：/home/kali/shell.php
     密码：admin888
     大小：688字节

用户: "查询example.com的域名信息"
助手: WHOIS信息：
     注册商：Example Registrar
     创建时间：1995-08-13
     域名状态：active
```

## 📚 相关资源

- [Kali Linux文档](https://www.kali.org/docs/)
- [MCP协议文档](https://modelcontextprotocol.io/)
- [Claude AI文档](https://docs.anthropic.com/)
- [OWASP测试指南](https://owasp.org/www-project-web-security-testing-guide/)

## 🔗 有用的链接

- [更新日志](CHANGELOG.md)
- [贡献指南](CONTRIBUTING.md)
- [安全政策](SECURITY.md)
- [演示视频](https://youtu.be/example)（待添加）

---

**English Version**: [README.md](README.md)

**Made with ❤️ for the security community**
