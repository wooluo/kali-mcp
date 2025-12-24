# Kali MCP Server - Quick Start Guide

快速开始使用Kali MCP服务器，将Kali Linux的安全工具集成到Claude AI中。

## 安装步骤

### 1. 环境准备

确保你在Kali Linux或兼容的系统上：

```bash
# 检查Python版本
python3 --version  # 需要 Python 3.11+
```

### 2. 安装Python依赖

```bash
# 创建虚拟环境（推荐）
python3 -m venv venv
source venv/bin/activate

# 安装Python包
pip install -r requirements.txt
```

### 3. 安装Kali工具（如果未安装）

```bash
# 更新包列表
sudo apt update

# 安装常用安全工具
sudo apt install -y \
    nmap \
    metasploit-framework \
    hydra \
    nikto \
    gobuster \
    sqlmap \
    wpscan \
    smbclient \
    whois \
    dnsutils \
    exploitdb \
    sslscan \
    dirb \
    john
```

### 4. 配置环境

```bash
# 复制环境变量模板
cp .env.example .env

# 编辑配置（可选）
nano .env
```

### 5. 配置Claude Desktop

编辑Claude Desktop配置文件：

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%/Claude/claude_desktop_config.json`

添加以下内容：

```json
{
  "mcpServers": {
    "kali": {
      "command": "python",
      "args": [
        "-m",
        "kali_mcp.server"
      ],
      "cwd": "/path/to/kali-mcp",
      "env": {
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

**重要**: 将 `/path/to/kali-mcp` 替换为实际的项目路径。

### 6. 重启Claude Desktop

重启Claude Desktop应用以加载MCP服务器。

## 使用示例

### 侦察（Reconnaissance）

```
# 端口扫描
"使用nmap扫描192.168.1.100的常用端口"

# WHOIS查询
"查询example.com的WHOIS信息"

# DNS枚举
"枚举example.com的DNS记录"

# DNS爆破
"对example.com进行子域名爆破"
```

### 漏洞扫描（Scanning）

```
# Web扫描
"用Nikto扫描http://example.com"

# SSL扫描
"扫描example.com的SSL配置"

# 目录爆破
"对http://example.com进行目录和文件爆破"
```

### 工具（Utilities）

```
# Base64编码/解码
"将'Hello World'编码为Base64"
"解码Base64: SGVsbG8gV29ybGQ="

# URL编码
"URL编码: hello world"

# 哈希计算
"计算字符串'password'的SHA256哈希值"

# 哈希识别
"识别这个哈希的类型: 5f4dcc3b5aa765d61d8327deb882cf99"

# 随机字符串生成
"生成一个32字符的字母数字随机字符串"
```

### 渗透测试（Exploitation） - 需要授权

```
# 搜索漏洞利用
"搜索Apache 2.4.49的漏洞利用"

# 生成Payload
"生成一个Linux reverse TCP payload，监听IP 192.168.1.50，端口4444"

# 密码破解（需要授权）
"使用hydra对ssh://192.168.1.100进行密码破解，用户名admin"
```

### 后渗透（Post-Exploitation） - 需要授权

```
# 权限提升建议
"给出Linux系统的权限提升建议"

# 持久化建议
"列出Windows系统的持久化方法"
```

## 安全特性

### 授权要求

以下操作需要明确授权：
- 任何渗透测试工具（hydra、msfconsole等）
- 后渗透操作
- 权限提升和持久化

### 审计日志

所有操作都会被记录到 `/var/log/kali_mcp.log`（默认）：

```bash
# 查看日志
tail -f /var/log/kali_mcp.log
```

### 网络限制

可以在 `config.yaml` 中配置允许/禁止的网络范围：

```yaml
authorization:
  allowed_ranges: ["192.168.1.0/24"]  # 仅允许此范围
  blocked_ranges: ["127.0.0.0/8"]     # 禁止此范围
```

## 故障排除

### 问题：工具未找到

```bash
# 安装缺失的工具
sudo apt install nmap nikto gobuster
```

### 问题：权限被拒绝

某些工具需要root权限：

```bash
# 使用sudo运行
sudo python -m kali_mcp.server
```

或在sudoers中添加特定命令权限。

### 问题：MCP服务器未启动

1. 检查Claude Desktop配置文件中的路径
2. 查看Claude Desktop日志
3. 手动测试服务器：
   ```bash
   python -m kali_mcp.server
   ```

### 问题：超时

某些扫描可能需要更长时间。可以在 `config.yaml` 中调整：

```yaml
tools:
  reconnaissance:
    timeout: 600  # 增加到10分钟
```

## 常见工作流程

### 1. 渗透测试工作流

```
1. 信息收集
   "扫描目标网络192.168.1.0/24的主机"
   "对发现的每个主机进行端口扫描"

2. 漏洞识别
   "扫描发现的Web服务"
   "枚举SMB共享"

3. 漏洞利用
   "搜索发现的服务的漏洞利用"
   "生成测试payload"

4. 后渗透
   "建议权限提升方法"
   "建议持久化机制"
```

### 2. Web应用安全测试

```
1. 侦察
   "获取example.com的HTTP头"
   "枚举DNS记录"

2. 扫描
   "使用Nikto扫描网站"
   "进行目录爆破"

3. 漏洞搜索
   "搜索发现的CMS版本的漏洞"
```

## 法律和道德使用

**重要提醒**：

- ⚠️ 仅在**授权**的系统上使用这些工具
- ⚠️ 获取书面测试许可
- ⚠️ 遵守当地法律法规
- ⚠️ 负责任地披露发现的漏洞
- ⚠️ 不要在生产环境中使用可能导致服务中断的测试

## 进阶配置

### 自定义Wordlist

在 `config.yaml` 中指定自定义字典文件路径。

### 代理配置

对于需要通过代理的扫描，设置环境变量：

```bash
export HTTP_PROXY=http://proxy.example.com:8080
export HTTPS_PROXY=http://proxy.example.com:8080
```

### 自定义工具路径

如果工具安装在非标准位置，可以在 `config.yaml` 中配置。

## 获取帮助

遇到问题？

1. 检查日志文件：`/var/log/kali_mcp.log`
2. 查看配置文件：`config.yaml`
3. 确认所有依赖已安装

## 贡献

欢迎提交问题和改进建议！

---

**免责声明**: 此工具仅用于授权的安全测试。用户对确保其使用合法性负有全部责任。
