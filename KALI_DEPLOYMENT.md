# Kali Linux 部署指南

本指南介绍如何将Kali MCP服务器部署到远程Kali Linux机器。

## 方法一：自动部署（推荐）

### 1. 修改部署配置

编辑 `deploy_to_kali.sh`，修改以下配置：

```bash
KALI_USER="kali"           # Kali机器的用户名
KALI_HOST="192.168.1.100"  # Kali机器的IP地址
KALI_PATH="/home/kali/kali-mcp"  # 部署路径
```

### 2. 运行部署脚本

在macOS上执行：

```bash
cd /Users/wooluo/DEV/kali
./deploy_to_kali.sh
```

脚本会自动：
- ✓ 检查SSH连接
- ✓ 同步项目文件
- ✓ 安装系统工具
- ✓ 创建Python虚拟环境
- ✓ 安装Python依赖
- ✓ 配置日志文件
- ✓ 创建systemd服务

---

## 方法二：手动部署

### 步骤1：准备Kali机器

确保Kali Linux机器可以SSH访问：

```bash
# 在Kali上启动SSH服务
sudo systemctl start ssh
sudo systemctl enable ssh

# 查看IP地址
ip addr show
```

### 步骤2：传输项目到Kali

在macOS上执行：

```bash
# 压缩项目
cd /Users/wooluo/DEV/kali
tar czf kali-mcp.tar.gz \
    --exclude='venv' \
    --exclude='__pycache__' \
    --exclude='.git' \
    .

# 传输到Kali（替换为实际IP）
scp kali-mcp.tar.gz kali@192.168.1.100:/home/kali/
```

### 步骤3：在Kali上解压和安装

SSH登录到Kali：

```bash
ssh kali@192.168.1.100
```

在Kali上执行：

```bash
# 解压
cd ~
tar xzf kali-mcp.tar.gz
mv kali kali-mcp
cd kali-mcp

# 更新软件包
sudo apt update

# 安装系统工具
sudo apt install -y \
    python3 python3-pip python3-venv python3-dev \
    nmap metasploit-framework hydra nikto gobuster \
    sqlmap wpscan smbclient whois dnsutils \
    exploitdb sslscan dirb john curl git \
    python3-dnspython

# 创建虚拟环境
python3 -m venv venv
source venv/bin/activate

# 安装Python依赖
pip install --upgrade pip
pip install -r requirements.txt

# 配置环境变量
cp .env.example .env

# 创建日志文件
sudo touch /var/log/kali_mcp.log
sudo chown $USER:$USER /var/log/kali_mcp.log
```

### 步骤4：测试服务器

在Kali上测试：

```bash
source venv/bin/activate
python -m kali_mcp.server
```

按 `Ctrl+C` 停止测试。

---

## 配置Claude Desktop连接到远程Kali

### 选项1：SSH远程连接（推荐）

编辑macOS上的Claude配置文件：

```bash
nano ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

添加以下内容（替换为实际IP和用户）：

```json
{
  "mcpServers": {
    "kali": {
      "command": "ssh",
      "args": [
        "kali@192.168.1.100",
        "cd /home/kali/kali-mcp && source venv/bin/activate && python -m kali_mcp.server"
      ],
      "env": {
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

### 选项2：在Kali上运行持久服务

在Kali上创建systemd服务：

```bash
sudo nano /etc/systemd/system/kali-mcp.service
```

添加以下内容：

```ini
[Unit]
Description=Kali MCP Server
After=network.target

[Service]
Type=simple
User=kali
WorkingDirectory=/home/kali/kali-mcp
Environment="PATH=/home/kali/kali-mcp/venv/bin:/usr/local/bin:/usr/bin:/bin"
Environment="LOG_LEVEL=INFO"
ExecStart=/home/kali/kali-mcp/venv/bin/python -m kali_mcp.server
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

启动服务：

```bash
sudo systemctl daemon-reload
sudo systemctl enable kali-mcp
sudo systemctl start kali-mcp
sudo systemctl status kali-mcp
```

然后通过SSH隧道连接：

```bash
ssh -L 3000:localhost:3000 kali@192.168.1.100
```

---

## 验证部署

### 1. 在Kali上直接测试

```bash
ssh kali@192.168.1.100
cd ~/kali-mcp
source venv/bin/activate
python -c "from kali_mcp.tools import Utils; u = Utils(); print(u.base64_encode('Hello'))"
```

### 2. 测试远程工具

启动Claude Desktop后，在对话中测试：

```
"将'Hello World'编码为Base64"
"查询 example.com 的WHOIS信息"
```

---

## 常见问题

### SSH连接失败

```bash
# 检查Kali上的SSH服务
sudo systemctl status ssh

# 启动SSH
sudo systemctl start ssh
```

### 权限错误

某些工具需要root权限。可以：

1. 使用sudo运行服务器（不推荐）
2. 配置sudoers允许特定命令
3. 修改配置文件降低安全限制（仅测试环境）

### Python导入错误

```bash
# 重新安装依赖
cd ~/kali-mcp
source venv/bin/activate
pip install --force-reinstall -r requirements.txt
```

### 工具未找到

```bash
# 安装缺失的工具
sudo apt install nmap nikto gobuster  # 示例
```

---

## 网络拓扑示例

```
┌─────────────────┐
│   macOS (Claude) │
│   192.168.1.50  │
└────────┬─────────┘
         │ SSH
         │
┌────────▼─────────┐
│   Kali Linux     │
│   192.168.1.100  │
│   MCP Server     │
└──────────────────┘
```

---

## 安全建议

1. **使用SSH密钥认证**
   ```bash
   ssh-copy-id kali@192.168.1.100
   ```

2. **限制网络访问**
   - 在`config.yaml`中配置允许的IP范围

3. **启用防火墙**
   ```bash
   sudo ufw enable
   sudo ufw allow from 192.168.1.50  # 允许你的IP
   ```

4. **定期更新**
   ```bash
   sudo apt update && sudo apt upgrade
   ```

---

## 下一步

部署完成后：

1. ✓ 重启Claude Desktop
2. ✓ 在对话中测试："你好Kali，列出可用工具"
3. ✓ 开始安全测试："扫描目标网络的在线主机"

**⚠️ 法律提醒**: 仅在获得授权的系统上使用这些工具！
