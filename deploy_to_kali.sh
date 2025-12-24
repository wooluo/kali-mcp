#!/bin/bash
#
# Kali MCP Server 部署脚本
# 将此项目部署到远程Kali Linux机器
#

set -e

# ============ 配置区域 ============
KALI_USER="wooluo"           # Kali机器的用户名
KALI_HOST="10.211.55.4"  # Kali机器的IP地址
KALI_PATH="/home/wooluo/kali-mcp"  # 部署路径

# ============ 颜色输出 ============
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# ============ 检查SSH连接 ============
info "检查SSH连接到 ${KALI_USER}@${KALI_HOST}..."

if ! ssh -o ConnectTimeout=5 "${KALI_USER}@${KALI_HOST}" "echo 'SSH连接成功'" 2>/dev/null; then
    error "无法连接到 ${KALI_USER}@${KALI_HOST}"
    echo ""
    echo "请确保："
    echo "1. Kali机器正在运行"
    echo "2. SSH服务已启用: sudo systemctl start ssh"
    echo "3. 网络连接正常"
    echo "4. 可以手动测试: ssh ${KALI_USER}@${KALI_HOST}"
    exit 1
fi

info "SSH连接正常 ✓"

# ============ 在Kali上创建项目目录 ============
info "在Kali上创建项目目录..."
ssh "${KALI_USER}@${KALI_HOST}" "mkdir -p ${KALI_PATH}"

# ============ 同步项目文件 ============
info "同步项目文件到Kali..."
rsync -avz --progress \
    --exclude 'venv' \
    --exclude '__pycache__' \
    --exclude '*.pyc' \
    --exclude '.git' \
    --exclude '.DS_Store' \
    ./ "${KALI_USER}@${KALI_HOST}:${KALI_PATH}/"

# ============ 在Kali上安装系统依赖 ============
info "在Kali上安装系统工具..."
ssh "${KALI_USER}@${KALI_HOST}" << 'ENDSSH'
set -e

echo "更新软件包列表..."
sudo apt update

echo "安装Python开发工具..."
sudo apt install -y python3 python3-pip python3-venv python3-dev

echo "安装安全工具..."
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
    john \
    curl \
    git

echo "安装Python DNS库..."
sudo apt install -y python3-dnspython

echo "系统工具安装完成 ✓"
ENDSSH

# ============ 在Kali上创建Python虚拟环境 ============
info "在Kali上创建Python虚拟环境..."
ssh "${KALI_USER}@${KALI_HOST}" << ENDSSH
cd ${KALI_PATH}

# 创建虚拟环境
python3 -m venv venv

# 激活虚拟环境并安装依赖
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "Python依赖安装完成 ✓"
ENDSSH

# ============ 配置环境变量 ============
info "配置环境变量..."
ssh "${KALI_USER}@${KALI_HOST}" << ENDSSH
cd ${KALI_PATH}

if [ ! -f .env ]; then
    cp .env.example .env
    echo "已创建 .env 文件"
fi
ENDSSH

# ============ 设置日志目录权限 ============
info "设置日志目录权限..."
ssh "${KALI_USER}@${KALI_HOST}" << 'ENDSSH'
# 创建日志目录
sudo mkdir -p /var/log
sudo touch /var/log/kali_mcp.log
sudo chown $USER:$USER /var/log/kali_mcp.log
echo "日志文件已设置: /var/log/kali_mcp.log"
ENDSSH

# ============ 测试MCP服务器 ============
info "测试MCP服务器..."
ssh "${KALI_USER}@${KALI_HOST}" << ENDSSH
cd ${KALI_PATH}
source venv/bin/activate

# 测试导入
python3 -c "from kali_mcp import __version__; print(f'Kali MCP Server version: {__version__}')"

echo "服务器测试成功 ✓"
ENDSSH

# ============ 创建systemd服务（可选）============
info "创建systemd服务..."
ssh "${KALI_USER}@${KALI_HOST}" << 'ENDSSH'
SERVICE_FILE="/tmp/kali-mcp.service"

cat > $SERVICE_FILE << 'EOF'
[Unit]
Description=Kali MCP Server
After=network.target

[Service]
Type=simple
User=wooluo
WorkingDirectory=/home/wooluo/kali-mcp
Environment="PATH=/home/wooluo/kali-mcp/venv/bin:/usr/local/bin:/usr/bin:/bin"
Environment="LOG_LEVEL=INFO"
ExecStart=/home/wooluo/kali-mcp/venv/bin/python -m kali_mcp.server
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

echo "服务文件已创建: $SERVICE_FILE"
echo "要启用服务，请运行:"
echo "  sudo mv $SERVICE_FILE /etc/systemd/system/"
echo "  sudo systemctl daemon-reload"
echo "  sudo systemctl enable kali-mcp"
echo "  sudo systemctl start kali-mcp"
ENDSSH

# ============ 显示连接信息 ============
info ""
info "=========================================="
info "部署完成！"
info "=========================================="
info ""
info "Kali机器: ${KALI_USER}@${KALI_HOST}"
info "项目路径: ${KALI_PATH}"
info ""
info "下一步："
info ""
info "1. 测试连接:"
echo "   ssh ${KALI_USER}@${KALI_HOST}"
echo ""
info "2. 在macOS上配置Claude Desktop"
echo ""
info "   编辑: ~/Library/Application Support/Claude/claude_desktop_config.json"
echo ""
info "   添加:"
cat << EOF

{
  "mcpServers": {
    "kali": {
      "command": "ssh",
      "args": [
        "${KALI_USER}@${KALI_HOST}",
        "cd ${KALI_PATH} && source venv/bin/activate && python -m kali_mcp.server"
      ]
    }
  }
}

EOF

info ""
info "3. 或者本地运行测试:"
echo "   ssh ${KALI_USER}@${KALI_HOST}"
echo "   cd ${KALI_PATH}"
echo "   source venv/bin/activate"
echo "   python -m kali_mcp.server"
echo ""
info "=========================================="
