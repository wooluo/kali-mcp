#!/bin/bash
#
# Kali MCP Server 安装脚本
# 在Kali Linux机器上运行此脚本
#

set -e

# ============ 颜色输出 ============
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
step() { echo -e "${BLUE}[STEP]${NC} $1"; }

info "=========================================="
info "  Kali MCP Server 安装脚本"
info "=========================================="
echo ""

# ============ 检查当前目录 ============
step "检查项目文件..."
if [ ! -f "requirements.txt" ] || [ ! -d "kali_mcp" ]; then
    error "请在项目根目录下运行此脚本"
    exit 1
fi

info "项目文件检查通过 ✓"
echo ""

# ============ 更新系统 ============
step "更新软件包列表..."
sudo apt update

info "软件包列表更新完成 ✓"
echo ""

# ============ 安装系统依赖 ============
step "安装系统工具和依赖..."

info "安装Python开发工具..."
sudo apt install -y python3 python3-pip python3-venv python3-dev

info "安装安全工具..."
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
    git \
    netcat-traditional

info "安装Python DNS库..."
sudo apt install -y python3-dnspython

info "安装其他Python库..."
sudo apt install -y python3-requests python3-aiohttp

info "系统工具安装完成 ✓"
echo ""

# ============ 创建Python虚拟环境 ============
step "创建Python虚拟环境..."

if [ -d "venv" ]; then
    warn "虚拟环境已存在，跳过创建"
else
    python3 -m venv venv
    info "虚拟环境创建完成 ✓"
fi

# 激活虚拟环境
source venv/bin/activate

# 升级pip
pip install --upgrade pip setuptools wheel

info "Python环境准备完成 ✓"
echo ""

# ============ 安装Python依赖 ============
step "安装Python依赖包..."

pip install -r requirements.txt

info "Python依赖安装完成 ✓"
echo ""

# ============ 配置环境 ============
step "配置环境..."

if [ ! -f ".env" ]; then
    cp .env.example .env
    info "已创建 .env 文件"
else
    info ".env 文件已存在"
fi

# 创建日志目录
sudo mkdir -p /var/log
sudo touch /var/log/kali_mcp.log
sudo chown $USER:$USER /var/log/kali_mcp.log

info "日志文件已创建: /var/log/kali_mcp.log"
echo ""

# ============ 测试导入 ============
step "测试Python模块导入..."

python3 -c "
import sys
try:
    from kali_mcp import __version__
    print(f'✓ Kali MCP Server version: {__version__}')

    from kali_mcp.tools import Utils
    from kali_mcp.tools import ReconTools
    from kali_mcp.tools import ScanTools
    from kali_mcp.tools import ExploitTools
    from kali_mcp.tools import PostTools
    print('✓ 所有工具模块导入成功')

    # 测试工具功能
    utils = Utils()
    result = utils.base64_encode('Hello Kali')
    if result['success']:
        print('✓ 工具功能测试通过')
    else:
        print('✗ 工具功能测试失败')
        sys.exit(1)

except Exception as e:
    print(f'✗ 导入测试失败: {e}')
    import traceback
    traceback.print_exc()
    sys.exit(1)
"

info "模块测试完成 ✓"
echo ""

# ============ 检查可用工具 ============
step "检查已安装的安全工具..."

tools_status=()

check_tool() {
    if command -v $1 &> /dev/null; then
        tools_status+=("✓ $2")
    else
        tools_status+=("✗ $2 (未安装)")
    fi
}

check_tool nmap "Nmap"
check_tool hydra "Hydra"
check_tool nikto "Nikto"
check_tool gobuster "Gobuster"
check_tool whois "WHOIS"
check_tool smbclient "SMBClient"
check_tool msfvenom "MSFvenom"
check_tool sqlmap "SQLMap"
check_tool john "John"

echo ""
info "工具状态："
for status in "${tools_status[@]}"; do
    if [[ $status == ✓* ]]; then
        echo -e "${GREEN}$status${NC}"
    else
        echo -e "${YELLOW}$status${NC}"
    fi
done
echo ""

# ============ 显示完成信息 ============
info "=========================================="
info "  安装完成！"
info "=========================================="
echo ""
info "项目路径: $(pwd)"
info "日志文件: /var/log/kali_mcp.log"
echo ""
info "下一步操作："
echo ""
echo "1. 测试服务器（手动运行）："
echo "   source venv/bin/activate"
echo "   python -m kali_mcp.server"
echo ""
echo "2. 或者启动后台服务："
echo "   ./install_service.sh"
echo ""
echo "3. 在macOS上配置Claude Desktop："
echo ""
cat << 'EOF'
   编辑: ~/Library/Application Support/Claude/claude_desktop_config.json

   添加:
   {
     "mcpServers": {
       "kali": {
         "command": "ssh",
         "args": [
           "wooluo@10.211.55.4",
           "cd $(pwd) && source venv/bin/activate && python -m kali_mcp.server"
         ]
       }
     }
   }
EOF

echo ""
echo "4. 重启Claude Desktop"
echo ""
echo "5. 测试连接："
echo "   在Claude中说: '将'Hello'编码为Base64'"
echo ""
info "=========================================="
