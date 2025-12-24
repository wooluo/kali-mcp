#!/bin/bash
#
# 安装systemd服务
# 使Kali MCP Server作为系统服务运行
#

set -e

GREEN='\033[0;32m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }

# 获取当前路径
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER=$(whoami)

info "创建systemd服务..."

# 创建服务文件
sudo tee /etc/systemd/system/kali-mcp.service > /dev/null << EOF
[Unit]
Description=Kali MCP Server
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$PROJECT_DIR
Environment="PATH=$PROJECT_DIR/venv/bin:/usr/local/bin:/usr/bin:/bin"
Environment="LOG_LEVEL=INFO"
ExecStart=$PROJECT_DIR/venv/bin/python -m kali_mcp.server
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

info "服务文件已创建"

# 重载systemd
sudo systemctl daemon-reload

info "启动服务..."
sudo systemctl start kali-mcp

info "启用开机自启..."
sudo systemctl enable kali-mcp

# 显示状态
sudo systemctl status kali-mcp --no-pager

echo ""
info "服务已安装并启动！"
info ""
info "常用命令："
echo "  查看状态: sudo systemctl status kali-mcp"
echo "  查看日志: sudo journalctl -u kali-mcp -f"
echo "  停止服务: sudo systemctl stop kali-mcp"
echo "  重启服务: sudo systemctl restart kali-mcp"
