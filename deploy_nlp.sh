#!/bin/bash

# Deploy Natural Language Processing updates to Kali

set -e

echo "========================================"
echo "Kali MCP NLP Update Deployment"
echo "========================================"
echo ""

KALI_HOST="wooluo@10.211.55.4"
KALI_DIR="~/kali"
LOCAL_DIR="/Users/wooluo/DEV/kali"

echo "Step 1: Copying assistant.py to Kali..."
scp $LOCAL_DIR/kali_mcp/assistant.py $KALI_HOST:$KALI_DIR/kali_mcp/assistant.py
echo "✓ assistant.py copied"
echo ""

echo "Step 2: Copying updated server.py to Kali..."
scp $LOCAL_DIR/kali_mcp/server.py $KALI_HOST:$KALI_DIR/kali_mcp/server.py
echo "✓ server.py copied"
echo ""

echo "Step 3: Restarting MCP server on Kali..."
ssh $KALI_HOST "pkill -9 -f 'python.*kali_mcp.server' || true"
sleep 1
ssh $KALI_HOST "cd $KALI_DIR && source venv/bin/activate && nohup python -m kali_mcp.server > /tmp/kali_mcp.log 2>&1 &"
echo "✓ MCP server restarted"
echo ""

echo "Step 4: Verifying deployment..."
ssh $KALI_HOST "ps aux | grep 'python.*kali_mcp.server' | grep -v grep"
echo ""

echo "========================================"
echo "✓ Deployment Complete!"
echo "========================================"
echo ""
echo "New feature: Natural Language Assistant!"
echo ""
echo "Usage examples in CherryStudio:"
echo "  kali_assistant with message='scan 192.168.1.1'"
echo "  kali_assistant with message='generate webshell password:123'"
echo "  kali_assistant with message='whois example.com'"
echo "  kali_assistant with message='扫描端口 192.168.1.1'"
echo "  kali_assistant with message='生成webshell 密码123'"
echo ""
echo "Just describe what you want in English or Chinese!"
echo ""
