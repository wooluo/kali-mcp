# 立即在Kali上安装

你已经在 `/home/wooluo/kali` 目录并有venv环境。

## 步骤1：运行安装脚本

```bash
cd /home/wooluo/kali
chmod +x install_current.sh
./install_current.sh
```

## 步骤2：测试服务器

```bash
# 方式1：手动测试
python -m kali_mcp.server

# 方式2：使用测试脚本
chmod +x test_server.sh
./test_server.sh
```

按 `Ctrl+C` 停止测试。

## 步骤3（可选）：安装为系统服务

```bash
chmod +x install_service_current.sh
./install_service_current.sh
```

## 步骤4：在macOS上配置Claude

编辑配置文件：
```bash
nano ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

添加：
```json
{
  "mcpServers": {
    "kali": {
      "command": "ssh",
      "args": [
        "wooluo@10.211.55.4",
        "cd /home/wooluo/kali && source venv/bin/activate && python -m kali_mcp.server"
      ]
    }
  }
}
```

重启Claude Desktop。
