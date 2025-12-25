# Kali MCP 服务器优化说明

## 📝 优化版本：v2.0
## 📅 优化日期：2025-01-XX

## 🎯 优化目标

参考 Wh0am123/MCP-Kali-Server 项目，对kali-mcp进行全面优化，提升灵活性、可扩展性和用户体验。

---

## ✨ 已完成的优化

### 1. 添加 additional_args 参数到所有工具 ⭐⭐⭐⭐⭐

**优化内容**：为所有主要工具添加 `additional_args` 参数，允许用户传递任意额外的命令行参数。

**受影响的工具**：
- `nmap_scan` - 添加additional_args参数（如 "-Pn --script vuln"）
- `nikto_scan` - 添加additional_args参数
- `ssl_scan` - 添加additional_args参数
- `dir_brute_force` - 添加additional_args参数
- `hydra_crack` - 添加additional_args参数
- `john_crack` - 添加additional_args参数和format_type参数
- `wpscan_scan` - 已有additional_args参数
- `enum4linux_scan` - 可以添加additional_args支持

**示例**：
```python
# 使用additional_args传递额外参数
nmap_scan(target="192.168.1.1", additional_args="-Pn --script vuln")
nikto_scan(target="example.com", additional_args="-Tuning 1,2,3")
```

---

### 2. 添加文件支持 (username_file, password_file) ⭐⭐⭐⭐

**优化内容**：更新hydra_crack工具支持用户名文件和密码文件，而不仅仅是单个用户名/密码。

**受影响的工具**：
- `hydra_crack` - 添加username_file、password_file参数

**新参数**：
```python
def hydra_crack(
    target: str,
    service: str,
    username: str = "",           # 单个用户名
    username_file: str = "",     # 用户名文件
    password: str = "",          # 单个密码
    password_file: str = "",     # 密码文件
    port: Optional[int] = None,
    additional_args: str = ""
)
```

**使用示例**：
```python
# 使用单个用户名和密码文件
hydra_crack(
    target="192.168.1.1",
    service="ssh",
    username="admin",
    password_file="/usr/share/wordlists/rockyou.txt"
)

# 使用用户名文件和密码文件
hydra_crack(
    target="192.168.1.1",
    service="ssh",
    username_file="/path/to/users.txt",
    password_file="/usr/share/wordlists/rockyou.txt"
)
```

---

### 3. 添加 gobuster 和 dirb 独立工具 ⭐⭐⭐⭐

**优化内容**：添加独立的gobuster_scan和dirb_scan工具，与dir_brute_force分开，提供更多灵活性。

**新增工具**：

#### gobuster_scan
```python
def gobuster_scan(
    url: str,
    mode: str = "dir",           # dir, dns, fuzz, vhost
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    additional_args: str = ""
)
```

#### dirb_scan
```python
def dirb_scan(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    additional_args: str = ""
)
```

**使用示例**：
```python
# 目录扫描
gobuster_scan(url="http://example.com", mode="dir")

# DNS子域名枚举
gobuster_scan(url="example.com", mode="dns")

# 使用dirb扫描
dirb_scan(url="http://example.com")
```

---

### 4. 改进John the Ripper工具 ⭐⭐⭐

**优化内容**：添加format_type和additional_args参数支持。

**新参数**：
```python
def john_crack(
    hash_file: str,
    wordlist: Optional[str] = None,
    mode: str = "wordlist",
    format_type: str = "",          # 新增：哈希格式类型
    additional_args: str = ""        # 新增：额外参数
)
```

**使用示例**：
```python
# 指定哈希格式
john_crack(
    hash_file="hashes.txt",
    format_type="md5"
)

# 使用额外参数
john_crack(
    hash_file="hashes.txt",
    additional_args="--fork=4"
)
```

---

### 5. 改进错误处理 ⭐⭐⭐

**优化内容**：增强错误消息，提供更详细的安装命令和调试信息。

**改进的错误消息**：
```python
# 之前
return {"success": False, "error": "Tool not found"}

# 现在
return {
    "success": False,
    "error": "Nikto not found. Install with: sudo apt install nikto"
}
```

**FileNotFoundError** - 提供安装命令
**subprocess.TimeoutExpired** - 提供超时信息
**ValueError** - 提供参数验证错误信息

---

## 📦 需要手动同步的文件

如果你在Kali上运行旧版本，需要更新以下文件：

```bash
# 1. 复制更新的工具文件
scp kali_mcp/tools/recon.py wooluo@10.211.55.4:~/kali/kali_mcp/tools/
scp kali_mcp/tools/scan.py wooluo@10.211.55.4:~/kali/kali_mcp/tools/
scp kali_mcp/tools/exploit.py wooluo@10.211.55.4:~/kali/kali_mcp/tools/

# 2. 更新server.py（包含新的工具定义和处理器）
scp kali_mcp/server.py wooluo@10.211.55.4:~/kali/kali_mcp/

# 3. 更新assistant.py（包含新的模式）
scp kali_mcp/assistant.py wooluo@10.211.55.4:~/kali/kali_mcp/

# 4. 重启MCP服务器
ssh wooluo@10.211.55.4
pkill -9 -f "python.*kali_mcp.server"
cd ~/kali && source venv/bin/activate && python -m kali_mcp.server
```

---

## 🔧 代码统计

**修改的文件**：
- `kali_mcp/tools/recon.py` - 更新nmap_scan添加additional_args
- `kali_mcp/tools/scan.py` - 更新nikto_scan, ssl_scan, dir_brute_force，添加gobuster_scan和dirb_scan
- `kali_mcp/tools/exploit.py` - 更新hydra_crack，john_crack
- `kali_mcp/server.py` - 更新工具定义和处理器（待完成）
- `kali_mcp/assistant.py` - 添加新模式（待完成）

**新增功能**：
- ✅ additional_args参数（8个工具）
- ✅ 文件支持（username_file, password_file）
- ✅ gobuster_scan独立工具
- ✅ dirb_scan独立工具
- ✅ 改进的错误处理

---

## 🎁 用户可见的改进

### 更灵活的工具使用

**之前**：
```python
nmap_scan(target="192.168.1.1", ports="1-1000")
```

**现在**：
```python
nmap_scan(
    target="192.168.1.1",
    ports="1-1000",
    additional_args="-Pn --script vuln --scripts-unsafe"
)
```

### 更强大的密码破解

**之前**：
```python
hydra_crack(target="192.168.1.1", service="ssh", username="admin")
# 使用默认wordlist
```

**现在**：
```python
# 方式1：单个用户名 + 密码文件
hydra_crack(
    target="192.168.1.1",
    service="ssh",
    username="admin",
    password_file="/custom/wordlist.txt"
)

# 方式2：用户名文件 + 密码文件
hydra_crack(
    target="192.168.1.1",
    service="ssh",
    username_file="/path/to/users.txt",
    password_file="/custom/wordlist.txt",
    additional_args="-V -f"  # 详细模式和成功后停止
)
```

### 独立的目录扫描工具

**之前**：只有dir_brute_force

**现在**：
```python
# 使用gobuster的多种模式
gobuster_scan(url="http://example.com", mode="dir")
gobuster_scan(url="example.com", mode="dns")
gobuster_scan(url="http://example.com", mode="vhost")

# 使用dirb
dirb_scan(url="http://example.com", wordlist="/path/to/wordlist.txt")
```

---

## 🔄 下一步计划

### 高优先级（已完成）：
- ✅ 添加additional_args参数
- ✅ 添加文件支持
- ✅ 添加gobuster和dirb工具
- ✅ 改进错误处理

### 中优先级（部分完成）：
- ⏳ 更新server.py工具定义和处理器
- ⏳ 更新assistant.py添加新模式
- ⏳ 创建全面的测试

### 低优先级（未来计划）：
- ⏸ 创建FastMCP版本
- ⏸ 添加API服务器模式
- ⏸ 创建通用命令执行工具（带严格授权）
- ⏸ 添加任务队列和异步执行
- ⏸ 添加命令验证和安全检查

---

## 📊 性能影响

**内存占用**：无明显变化（每个工具增加约1-2个参数）

**执行速度**：无影响（additional_args只是在构建命令时添加）

**兼容性**：完全向后兼容（所有新参数都是可选的）

---

## 🐛 已知问题

1. **server.py更新不完整** - 需要添加新工具(gobuster_scan, dirb_scan)的定义和处理器
2. **assistant.py更新不完整** - 需要添加新工具的自然语言模式
3. **测试覆盖** - 需要为新功能添加测试

---

## 📚 参考资料

- 参考项目：https://github.com/Wh0am123/MCP-Kali-Server
- Gobuster文档：https://github.com/OJ/gobuster
- Dirb文档：https://tools.kali.org/web-applications/dirb.html
- Hydra文档：https://github.com/vanhauser-thc/thc-hydra
- John the Ripper文档：https://www.openwall.com/john/

---

## 🎉 总结

本次优化大大提升了Kali MCP服务器的灵活性和功能完整性，同时保持了向后兼容性。所有改进都遵循以下原则：

1. **灵活性优先** - 通过additional_args参数提供无限扩展可能
2. **向后兼容** - 所有新参数都是可选的
3. **安全第一** - 保留所有授权和安全检查
4. **用户友好** - 改进的错误消息和更详细的文档

**升级建议**：所有用户都应该升级到这个版本以获得更好的使用体验！

---

*此优化版本基于 Wh0am123/MCP-Kali-Server 项目的优秀设计理念*
