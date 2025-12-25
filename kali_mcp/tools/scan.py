"""
Vulnerability Scanning Tools

Provides vulnerability scanning capabilities.
"""

import subprocess
import re
import os
from typing import Dict, Any, List, Optional

from ..security import OperationType, get_security_manager


class ScanTools:
    """Vulnerability scanning tools"""

    def __init__(self):
        self.security = get_security_manager()
        self.operation_type = OperationType.SCAN

    def nikto_scan(self, target: str, port: int = 80, use_https: bool = False,
                   scan_type: str = "basic", additional_args: str = "") -> Dict[str, Any]:
        """
        Run Nikto web server scanner

        Args:
            target: Target hostname or IP
            port: Port number
            use_https: Use HTTPS instead of HTTP
            scan_type: Scan intensity (basic, light, heavy)
            additional_args: Additional Nikto arguments

        Returns:
            Dictionary with scan results
        """
        allowed, reason = self.security.validate_operation(self.operation_type, target)
        if not allowed:
            return {"success": False, "error": reason}

        try:
            protocol = "https" if use_https else "http"
            url = f"{protocol}://{target}:{port}"

            cmd = ["nikto", "-h", url]

            # Add additional arguments if provided
            if additional_args:
                cmd.extend(additional_args.split())

            cmd.extend(["-Format", "json", "-output", "-"])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            # Nikto outputs JSON with some prefix text
            output = result.stdout

            # Try to extract vulnerabilities
            vulnerabilities = []
            vuln_pattern = r'(\+|OSVDB-\d+):(.+)'
            for line in output.split('\n'):
                match = re.match(vuln_pattern, line)
                if match:
                    vulnerabilities.append(match.group(2).strip())

            self.security.log_operation(
                self.operation_type, "nikto_scan", target,
                {"port": port, "https": use_https},
                f"success - {len(vulnerabilities)} findings"
            )

            return {
                "success": True,
                "target": url,
                "vulnerabilities": vulnerabilities[:50],  # Limit results
                "raw_output": output[:10000],
                "finding_count": len(vulnerabilities)
            }

        except FileNotFoundError:
            return {
                "success": False,
                "error": "Nikto not found. Install with: sudo apt install nikto"
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Scan timed out after 5 minutes"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def ssl_scan(self, hostname: str, port: int = 443, additional_args: str = "") -> Dict[str, Any]:
        """
        Scan SSL/TLS configuration using testssl.sh or sslscan

        Args:
            hostname: Target hostname
            port: Port number
            additional_args: Additional sslscan arguments

        Returns:
            Dictionary with SSL scan results
        """
        allowed, reason = self.security.validate_operation(self.operation_type, hostname)
        if not allowed:
            return {"success": False, "error": reason}

        # Try sslscan first
        try:
            cmd = ["sslscan"]

            # Add additional arguments if provided
            if additional_args:
                cmd.extend(additional_args.split())

            cmd.append(f"{hostname}:{port}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            output = result.stdout

            # Parse key findings
            findings = []

            # Check for weak ciphers
            if "WEAK" in output:
                findings.append("Weak ciphers detected")

            # Check for expired certificate
            if "expired" in output.lower():
                findings.append("Certificate expired or expiring soon")

            # Check for self-signed certificate
            if "self-signed" in output.lower():
                findings.append("Self-signed certificate detected")

            self.security.log_operation(
                self.operation_type, "ssl_scan", hostname,
                {"port": port}, "success"
            )

            return {
                "success": True,
                "target": f"{hostname}:{port}",
                "findings": findings,
                "raw_output": output[:5000]
            }

        except FileNotFoundError:
            # sslscan not available, try testssl.sh
            try:
                testssl_path = "/usr/bin/testssl.sh"
                if not os.path.exists(testssl_path):
                    return {
                        "success": False,
                        "error": "SSL scanning tools not found. Install with: sudo apt install sslscan"
                    }

                cmd = [testssl_path, "--quiet", "--color", "0", f"{hostname}:{port}"]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=120
                )

                return {
                    "success": True,
                    "target": f"{hostname}:{port}",
                    "raw_output": result.stdout[:5000],
                    "tool": "testssl.sh"
                }

            except Exception as e:
                return {"success": False, "error": f"SSL scan failed: {str(e)}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def dir_brute_force(self, target: str, port: int = 80,
                        wordlist: Optional[str] = None,
                        use_https: bool = False,
                        extensions: Optional[List[str]] = None,
                        additional_args: str = "") -> Dict[str, Any]:
        """
        Brute force directories and files using gobuster or similar

        Args:
            target: Target hostname or IP
            port: Port number
            wordlist: Path to wordlist
            use_https: Use HTTPS
            extensions: File extensions to check
            additional_args: Additional gobuster arguments

        Returns:
            Dictionary with discovered paths
        """
        allowed, reason = self.security.validate_operation(self.operation_type, target)
        if not allowed:
            return {"success": False, "error": reason}

        # Default wordlist
        if wordlist is None:
            wordlist = "/usr/share/wordlists/dirb/common.txt"

        if not os.path.exists(wordlist):
            return {"success": False, "error": f"Wordlist not found: {wordlist}"}

        try:
            protocol = "https" if use_https else "http"
            url = f"{protocol}://{target}:{port}"

            # Try gobuster
            cmd = [
                "gobuster", "dir",
                "-u", url,
                "-w", wordlist,
                "-t", "10",
                "-x", ",".join(extensions or ["php", "html", "txt"]),
                "-k",  # Skip TLS verification
                "-q"   # Quiet mode
            ]

            # Add additional arguments if provided
            if additional_args:
                cmd.extend(additional_args.split())

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            # Parse output
            discovered = []
            for line in result.stdout.split('\n'):
                if line.strip() and 'Status:' in line:
                    # Parse gobuster output: /path (Status: 200) [Size: 1234]
                    match = re.match(r'(/\S+).*?Status: (\d+)', line)
                    if match:
                        path, status = match.groups()
                        discovered.append({
                            "path": path,
                            "status_code": int(status),
                            "url": f"{url}{path}"
                        })

            self.security.log_operation(
                self.operation_type, "dir_brute", target,
                {"port": port, "wordlist": wordlist},
                f"success - {len(discovered)} paths found"
            )

            return {
                "success": True,
                "target": url,
                "discovered": discovered,
                "total_found": len(discovered)
            }

        except FileNotFoundError:
            # Try dirb as fallback
            try:
                cmd = ["dirb", f"{target}:{port}", wordlist]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=120
                )

                return {
                    "success": True,
                    "target": f"{target}:{port}",
                    "raw_output": result.stdout[:5000],
                    "tool": "dirb"
                }

            except FileNotFoundError:
                return {
                    "success": False,
                    "error": "Directory brute force tools not found. Install with: sudo apt install gobuster dirb"
                }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Scan timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def smb_enum(self, target: str) -> Dict[str, Any]:
        """
        Enumerate SMB shares and information

        Args:
            target: Target IP or hostname

        Returns:
            Dictionary with SMB information
        """
        allowed, reason = self.security.validate_operation(self.operation_type, target)
        if not allowed:
            return {"success": False, "error": reason}

        try:
            # Try smbclient
            cmd = ["smbclient", "-L", f"//{target}", "-N"]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            output = result.stdout

            # Parse shares
            shares = []
            for line in output.split('\n'):
                if line.strip() and not line.startswith('---') and not line.startswith('Sharename'):
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] not in ['$', 'IPC$']:
                        shares.append({
                            "name": parts[0],
                            "type": parts[1] if len(parts) > 1 else "Unknown"
                        })

            self.security.log_operation(
                self.operation_type, "smb_enum", target,
                {}, f"success - {len(shares)} shares found"
            )

            return {
                "success": True,
                "target": target,
                "shares": shares,
                "raw_output": output[:3000]
            }

        except FileNotFoundError:
            return {
                "success": False,
                "error": "SMB tools not found. Install with: sudo apt install smbclient"
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def wordpress_scan(self, url: str) -> Dict[str, Any]:
        """
        Scan WordPress installations using WPScan

        Args:
            url: Target WordPress URL

        Returns:
            Dictionary with WordPress vulnerabilities
        """
        allowed, reason = self.security.validate_operation(self.operation_type, url)
        if not allowed:
            return {"success": False, "error": reason}

        try:
            cmd = ["wpscan", "--url", url, "--no-update", "--enumerate", "vp"]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            output = result.stdout

            # Parse vulnerabilities
            vulnerabilities = []
            vuln_pattern = r'(\w+\s*\|\s*\w+).*?\[(\w+)\]'
            for match in re.finditer(vuln_pattern, output):
                vuln = match.group(1)
                vul_type = match.group(2)
                vulnerabilities.append({
                    "name": vuln,
                    "type": vul_type
                })

            self.security.log_operation(
                self.operation_type, "wordpress_scan", url,
                {}, f"success - {len(vulnerabilities)} findings"
            )

            return {
                "success": True,
                "target": url,
                "vulnerabilities": vulnerabilities[:20],
                "raw_output": output[:10000]
            }

        except FileNotFoundError:
            return {
                "success": False,
                "error": "WPScan not found. Install with: sudo apt install wpscan"
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def sqlmap_scan(self, url: str, param: Optional[str] = None) -> Dict[str, Any]:
        """
        Test for SQL injection using sqlmap

        Args:
            url: Target URL
            param: Parameter to test

        Returns:
            Dictionary with SQL injection test results
        """
        allowed, reason = self.security.validate_operation(self.operation_type, url)
        if not allowed:
            return {"success": False, "error": reason}

        try:
            cmd = ["sqlmap", "--url", url, "--batch", "--level=1", "--risk=1"]

            if param:
                cmd.extend(["-p", param])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            output = result.stdout

            # Check for injection results
            injection_detected = "sql injection" in output.lower()
            vulnerable = injection_detected and "vulnerable" in output.lower()

            self.security.log_operation(
                self.operation_type, "sqlmap_scan", url,
                {"param": param}, f"complete - vulnerable: {vulnerable}"
            )

            return {
                "success": True,
                "target": url,
                "vulnerable": vulnerable,
                "injection_detected": injection_detected,
                "raw_output": output[:10000]
            }

        except FileNotFoundError:
            return {
                "success": False,
                "error": "sqlmap not found. Install with: sudo apt install sqlmap"
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def gobuster_scan(self, url: str, mode: str = "dir",
                      wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                      additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Gobuster to find directories, DNS subdomains, or virtual hosts

        Args:
            url: The target URL
            mode: Scan mode (dir, dns, fuzz, vhost)
            wordlist: Path to wordlist file
            additional_args: Additional Gobuster arguments

        Returns:
            Scan results
        """
        allowed, reason = self.security.validate_operation(self.operation_type, url)
        if not allowed:
            return {"success": False, "error": reason}

        # Validate mode
        if mode not in ["dir", "dns", "fuzz", "vhost"]:
            return {
                "success": False,
                "error": f"Invalid mode: {mode}. Must be one of: dir, dns, fuzz, vhost"
            }

        try:
            cmd = ["gobuster", mode, "-u", url, "-w", wordlist]

            # Add additional arguments if provided
            if additional_args:
                cmd.extend(additional_args.split())

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            output = result.stdout

            # Parse results based on mode
            results = []
            if mode == "dir":
                for line in output.split('\n'):
                    if 'Status:' in line:
                        match = re.match(r'(/\S+).*?Status: (\d+)', line)
                        if match:
                            path, status = match.groups()
                            results.append({
                                "path": path,
                                "status_code": int(status),
                                "url": f"{url}{path}"
                            })

            self.security.log_operation(
                self.operation_type, "gobuster_scan", url,
                {"mode": mode}, f"success - {len(results)} results"
            )

            return {
                "success": True,
                "target": url,
                "mode": mode,
                "results": results[:100],  # Limit results
                "raw_output": output[:10000]
            }

        except FileNotFoundError:
            return {
                "success": False,
                "error": "Gobuster not found. Install with: sudo apt install gobuster"
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Scan timed out after 5 minutes"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def dirb_scan(self, url: str,
                  wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                  additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Dirb web content scanner

        Args:
            url: The target URL
            wordlist: Path to wordlist file
            additional_args: Additional Dirb arguments

        Returns:
            Scan results
        """
        allowed, reason = self.security.validate_operation(self.operation_type, url)
        if not allowed:
            return {"success": False, "error": reason}

        try:
            cmd = ["dirb", url, wordlist]

            # Add additional arguments if provided
            if additional_args:
                cmd.extend(additional_args.split())

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            output = result.stdout

            # Parse dirb output
            discovered = []
            for line in output.split('\n'):
                if line.strip() and '=>' in line and 'CODE:' in line:
                    # Parse: /path (CODE:200|SIZE:1234)
                    match = re.match(r'(/\S+).*?CODE:(\d+)', line)
                    if match:
                        path, code = match.groups()
                        discovered.append({
                            "path": path,
                            "status_code": int(code),
                            "url": f"{url}{path}"
                        })

            self.security.log_operation(
                self.operation_type, "dirb_scan", url,
                {"wordlist": wordlist}, f"success - {len(discovered)} found"
            )

            return {
                "success": True,
                "target": url,
                "discovered": discovered[:100],
                "raw_output": output[:10000]
            }

        except FileNotFoundError:
            return {
                "success": False,
                "error": "Dirb not found. Install with: sudo apt install dirb"
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Scan timed out after 5 minutes"}
        except Exception as e:
            return {"success": False, "error": str(e)}
