"""
Utility Tools

Provides encoding, decoding, and other utility functions.
"""

import base64
import hashlib
import binascii
import urllib.parse
import re
import json
from typing import Optional, Dict, Any

from ..security import OperationType, get_security_manager


class Utils:
    """Utility functions for encoding, decoding, and data manipulation"""

    def __init__(self):
        self.security = get_security_manager()
        self.operation_type = OperationType.UTILITY

    def base64_encode(self, data: str) -> Dict[str, Any]:
        """
        Encode data to Base64

        Args:
            data: String data to encode

        Returns:
            Dictionary with encoded data
        """
        try:
            encoded = base64.b64encode(data.encode()).decode()
            self.security.log_operation(
                self.operation_type, "base64_encode", None,
                {"data_length": len(data)}, "success"
            )
            return {
                "success": True,
                "encoded": encoded,
                "original_length": len(data),
                "encoded_length": len(encoded)
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def base64_decode(self, data: str) -> Dict[str, Any]:
        """
        Decode Base64 data

        Args:
            data: Base64 encoded string

        Returns:
            Dictionary with decoded data
        """
        try:
            decoded = base64.b64decode(data).decode()
            self.security.log_operation(
                self.operation_type, "base64_decode", None,
                {"data_length": len(data)}, "success"
            )
            return {
                "success": True,
                "decoded": decoded,
                "original_length": len(data),
                "decoded_length": len(decoded)
            }
        except Exception as e:
            return {"success": False, "error": f"Invalid Base64: {str(e)}"}

    def url_encode(self, data: str) -> Dict[str, Any]:
        """
        URL encode data

        Args:
            data: String to encode

        Returns:
            Dictionary with encoded data
        """
        try:
            encoded = urllib.parse.quote(data)
            self.security.log_operation(
                self.operation_type, "url_encode", None,
                {"data_length": len(data)}, "success"
            )
            return {
                "success": True,
                "encoded": encoded,
                "original": data
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def url_decode(self, data: str) -> Dict[str, Any]:
        """
        URL decode data

        Args:
            data: URL encoded string

        Returns:
            Dictionary with decoded data
        """
        try:
            decoded = urllib.parse.unquote(data)
            self.security.log_operation(
                self.operation_type, "url_decode", None,
                {"data_length": len(data)}, "success"
            )
            return {
                "success": True,
                "decoded": decoded,
                "original": data
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def hex_encode(self, data: str) -> Dict[str, Any]:
        """
        Encode data to hexadecimal

        Args:
            data: String to encode

        Returns:
            Dictionary with hex encoded data
        """
        try:
            encoded = data.encode().hex()
            self.security.log_operation(
                self.operation_type, "hex_encode", None,
                {"data_length": len(data)}, "success"
            )
            return {
                "success": True,
                "encoded": encoded,
                "original": data
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def hex_decode(self, data: str) -> Dict[str, Any]:
        """
        Decode hexadecimal data

        Args:
            data: Hexadecimal string

        Returns:
            Dictionary with decoded data
        """
        try:
            decoded = bytes.fromhex(data).decode()
            self.security.log_operation(
                self.operation_type, "hex_decode", None,
                {"data_length": len(data)}, "success"
            )
            return {
                "success": True,
                "decoded": decoded,
                "original": data
            }
        except Exception as e:
            return {"success": False, "error": f"Invalid hex: {str(e)}"}

    def hash_data(self, data: str, algorithm: str = "sha256") -> Dict[str, Any]:
        """
        Hash data with specified algorithm

        Args:
            data: String to hash
            algorithm: Hash algorithm (md5, sha1, sha256, sha512)

        Returns:
            Dictionary with hash result
        """
        try:
            algorithm = algorithm.lower()
            if algorithm == "md5":
                hash_obj = hashlib.md5()
            elif algorithm == "sha1":
                hash_obj = hashlib.sha1()
            elif algorithm == "sha256":
                hash_obj = hashlib.sha256()
            elif algorithm == "sha512":
                hash_obj = hashlib.sha512()
            else:
                return {"success": False, "error": f"Unsupported algorithm: {algorithm}"}

            hash_obj.update(data.encode())
            hashed = hash_obj.hexdigest()

            self.security.log_operation(
                self.operation_type, "hash", None,
                {"algorithm": algorithm, "data_length": len(data)}, "success"
            )

            return {
                "success": True,
                "hash": hashed,
                "algorithm": algorithm,
                "input_length": len(data)
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def identify_hash(self, hash_value: str) -> Dict[str, Any]:
        """
        Identify the type of hash based on length and format

        Args:
            hash_value: Hash string to identify

        Returns:
            Dictionary with identified hash type(s)
        """
        hash_types = []

        # Check length
        length = len(hash_value)

        if length == 32:
            hash_types.append("MD5")
        elif length == 40:
            hash_types.append("SHA-1")
        elif length == 64:
            hash_types.append("SHA-256")
        elif length == 128:
            hash_types.append("SHA-512")
        elif length == 16:
            hash_types.append("MySQL323")
        elif length == 41 and hash_value.startswith("*"):
            hash_types.append("MySQL SHA-1")

        # Check format
        if re.match(r'^\$[156]\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}', hash_value):
            hash_types.append("Unix crypt (MD5/SHA-256/SHA-512)")

        if re.match(r'^\$2[aby]?\$', hash_value):
            hash_types.append("bcrypt")

        if re.match(r'^\$argon2', hash_value):
            hash_types.append("Argon2")

        self.security.log_operation(
            self.operation_type, "identify_hash", None,
            {"hash_length": length}, "success"
        )

        return {
            "success": True,
            "hash_value": hash_value,
            "length": length,
            "possible_types": hash_types if hash_types else ["Unknown or custom format"]
        }

    def rot13(self, data: str) -> Dict[str, Any]:
        """
        Apply ROT13 cipher

        Args:
            data: String to encode/decode

        Returns:
            Dictionary with ROT13 result
        """
        try:
            result = ""
            for char in data:
                if 'a' <= char <= 'z':
                    result += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
                elif 'A' <= char <= 'Z':
                    result += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
                else:
                    result += char

            self.security.log_operation(
                self.operation_type, "rot13", None,
                {"data_length": len(data)}, "success"
            )

            return {
                "success": True,
                "result": result,
                "original": data
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def xor_data(self, data: str, key: str) -> Dict[str, Any]:
        """
        XOR encode/decode data with a key

        Args:
            data: String to encode/decode
            key: XOR key

        Returns:
            Dictionary with XOR result
        """
        try:
            data_bytes = data.encode()
            key_bytes = key.encode()

            result = bytearray()
            for i, byte in enumerate(data_bytes):
                result.append(byte ^ key_bytes[i % len(key_bytes)])

            result_hex = result.hex()

            self.security.log_operation(
                self.operation_type, "xor", None,
                {"data_length": len(data), "key_length": len(key)}, "success"
            )

            return {
                "success": True,
                "result_hex": result_hex,
                "result_raw": result.decode(errors='replace'),
                "key": key
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def json_format(self, data: str) -> Dict[str, Any]:
        """
        Format JSON string

        Args:
            data: JSON string

        Returns:
            Dictionary with formatted JSON
        """
        try:
            parsed = json.loads(data)
            formatted = json.dumps(parsed, indent=2)

            self.security.log_operation(
                self.operation_type, "json_format", None,
                {"data_length": len(data)}, "success"
            )

            return {
                "success": True,
                "formatted": formatted,
                "parsed": parsed
            }
        except Exception as e:
            return {"success": False, "error": f"Invalid JSON: {str(e)}"}

    def generate_random_string(self, length: int = 16, charset: str = "alphanumeric") -> Dict[str, Any]:
        """
        Generate a random string

        Args:
            length: Length of string to generate
            charset: Character set (alphanumeric, alpha, numeric, hex)

        Returns:
            Dictionary with generated string
        """
        import secrets
        import string

        try:
            if charset == "alphanumeric":
                chars = string.ascii_letters + string.digits
            elif charset == "alpha":
                chars = string.ascii_letters
            elif charset == "numeric":
                chars = string.digits
            elif charset == "hex":
                chars = string.hexdigits.lower()
            else:
                return {"success": False, "error": f"Unknown charset: {charset}"}

            result = ''.join(secrets.choice(chars) for _ in range(length))

            self.security.log_operation(
                self.operation_type, "random_string", None,
                {"length": length, "charset": charset}, "success"
            )

            return {
                "success": True,
                "string": result,
                "length": length,
                "charset": charset
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def system_health_check(self) -> Dict[str, Any]:
        """
        Check system health and installed tools availability

        Returns:
            Dictionary with health status and tool availability
        """
        import subprocess
        import platform
        
        essential_tools = {
            "nmap": "Port scanner",
            "gobuster": "Directory brute force",
            "dirb": "Directory brute force alternative", 
            "nikto": "Web vulnerability scanner",
            "hydra": "Password cracker",
            "sqlmap": "SQL injection tester",
            "msfconsole": "Metasploit framework",
            "weevely": "Webshell tool",
            "john": "Password cracker",
            "wpscan": "WordPress scanner",
            "enum4linux": "SMB/Windows enumerator"
        }

        tools_status = {}
        for tool, description in essential_tools.items():
            try:
                result = subprocess.run(
                    ["which", tool],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                installed = result.returncode == 0
                tools_status[tool] = {
                    "installed": installed,
                    "description": description,
                    "path": result.stdout.strip() if installed else None
                }
            except:
                tools_status[tool] = {
                    "installed": False,
                    "description": description,
                    "error": "Check failed"
                }

        # Count statistics
        total_tools = len(essential_tools)
        installed_tools = sum(1 for t in tools_status.values() if t.get("installed", False))
        
        # System info
        system_info = {
            "platform": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "architecture": platform.machine(),
            "hostname": platform.node()
        }

        # Python packages check
        python_packages = {}
        packages_to_check = ["mako", "prettytable", "pyyaml", "requests", "paramiko"]
        for package in packages_to_check:
            try:
                __import__(package)
                python_packages[package] = True
            except ImportError:
                python_packages[package] = False

        return {
            "success": True,
            "system_info": system_info,
            "tools_status": tools_status,
            "summary": {
                "total_tools": total_tools,
                "installed_tools": installed_tools,
                "missing_tools": total_tools - installed_tools,
                "readiness": installed_tools / total_tools * 100
            },
            "python_packages": python_packages,
            "recommendations": self._generate_recommendations(tools_status, python_packages)
        }

    def _generate_recommendations(self, tools_status: Dict, python_packages: Dict) -> list:
        """Generate installation recommendations based on missing tools"""
        recommendations = []

        # Missing Kali tools
        missing_tools = [name for name, status in tools_status.items() 
                         if not status.get("installed", False)]
        if missing_tools:
            recommendations.append({
                "type": "kali_tools",
                "priority": "high",
                "message": f"Install missing Kali tools: {', '.join(missing_tools)}",
                "command": f"sudo apt install -y {' '.join(missing_tools)}"
            })

        # Missing Python packages
        missing_packages = [name for name, installed in python_packages.items() 
                           if not installed]
        if missing_packages:
            recommendations.append({
                "type": "python_packages",
                "priority": "medium",
                "message": f"Install missing Python packages: {', '.join(missing_packages)}",
                "command": f"pip install {' '.join(missing_packages)}"
            })

        return recommendations
