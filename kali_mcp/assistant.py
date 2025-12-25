"""
Natural Language Assistant for Kali MCP

Allows users to use natural language to interact with Kali tools
"""

import re
import json
from typing import Dict, Any, Optional, List
import subprocess

from .tools import ReconTools, ScanTools, ExploitTools, PostTools, Utils
from .security import OperationType, get_security_manager


class KaliAssistant:
    """Natural language assistant for Kali tools"""

    def __init__(self):
        self.recon_tools = ReconTools()
        self.scan_tools = ScanTools()
        self.exploit_tools = ExploitTools()
        self.post_tools = PostTools()
        self.utils = Utils()
        self.security = get_security_manager()

        # Intent patterns for natural language understanding
        self.intent_patterns = {
            'nmap_scan': [
                r'scan\s+(\S+)',
                r'nmap\s+(\S+)',
                r'check\s+open\s+ports?\s+(?:on\s+)?(\S+)',
                r'port\s+scan\s+(\S+)',
                r'枚举.*?端口\s*(\S+)',
                r'扫描.*?端口\s*(\S+)',
            ],
            'ping_sweep': [
                r'ping\s+sweep\s+(\S+)',
                r'find\s+live\s+hosts?\s+(\S+)',
                r'discover\s+hosts?\s+(\S+)',
                r'查找.*?主机\s*(\S+)',
            ],
            'whois': [
                r'whois\s+(\S+)',
                r'lookup\s+(?:domain\s+)?(\S+)',
                r'查询.*?域名\s*(\S+)|whois\s*(\S+)',
            ],
            'dns_enum': [
                r'dns\s+enum\s+(\S+)',
                r'enumerate\s+dns\s+(\S+)',
                r'get\s+dns\s+records?\s+(\S+)',
                r'枚举.*?DNS\s*(\S+)',
            ],
            'nikto_scan': [
                r'nikto\s+(\S+)',
                r'web\s+scan\s+(\S+)',
                r'scan\s+web\s+server\s+(\S+)',
                r'网站.*?扫描\s*(\S+)',
            ],
            'ssl_scan': [
                r'ssl\s+scan\s+(\S+)',
                r'check\s+ssl\s+(\S+)',
                r'test\s+tls\s+(\S+)',
                r'检查.*?SSL\s*(\S+)',
            ],
            'dir_brute': [
                r'brute\s+force\s+dirs?\s+(\S+)',
                r'directory\s+brute\s+(\S+)',
                r'find\s+dirs?\s+(\S+)',
                r'爆破.*?目录\s*(\S+)',
            ],
            'smb_enum': [
                r'smb\s+enum\s+(\S+)',
                r'enumerate\s+smb\s+(\S+)',
                r'check\s+smb\s+shares?\s+(\S+)',
                r'枚举.*?SMB\s*(\S+)',
            ],
            'searchsploit': [
                r'search\s+(?:exploit|exploits?)\s+(\S+)',
                r'find\s+exploits?\s+(\S+)',
                r'searchsploit\s+(\S+)',
                r'搜索.*?漏洞\s*(\S+)',
            ],
            'hydra_crack': [
                r'crack\s+(\S+)',
                r'hydra\s+(\S+)',
                r'brute\s+force\s+(\S+)',
                r'爆破.*?密码\s*(\S+)',
            ],
            'john_crack': [
                r'john\s+(\S+)',
                r'crack\s+hash(?:es)?\s+(\S+)',
                r'john\s+the\s+ripper\s+(\S+)',
                r'使用.*?john.*?破解\s*(\S+)',
            ],
            'wpscan': [
                r'wpscan\s+(\S+)',
                r'scan\s+wordpress\s+(\S+)',
                r'wordpress\s+scan\s+(\S+)',
                r'扫描.*?wordpress\s*(\S+)',
            ],
            'enum4linux': [
                r'enum4linux\s+(\S+)',
                r'enum\s+windows\s+(\S+)',
                r'enum\s+samba\s+(\S+)',
                r'枚举.*?windows\s*(\S+)',
            ],
            'health_check': [
                r'health\s+check',
                r'check\s+health',
                r'system\s+status',
                r'健康.*?检查',
                r'系统.*?状态',
            ],
            'generate_payload': [
                r'generate\s+payload',
                r'create\s+payload',
                r'make\s+payload',
                r'生成\s+载荷',
            ],
            'generate_webshell': [
                r'generate\s+webshell',
                r'create\s+webshell',
                r'make\s+shell',
                r'生成\s+webshell|生成\s+shell',
            ],
            'sqlmap': [
                r'sqlmap\s+(\S+)',
                r'test\s+sql\s+inject\s+(\S+)',
                r'sql\s+inject(?:ion)?\s+(\S+)',
                r'SQL.*?注入\s*(\S+)',
            ],
            'base64': [
                r'base64\s+(encode|decode)\s+(.+)',
                r'(encode|decode)\s+base64\s+(.+)',
            ],
            'hash': [
                r'hash\s+(\w+)\s+(.+)',
                r'(md5|sha1|sha256|sha512)\s+(.+)',
            ],
            'suggest_privesc': [
                r'suggest\s+privilege\s+escalation',
                r'privilege\s+escalation\s+suggestions?',
                r'提权.*?建议',
            ],
            'suggest_persistence': [
                r'suggest\s+persistence',
                r'persistence\s+suggestions?',
                r'持久化.*?建议',
            ],
        }

    def parse_intent(self, text: str) -> Dict[str, Any]:
        """
        Parse natural language to extract intent and parameters

        Args:
            text: Natural language input

        Returns:
            Dictionary with intent, parameters, and confidence
        """
        text = text.strip().lower()

        best_match = None
        best_confidence = 0

        for intent, patterns in self.intent_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    # Calculate confidence based on match specificity
                    confidence = len(match.group(0)) / len(text)
                    if confidence > best_confidence:
                        best_confidence = confidence
                        best_match = {
                            'intent': intent,
                            'params': list(match.groups()),
                            'full_text': text,
                            'confidence': confidence
                        }

        if best_match and best_confidence > 0.3:
            return best_match

        return {
            'intent': None,
            'params': [],
            'full_text': text,
            'confidence': 0,
            'error': 'Could not understand the request'
        }

    def execute_natural_command(self, text: str) -> Dict[str, Any]:
        """
        Execute a natural language command

        Args:
            text: Natural language command

        Returns:
            Execution result
        """
        # Parse intent
        parsed = self.parse_intent(text)

        if not parsed['intent']:
            return {
                'success': False,
                'error': 'I could not understand your request',
                'input': text,
                'suggestions': self.get_command_suggestions()
            }

        intent = parsed['intent']
        params = parsed['params']

        # Execute the appropriate tool
        try:
            if intent == 'nmap_scan':
                target = params[0]
                # Check for additional parameters in text
                ports = self.extract_param(text, r'ports?\s*:?\s*(\d+(?:-\d+)?)', r'(\d+-\d+)', '1-1024')
                return self.recon_tools.nmap_scan(target=target, ports=ports)

            elif intent == 'ping_sweep':
                network = params[0]
                return self.recon_tools.ping_sweep(network=network)

            elif intent == 'whois':
                domain = params[0]
                return self.recon_tools.whois_lookup(domain=domain)

            elif intent == 'dns_enum':
                domain = params[0]
                return self.recon_tools.dns_enumerate(domain=domain)

            elif intent == 'nikto_scan':
                target = params[0]
                port = self.extract_param(text, r'port\s*:?\s*(\d+)', '(\d+)', 80)
                use_https = 'https' in text or 'tls' in text
                return self.scan_tools.nikto_scan(target=target, port=port, use_https=use_https)

            elif intent == 'ssl_scan':
                hostname = params[0]
                port = self.extract_param(text, r'port\s*:?\s*(\d+)', '(\d+)', 443)
                return self.scan_tools.ssl_scan(hostname=hostname, port=port)

            elif intent == 'dir_brute':
                target = params[0]
                port = self.extract_param(text, r'port\s*:?\s*(\d+)', '(\d+)', 80)
                use_https = 'https' in text
                return self.scan_tools.dir_brute_force(target=target, port=port, use_https=use_https)

            elif intent == 'smb_enum':
                target = params[0]
                return self.scan_tools.smb_enum(target=target)

            elif intent == 'searchsploit':
                query = params[0]
                return self.exploit_tools.searchsploit_search(query=query)

            elif intent == 'hydra_crack':
                target = params[0]
                service = self.extract_param(text, r'service\s*:?\s*(\w+)', '(ssh|ftp|http|https)', 'ssh')
                username = self.extract_param(text, r'user\s*:?\s*(\w+)', '(\w+)', 'admin')
                return self.exploit_tools.hydra_crack(target=target, service=service, username=username)

            elif intent == 'john_crack':
                hash_file = params[0]
                wordlist = self.extract_param(text, r'wordlist\s*:?\s*(\S+)', '(\S+)', None)
                mode = self.extract_param(text, r'mode\s*:?\s*(\w+)', '(wordlist|single|incremental)', 'wordlist')
                return self.exploit_tools.john_crack(hash_file=hash_file, wordlist=wordlist, mode=mode)

            elif intent == 'wpscan':
                url = params[0]
                enumerate_type = self.extract_param(text, r'enum(?:erate)?\s*:?\s*(\w+)', '(\w+)', 'vp')
                return self.exploit_tools.wpscan_scan(url=url, enumerate_type=enumerate_type)

            elif intent == 'enum4linux':
                target = params[0]
                enumerate_all = 'all' in text or '-a' in text
                return self.exploit_tools.enum4linux_scan(target=target, enumerate_all=enumerate_all)

            elif intent == 'health_check':
                return self.utils.system_health_check()

            elif intent == 'generate_payload':
                # Extract parameters
                payload_type = self.extract_param(text, r'(?:payload|type)\s*:?\s*([\w/]+)', '[\w/]+', 'linux/meterpreter/reverse_tcp')
                lhost = self.extract_param(text, r'lhost\s*:?\s*([\d.]+)', '[\d.]+', '10.211.55.1')
                lport = int(self.extract_param(text, r'lport\s*:?\s*(\d+)', '(\d+)', '4444'))
                format_type = self.extract_param(text, r'format\s*:?\s*(\w+)', '(\w+)', 'raw')
                return self.exploit_tools.generate_payload(
                    payload_type=payload_type,
                    lhost=lhost,
                    lport=lport,
                    format=format_type
                )

            elif intent == 'generate_webshell':
                password = self.extract_param(text, r'pass(?:word)?\s*:?\s*(\S+)', '(\S+)', '123')
                filename = self.extract_param(text, r'file\s*:?\s*(\S+)', '(\S+)', 'shell.php')
                return self.post_tools.generate_webshell(password=password, filename=filename)

            elif intent == 'sqlmap':
                url = params[0]
                return self.exploit_tools.sqlmap_scan(url=url)

            elif intent == 'base64':
                action = params[0]
                data = params[1]
                if action == 'encode':
                    return self.utils.base64_encode(data)
                else:
                    return self.utils.base64_decode(data)

            elif intent == 'hash':
                algorithm = params[0]
                data = params[1]
                return self.utils.hash_data(data=data, algorithm=algorithm)

            elif intent == 'suggest_privesc':
                os_type = self.extract_param(text, r'(windows|linux)', '(windows|linux)', 'linux')
                return self.post_tools.suggest_privilege_escalation(os_type=os_type)

            elif intent == 'suggest_persistence':
                os_type = self.extract_param(text, r'(windows|linux)', '(windows|linux)', 'linux')
                return self.post_tools.suggest_persistence(os_type=os_type)

            else:
                return {
                    'success': False,
                    'error': f'Intent "{intent}" not yet implemented',
                    'parsed_intent': parsed
                }

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'parsed_intent': parsed,
                'traceback': str(e)
            }

    def extract_param(self, text: str, *patterns) -> str:
        """
        Extract parameter from text using multiple patterns

        Args:
            text: Input text
            *patterns: Variable number of (pattern, default) tuples or just patterns

        Returns:
            Extracted value or default
        """
        for item in patterns:
            if isinstance(item, tuple) and len(item) == 2:
                pattern, default = item
            else:
                pattern = item
                default = None

            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)

            if default is not None:
                return default

        return ""

    def get_command_suggestions(self) -> List[str]:
        """Get list of example commands"""
        return [
            "Scan a target: 'scan 192.168.1.1' or 'nmap 192.168.1.1'",
            "Ping sweep: 'ping sweep 192.168.1.0/24'",
            "WHOIS lookup: 'whois example.com'",
            "DNS enumeration: 'dns enum example.com'",
            "Web scan: 'nikto scan example.com'",
            "SSL check: 'ssl scan example.com'",
            "Directory brute force: 'brute force dirs example.com'",
            "SMB enumeration: 'smb enum 192.168.1.1'",
            "Search exploits: 'search exploit vsftpd 2.3.4'",
            "Generate webshell: 'generate webshell password:123 file:shell.php'",
            "SQL injection test: 'sqlmap http://example.com/page?id=1'",
            "Base64 encode/decode: 'base64 encode hello world'",
            "Generate hash: 'hash sha256 password123'",
            "Privilege escalation suggestions: 'suggest privilege escalation'",
            "John the Ripper: 'john hashes.txt wordlist:/path/to/wordlist.txt'",
            "WPScan: 'wpscan https://example.com'",
            "Enum4linux: 'enum4linux 192.168.1.1'",
            "Health check: 'health check' or 'system status'",
        ]

    def chat(self, message: str) -> Dict[str, Any]:
        """
        Chat interface for natural language interaction

        Args:
            message: User message

        Returns:
            Response with result or suggestions
        """
        # Check for greetings
        greetings = r'^(hi|hello|hey|help|what can you do|帮助|你好)$'
        if re.match(greetings, message, re.IGNORECASE):
            return {
                'success': True,
                'message': 'Hello! I\'m your Kali security assistant. I can help you with:',
                'capabilities': [
                    'Network reconnaissance (nmap, ping sweep, whois, DNS)',
                    'Vulnerability scanning (nikto, SSL, directory brute force)',
                    'Exploitation tools (searchsploit, hydra, sqlmap, metasploit)',
                    'Post-exploitation (webshells, persistence, privilege escalation)',
                    'Utilities (base64, hashing, encoding)',
                ],
                'examples': self.get_command_suggestions()[:5],
                'usage': 'Just tell me what you want to do in plain English or Chinese!'
            }

        # Execute command
        result = self.execute_natural_command(message)

        # Add human-readable response
        if result.get('success'):
            result['message'] = f"✓ Command completed successfully"
        else:
            result['message'] = f"✗ Command failed: {result.get('error', 'Unknown error')}"

        return result
