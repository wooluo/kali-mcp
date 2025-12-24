"""
Reconnaissance Tools

Provides network reconnaissance and information gathering capabilities.
"""

import subprocess
import socket
import json
import re
from typing import Dict, Any, List, Optional
from ipaddress import ip_network, ip_address

from ..security import OperationType, get_security_manager


class ReconTools:
    """Reconnaissance tools for network information gathering"""

    def __init__(self):
        self.security = get_security_manager()
        self.operation_type = OperationType.RECON

    def nmap_scan(self, target: str, ports: str = "1-1024",
                  scan_type: str = "-sS", timing: str = "T3",
                  service_detection: bool = True,
                  os_detection: bool = False) -> Dict[str, Any]:
        """
        Perform an Nmap scan

        Args:
            target: Target IP address, hostname, or CIDR range
            ports: Port range (e.g., "1-1024", "22,80,443", "top1000")
            scan_type: Nmap scan type (-sS SYN, -sT TCP, -sU UDP, -sA ACK)
            timing: Timing template (T0 paranoid - T5 insane)
            service_detection: Enable service version detection (-sV)
            os_detection: Enable OS detection (-O)

        Returns:
            Dictionary with scan results
        """
        # Security check
        allowed, reason = self.security.validate_operation(self.operation_type, target)
        if not allowed:
            return {"success": False, "error": reason}

        try:
            # Build nmap command
            cmd = ["nmap", scan_type, "-p", ports, f"-{timing}"]

            if service_detection:
                cmd.append("-sV")

            if os_detection:
                cmd.append("-O")

            # Add output formats
            cmd.extend(["-oX", "-"])  # XML output to stdout
            cmd.append(target)

            # Run scan
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            if result.returncode != 0:
                # Nmap might still return results even with errors
                if not result.stdout:
                    self.security.log_operation(
                        self.operation_type, "nmap_scan", target,
                        {"ports": ports, "scan_type": scan_type}, "failed"
                    )
                    return {
                        "success": False,
                        "error": result.stderr or "Scan failed",
                        "command": " ".join(cmd)
                    }

            # Parse results
            # For now, return raw output and try to extract key info
            output = result.stdout

            # Try to extract open ports
            open_ports = []
            port_pattern = r'<port protocol="(\w+)" portid="(\d+)">.*?<state state="(\w+)"[^>]*>.*?<service name="([^"]*)"'
            for match in re.finditer(port_pattern, output, re.DOTALL):
                protocol, portid, state, service = match.groups()
                if state == "open":
                    open_ports.append({
                        "port": int(portid),
                        "protocol": protocol,
                        "service": service
                    })

            self.security.log_operation(
                self.operation_type, "nmap_scan", target,
                {"ports": ports, "scan_type": scan_type},
                f"success - {len(open_ports)} open ports found"
            )

            return {
                "success": True,
                "target": target,
                "open_ports": open_ports,
                "raw_output": output[:10000] if len(output) > 10000 else output,  # Truncate if too long
                "command": " ".join(cmd),
                "open_port_count": len(open_ports)
            }

        except subprocess.TimeoutExpired:
            self.security.log_operation(
                self.operation_type, "nmap_scan", target,
                {"ports": ports}, "timeout"
            )
            return {"success": False, "error": "Scan timed out after 5 minutes"}
        except FileNotFoundError:
            return {"success": False, "error": "Nmap not found. Install with: sudo apt install nmap"}
        except Exception as e:
            self.security.log_operation(
                self.operation_type, "nmap_scan", target,
                {"ports": ports}, f"error: {str(e)}"
            )
            return {"success": False, "error": str(e)}

    def ping_sweep(self, network: str) -> Dict[str, Any]:
        """
        Perform a ping sweep to find live hosts

        Args:
            network: Network CIDR (e.g., "192.168.1.0/24")

        Returns:
            Dictionary with live hosts
        """
        # Security check
        allowed, reason = self.security.validate_operation(self.operation_type, network)
        if not allowed:
            return {"success": False, "error": reason}

        try:
            # Validate network
            net = ip_network(network, strict=False)

            live_hosts = []

            # Use nmap for ping sweep
            cmd = ["nmap", "-sn", "-PE", str(net)]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode == 0:
                # Parse output for live hosts
                output = result.stdout
                # Look for IP addresses in the output
                ip_pattern = r'Nmap scan report for ([\d.]+)'
                for match in re.finditer(ip_pattern, output):
                    ip = match.group(1)
                    live_hosts.append(ip)

            self.security.log_operation(
                self.operation_type, "ping_sweep", network,
                {}, f"success - {len(live_hosts)} hosts found"
            )

            return {
                "success": True,
                "network": network,
                "live_hosts": live_hosts,
                "host_count": len(live_hosts)
            }

        except ValueError:
            return {"success": False, "error": "Invalid CIDR notation"}
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Ping sweep timed out"}
        except FileNotFoundError:
            return {"success": False, "error": "Nmap not found"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def whois_lookup(self, domain: str) -> Dict[str, Any]:
        """
        Perform WHOIS lookup

        Args:
            domain: Domain name or IP address

        Returns:
            Dictionary with WHOIS information
        """
        try:
            cmd = ["whois", domain]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                self.security.log_operation(
                    self.operation_type, "whois", domain,
                    {}, "failed"
                )
                return {"success": False, "error": result.stderr or "WHOIS lookup failed"}

            # Parse key information
            output = result.stdout

            # Extract common fields
            fields = {
                "domain_name": r"Domain Name:\s*([^\n]+)",
                "registrar": r"Registrar:\s*([^\n]+)",
                "creation_date": r"Creation Date:\s*([^\n]+)",
                "expiration_date": r"Expiration Date:\s*([^\n]+)",
                "name_servers": r"Name Server:\s*([^\n]+)",
                "org": r"Organization:\s*([^\n]+)",
                "country": r"Country:\s*([^\n]+)",
            }

            parsed = {}
            for field, pattern in fields.items():
                matches = re.findall(pattern, output, re.IGNORECASE)
                if matches:
                    parsed[field] = matches[0].strip() if len(matches) == 1 else matches

            self.security.log_operation(
                self.operation_type, "whois", domain,
                {}, "success"
            )

            return {
                "success": True,
                "domain": domain,
                "parsed_info": parsed,
                "raw_output": output[:5000] if len(output) > 5000 else output
            }

        except FileNotFoundError:
            return {"success": False, "error": "whois command not found. Install with: sudo apt install whois"}
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "WHOIS lookup timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def dns_enumerate(self, domain: str, record_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Enumerate DNS records for a domain

        Args:
            domain: Domain name
            record_types: List of record types to query (default: A, AAAA, MX, NS, TXT)

        Returns:
            Dictionary with DNS records
        """
        if record_types is None:
            record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

        try:
            import dns.resolver
            import dns.exception

            records = {}

            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    records[record_type] = [str(rdata) for rdata in answers]
                except dns.resolver.NoAnswer:
                    records[record_type] = []
                except dns.resolver.NXDOMAIN:
                    return {"success": False, "error": f"Domain {domain} does not exist"}
                except Exception:
                    records[record_type] = []

            self.security.log_operation(
                self.operation_type, "dns_enumerate", domain,
                {"record_types": record_types}, "success"
            )

            return {
                "success": True,
                "domain": domain,
                "records": records
            }

        except ImportError:
            # Fallback to nslookup if dnspython not available
            return self._dns_enumerate_nslookup(domain, record_types)
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _dns_enumerate_nslookup(self, domain: str, record_types: List[str]) -> Dict[str, Any]:
        """Fallback DNS enumeration using nslookup"""
        try:
            # Only query A record with nslookup
            cmd = ["nslookup", domain]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            output = result.stdout

            # Try to extract A records
            a_records = []
            for line in output.split('\n'):
                if 'Address:' in line and '53' not in line:  # Exclude DNS server
                    addr = line.split('Address:')[-1].strip()
                    if addr and addr != '#53':
                        a_records.append(addr)

            records = {"A": a_records}

            self.security.log_operation(
                self.operation_type, "dns_enumerate", domain,
                {"record_types": record_types, "method": "nslookup"}, "success"
            )

            return {
                "success": True,
                "domain": domain,
                "records": records,
                "note": "Limited enumeration (nslookup fallback)"
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def dns_brute_force(self, domain: str, wordlist: Optional[str] = None,
                        subdomains: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Brute force DNS subdomains

        Args:
            domain: Target domain
            wordlist: Path to wordlist file (optional)
            subdomains: List of subdomains to check (optional)

        Returns:
            Dictionary with discovered subdomains
        """
        if subdomains is None:
            # Default common subdomains
            subdomains = [
                "www", "mail", "ftp", "admin", "api", "dev", "staging",
                "test", "beta", "app", "blog", "shop", "secure", "vpn",
                "portal", "dashboard", "monitor", "prometheus", "grafana",
                "jenkins", "gitlab", "jira", "confluence", "wiki"
            ]

        discovered = []

        for subdomain in subdomains:
            full_domain = f"{subdomain}.{domain}"

            try:
                # Try to resolve
                ip = socket.gethostbyname(full_domain)
                discovered.append({
                    "subdomain": full_domain,
                    "ip": ip
                })
            except socket.gaierror:
                # Subdomain doesn't exist
                pass
            except Exception:
                pass

        self.security.log_operation(
            self.operation_type, "dns_brute", domain,
            {"subdomain_count": len(subdomains)},
            f"success - {len(discovered)} found"
        )

        return {
            "success": True,
            "domain": domain,
            "discovered": discovered,
            "total_checked": len(subdomains),
            "found_count": len(discovered)
        }

    def http_headers(self, url: str) -> Dict[str, Any]:
        """
        Get HTTP headers from a URL

        Args:
            url: Target URL (e.g., "https://example.com")

        Returns:
            Dictionary with HTTP headers
        """
        try:
            import requests

            response = requests.get(url, timeout=10)

            headers = dict(response.headers)

            self.security.log_operation(
                self.operation_type, "http_headers", url,
                {}, "success"
            )

            return {
                "success": True,
                "url": url,
                "status_code": response.status_code,
                "headers": headers
            }

        except ImportError:
            # Fallback to curl
            try:
                cmd = ["curl", "-I", "-s", url]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                headers = {}
                for line in result.stdout.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip()] = value.strip()

                self.security.log_operation(
                    self.operation_type, "http_headers", url,
                    {"method": "curl"}, "success"
                )

                return {
                    "success": True,
                    "url": url,
                    "headers": headers,
                    "raw": result.stdout
                }

            except Exception as e:
                return {"success": False, "error": str(e)}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def ssl_cert_info(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """
        Get SSL/TLS certificate information

        Args:
            hostname: Target hostname
            port: Port number (default: 443)

        Returns:
            Dictionary with certificate information
        """
        try:
            import ssl
            import socket
            from datetime import datetime

            context = ssl.create_default_context()

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    # Parse certificate
                    cert_info = {
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "version": cert.get("version"),
                        "serial_number": cert.get("serialNumber"),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "alt_names": cert.get("subjectAltName", [])
                    }

                    self.security.log_operation(
                        self.operation_type, "ssl_cert", hostname,
                        {"port": port}, "success"
                    )

                    return {
                        "success": True,
                        "hostname": hostname,
                        "certificate": cert_info
                    }

        except ImportError:
            # Fallback to openssl
            try:
                cmd = ["echo", "|", "openssl", "s_client", "-connect", f"{hostname}:{port}", "-servername", hostname]
                # This is more complex to parse, so just indicate availability
                return {
                    "success": False,
                    "error": "SSL module not available. Use: openssl s_client -connect {}:{}".format(hostname, port)
                }
            except Exception as e:
                return {"success": False, "error": str(e)}
        except Exception as e:
            return {"success": False, "error": str(e)}
