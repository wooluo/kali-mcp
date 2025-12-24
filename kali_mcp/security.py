"""
Security and Authorization Module

Handles security checks, authorization, and audit logging for all operations.
"""

import ipaddress
import logging
import os
import yaml
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
from enum import Enum


class DangerLevel(Enum):
    """Danger levels for different operations"""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class OperationType(Enum):
    """Types of security operations"""
    RECON = "reconnaissance"
    SCAN = "scanning"
    EXPLOIT = "exploitation"
    POST_EXPLOIT = "post_exploitation"
    UTILITY = "utility"


class SecurityManager:
    """Manages security policies and network restrictions"""

    def __init__(self, config_path: str = "config.yaml"):
        self.config = self._load_config(config_path)
        self._setup_logging()

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        if not os.path.exists(config_path):
            # Return default config
            return {
                "authorization": {
                    "allowed_ranges": [],
                    "blocked_ranges": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
                },
                "security": {
                    "rate_limit": {"enabled": True, "max_requests_per_minute": 60}
                }
            }

        with open(config_path, 'r') as f:
            return yaml.safe_load(f)

    def _setup_logging(self):
        """Setup audit logging"""
        log_config = self.config.get("logging", {})
        log_file = log_config.get("file", "/var/log/kali_mcp.log")
        log_level = getattr(logging, log_config.get("level", "INFO"))

        # Ensure log directory exists
        os.makedirs(os.path.dirname(log_file) if os.path.dirname(log_file) else ".", exist_ok=True)

        logging.basicConfig(
            level=log_level,
            format=log_config.get("format", "%(asctime)s - %(name)s - %(levelname)s - %(message)s"),
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("SecurityManager")

    def is_target_allowed(self, target: str) -> tuple[bool, str]:
        """
        Check if a target is allowed based on configuration

        Args:
            target: IP address or hostname

        Returns:
            Tuple of (is_allowed, reason)
        """
        # If it's a hostname, we can't check ranges - allow it
        try:
            ip = ipaddress.ip_address(target)
        except ValueError:
            return True, "Hostname (cannot verify range)"

        # Check blocked ranges
        blocked_ranges = self.config.get("authorization", {}).get("blocked_ranges", [])
        for range_str in blocked_ranges:
            try:
                network = ipaddress.ip_network(range_str)
                if ip in network:
                    return False, f"Target in blocked range: {range_str}"
            except ValueError:
                continue

        # Check allowed ranges (if specified)
        allowed_ranges = self.config.get("authorization", {}).get("allowed_ranges", [])
        if allowed_ranges:
            for range_str in allowed_ranges:
                try:
                    network = ipaddress.ip_network(range_str)
                    if ip in network:
                        return True, "Target in allowed range"
                except ValueError:
                    continue
            return False, "Target not in allowed ranges"

        return True, "No restrictions"

    def validate_operation(self, operation_type: OperationType, target: Optional[str] = None) -> tuple[bool, str]:
        """
        Validate if an operation is allowed

        Args:
            operation_type: Type of operation
            target: Target address (optional)

        Returns:
            Tuple of (is_allowed, reason)
        """
        # Check target if provided
        if target:
            allowed, reason = self.is_target_allowed(target)
            if not allowed:
                self.logger.warning(f"Blocked {operation_type.value} on {target}: {reason}")
                return False, f"Target not allowed: {reason}"

        return True, "Operation allowed"

    def log_operation(self, operation_type: OperationType, tool: str, target: Optional[str],
                     params: Dict[str, Any], result: str, user_id: Optional[str] = None):
        """
        Log an operation for audit purposes

        Args:
            operation_type: Type of operation
            tool: Tool name
            target: Target address
            params: Tool parameters
            result: Operation result
            user_id: User identifier
        """
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "operation_type": operation_type.value,
            "tool": tool,
            "target": target,
            "params": params,
            "result": result,
            "user_id": user_id or "unknown"
        }

        self.logger.info(f"AUDIT: {log_entry}")


class Authorizer:
    """Handles explicit user authorization for dangerous operations"""

    def __init__(self, security_manager: SecurityManager):
        self.security_manager = security_manager
        self.pending_authorizations: Dict[str, Any] = {}

    def get_danger_level(self, operation_type: OperationType) -> DangerLevel:
        """
        Get the danger level for an operation type

        Args:
            operation_type: Type of operation

        Returns:
            DangerLevel enum
        """
        danger_levels = {
            OperationType.RECON: DangerLevel.LOW,
            OperationType.SCAN: DangerLevel.MEDIUM,
            OperationType.UTILITY: DangerLevel.SAFE,
            OperationType.EXPLOIT: DangerLevel.CRITICAL,
            OperationType.POST_EXPLOIT: DangerLevel.CRITICAL,
        }
        return danger_levels.get(operation_type, DangerLevel.MEDIUM)

    def requires_authorization(self, operation_type: OperationType) -> bool:
        """
        Check if an operation type requires explicit authorization

        Args:
            operation_type: Type of operation

        Returns:
            True if authorization is required
        """
        # Exploitation and post-exploitation always require authorization
        if operation_type in [OperationType.EXPLOIT, OperationType.POST_EXPLOIT]:
            return True

        # Check config
        config_require = self.security_manager.config.get("authorization", {}).get(
            "require_auth_for_exploitation", True
        )
        return config_require

    def request_authorization(self, operation_type: OperationType, tool: str,
                            target: str, params: Dict[str, Any]) -> str:
        """
        Request authorization for an operation

        Args:
            operation_type: Type of operation
            tool: Tool name
            target: Target address
            params: Operation parameters

        Returns:
            Authorization message explaining what needs to be authorized
        """
        danger_level = self.get_danger_level(operation_type)

        warning_messages = {
            DangerLevel.SAFE: "This is a safe operation.",
            DangerLevel.LOW: "This is a low-risk operation.",
            DangerLevel.MEDIUM: "This is a medium-risk operation that may be detected.",
            DangerLevel.HIGH: "This is a high-risk operation that could affect system availability.",
            DangerLevel.CRITICAL: (
                "⚠️ CRITICAL OPERATION ⚠️\n"
                "This operation could:\n"
                "- Gain unauthorized access to systems\n"
                "- Modify or delete data\n"
                "- Disrupt services\n"
                "\n"
                "You must have WRITTEN AUTHORIZATION from the system owner.\n"
                "Only proceed if you have explicit permission."
            )
        }

        msg = f"\n{'='*60}\n"
        msg += f"Authorization Required\n"
        msg += f"{'='*60}\n"
        msg += f"Operation: {operation_type.value.upper()}\n"
        msg += f"Tool: {tool}\n"
        msg += f"Target: {target}\n"
        msg += f"Danger Level: {danger_level.value.upper()}\n"
        msg += f"\n{warning_messages[danger_level]}\n"
        msg += f"\n{'='*60}\n"
        msg += f"Type 'I have authorization' to proceed, or 'cancel' to abort.\n"

        return msg

    def confirm_authorization(self, user_response: str) -> bool:
        """
        Confirm that the user has provided authorization

        Args:
            user_response: User's response

        Returns:
            True if user confirmed authorization
        """
        affirmative_responses = [
            "i have authorization",
            "yes",
            "authorized",
            "confirmed",
            "proceed",
            "i have written authorization"
        ]
        return user_response.lower().strip() in affirmative_responses


# Global instances
_security_manager = None
_authorizer = None


def get_security_manager() -> SecurityManager:
    """Get or create the global SecurityManager instance"""
    global _security_manager
    if _security_manager is None:
        config_path = os.environ.get("MCP_CONFIG_PATH", "config.yaml")
        _security_manager = SecurityManager(config_path)
    return _security_manager


def get_authorizer() -> Authorizer:
    """Get or create the global Authorizer instance"""
    global _authorizer
    if _authorizer is None:
        _authorizer = Authorizer(get_security_manager())
    return _authorizer
