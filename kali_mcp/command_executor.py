"""
Improved Command Executor with timeout handling and partial results
"""

import subprocess
import threading
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


class CommandExecutor:
    """Enhanced command executor with better timeout management"""
    
    def __init__(self, command: str, timeout: int = 180):
        """
        Initialize command executor
        
        Args:
            command: Command to execute
            timeout: Timeout in seconds (default: 180)
        """
        self.command = command
        self.timeout = timeout
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.stdout_thread = None
        self.stderr_thread = None
        self.return_code = None
        self.timed_out = False
    
    def _read_stdout(self):
        """Thread function to continuously read stdout"""
        try:
            for line in iter(self.process.stdout.readline, ''):
                if line:
                    self.stdout_data += line
        except Exception as e:
            logger.error(f"Error reading stdout: {e}")
    
    def _read_stderr(self):
        """Thread function to continuously read stderr"""
        try:
            for line in iter(self.process.stderr.readline, ''):
                if line:
                    self.stderr_data += line
        except Exception as e:
            logger.error(f"Error reading stderr: {e}")
    
    def execute(self) -> Dict[str, Any]:
        """
        Execute the command and handle timeout gracefully
        
        Returns:
            Dictionary with execution results
        """
        logger.info(f"Executing command: {self.command[:100]}...")
        
        try:
            self.process = subprocess.Popen(
                self.command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # Line buffered
            )
            
            # Start threads to read output continuously
            self.stdout_thread = threading.Thread(target=self._read_stdout, daemon=True)
            self.stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
            self.stdout_thread.start()
            self.stderr_thread.start()
            
            # Wait for the process to complete or timeout
            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                # Process completed, join the threads
                self.stdout_thread.join(timeout=2)
                self.stderr_thread.join(timeout=2)
            except subprocess.TimeoutExpired:
                # Process timed out but we might have partial results
                self.timed_out = True
                logger.warning(f"Command timed out after {self.timeout} seconds. Terminating process.")
                
                # Try to terminate gracefully first
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)  # Give it 5 seconds to terminate
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate
                    logger.warning("Process not responding to termination. Killing.")
                    self.process.kill()
                
                # Wait a bit for threads to finish reading
                self.stdout_thread.join(timeout=1)
                self.stderr_thread.join(timeout=1)
            
            # Consider it success if we have output, even with timeout
            has_output = bool(self.stdout_data or self.stderr_data)
            success = (self.return_code == 0) or (self.timed_out and has_output)
            
            return {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and has_output
            }
        
        except Exception as e:
            logger.error(f"Error executing command: {str(e)}")
            return {
                "stdout": self.stdout_data,
                "stderr": f"Error executing command: {str(e)}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data)
            }


def execute_command(command: str, timeout: int = 180) -> Dict[str, Any]:
    """
    Execute a shell command with improved timeout handling
    
    Args:
        command: The command to execute
        timeout: Timeout in seconds
        
    Returns:
        Dictionary containing execution results
    """
    executor = CommandExecutor(command, timeout)
    return executor.execute()
