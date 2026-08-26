"""
Docker-based Scanner Orchestrator.
Replaces local process execution with isolated container execution.
"""
import subprocess
import os
from pathlib import Path

class DockerScannerManager:
    def __init__(self, target_dir: Path):
        self.target_dir = target_dir
        self.abs_path = str(target_dir.resolve())

    def run_scanner(self, scanner_cmd: str):
        """
        Runs a scanner command inside the optimized security container.
        Example: scanner_cmd = "bandit -r /app/scan_target"
        """
        # Command to run the container, mount the source code, and execute the tool
        docker_cmd = [
            "docker", "run", "--rm",
            "-v", f"{self.abs_path}:/app/scan_target",
            "cybercode-scanners:latest",
            "sh", "-c", scanner_cmd
        ]
        
        try:
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            return "Error: Scanner timed out after 5 minutes"
        except Exception as e:
            return f"Error running docker scanner: {str(e)}"

    def check_docker_available(self) -> bool:
        try:
            subprocess.run(["docker", "--version"], capture_output=True)
            return True
        except FileNotFoundError:
            return False
