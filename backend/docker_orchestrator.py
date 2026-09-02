"""
Reserved for a future Docker-based scanner-isolation layer.

This module previously exported DockerScannerManager which was
imported but never instantiated. It has been removed because the
current scanner pipeline runs each external tool via subprocess
in-process. See STRENGTHS_WEAKNESSES.md for the tracking issue.

To re-enable Docker-isolated execution, port the implementation
out of git history and ensure callers instantiate the manager
inside the per-scan orchestration path.
"""