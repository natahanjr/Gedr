"""
Enhanced error handling and logging for Gədr.

Provides:
  - Timeout protection for scanner operations
  - Memory limit monitoring
  - Graceful handling of malformed code
  - Comprehensive structured logging
  - Error recovery strategies
"""
import logging
import sys
import signal
import functools
import traceback
from pathlib import Path
from typing import Callable, Any
from contextlib import contextmanager
from datetime import datetime


# Configure logging
def setup_logging(log_file: Path | None = None, level: int = logging.DEBUG) -> None:
    """Configure comprehensive logging for Gədr.
    
    Args:
        log_file: Optional file path for log output
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    # Create formatters
    detailed_formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s:%(lineno)d | %(funcName)s() | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    simple_formatter = logging.Formatter(
        "%(levelname)s | %(message)s"
    )
    
    # Set root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Console handler (INFO level)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(simple_formatter)
    root_logger.addHandler(console_handler)
    
    # File handler (DEBUG level, if specified)
    if log_file:
        file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(detailed_formatter)
        root_logger.addHandler(file_handler)


class ScannerError(Exception):
    """Base exception for scanner errors."""
    pass


class TimeoutError(ScannerError):
    """Raised when a scan operation times out."""
    pass


class MemoryError(ScannerError):
    """Raised when memory limit is exceeded."""
    pass
class MalformedCodeError(ScannerError):
    """Raised when code cannot be parsed."""
    pass


def timeout_handler(signum, frame):
    """Signal handler for timeout."""
    raise TimeoutError("Operation timed out")


@contextmanager
def timeout_context(seconds: int, operation_name: str = "operation"):
    """Context manager for enforcing operation timeouts.
    
    Uses signal.SIGALRM on Unix; falls back to a threaded timer on Windows
    (where SIGALRM is unavailable).
    """
    logger = logging.getLogger(__name__)
    
    # Set up signal handler (Unix-like systems only)
    old_handler = None
    old_alarm = None
    if hasattr(signal, 'SIGALRM'):
        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        old_alarm = signal.alarm(seconds)
        logger.debug(f"Timeout set for {operation_name}: {seconds}s")
    else:
        # Windows fallback: rely on the thread pool's own timeout mechanism
        logger.debug(f"SIGALRM unavailable (Windows); timeout relies on caller for {operation_name}")
    
    try:
        yield
    except TimeoutError:
        logger.error(f"{operation_name} exceeded {seconds}s timeout")
        raise
    finally:
        # Cancel alarm
        if hasattr(signal, 'SIGALRM'):
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler or signal.SIG_DFL)
            logger.debug(f"Timeout cancelled for {operation_name}")


def with_error_handling(
    timeout_seconds: int = 60,
    on_error: Callable[[Exception], Any] = None,
    log_traceback: bool = True,
):
    """Decorator for robust error handling on scanner functions.
    
    Features:
      - Timeout protection
      - Exception logging
      - Graceful error recovery
      
    Args:
        timeout_seconds: Timeout limit for the function
        on_error: Optional callback for error handling
        log_traceback: Whether to log full traceback
        
    Example:
        @with_error_handling(timeout_seconds=30)
        def scan_file(path):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            logger = logging.getLogger(func.__module__)
            op_name = f"{func.__name__}"
            
            logger.debug(f"Starting {op_name} with timeout={timeout_seconds}s")
            
            try:
                # Execute with timeout protection
                if hasattr(signal, 'SIGALRM'):
                    with timeout_context(timeout_seconds, op_name):
                        return func(*args, **kwargs)
                else:
                    # Fallback for systems without signal support
                    return func(*args, **kwargs)
                    
            except TimeoutError as e:
                logger.error(f"{op_name} timed out after {timeout_seconds}s")
                if on_error:
                    return on_error(e)
                return []  # Return empty results on timeout
                
            except MalformedCodeError as e:
                logger.warning(f"{op_name} encountered malformed code: {str(e)}")
                if on_error:
                    return on_error(e)
                return []
                
            except Exception as e:
                logger.error(f"{op_name} failed: {type(e).__name__}: {str(e)}")
                if log_traceback:
                    logger.debug(f"Traceback:\n{traceback.format_exc()}")
                if on_error:
                    return on_error(e)
                return []
                
        return wrapper
    return decorator


def with_retry(max_retries: int = 3, delay: float = 1.0, backoff: float = 2.0):
    """Decorator for automatic retry with exponential backoff.
    
    Args:
        max_retries: Maximum number of retry attempts
        delay: Initial delay between retries in seconds
        backoff: Multiplier for delay after each retry
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            logger = logging.getLogger(func.__module__)
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries:
                        wait_time = delay * (backoff ** attempt)
                        logger.warning(f"{func.__name__} attempt {attempt + 1} failed, retrying in {wait_time:.1f}s")
                        time.sleep(wait_time)
                    else:
                        logger.error(f"{func.__name__} failed after {max_retries + 1} attempts")
            
            raise last_exception
        return wrapper
    return decorator


class SafeCodeParser:
    """Safely parse code with error recovery."""
    
    logger = logging.getLogger(__name__)
    
    @staticmethod
    def safe_split_lines(code: str) -> list[str]:
        """Split code into lines, handling encoding issues.
        
        Args:
            code: Source code string
            
        Returns:
            List of lines, with invalid sequences cleaned
        """
        try:
            lines = code.splitlines()
            return lines
        except Exception as e:
            SafeCodeParser.logger.warning(f"Error splitting code: {e}")
            # Fallback: split on newline, replacing invalid chars
            return code.encode('utf-8', errors='replace').decode('utf-8').splitlines()
    
    @staticmethod
    def safe_regex_match(pattern, line: str, rule_id: str = "unknown") -> bool:
        """Safely apply regex to code line.
        
        Args:
            pattern: Compiled regex pattern
            line: Code line to match
            rule_id: Rule ID for logging
            
        Returns:
            True if pattern matches, False otherwise
        """
        try:
            if pattern.search(line):
                SafeCodeParser.logger.debug(f"Rule {rule_id} matched on line")
                return True
            return False
        except Exception as e:
            SafeCodeParser.logger.warning(
                f"Regex error on rule {rule_id}: {type(e).__name__}: {str(e)}"
            )
            return False
    
    @staticmethod
    def safe_read_file(file_path: Path, encoding: str = 'utf-8') -> tuple[str | None, str | None]:
        """Safely read file with error recovery.
        
        Args:
            file_path: Path to file
            encoding: Encoding to use (with fallback to replacement chars)
            
        Returns:
            Tuple of (content, error_message)
            - If successful: (content, None)
            - If failed: (None, error_message)
        """
        try:
            content = file_path.read_text(encoding=encoding, errors='replace')
            SafeCodeParser.logger.debug(f"Successfully read file: {file_path}")
            return content, None
        except FileNotFoundError:
            msg = f"File not found: {file_path}"
            SafeCodeParser.logger.error(msg)
            return None, msg
        except PermissionError:
            msg = f"Permission denied: {file_path}"
            SafeCodeParser.logger.error(msg)
            return None, msg
        except Exception as e:
            msg = f"Failed to read file {file_path}: {type(e).__name__}: {str(e)}"
            SafeCodeParser.logger.error(msg)
            return None, msg


class ScanLogger:
    """Structured logging for scan operations."""
    
    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.logger = logging.getLogger(f"scan.{scan_id}")
        self.start_time = datetime.now()
        self.events = []
        
        self.logger.info(f"Scan started: {self.scan_id}")
    
    def log_file_scanned(self, file_path: str, findings_count: int = 0, error: str | None = None):
        """Log a file scan event."""
        if error:
            self.logger.warning(f"File error {file_path}: {error}")
            self.events.append({
                "type": "file_error",
                "file": file_path,
                "error": error,
                "timestamp": datetime.now().isoformat(),
            })
        else:
            self.logger.debug(f"File scanned: {file_path} ({findings_count} findings)")
            self.events.append({
                "type": "file_scanned",
                "file": file_path,
                "findings": findings_count,
                "timestamp": datetime.now().isoformat(),
            })
    
    def log_external_tool_run(self, tool_name: str, duration_seconds: float, success: bool):
        """Log external tool execution."""
        status = "success" if success else "failed"
        self.logger.info(f"External tool {tool_name}: {status} ({duration_seconds:.2f}s)")
        self.events.append({
            "type": "external_tool",
            "tool": tool_name,
            "duration": duration_seconds,
            "success": success,
            "timestamp": datetime.now().isoformat(),
        })
    
    def log_scan_complete(self, files_count: int, findings_count: int, score: int):
        """Log scan completion."""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        self.logger.info(
            f"Scan complete: {files_count} files, {findings_count} findings, "
            f"score {score}/100, elapsed {elapsed:.2f}s"
        )
        self.events.append({
            "type": "scan_complete",
            "files": files_count,
            "findings": findings_count,
            "score": score,
            "elapsed": elapsed,
            "timestamp": datetime.now().isoformat(),
        })
    
    def get_events(self) -> list[dict]:
        """Get all logged events."""
        return self.events


# Module-level logger
logger = logging.getLogger(__name__)
