"""
Hunt3r-v1: Structured Logging Module
Centralized logging for consistency and security.
"""

import logging
import os
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional

# Ensure logs directory exists
LOGS_DIR = Path("logs")
LOGS_DIR.mkdir(exist_ok=True)

# Main log file
LOG_FILE = LOGS_DIR / "hunt3r.log"


def get_logger(name: str, level=logging.INFO) -> logging.Logger:
    """
    Get a configured logger instance.
    
    Args:
        name: Logger name (usually __name__)
        level: Logging level
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Avoid duplicate handlers
    if logger.handlers:
        return logger
    
    # File handler
    try:
        file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        print(f"Failed to setup file logging: {e}", file=sys.stderr)
    
    # Console handler (errors only)
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.ERROR)
    console_formatter = logging.Formatter('[%(levelname)s] %(name)s: %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    return logger


def log_subprocess_execution(logger: logging.Logger, command: list, timeout: Optional[int] = None):
    """Log subprocess execution for debugging."""
    cmd_str = ' '.join(str(c) for c in command)
    if timeout:
        logger.debug(f"Executing: {cmd_str} (timeout={timeout}s)")
    else:
        logger.debug(f"Executing: {cmd_str}")


def log_subprocess_result(logger: logging.Logger, command: list, returncode: int, 
                          stderr: Optional[str] = None, stdout_lines: int = 0):
    """Log subprocess result."""
    cmd_str = ' '.join(str(c) for c in command[:3])  # Truncate for readability
    if returncode == 0:
        logger.debug(f"✓ {cmd_str} (rc={returncode}, output={stdout_lines} lines)")
    else:
        error_msg = stderr[:200] if stderr else "No error output"
        logger.error(f"✗ {cmd_str} failed (rc={returncode}): {error_msg}")


def log_api_call(logger: logging.Logger, method: str, url: str, status_code: Optional[int] = None,
                 error: Optional[str] = None):
    """Log API calls securely (without exposing keys)."""
    # Sanitize URL - remove query params with potential keys
    sanitized_url = url.split('?')[0] if '?' in url else url
    
    if status_code:
        logger.debug(f"{method} {sanitized_url} -> {status_code}")
    elif error:
        logger.error(f"{method} {sanitized_url} failed: {error}")
    else:
        logger.debug(f"{method} {sanitized_url}")


def log_security_event(logger: logging.Logger, event_type: str, details: str):
    """Log security-related events."""
    logger.warning(f"[SECURITY] {event_type}: {details}")


def log_validation_error(logger: logging.Logger, field: str, reason: str):
    """Log input validation errors."""
    logger.warning(f"[VALIDATION] {field}: {reason}")


def setup_logging(level=logging.INFO):
    """Configure root logger with sensible defaults."""
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # File handler with rotation
    from logging.handlers import RotatingFileHandler
    try:
        handler = RotatingFileHandler(
            LOG_FILE,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        root_logger.addHandler(handler)
    except Exception as e:
        print(f"Failed to setup rotating file logging: {e}", file=sys.stderr)


# Configure on module import
setup_logging()
