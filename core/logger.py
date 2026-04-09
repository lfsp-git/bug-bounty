"""Structured logging with JSON output for audit trail."""
import os
import json
import logging
from datetime import datetime
from typing import Any, Optional

class StructuredLogger:
    """Centralized structured JSON logger for Hunt3r."""
    
    LOG_DIR = os.path.expanduser("~/.hunt3r/logs")
    
    def __init__(self, name: str = "hunt3r"):
        os.makedirs(self.LOG_DIR, exist_ok=True)
        self.name = name
        self.logger = logging.getLogger(name)
        self._setup_handlers()
    
    def _setup_handlers(self):
        """Setup JSON and console handlers."""
        # JSON file handler (JSONL: one JSON per line)
        log_file = os.path.join(
            self.LOG_DIR,
            f"{datetime.now().strftime('%Y%m%d')}.jsonl"
        )
        
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setFormatter(logging.Formatter('%(message)s'))
        file_handler.setLevel(logging.DEBUG)
        
        # Console handler (simplified output)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
        console_handler.setLevel(logging.INFO)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        self.logger.setLevel(logging.DEBUG)
    
    def _make_log_entry(
        self,
        level: str,
        message: str,
        module: str = "",
        function: str = "",
        context: Optional[dict] = None
    ) -> str:
        """Create structured JSON log entry."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "level": level.upper(),
            "logger": self.name,
            "module": module or "main",
            "function": function or "unknown",
            "message": message,
        }
        
        if context:
            entry["context"] = context
        
        return json.dumps(entry, ensure_ascii=False)
    
    def info(
        self,
        message: str,
        module: str = "",
        function: str = "",
        context: Optional[dict] = None
    ):
        """Log info level."""
        entry = self._make_log_entry("info", message, module, function, context)
        self.logger.info(entry)
    
    def warning(
        self,
        message: str,
        module: str = "",
        function: str = "",
        context: Optional[dict] = None
    ):
        """Log warning level."""
        entry = self._make_log_entry("warning", message, module, function, context)
        self.logger.warning(entry)
    
    def error(
        self,
        message: str,
        module: str = "",
        function: str = "",
        context: Optional[dict] = None
    ):
        """Log error level."""
        entry = self._make_log_entry("error", message, module, function, context)
        self.logger.error(entry)
    
    def critical(
        self,
        message: str,
        module: str = "",
        function: str = "",
        context: Optional[dict] = None
    ):
        """Log critical level."""
        entry = self._make_log_entry("critical", message, module, function, context)
        self.logger.critical(entry)
    
    def debug(
        self,
        message: str,
        module: str = "",
        function: str = "",
        context: Optional[dict] = None
    ):
        """Log debug level."""
        entry = self._make_log_entry("debug", message, module, function, context)
        self.logger.debug(entry)
    
    def log_scan_start(self, target: str, domains: list):
        """Log scan start event."""
        self.info(
            f"Scan started for target {target}",
            module="orchestrator",
            function="start_mission",
            context={
                "target": target,
                "domains": domains,
                "domain_count": len(domains)
            }
        )
    
    def log_scan_end(self, target: str, findings_count: int, duration_sec: float):
        """Log scan end event."""
        self.info(
            f"Scan completed for target {target}",
            module="orchestrator",
            function="finish_mission",
            context={
                "target": target,
                "findings": findings_count,
                "duration_seconds": duration_sec
            }
        )
    
    def log_tool_execution(self, tool_name: str, status: str, duration_sec: float = 0, error: str = ""):
        """Log tool execution."""
        level = "error" if status == "failed" else "info"
        message = f"Tool {tool_name} {status}"
        
        context = {
            "tool": tool_name,
            "status": status,
            "duration_seconds": duration_sec
        }
        
        if error:
            context["error"] = error
        
        if level == "error":
            self.error(message, module="recon.engines", function="run_tool", context=context)
        else:
            self.info(message, module="recon.engines", function="run_tool", context=context)
    
    def log_finding(self, target: str, finding_type: str, severity: str, title: str):
        """Log finding discovery."""
        self.info(
            f"Finding discovered: {title}",
            module="core.fp_filter",
            function="sanitize_findings",
            context={
                "target": target,
                "type": finding_type,
                "severity": severity,
                "title": title
            }
        )
    
    def log_api_call(self, platform: str, endpoint: str, status_code: int = 0, error: str = ""):
        """Log API call."""
        context = {
            "platform": platform,
            "endpoint": endpoint,
            "status_code": status_code
        }
        
        if error:
            context["error"] = error
            self.warning(
                f"API call to {platform} {endpoint} failed",
                module="recon.platforms",
                function="api_call",
                context=context
            )
        else:
            self.debug(
                f"API call to {platform} {endpoint}",
                module="recon.platforms",
                function="api_call",
                context=context
            )


# Global logger instance
_logger = None

def get_logger() -> StructuredLogger:
    """Get or create the global logger instance."""
    global _logger
    if _logger is None:
        _logger = StructuredLogger()
    return _logger
