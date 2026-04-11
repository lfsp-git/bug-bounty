"""Unified runner interface over scanner orchestration."""

from core.scanner import MissionRunner, ProOrchestrator
import core.scanner as _scanner


def set_record_tool_times(enabled: bool) -> None:
    _scanner._RECORD_TOOL_TIMES = enabled


def set_runtime_cache_enabled(enabled: bool) -> None:
    _scanner._DISABLE_RUNTIME_CACHE = not enabled
