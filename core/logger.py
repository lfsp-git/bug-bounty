"""
HUNT3R — Centralized logging setup.

Two log files:
  logs/hunt3r.log  — INFO+   simple one-liner per event (existing behaviour)
  logs/debug.log   — DEBUG+  full tracebacks, file:line, function name

Key feature: AutoExcInfoHandler automatically captures the active exception
traceback for WARNING/ERROR records even when the caller didn't pass
exc_info=True — so no existing call sites need to change.

Call setup_logging() once at process start (done from core/ui.py).
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import sys
import threading
import traceback

_LOG_DIR = "logs"
_DEBUG_LOG = os.path.join(_LOG_DIR, "debug.log")
_HUNT3R_LOG = os.path.join(_LOG_DIR, "hunt3r.log")

_MAX_BYTES = 10 * 1024 * 1024   # 10 MB per file
_BACKUP_COUNT = 3                # keep debug.log, debug.log.1, debug.log.2, debug.log.3

_SETUP_DONE = False


class _AutoExcInfoHandler(logging.handlers.RotatingFileHandler):
    """
    RotatingFileHandler that silently attaches the currently active exception
    (if any) to WARNING/ERROR/CRITICAL records that don't already carry exc_info.
    This means every `logging.error("msg: %s", e)` inside an except block
    automatically gets the full traceback in debug.log without caller changes.
    """

    def emit(self, record: logging.LogRecord) -> None:
        if record.levelno >= logging.WARNING and not record.exc_info:
            exc = sys.exc_info()
            if exc[0] is not None:
                record.exc_info = exc
        super().emit(record)


def setup_logging() -> None:
    """Configure root logger with hunt3r.log (INFO) and debug.log (DEBUG)."""
    global _SETUP_DONE
    if _SETUP_DONE:
        return
    _SETUP_DONE = True

    os.makedirs(_LOG_DIR, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    # Remove any handlers added by stray basicConfig() calls before this runs
    root.handlers.clear()

    # ── hunt3r.log — INFO, simple format (existing behaviour preserved) ──────
    hunt3r_handler = logging.handlers.RotatingFileHandler(
        _HUNT3R_LOG, maxBytes=_MAX_BYTES, backupCount=_BACKUP_COUNT, encoding="utf-8"
    )
    hunt3r_handler.setLevel(logging.INFO)
    hunt3r_handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s | %(message)s",
        datefmt="%H:%M:%S",
    ))
    root.addHandler(hunt3r_handler)

    # ── debug.log — DEBUG, full context + auto exc_info ─────────────────────
    debug_handler = _AutoExcInfoHandler(
        _DEBUG_LOG, maxBytes=_MAX_BYTES, backupCount=_BACKUP_COUNT, encoding="utf-8"
    )
    debug_handler.setLevel(logging.DEBUG)
    debug_handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s [%(levelname)-8s] %(name)s %(filename)s:%(lineno)d in %(funcName)s()\n  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    root.addHandler(debug_handler)

    # ── Global uncaught exception hooks ─────────────────────────────────────
    _install_exception_hooks()


def _install_exception_hooks() -> None:
    """Catch any unhandled exception (main thread + worker threads) into debug.log."""
    _debug_logger = logging.getLogger("hunt3r.uncaught")

    def _excepthook(exc_type, exc_value, exc_tb):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_tb)
            return
        _debug_logger.critical(
            "Uncaught exception: %s",
            "".join(traceback.format_exception(exc_type, exc_value, exc_tb)).strip(),
            exc_info=(exc_type, exc_value, exc_tb),
        )

    sys.excepthook = _excepthook

    def _thread_excepthook(args):
        if args.exc_type is SystemExit or args.exc_type is KeyboardInterrupt:
            return
        tb_str = "".join(
            traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback)
        ).strip()
        thread_name = getattr(args.thread, "name", "unknown-thread")
        _debug_logger.critical(
            "Uncaught exception in thread [%s]: %s", thread_name, tb_str,
            exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
        )

    threading.excepthook = _thread_excepthook
