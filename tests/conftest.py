"""
pytest conftest — run before any test module is imported.

Removes file-based log handlers installed by core/ui.py so that test
execution does not pollute hunt3r.log / debug.log with test noise.
"""
import logging


def pytest_configure(config):
    """Strip RotatingFileHandler / FileHandler from root logger on test startup."""
    root = logging.getLogger()
    for handler in list(root.handlers):
        if isinstance(handler, (logging.FileHandler,)):
            root.removeHandler(handler)
            handler.close()


def pytest_runtest_setup(item):
    """Re-check before each test in case a module-level import re-added handlers."""
    root = logging.getLogger()
    for handler in list(root.handlers):
        if isinstance(handler, logging.FileHandler):
            root.removeHandler(handler)
            handler.close()
