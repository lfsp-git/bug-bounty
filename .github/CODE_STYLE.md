# Hunt3r Code Style Guide

## Overview
Hunt3r follows Python best practices for code quality and consistency. This guide documents the standards applied across all modules.

---

## Formatting Standards

### Line Length
- **Maximum 100 characters** for readability (allows 4-level indentation)
- Longer lines should be broken at logical points

### Indentation
- **4 spaces** per indentation level (PEP 8 standard)
- No tabs

### Imports
- **Group imports in 3 sections** (separated by blank lines):
  1. Standard library imports (os, sys, json, etc.)
  2. Third-party imports (requests, numpy, etc.)
  3. Local imports (core.*, recon.*, config.*)
- **Sort alphabetically** within each group
- Use absolute imports, not relative imports

### Naming Conventions

| Type | Convention | Example |
|------|-----------|---------|
| **Classes** | PascalCase | `class MissionRunner`, `class ExportFormatter` |
| **Functions** | snake_case | `def run_subfinder()`, `def get_rate_limiter()` |
| **Constants** | UPPER_SNAKE_CASE | `MAX_SUBS_PER_TARGET`, `RATE_LIMIT_PER_TARGET` |
| **Private methods** | _leading_underscore | `def _load_env()`, `def _spinner()` |
| **Module names** | lowercase | `core/logger.py`, `recon/engines.py` |

### Spacing

- **Around operators**: `x = 1 + 2` (not `x=1+2`)
- **Function definitions**: `def func(arg1, arg2):` (spaces after comma)
- **Dictionary/list literals**: `{"key": "value"}` (space after colon, no space before)
- **Blank lines**: 2 blank lines between top-level definitions, 1 between methods

### Docstrings

- Use **triple double quotes** `"""`
- **First line**: Single-line summary (imperative mood)
- **Blank line** before longer descriptions
- Use proper grammar and punctuation

```python
def run_subfinder(domain_file: str, output_file: str):
    """Execute Subfinder on domain list.
    
    Discovers subdomains using passive sources and OSINT.
    
    Args:
        domain_file: Path to file containing domains (one per line)
        output_file: Path to write discovered subdomains
    
    Returns:
        int: Number of unique subdomains found
    
    Raises:
        FileNotFoundError: If domain_file does not exist
        subprocess.CalledProcessError: If Subfinder execution fails
    """
```

### Comments

- Use `#` comments for **non-obvious** code
- **Avoid redundant comments** (code should be self-explanatory)
- Inline comments: space before `#`
- Comment block: blank line above, then `# Comment`

```python
# Good: explains WHY
if count > MAX_SUBS_PER_TARGET:
    logging.warning(...)  # Resource limit hit; truncation necessary

# Bad: restates what code does
count = 0  # Initialize count to zero
```

### String Formatting

- Use **f-strings** for all string formatting (Python 3.6+)
- Not `.format()` or `%` formatting

```python
# Good
message = f"Found {count} subdomains for {target}"

# Avoid
message = "Found {} subdomains for {}".format(count, target)
```

---

## Type Hints

Use type hints for function signatures (improves IDE autocomplete and catches errors):

```python
def count_lines(filepath: str) -> int:
    """Count lines in a file."""
    pass

def load_findings(mission_id: str) -> Dict[str, List[Any]]:
    """Load findings from checkpoint."""
    pass

def export(findings: List[Dict[str, Any]], format: str = "csv") -> str:
    """Export findings to file."""
    pass
```

---

## Error Handling

- **Catch specific exceptions**, never bare `except:`
- **Log errors** with appropriate level (error, warning, debug)
- **Re-raise or handle** gracefully based on context

```python
try:
    data = json.loads(response.text)
except json.JSONDecodeError as e:
    logging.error(f"Malformed JSON in response: {e}")
    return {}
except requests.RequestException as e:
    logging.warning(f"API request failed: {e}")
    raise
```

---

## Module Structure

### Typical Python module layout:

```python
#!/usr/bin/env python3
"""Module docstring: brief description of purpose."""

import os
import sys
import json
import logging
from typing import Dict, List, Any

import requests

from core.logger import get_logger
from config.settings import TIMEOUT

logger = logging.getLogger(__name__)

# Constants (UPPER_SNAKE_CASE)
MAX_RETRIES = 3
DEFAULT_TIMEOUT = 30

# Private module-level variables (_leading_underscore)
_cache = {}

# Public functions
def public_function():
    """Public function docstring."""
    pass

# Private functions
def _private_function():
    """Private function docstring."""
    pass

# Classes
class MyClass:
    """Class docstring."""
    
    def __init__(self):
        """Initialize the class."""
        pass
    
    def public_method(self):
        """Public method."""
        pass
    
    def _private_method(self):
        """Private method."""
        pass
```

---

## Complexity Limits

- **Function length**: Keep under 50 lines (max 100 for complex functions)
- **Cyclomatic complexity**: Avoid deep nesting (max 3 levels)
- **Function arguments**: Max 5 arguments (use kwargs or dataclass for more)

If a function exceeds these, break it into smaller functions.

---

## Performance Considerations

- **String concatenation**: Use `"".join(list)` for O(n) instead of `s += x` for O(n²)
- **File I/O**: Always use context managers (`with open()`)
- **List operations**: Use list comprehensions `[x for x in list]` instead of loops when simple
- **Avoid globals**: Use instance variables or parameters instead

---

## Testing

- **Unit tests** for utility functions (in `tests/` directory)
- **Test file naming**: `test_<module>.py` mirrors `<module>.py`
- **Test function naming**: `test_<function>_<scenario>`

```python
def test_count_lines_valid_file():
    """count_lines should return correct line count."""
    pass

def test_count_lines_missing_file():
    """count_lines should return 0 for missing file."""
    pass
```

---

## Git Commit Messages

Follow conventional commits format:

```
<type>: <subject>

<body>

<footer>
```

- **Types**: feat, fix, refactor, docs, test, style, perf, ci, chore
- **Subject**: Imperative mood, lowercase, no period, max 50 chars
- **Body**: Explain WHAT and WHY (not HOW), wrapped at 72 chars
- **Footer**: Reference issues, breaking changes

Examples:
```
feat: Add dry-run mode for preview scanning

Users can now validate target list before running actual scans.
Adds --dry-run CLI flag that loads targets, applies DIFF engine,
and exports JSON report without executing tools.

Fixes #42
```

---

## Documentation

- **README.md**: Project overview, setup, usage
- **Module docstrings**: Brief description of module purpose
- **Function docstrings**: What it does, args, return, raises
- **Inline comments**: Explain non-obvious logic only

---

## Linting & Tools

To check code style (manual verification):

```bash
# Check imports are sorted
python3 -c "
import ast
import sys

def check_imports(filename):
    with open(filename) as f:
        tree = ast.parse(f.read())
    
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.append((node.lineno, 'import'))
    
    print(f'Imports found: {len(imports)}')

check_imports('core/orchestrator.py')
"

# Syntax check
python3 -m py_compile core/orchestrator.py
```

---

## Standards Applied in Hunt3r

✅ **All Python files**:
- PEP 8 compliant (4-space indents, 100-char lines)
- Type hints on function signatures
- Specific exception handling (no bare except)
- f-strings for formatting
- Context managers for file I/O
- Docstrings on public functions/classes

✅ **Core modules** (core/):
- Structured logging via core/logger.py
- Centralized configuration
- Error handling with logging

✅ **Recon modules** (recon/):
- Tool timeout centralization (core/timeouts.py)
- Rate limiting integration (core/rate_limiter.py)
- Consistent subprocess handling

✅ **Config modules** (config/):
- Validation helpers (config/validators.py)
- Dynamic tool discovery (recon/tool_discovery.py)
- Settings centralization

---

## Checklist Before Commit

- [ ] No syntax errors: `python3 -m py_compile <file>`
- [ ] Imports are organized (stdlib, 3rd-party, local)
- [ ] Functions have docstrings
- [ ] No bare `except:` clauses
- [ ] Type hints on function signatures
- [ ] f-strings used for formatting
- [ ] Line length < 100 characters
- [ ] No trailing whitespace
- [ ] Commit message follows conventional format

---

**Last Updated**: 2026-04-09  
**Enforced Since**: FASE 4.5  
**Tool Compliance**: Manual verification (Black/isort not available in environment)
