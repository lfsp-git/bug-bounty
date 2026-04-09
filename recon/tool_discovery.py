"""Dynamic tool path discovery for Hunt3r reconnaissance engines."""
import os
import shutil
import logging

# Standard search paths for tools (checked in order)
TOOL_SEARCH_PATHS = [
    os.path.expanduser("~/.pdtm/go/bin"),  # PDTM custom install
    os.path.expanduser("~/go/bin"),         # Go workspace default
    "/usr/local/bin",                       # System default
    "/usr/bin",                             # Fallback system
    os.environ.get("PATH", "").split(os.pathsep),  # System PATH
]

# Cache for found tools to avoid repeated searches
_tool_cache = {}

def find_tool(tool_name: str) -> str:
    """
    Find tool executable in standard locations.
    Returns full path if found, otherwise returns tool_name (fallback to PATH).
    Caches results to avoid repeated filesystem lookups.
    """
    if tool_name in _tool_cache:
        return _tool_cache[tool_name]
    
    # Try each search path
    for search_path in TOOL_SEARCH_PATHS:
        if isinstance(search_path, str):
            paths_to_check = [search_path]
        else:
            paths_to_check = search_path  # If it's a list (from PATH)
        
        for path in paths_to_check:
            if not path:
                continue
            tool_path = os.path.join(path, tool_name)
            if os.path.isfile(tool_path) and os.access(tool_path, os.X_OK):
                logging.debug(f"Found {tool_name} at {tool_path}")
                _tool_cache[tool_name] = tool_path
                return tool_path
    
    # Fallback: try shutil.which (searches system PATH)
    which_result = shutil.which(tool_name)
    if which_result:
        logging.debug(f"Found {tool_name} via PATH: {which_result}")
        _tool_cache[tool_name] = which_result
        return which_result
    
    # Not found anywhere - return tool_name and let run_cmd() handle the error
    logging.warning(f"Tool {tool_name} not found in any search path. Attempting system PATH fallback.")
    _tool_cache[tool_name] = tool_name
    return tool_name

def clear_tool_cache():
    """Clear the tool cache (useful for testing or after tool updates)."""
    _tool_cache.clear()
