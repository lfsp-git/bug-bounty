"""Centralized timeout configuration for Hunt3r tools and operations."""

# Tool execution timeouts (seconds)
TOOL_TIMEOUTS = {
    # Recon phase
    "subfinder": 60,   # Domain enumeration (slow on large targets)
    "dnsx": 60,        # DNS validation (can be slow)
    "uncover": 90,     # Public data aggregation (multiple APIs)
    "httpx": 120,      # HTTP probing (network I/O bound)
    
    # Tactical phase
    "katana": 180,     # Web crawling (can be slow on large sites)
    "js_hunter": 30,   # In-memory JS scanning (fast)
    "nuclei": 300,     # Vulnerability scanning (can be very slow)
    
    # API operations
    "api_request": 15,              # Generic API call timeout
    "ai_inference_short": 30,       # AI short response (tags, classification)
    "ai_inference_long": 60,        # AI long response (analysis, explanation)
    "openrouter_request": 60,       # OpenRouter API calls
    
    # Notifications
    "webhook_post": 10,             # Telegram/Discord webhook
    
    # Utility operations
    "http_get": 15,                 # Generic HTTP GET
    "tool_update": 120,             # Tool download/update operations
}

def get_timeout(tool_name: str, default: int = 30) -> int:
    """Get timeout for a tool, with fallback to default."""
    return TOOL_TIMEOUTS.get(tool_name.lower(), default)

def get_tool_timeout(tool_name: str) -> int:
    """Get timeout for recon/tactical tool execution."""
    return get_timeout(tool_name, default=60)

def get_api_timeout() -> int:
    """Get timeout for generic API operations."""
    return TOOL_TIMEOUTS.get("api_request", 15)

def get_webhook_timeout() -> int:
    """Get timeout for webhook/notification operations."""
    return TOOL_TIMEOUTS.get("webhook_post", 10)
