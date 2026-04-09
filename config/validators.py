"""Input validators for CLI arguments and user input."""
import re
import logging

# Domain regex: valid fqdn
DOMAIN_PATTERN = re.compile(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$', re.IGNORECASE)

# URL regex: http(s)://...
URL_PATTERN = re.compile(r'^https?://(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', re.IGNORECASE)

def validate_domain(domain: str) -> bool:
    """Check if domain is a valid FQDN."""
    if not domain or len(domain) > 253:
        return False
    # Remove trailing dot if present (valid in DNS)
    domain = domain.rstrip('.')
    return DOMAIN_PATTERN.match(domain) is not None

def validate_url(url: str) -> bool:
    """Check if URL starts with valid http(s)://domain."""
    if not url or len(url) > 2048:
        return False
    return URL_PATTERN.match(url) is not None

def validate_and_extract_domain(input_str: str) -> str:
    """Extract domain from URL or validate domain, return clean domain or empty string."""
    if not input_str:
        return ""
    
    input_str = input_str.strip().lower()
    
    # If it looks like a URL, extract domain
    if input_str.startswith(('http://', 'https://')):
        if not validate_url(input_str):
            logging.warning(f"Invalid URL format: {input_str}")
            return ""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(input_str)
            domain = parsed.hostname
            if domain and validate_domain(domain):
                return domain
        except Exception as e:
            logging.warning(f"Failed to parse URL {input_str}: {e}")
            return ""
    
    # Otherwise treat as domain
    if validate_domain(input_str):
        return input_str
    
    logging.warning(f"Invalid domain format: {input_str}")
    return ""
