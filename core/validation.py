"""
Hunt3r-v1: Input Validation Module
Centralized validation for domains, URLs, and other inputs.
"""

import re
import logging
from typing import List, Optional

logger = logging.getLogger(__name__)

# Regex patterns for validation
DOMAIN_PATTERN = re.compile(
    r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$',
    re.IGNORECASE
)

WILDCARD_DOMAIN_PATTERN = re.compile(
    r'^(\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$',
    re.IGNORECASE
)

URL_PATTERN = re.compile(
    r'^https?://[^\s/$.?#].[^\s]*$',
    re.IGNORECASE
)

IP_PATTERN = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)

SAFE_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\-\.]+$')


class ValidationError(ValueError):
    """Custom exception for validation failures."""
    pass


def validate_domain(domain: str, allow_wildcard: bool = False) -> str:
    """
    Validate domain name format.
    
    Args:
        domain: Domain to validate
        allow_wildcard: If True, allow *.domain.com format
        
    Returns:
        Cleaned domain string
        
    Raises:
        ValidationError: If domain is invalid
    """
    if not domain or not isinstance(domain, str):
        raise ValidationError("Domain must be a non-empty string")
    
    domain = domain.lower().strip()
    
    # Remove common prefixes
    for prefix in ['http://', 'https://', '*.', 'www.']:
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    
    domain = domain.rstrip('/')
    
    if len(domain) > 255:
        raise ValidationError("Domain name too long (max 255 characters)")
    
    if len(domain) < 4:
        raise ValidationError("Domain name too short (min 4 characters)")
    
    pattern = WILDCARD_DOMAIN_PATTERN if allow_wildcard else DOMAIN_PATTERN
    if not pattern.match(domain):
        raise ValidationError(f"Invalid domain format: {domain}")
    
    return domain


def validate_url(url: str) -> str:
    """
    Validate URL format.
    
    Args:
        url: URL to validate
        
    Returns:
        Cleaned URL string
        
    Raises:
        ValidationError: If URL is invalid
    """
    if not url or not isinstance(url, str):
        raise ValidationError("URL must be a non-empty string")
    
    url = url.strip()
    
    if len(url) > 2048:
        raise ValidationError("URL too long (max 2048 characters)")
    
    if not URL_PATTERN.match(url):
        raise ValidationError(f"Invalid URL format: {url}")
    
    # Validate domain part
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.netloc:
            validate_domain(parsed.netloc)
    except ValidationError as e:
        raise ValidationError(f"Invalid domain in URL: {e}")
    
    return url


def validate_domains_list(domains: List[str]) -> List[str]:
    """
    Validate and clean a list of domains.
    
    Args:
        domains: List of domains to validate
        
    Returns:
        List of valid cleaned domains
        
    Raises:
        ValidationError: If list is empty or invalid
    """
    if not domains or not isinstance(domains, list):
        raise ValidationError("Domains must be a non-empty list")
    
    if len(domains) > 10000:
        raise ValidationError("Too many domains (max 10000)")
    
    valid_domains = []
    for domain in domains:
        try:
            valid_domain = validate_domain(domain, allow_wildcard=False)
            if valid_domain not in valid_domains:  # Deduplicate
                valid_domains.append(valid_domain)
        except ValidationError as e:
            logger.warning(f"Skipping invalid domain: {e}")
            continue
    
    if not valid_domains:
        raise ValidationError("No valid domains provided")
    
    return valid_domains


def validate_target_handle(handle: str) -> str:
    """
    Validate bug bounty program handle.
    
    Args:
        handle: Program handle to validate
        
    Returns:
        Cleaned handle
        
    Raises:
        ValidationError: If handle is invalid
    """
    if not handle or not isinstance(handle, str):
        raise ValidationError("Handle must be a non-empty string")
    
    handle = handle.strip().lower()
    
    if len(handle) > 100:
        raise ValidationError("Handle too long (max 100 characters)")
    
    if not re.match(r'^[a-z0-9\-_]+$', handle):
        raise ValidationError("Handle contains invalid characters")
    
    return handle


def validate_api_key(key: str, key_type: str = "generic") -> str:
    """
    Validate API key format (length and charset).
    
    Args:
        key: API key to validate
        key_type: Type of key (generic, aws, stripe, etc)
        
    Returns:
        Cleaned key
        
    Raises:
        ValidationError: If key is invalid
    """
    if not key or not isinstance(key, str):
        raise ValidationError("API key must be a non-empty string")
    
    key = key.strip()
    
    if len(key) < 10:
        raise ValidationError("API key too short")
    
    if len(key) > 500:
        raise ValidationError("API key too long")
    
    # Type-specific validation
    if key_type == "aws" and not key.startswith("AKIA"):
        logger.warning("AWS key should start with AKIA")
    elif key_type == "stripe" and not (key.startswith("sk_") or key.startswith("rk_")):
        logger.warning("Stripe key should start with sk_ or rk_")
    
    return key


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent directory traversal attacks.
    
    Args:
        filename: Filename to sanitize
        
    Returns:
        Safe filename
        
    Raises:
        ValidationError: If filename is invalid
    """
    if not filename or not isinstance(filename, str):
        raise ValidationError("Filename must be a non-empty string")
    
    filename = filename.strip()
    
    # Remove path separators
    if '/' in filename or '\\' in filename:
        raise ValidationError("Filename contains path separators")
    
    # Remove dangerous characters
    if '..' in filename:
        raise ValidationError("Filename contains parent directory reference")
    
    if len(filename) > 255:
        raise ValidationError("Filename too long")
    
    if not SAFE_FILENAME_PATTERN.match(filename):
        raise ValidationError("Filename contains invalid characters")
    
    return filename


from typing import Optional as _Optional

def validate_positive_int(value: str, min_val: int = 0, max_val: _Optional[int] = None) -> int:
    """
    Validate and convert string to positive integer.
    
    Args:
        value: String value to convert
        min_val: Minimum allowed value
        max_val: Maximum allowed value (None = no limit)
        
    Returns:
        Validated integer
        
    Raises:
        ValidationError: If value is invalid
    """
    try:
        num = int(value)
    except (ValueError, TypeError):
        raise ValidationError(f"Must be an integer, got: {value}")
    
    if num < min_val:
        raise ValidationError(f"Value must be >= {min_val}, got: {num}")
    
    if max_val is not None and num > max_val:
        raise ValidationError(f"Value must be <= {max_val}, got: {num}")
    
    return num
