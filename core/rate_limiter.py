"""Per-target rate limiting for Hunt3r reconnaissance."""
import time
import logging
from collections import defaultdict

class PerTargetRateLimiter:
    """Throttles API calls per target to avoid overwhelming targets or hitting rate limits."""
    
    def __init__(self, requests_per_second: float = 1.0):
        """
        Initialize rate limiter.
        
        Args:
            requests_per_second: Max requests per second per target (default 1.0 = 1 req/s)
        """
        self.requests_per_second = requests_per_second
        self.min_interval = 1.0 / requests_per_second  # Seconds between requests
        self.target_last_request = defaultdict(float)  # Track last request time per target
    
    def wait_and_record(self, target: str):
        """
        Wait if necessary to respect rate limit, then record this request.
        
        Args:
            target: Target identifier (domain/handle) to rate limit per-target
        """
        now = time.time()
        last_request = self.target_last_request.get(target, 0)
        elapsed_since_last = now - last_request
        
        # If less than min_interval has passed, sleep for the remaining time
        if elapsed_since_last < self.min_interval:
            sleep_time = self.min_interval - elapsed_since_last
            logging.debug(f"Rate limit: {target} - sleeping {sleep_time:.2f}s")
            time.sleep(sleep_time)
        
        # Record this request time
        self.target_last_request[target] = time.time()

# Global instance for use across modules
_global_limiter = None

def get_rate_limiter(requests_per_second: float = 1.0) -> PerTargetRateLimiter:
    """Get or create global rate limiter instance."""
    global _global_limiter
    if _global_limiter is None:
        _global_limiter = PerTargetRateLimiter(requests_per_second)
    return _global_limiter

def reset_rate_limiter():
    """Reset global rate limiter (for testing)."""
    global _global_limiter
    _global_limiter = None
