"""Simple TTL-based API response caching."""
import time
import json
import os
import logging
from functools import wraps
from typing import Callable, Any

# Cache storage: {cache_key: (timestamp, data)}
_memory_cache = {}
_cache_dir = "recon/cache"

def ttl_cache(ttl_seconds: int = 3600):
    """Decorator to cache function results with TTL (time-to-live)."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # Generate cache key from function name and args
            cache_key = f"{func.__name__}:{str(args)}{str(kwargs)}"
            now = time.time()
            
            # Check memory cache
            if cache_key in _memory_cache:
                timestamp, cached_data = _memory_cache[cache_key]
                if now - timestamp < ttl_seconds:
                    logging.debug(f"Cache hit: {func.__name__} (age: {int(now - timestamp)}s)")
                    return cached_data
                else:
                    del _memory_cache[cache_key]
            
            # Cache miss - execute function
            logging.debug(f"Cache miss: {func.__name__} - executing")
            result = func(*args, **kwargs)
            
            # Store in memory cache
            _memory_cache[cache_key] = (now, result)
            return result
        
        return wrapper
    return decorator

def file_cache(ttl_seconds: int = 3600):
    """Decorator to cache function results to disk with TTL."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            os.makedirs(_cache_dir, exist_ok=True)
            cache_key = f"{func.__name__}_{hash(str(args) + str(kwargs))}"
            cache_file = os.path.join(_cache_dir, f"{cache_key}.json")
            now = time.time()
            
            # Check disk cache
            if os.path.exists(cache_file):
                try:
                    stat = os.stat(cache_file)
                    if now - stat.st_mtime < ttl_seconds:
                        with open(cache_file) as f:
                            cached_data = json.load(f)
                        logging.debug(f"Disk cache hit: {func.__name__} (age: {int(now - stat.st_mtime)}s)")
                        return cached_data
                except Exception as e:
                    logging.debug(f"Cache read failed: {e}")
            
            # Cache miss - execute function
            logging.debug(f"Cache miss: {func.__name__} - executing")
            result = func(*args, **kwargs)
            
            # Store on disk
            try:
                with open(cache_file, 'w') as f:
                    json.dump(result, f)
            except Exception as e:
                logging.debug(f"Cache write failed: {e}")
            
            return result
        
        return wrapper
    return decorator

def clear_cache():
    """Clear all in-memory cache."""
    global _memory_cache
    _memory_cache.clear()
    logging.debug("Memory cache cleared")

def clear_file_cache():
    """Clear all disk cache."""
    if os.path.exists(_cache_dir):
        try:
            for f in os.listdir(_cache_dir):
                os.remove(os.path.join(_cache_dir, f))
            logging.debug("Disk cache cleared")
        except Exception as e:
            logging.error(f"Failed to clear disk cache: {e}")
