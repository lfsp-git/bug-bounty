"""Unified deduplication utilities for Hunt3r."""
import logging
from typing import List, Set, Iterable

class DedupStrategy:
    """Base class for deduplication strategies."""
    
    @staticmethod
    def deduplicate(items: Iterable[str]) -> List[str]:
        """Remove duplicates while preserving order. Returns list of unique items."""
        seen: Set[str] = set()
        result: List[str] = []
        for item in items:
            if item:
                clean = item.strip().lower()
                if clean not in seen:
                    seen.add(clean)
                    result.append(item.strip())  # Return original case
        return result
    
    @staticmethod
    def deduplicate_preserve_case(items: Iterable[str]) -> List[str]:
        """Remove duplicates case-sensitively, preserving original case of first occurrence."""
        seen: Set[str] = set()
        result: List[str] = []
        for item in items:
            if item:
                clean = item.strip()
                if clean not in seen:
                    seen.add(clean)
                    result.append(clean)
        return result
    
    @staticmethod
    def to_set(items: Iterable[str]) -> Set[str]:
        """Convert to set, stripping and lowercasing all items."""
        return {item.strip().lower() for item in items if item}
    
    @staticmethod
    def merge_lists(*lists: List[str]) -> List[str]:
        """Merge multiple lists, deduplicate, return as list preserving case."""
        merged = []
        for lst in lists:
            if lst:
                merged.extend(lst)
        return DedupStrategy.deduplicate(merged)

# Singleton instance
_dedup = DedupStrategy()

def deduplicate(items: Iterable[str]) -> List[str]:
    """Remove duplicates from iterable, return sorted unique list."""
    return _dedup.deduplicate(items)

def deduplicate_preserve_case(items: Iterable[str]) -> List[str]:
    """Remove duplicates case-sensitively."""
    return _dedup.deduplicate_preserve_case(items)

def to_set(items: Iterable[str]) -> Set[str]:
    """Convert to deduplicated set (lowercased)."""
    return _dedup.to_set(items)

def merge_lists(*lists: List[str]) -> List[str]:
    """Merge multiple lists and deduplicate."""
    return _dedup.merge_lists(*lists)
