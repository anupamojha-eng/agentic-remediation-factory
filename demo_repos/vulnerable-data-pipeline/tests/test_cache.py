"""Unit tests for the cache layer — run by Sentinel's verify step after patching."""
import pytest
from app.cache import ResultCache


def test_set_and_get_roundtrip():
    cache = ResultCache()
    cache.set("k1", {"data": [1, 2, 3], "label": "test"})
    result = cache.get("k1")
    assert result == {"data": [1, 2, 3], "label": "test"}


def test_get_missing_key_returns_none():
    cache = ResultCache()
    assert cache.get("nonexistent") is None


def test_overwrite_existing_key():
    cache = ResultCache()
    cache.set("k", "first")
    cache.set("k", "second")
    assert cache.get("k") == "second"


def test_multiple_keys_independent():
    cache = ResultCache()
    cache.set("a", 1)
    cache.set("b", 2)
    assert cache.get("a") == 1
    assert cache.get("b") == 2
