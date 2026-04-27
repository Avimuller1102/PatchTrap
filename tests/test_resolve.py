"""
test_resolve.py — tests for _resolve_dotted
"""
import pytest
from patchtrap_mil import _resolve_dotted

def test_resolve_builtin():
    container, val, qual, attr = _resolve_dotted("builtins.open")
    import builtins
    assert container is builtins
    assert val is builtins.open
    assert attr == "open"
    assert "builtins" in qual

def test_resolve_nested():
    import urllib.request
    container, val, qual, attr = _resolve_dotted("urllib.request.urlopen")
    assert container is urllib.request
    assert val is urllib.request.urlopen
    assert attr == "urlopen"

def test_resolve_invalid():
    with pytest.raises(ValueError):
        _resolve_dotted("nodot")
    with pytest.raises(AttributeError):
        _resolve_dotted("builtins.nonexistent_attr_123")
