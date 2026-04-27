"""
test_fingerprint.py — tests for _fingerprint_callable
"""
import pytest
from patchtrap_mil import _fingerprint_callable

def sample_func():
    return 42

def another_func():
    return 42

def func_with_diff_code():
    return 43

class DummyClass:
    def method(self): pass

class TestFingerprint:
    def test_same_func_stable_fingerprint(self):
        fp1 = _fingerprint_callable(sample_func)
        fp2 = _fingerprint_callable(sample_func)
        assert fp1["hash"] == fp2["hash"]

    def test_different_funcs_different_hash(self):
        fp1 = _fingerprint_callable(sample_func)
        fp2 = _fingerprint_callable(another_func)
        assert fp1["hash"] != fp2["hash"]

    def test_bytecode_change_alters_hash(self):
        fp1 = _fingerprint_callable(sample_func)
        fp2 = _fingerprint_callable(func_with_diff_code)
        assert fp1["hash"] != fp2["hash"]

    def test_builtins_fingerprint(self):
        fp = _fingerprint_callable(len)
        assert "builtin_function_or_method" in fp["type"]
        assert "hash" in fp
        assert fp["hash"] == _fingerprint_callable(len)["hash"]

    def test_methods_fingerprint(self):
        obj = DummyClass()
        fp = _fingerprint_callable(obj.method)
        assert "hash" in fp

    def test_unsupported_object_does_not_crash(self):
        # Fingerprinting a string (not callable) should fallback gracefully
        fp = _fingerprint_callable("hello")
        assert fp["hash"] is not None
        assert "not-callable" in fp.get("where", "")
