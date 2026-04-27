"""
test_policy.py — tests for Policy and SecurityError
"""
import pytest
from patchtrap_mil import Policy, SecurityError

class TestPolicy:
    def test_no_enforce(self):
        pol = Policy(enforce=False, deny=["*"])
        # Should not raise
        pol.check("builtins.open")

    def test_enforce_deny(self):
        pol = Policy(enforce=True, deny=["builtins.*"])
        with pytest.raises(SecurityError, match="Denied by policy"):
            pol.check("builtins.open")

    def test_enforce_allow(self):
        pol = Policy(enforce=True, allow=["socket.*"])
        # socket allowed
        pol.check("socket.socket")
        # others not allowed
        with pytest.raises(SecurityError, match="Not allowed by policy"):
            pol.check("builtins.open")

    def test_deny_overrides_allow(self):
        pol = Policy(enforce=True, allow=["*"], deny=["subprocess.*"])
        pol.check("builtins.open") # ok
        with pytest.raises(SecurityError, match="Denied by policy"):
            pol.check("subprocess.Popen")
