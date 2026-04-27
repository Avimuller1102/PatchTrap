"""
test_patchtrap.py — tests for PatchTrapMIL core functionality.
"""
import os
import sys
import pytest
from patchtrap_mil import PatchTrapMIL, SecurityError

def dummy_target():
    return "original"

def malicious_target():
    return "hacked"

# We put this in sys.modules so _resolve_dotted can find it via __name__
sys.modules[__name__] = sys.modules.get(__name__, sys.modules[__name__])

class TestPatchTrapCore:
    def test_seal_and_no_tamper(self):
        pt = PatchTrapMIL([f"{__name__}.dummy_target"])
        pt.seal()
        pt._scan_once("test")
        # No alerts
        assert len([a for a in pt.alerts if a["kind"] == "replaced"]) == 0

    def test_detect_and_restore(self):
        global dummy_target
        pt = PatchTrapMIL([f"{__name__}.dummy_target"], auto_restore=True)
        pt.seal()

        # monkey-patch
        dummy_target = malicious_target
        assert dummy_target() == "hacked"

        pt._scan_once("test")

        # should have an alert
        alerts = [a for a in pt.alerts if a["kind"] == "replaced"]
        assert len(alerts) == 1
        assert alerts[0]["target"] == f"{__name__}.dummy_target"

        # should be restored
        assert dummy_target() == "original"

    def test_fail_closed_on_tamper(self):
        global dummy_target
        pt = PatchTrapMIL([f"{__name__}.dummy_target"], auto_restore=False, fail_closed=True)
        pt.seal()
        dummy_target = malicious_target
        
        with pytest.raises(SecurityError, match="Tamper detected"):
            pt._scan_once("test")

    def test_env_changes(self):
        pt = PatchTrapMIL([], fail_closed=False)
        pt.seal()
        
        os.environ["PATCHTRAP_DUMMY_VAR"] = "1"
        pt._scan_once("test")
        
        env_alerts = [a for a in pt.alerts if a["kind"] == "env_changed"]
        assert len(env_alerts) == 1
        assert "PATCHTRAP_DUMMY_VAR" in env_alerts[0]["added"]
        del os.environ["PATCHTRAP_DUMMY_VAR"]

    def test_meta_path_changes(self):
        pt = PatchTrapMIL([], fail_closed=False)
        pt.seal()
        
        class DummyFinder: pass
        sys.meta_path.append(DummyFinder())
        pt._scan_once("test")
        
        mp_alerts = [a for a in pt.alerts if a["kind"] == "meta_path_changed"]
        assert len(mp_alerts) == 1
        sys.meta_path.pop()
