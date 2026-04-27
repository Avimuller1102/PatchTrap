"""
test_cli.py — end-to-end tests for the CLI interface.
"""
import os
import sys
import pytest
from unittest.mock import patch
from patchtrap_mil import main

def test_cli_run(target_script_path, tmp_path):
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        # We catch SystemExit(0)
        with patch.object(sys, "argv", ["patchtrap_mil", "run", target_script_path, "--watch", "builtins.open", "--auto-restore", "1"]):
            with pytest.raises(SystemExit) as e:
                main()
            assert getattr(e.value, "code", None) == 0
            
        assert os.path.exists("patchtrap_report.json")
    finally:
        os.chdir(cwd)

def test_cli_verify_valid(target_script_path, tmp_path):
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        # First generate a report
        with patch.object(sys, "argv", ["patchtrap_mil", "run", target_script_path, "--watch", "builtins.open"]):
            with pytest.raises(SystemExit):
                main()
        
        # Now verify it
        with patch.object(sys, "argv", ["patchtrap_mil", "verify", "patchtrap_report.json"]):
            with pytest.raises(SystemExit) as e:
                main()
            assert getattr(e.value, "code", None) == 0
    finally:
        os.chdir(cwd)

def test_cli_sign_and_verify_hmac(target_script_path, tmp_path):
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        # Generate report
        with patch.object(sys, "argv", ["patchtrap_mil", "run", target_script_path, "--watch", "builtins.open"]):
            with pytest.raises(SystemExit):
                main()
        
        # Sign it
        with patch.object(sys, "argv", ["patchtrap_mil", "sign", "--file", "patchtrap_report.json", "--hmac-key", "secret"]):
            main() # returns without sys.exit
            
        assert os.path.exists("patchtrap_report.json.hmac")
        
        # Verify sign
        with patch.object(sys, "argv", ["patchtrap_mil", "verify-sign", "--file", "patchtrap_report.json", "--hmac-key", "secret"]):
            with pytest.raises(SystemExit) as e:
                main()
            assert getattr(e.value, "code", None) == 0
    finally:
        os.chdir(cwd)
