"""
conftest.py — shared fixtures for PatchTrap tests.
"""
import os
import sys
import pytest

# Insert the project root into sys.path so tests can import patchtrap_mil
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

@pytest.fixture
def target_script_path():
    """Return the absolute path to target_app.py."""
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "target_app.py"))
