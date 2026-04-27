"""
test_signing.py — tests for HMAC signing and report integrity verification.
"""
import json
import os
import pytest
from patchtrap_mil import (
    canonical_bytes, _sha256, leaf_hash, merkle_root, chain_next,
    sign_hmac, verify_hmac, report_verify_integrity, PatchTrapMIL
)

def test_report_verify_integrity_valid():
    # Construct a valid report manually
    alerts = [{"kind": "test", "val": 1}, {"kind": "test", "val": 2}]
    leaves = [leaf_hash(a) for a in alerts]
    mr = merkle_root(leaves).hex()
    ch = _sha256(b"")
    for lf in leaves:
        ch = chain_next(ch, lf)
    
    report = {
        "summary": {
            "merkle_root": mr,
            "chain_tip": ch.hex()
        },
        "alerts": alerts
    }
    
    ok, info = report_verify_integrity(report)
    assert ok is True
    assert info == mr

def test_report_verify_integrity_tampered():
    alerts = [{"kind": "test", "val": 1}]
    leaves = [leaf_hash(a) for a in alerts]
    mr = merkle_root(leaves).hex()
    
    # Tamper with the report
    report = {
        "summary": {
            "merkle_root": mr, # correct root
            "chain_tip": "wrong" # tampered chain tip
        },
        "alerts": alerts
    }
    
    ok, info = report_verify_integrity(report)
    assert ok is False
    assert "recalc_chain=" in info

def test_hmac_sign_verify(tmp_path):
    report_file = tmp_path / "report.json"
    report_file.write_text('{"test": 1}')
    
    key = b"secret_key"
    out_sig = sign_hmac(str(report_file), key)
    
    assert os.path.exists(out_sig)
    
    with open(out_sig, "r") as f:
        sig_hex = f.read().strip()
        
    assert verify_hmac(str(report_file), key, sig_hex) is True
    assert verify_hmac(str(report_file), b"wrong_key", sig_hex) is False
