"""
test_hash.py — tests for canonical_bytes, _sha256, leaf_hash, merkle_root, chain_next.
"""
import hashlib
import json
import pytest
from patchtrap_mil import (
    canonical_bytes, _sha256, leaf_hash, node_hash, merkle_root, chain_next
)

class TestCanonicalBytes:
    def test_scalars(self):
        assert canonical_bytes(None) == b"null"
        assert canonical_bytes(True) == b"true"
        assert canonical_bytes(42) == b"42"
        assert canonical_bytes("test") == b'"test"'

    def test_bytes_b64(self):
        b = b"hello"
        res = json.loads(canonical_bytes(b))
        assert "__b64" in res

    def test_dict_sorted(self):
        d = {"z": 1, "a": 2}
        res = canonical_bytes(d)
        assert res.find(b'"a"') < res.find(b'"z"')

    def test_list_and_tuple(self):
        assert canonical_bytes([1, 2]) == b"[1,2]"
        assert canonical_bytes((1, 2)) == b"[1,2]"

    def test_fallback_repr(self):
        class Obj:
            def __repr__(self): return "Obj"
        res = json.loads(canonical_bytes(Obj()))
        assert "_repr_" in res
        assert res["_repr_"] == "Obj"


class TestMerklePrimitives:
    def test_leaf_hash(self):
        ev = {"type": "test"}
        lf = leaf_hash(ev)
        assert len(lf) == 32
        expected = hashlib.sha256(b"\x00" + canonical_bytes(ev)).digest()
        assert lf == expected

    def test_node_hash(self):
        L, R = b"A"*32, b"B"*32
        nh = node_hash(L, R)
        assert len(nh) == 32
        expected = hashlib.sha256(b"\x01" + L + R).digest()
        assert nh == expected

    def test_merkle_root_empty(self):
        assert merkle_root([]) == hashlib.sha256(b"").digest()

    def test_merkle_root_single(self):
        lf = leaf_hash({"x": 1})
        assert merkle_root([lf]) == lf

    def test_merkle_root_two(self):
        l1, l2 = leaf_hash({"x": 1}), leaf_hash({"x": 2})
        assert merkle_root([l1, l2]) == node_hash(l1, l2)

    def test_chain_next(self):
        prev = b"X" * 32
        lf = b"Y" * 32
        cn = chain_next(prev, lf)
        assert len(cn) == 32
        expected = hashlib.sha256(b"\x02" + prev + lf).digest()
        assert cn == expected
