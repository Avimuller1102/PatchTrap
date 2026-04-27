
"""
patchtrap_mil.py — single-file patch/tamper detector with auto-restore,
tamper-evident logging (Merkle + cumulative hash chain), and optional signing.

Key features (EN):
- Fingerprints Python callables (bytecode-based when possible) and detects monkey-patching.
- Auto-restore originals on tamper (fail-closed option).
- Tracks and reports changes to sys.meta_path, environment, and (optionally) sys.modules.
- Tamper-evident report: canonical JSON + Merkle root + cumulative chain tip.
- Optional signing: HMAC-SHA256 (stdlib) or Ed25519 (if 'cryptography' installed).
- Policy enforcement: allow/deny for targets; fail-closed if violated.
- Robust CLI with deterministic output (for CI/forensics).
- Single-file; stdlib only (Ed25519 is optional).

Usage (quick):
  python patchtrap_mil.py run suspicious.py --watch builtins.open,socket.socket --auto-restore 1
  python patchtrap_mil.py run app.py --interval 0.3 --scan-during 1 --fail-closed 1
  python patchtrap_mil.py verify patchtrap_report.json       # verify Merkle/chain
  python patchtrap_mil.py sign --file patchtrap_report.json --hmac-key "supersecret"
  python patchtrap_mil.py sign --file patchtrap_report.json --ed25519-priv ed25519-key.pem
  python patchtrap_mil.py verify-sign --file patchtrap_report.json --hmac-key "supersecret"
  python patchtrap_mil.py verify-sign --file patchtrap_report.json --ed25519-pub ed25519-pub.pem
"""

from __future__ import annotations

__version__ = "1.0.0"
__all__ = [
    # Core
    "PatchTrapMIL",
    "Policy",
    "SecurityError",
    # Crypto/Hash Utils
    "canonical_bytes",
    "leaf_hash",
    "node_hash",
    "merkle_root",
    "chain_next",
    # Fingerprinting
    "_fingerprint_callable",
    "_resolve_dotted",
    # Signing/Verification
    "report_load",
    "report_verify_integrity",
    "sign_hmac",
    "verify_hmac",
    "sign_ed25519",
    "verify_ed25519",
    # CLI
    "main"
]
import argparse
import base64
import hashlib
import hmac
import importlib
import inspect
import io
import json
import os
import runpy
import sys
import threading
import time
import types
from dataclasses import dataclass, field
from typing import Any, Dict, Tuple, List, Iterable, Optional

# Optional Ed25519 (recommended but not required)
_ED25519 = False
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey
    )
    from cryptography.hazmat.primitives import serialization
    _ED25519 = True
except Exception:
    _ED25519 = False

# ===========
# Hash utils
# ===========
def _sha256_hex(b: bytes) -> str:
    h = hashlib.sha256(); h.update(b); return h.hexdigest()

def _sha256(b: bytes) -> bytes:
    h = hashlib.sha256(); h.update(b); return h.digest()

def _canonical_enc(o: Any) -> Any:
    """Deterministic JSON encoder: sorted keys; bytes->b64; tuples->lists; repr fallback."""
    if o is None or isinstance(o, (bool, int, float, str)):
        return o
    if isinstance(o, (bytes, bytearray)):
        return {"__b64": base64.b64encode(bytes(o)).decode("ascii")}
    if isinstance(o, dict):
        return {str(k): _canonical_enc(o[k]) for k in sorted(o.keys(), key=lambda x: str(x))}
    if isinstance(o, (list, tuple)):
        return [_canonical_enc(x) for x in o]
    return {"_repr_": repr(o)}

def canonical_bytes(o: Any) -> bytes:
    return json.dumps(_canonical_enc(o), separators=(",", ":"), ensure_ascii=True).encode("utf-8")

# Merkle / chain (tamper-evident)
def leaf_hash(event: Dict[str, Any]) -> bytes:
    return _sha256(b"\x00" + canonical_bytes(event))

def node_hash(l: bytes, r: bytes) -> bytes:
    return _sha256(b"\x01" + l + r)

def merkle_root(leaves: Iterable[bytes]) -> bytes:
    nodes = list(leaves)
    if not nodes:
        return _sha256(b"")
    while len(nodes) > 1:
        nxt = []
        for i in range(0, len(nodes), 2):
            L = nodes[i]; R = nodes[i+1] if i+1 < len(nodes) else nodes[i]
            nxt.append(node_hash(L, R))
        nodes = nxt
    return nodes[0]

def chain_next(prev: bytes, leaf: bytes) -> bytes:
    return _sha256(b"\x02" + prev + leaf)

# ==========================
# Fingerprinting & resolving
# ==========================
def _fingerprint_callable(obj: Any) -> Dict[str, Any]:
    """
    Produce a robust fingerprint for Python callables.
    - For functions/methods: hash bytecode + consts + names + filename + firstlineno.
    - For builtins/C callables: module/qualname/repr hash.
    - For other callables: class+repr hash.
    """
    fp: Dict[str, Any] = {"type": type(obj).__name__}
    try:
        if inspect.isfunction(obj) or inspect.ismethod(obj):
            code = obj.__code__
            payload = b"||".join([
                code.co_code,
                repr(code.co_consts).encode(),
                repr(code.co_names).encode(),
                repr(code.co_varnames).encode(),
                repr(code.co_filename).encode(),
                repr(code.co_firstlineno).encode(),
            ])
            fp["hash"] = _sha256_hex(payload)
            fp["where"] = f"{obj.__module__}.{getattr(obj, '__qualname__', getattr(obj, '__name__', ''))}"
        elif isinstance(obj, (types.BuiltinFunctionType, types.BuiltinMethodType)):
            tag = f"{getattr(obj, '__module__', '')}:{getattr(obj, '__qualname__', getattr(obj, '__name__', ''))}:{repr(obj)[:80]}"
            fp["hash"] = _sha256_hex(tag.encode())
            fp["where"] = tag
        elif callable(obj):
            tag = f"{obj.__class__.__module__}.{obj.__class__.__qualname__}:{repr(obj)[:80]}"
            fp["hash"] = _sha256_hex(tag.encode())
            fp["where"] = tag
        else:
            tag = f"not-callable:{repr(obj)[:80]}"
            fp["hash"] = _sha256_hex(tag.encode())
            fp["where"] = tag
    except Exception as e:
        tag = f"error:{type(obj).__name__}:{repr(e)[:60]}"
        fp["hash"] = _sha256_hex(tag.encode()); fp["where"] = tag
    return fp

def _resolve_dotted(name: str) -> Tuple[Any, Any, str, str]:
    """
    Resolve a dotted name like 'module.sub.obj' and return:
    (container_object, attribute_value, container_qualname, attr_name)
    """
    parts = name.split(".")
    if len(parts) < 2:
        raise ValueError(f"invalid dotted name: {name}")
    mod = importlib.import_module(parts[0])
    obj: Any = mod
    for p in parts[1:-1]:
        obj = getattr(obj, p)
    attr = parts[-1]
    val = getattr(obj, attr)
    container_qual = f"{obj.__module__}.{getattr(obj, '__qualname__', getattr(obj, '__name__', ''))}" if hasattr(obj, "__module__") else repr(obj)
    return obj, val, container_qual, attr

# ==========================
# Policy & configuration
# ==========================
@dataclass
class Policy:
    """Allow/Deny lists for targets; fail-closed if enforce=True."""
    enforce: bool = False
    allow: List[str] = field(default_factory=list)
    deny: List[str] = field(default_factory=list)

    def __post_init__(self):
        self.allow = self.allow or []
        self.deny = self.deny or []

    def check(self, dotted: str):
        if not self.enforce:
            return
        if any(_glob_match(dotted, pat) for pat in (self.deny or [])):
            raise SecurityError(f"Denied by policy: {dotted}")
        if self.allow and not any(_glob_match(dotted, pat) for pat in self.allow):
            raise SecurityError(f"Not allowed by policy: {dotted}")

def _glob_match(text: str, pattern: str) -> bool:
    # very small fnmatch-style matcher (** supported)
    import fnmatch
    return fnmatch.fnmatch(text, pattern)

class SecurityError(RuntimeError):
    pass

# ==========================
# PatchTrap
# ==========================
def _short(x: Any) -> str:
    try:
        s = repr(x);  return s if len(s) <= 240 else s[:240]+"..."
    except Exception:
        return "<unrepr>"

class PatchTrapMIL:
    """
    PatchTrap:
    - Seals baseline (fingerprints + originals)
    - Live detection of tampering (monkey-patching, sys.meta_path/env changes)
    - Optional sys.modules checks
    - Auto-restore of originals on tamper
    - Tamper-evident logging: Merkle root + cumulative hash-chain
    - Optional fail-closed policy (deny/allow) for target list
    """
    def __init__(self,
                 targets: List[str],
                 auto_restore: bool = True,
                 interval: float = 0.0,
                 scan_during: bool = False,
                 fail_closed: bool = False,
                 check_modules: bool = False,
                 policy: Optional[Policy] = None):
        self.targets = targets
        self.auto_restore = bool(auto_restore)
        self.interval = max(0.0, float(interval))
        self.scan_during = bool(scan_during)
        self.fail_closed = bool(fail_closed)
        self.baseline: Dict[str, Dict[str, Any]] = {}
        self.originals: Dict[str, Any] = {}
        self.alerts: List[Dict[str, Any]] = []
        self.meta_path0 = list(sys.meta_path)
        self.env0 = dict(os.environ)
        self.modules0 = set(sys.modules.keys())
        self.check_modules = bool(check_modules)
        self.policy = policy or Policy(enforce=False)
        # tamper-evident aggregation
        self._leaves: List[bytes] = []
        self._chain_tip: bytes = _sha256(b'')  # cumulative rolling hash

    # --- tamper-evident ingest
    def _ingest(self, event: Dict[str, Any]):
        """Add an event into Merkle + chain."""
        lf = leaf_hash(event)
        self._leaves.append(lf)
        self._chain_tip = chain_next(self._chain_tip, lf)
        self.alerts.append(event)

    # --- sealing
    def seal(self):
        for dotted in self.targets:
            # policy pre-check for targets (fail-closed if needed)
            if self.fail_closed:
                self.policy.check(dotted)
            container, val, container_qual, attr = _resolve_dotted(dotted)
            self.originals[dotted] = val
            self.baseline[dotted] = {
                "fp": _fingerprint_callable(val),
                "container": container_qual,
                "attr": attr,
            }

    # --- scanning
    def _scan_once(self, phase: str):
        # detect target replacement
        for dotted in self.targets:
            try:
                container, current, container_qual, attr = _resolve_dotted(dotted)
            except Exception as e:
                self._ingest({"kind":"resolve_error","phase":phase,"target": dotted, "error": repr(e)})
                continue
            base = self.baseline.get(dotted)
            if not base:  # should not happen
                continue
            fp_now = _fingerprint_callable(current)
            if fp_now["hash"] != base["fp"]["hash"]:
                ev = {
                    "kind":"replaced","phase":phase,"target": dotted,
                    "before": base["fp"], "after": fp_now
                }
                self._ingest(ev)
                if self.auto_restore:
                    try:
                        setattr(container, attr, self.originals[dotted])
                        self._ingest({"kind":"restore","phase":phase,"target": dotted,"status":"ok"})
                    except Exception as e:
                        self._ingest({"kind":"restore","phase":phase,"target": dotted,"status":"fail","error": repr(e)})
                elif self.fail_closed:
                    raise SecurityError(f"Tamper detected on {dotted}")

        # import hooks (meta_path)
        mp_before = [type(x).__name__ for x in self.meta_path0]
        mp_now = [type(x).__name__ for x in list(sys.meta_path)]
        if mp_now != mp_before:
            self._ingest({"kind":"meta_path_changed","phase":phase,"before": mp_before,"after": mp_now})
            if self.fail_closed:
                raise SecurityError("meta_path changed")

        # environment
        env_now = dict(os.environ)
        added = sorted(set(env_now) - set(self.env0))
        removed = sorted(set(self.env0) - set(env_now))
        changed = sorted(k for k in set(env_now).intersection(self.env0) if env_now[k] != self.env0[k])
        if added or removed or changed:
            self._ingest({
                "kind":"env_changed","phase":phase,
                "added": {k: env_now[k] for k in added},
                "removed": {k: self.env0[k] for k in removed},
                "changed": {k: {"before": self.env0[k], "after": env_now[k]} for k in changed},
            })
            if self.fail_closed:
                raise SecurityError("environment changed")

        # modules (optional)
        if self.check_modules:
            mods_now = set(sys.modules.keys())
            if mods_now != self.modules0:
                newmods = sorted(list(mods_now - self.modules0))[:50]
                delmods = sorted(list(self.modules0 - mods_now))[:50]
                self._ingest({"kind":"modules_changed","phase":phase,"added": newmods,"removed": delmods})
                # don’t fail-closed here; module churn can be normal. Toggle if needed.

    # --- execution
    def run(self, target_path: str, args_line: str = "") -> int:
        old_argv = sys.argv[:]
        sys.argv = [target_path] + (args_line.split() if args_line else [])
        rc = 0
        start = time.time()

        # header event
        self._ingest({
            "kind":"patchtrap.start",
            "ts": start,
            "targets": self.targets,
            "policy": {"enforce": self.policy.enforce, "allow": self.policy.allow, "deny": self.policy.deny},
            "python": sys.version, "platform": sys.platform, "cwd": os.getcwd()
        })

        try:
            print(f"[patchtrap] sealed {len(self.targets)} targets; env/meta_path baselined")
            print(f"[patchtrap] run begin: {os.path.abspath(target_path)}")
            # pre-scan
            self._scan_once(phase="pre")
            if self.scan_during and self.interval > 0.0:
                # run + cooperative periodic scans (same thread)
                next_tick = time.time() + self.interval
                runpy.run_path(target_path, run_name="__main__")
                # single additional during-scan to catch late patches
                while time.time() < next_tick:
                    time.sleep(0.01)
                self._scan_once(phase="during")
            else:
                runpy.run_path(target_path, run_name="__main__")
            # post-scan
            self._scan_once(phase="post")
            print("[patchtrap] run end: status=ok")
        except SystemExit as e:
            rc = int(getattr(e, "code", 0) or 0)
            self._ingest({"kind":"system_exit","code": rc})
            print(f"[patchtrap] run end: SystemExit({rc})")
        except SecurityError as e:
            rc = 2
            self._ingest({"kind":"security_error","error": repr(e)})
            print("[patchtrap] run end: FAIL-CLOSED (security policy)")
        except Exception as e:
            rc = 1
            self._ingest({"kind":"exception","error": repr(e)})
            print("[patchtrap] run end: status=exception")
        finally:
            sys.argv = old_argv
            dur = round(time.time() - start, 6)
            merkle = merkle_root(self._leaves).hex()
            chain_tip = self._chain_tip.hex()
            report = {
                "summary": {
                    "duration_sec": dur,
                    "targets": self.targets,
                    "auto_restore": self.auto_restore,
                    "fail_closed": self.fail_closed,
                    "check_modules": self.check_modules,
                    "interval": self.interval,
                    "scan_during": self.scan_during,
                    "alerts_count": len(self.alerts),
                    "merkle_root": merkle,
                    "chain_tip": chain_tip
                },
                "alerts": self.alerts
            }
            out = "patchtrap_report.json"
            with open(out, "wb") as f:
                f.write(canonical_bytes(report))
            print(f"[patchtrap] report saved: {out}")
        return rc

# ==========================
# Signing & verification
# ==========================
def report_load(path: str) -> Dict[str, Any]:
    return json.loads(open(path, "rb").read().decode("utf-8"))

def report_verify_integrity(report: Dict[str, Any]) -> Tuple[bool, str]:
    """Rebuild Merkle and chain from alerts and compare to summary."""
    alerts = report.get("alerts", [])
    leaves = [leaf_hash(ev) for ev in alerts]
    mr = merkle_root(leaves).hex()
    ch = _sha256(b'')
    for lf in leaves:
        ch = chain_next(ch, lf)
    chx = ch.hex()
    ok = (mr == report.get("summary", {}).get("merkle_root")) and (chx == report.get("summary", {}).get("chain_tip"))
    return ok, (mr if ok else f"recalc_merkle={mr} recalc_chain={chx}")

def sign_hmac(file_path: str, key: bytes) -> str:
    data = open(file_path, "rb").read()
    sig = hmac.new(key, data, hashlib.sha256).hexdigest()
    out = file_path + ".hmac"
    open(out, "w").write(sig)
    return out

def verify_hmac(file_path: str, key: bytes, sig_hex: str) -> bool:
    data = open(file_path, "rb").read()
    exp = hmac.new(key, data, hashlib.sha256).hexdigest()
    return hmac.compare_digest(exp, sig_hex)

def sign_ed25519(file_path: str, priv_pem: bytes) -> str:
    if not _ED25519:
        raise RuntimeError("Ed25519 unavailable. Install 'cryptography'.")
    key = serialization.load_pem_private_key(priv_pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise RuntimeError("Not an Ed25519 private key")
    data = open(file_path, "rb").read()
    sig = key.sign(data)
    out = file_path + ".ed25519"
    open(out, "wb").write(sig)
    return out

def verify_ed25519(file_path: str, pub_pem: bytes, sig_bytes: bytes) -> bool:
    if not _ED25519:
        raise RuntimeError("Ed25519 unavailable.")
    pub = serialization.load_pem_public_key(pub_pem)
    if not isinstance(pub, Ed25519PublicKey):
        raise RuntimeError("Not an Ed25519 public key")
    data = open(file_path, "rb").read()
    try:
        pub.verify(sig_bytes, data)
        return True
    except Exception:
        return False

# ==========================
# CLI
# ==========================
def cli():
    p = argparse.ArgumentParser(prog="patchtrap_mil.py", description="Patch/tamper detector (single-file).")
    sub = p.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("run", help="Run a target script under PatchTrap.")
    pr.add_argument("target", help="Path to script (e.g., suspicious.py)")
    pr.add_argument("--args", default="", help="Arguments passed to the target (single string)")
    pr.add_argument("--watch", default="builtins.open,socket.socket,subprocess.Popen,random.random",
                    help="Comma-separated dotted names to watch")
    pr.add_argument("--auto-restore", type=int, default=1, help="1 to restore originals on tamper")
    pr.add_argument("--interval", type=float, default=0.0, help="Scan interval (seconds) for during-scan timing window")
    pr.add_argument("--scan-during", type=int, default=1, help="1 to scan both before and after (and once during)")
    pr.add_argument("--fail-closed", type=int, default=0, help="1 to raise SecurityError on tamper/policy violation")
    pr.add_argument("--check-modules", type=int, default=0, help="1 to report sys.modules churn")
    pr.add_argument("--policy-allow", default="", help="Comma-separated allow patterns (optional)")
    pr.add_argument("--policy-deny", default="", help="Comma-separated deny patterns (optional)")
    pr.add_argument("--policy-enforce", type=int, default=0, help="1 to enforce policy pre-checks")

    pv = sub.add_parser("verify", help="Verify Merkle root and chain tip for a report JSON.")
    pv.add_argument("file", help="patchtrap_report.json")

    ps = sub.add_parser("sign", help="Sign report file (HMAC or Ed25519).")
    ps.add_argument("--file", required=True)
    ps.add_argument("--hmac-key", help="HMAC key (string) — stdlib option")
    ps.add_argument("--ed25519-priv", help="Path to Ed25519 private key (PEM)")

    pvs = sub.add_parser("verify-sign", help="Verify signature for report file.")
    pvs.add_argument("--file", required=True)
    pvs.add_argument("--hmac-key", help="HMAC key (string)")
    pvs.add_argument("--ed25519-pub", help="Path to Ed25519 public key (PEM)")
    pvs.add_argument("--sig", help="Signature file (.hmac or .ed25519). If omitted, auto-infer extension.")

    return p

def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    p = cli()
    a = p.parse_args(argv)

    if a.cmd == "run":
        targets = [x.strip() for x in a.watch.split(",") if x.strip()]
        policy = Policy(
            enforce=bool(a.policy_enforce),
            allow=[x.strip() for x in a.policy_allow.split(",") if x.strip()],
            deny=[x.strip() for x in a.policy_deny.split(",") if x.strip()],
        )
        guard = PatchTrapMIL(
            targets=targets,
            auto_restore=bool(a.auto_restore),
            interval=a.interval,
            scan_during=bool(a.scan_during),
            fail_closed=bool(a.fail_closed),
            check_modules=bool(a.check_modules),
            policy=policy
        )
        guard.seal()
        rc = guard.run(a.target, args_line=a.args)
        sys.exit(rc)

    if a.cmd == "verify":
        rep = report_load(a.file)
        ok, info = report_verify_integrity(rep)
        print("OK" if ok else "FAIL", info)
        sys.exit(0 if ok else 3)

    if a.cmd == "sign":
        if a.ed25519_priv:
            if not _ED25519:
                print("Ed25519 unavailable. Install 'cryptography'.", file=sys.stderr); sys.exit(4)
            pem = open(a.ed25519_priv, "rb").read()
            out = sign_ed25519(a.file, pem)
            print("Signed (Ed25519) ->", out)
        elif a.hmac_key:
            out = sign_hmac(a.file, a.hmac_key.encode("utf-8"))
            print("Signed (HMAC) ->", out)
        else:
            print("Provide --hmac-key or --ed25519-priv", file=sys.stderr); sys.exit(2)
        return

    if a.cmd == "verify-sign":
        if a.ed25519_pub:
            if not _ED25519:
                print("Ed25519 unavailable.", file=sys.stderr); sys.exit(4)
            sig_path = a.sig or (a.file + ".ed25519")
            ok = verify_ed25519(a.file, open(a.ed25519_pub, "rb").read(), open(sig_path, "rb").read())
            print("VALID" if ok else "INVALID"); sys.exit(0 if ok else 5)
        elif a.hmac_key:
            sig_path = a.sig or (a.file + ".hmac")
            ok = verify_hmac(a.file, a.hmac_key.encode("utf-8"), open(sig_path, "r").read().strip())
            print("VALID" if ok else "INVALID"); sys.exit(0 if ok else 5)
        else:
            print("Provide --hmac-key or --ed25519-pub", file=sys.stderr); sys.exit(2)

if __name__ == "__main__":
    main()

