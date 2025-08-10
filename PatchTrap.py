import argparse
import hashlib
import inspect
import importlib
import json
import os
import runpy
import sys
import time
import types
from typing import Any, Dict, Tuple, List

# ---------------------------
# tiny helpers and fingerprint
# ---------------------------

def _sha256_bytes(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()

def _fingerprint_callable(obj: Any) -> Dict[str, Any]:
    """
    produce a stable-ish fingerprint for python callables.
    for python functions/methods: hash bytecode + consts + names.
    for builtins and c-implemented callables: fall back to repr + module + qualname.
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
            fp["hash"] = _sha256_bytes(payload)
            fp["where"] = f"{obj.__module__}.{getattr(obj, '__qualname__', getattr(obj, '__name__', ''))}"
            return fp
        elif isinstance(obj, (types.BuiltinFunctionType, types.BuiltinMethodType)):
            # builtins don't have python bytecode; use module/qualname/repr
            tag = f"{getattr(obj, '__module__', '')}:{getattr(obj, '__qualname__', getattr(obj, '__name__', ''))}:{repr(obj)[:80]}"
            fp["hash"] = _sha256_bytes(tag.encode())
            fp["where"] = tag
            return fp
        elif callable(obj):
            # generic callable (class with __call__, partial, etc.)
            tag = f"{obj.__class__.__module__}.{obj.__class__.__qualname__}:{repr(obj)[:80]}"
            fp["hash"] = _sha256_bytes(tag.encode())
            fp["where"] = tag
            return fp
        else:
            tag = f"not-callable:{repr(obj)[:80]}"
            fp["hash"] = _sha256_bytes(tag.encode())
            fp["where"] = tag
            return fp
    except Exception as e:
        tag = f"error:{type(obj).__name__}:{repr(e)[:60]}"
        fp["hash"] = _sha256_bytes(tag.encode())
        fp["where"] = tag
        return fp

def _resolve_dotted(name: str) -> Tuple[Any, Any, str, str]:
    """
    resolve a dotted name like 'module.sub.obj' and return:
    (container_object, attribute_value, container_qualname, attr_name)
    so we can restore by setattr(container, attr_name, original)
    """
    parts = name.split(".")
    if len(parts) < 2:
        raise ValueError(f"invalid dotted name: {name}")
    module_name = parts[0]
    # import the top-level module
    mod = importlib.import_module(module_name)
    obj: Any = mod
    for p in parts[1:-1]:
        obj = getattr(obj, p)
    attr = parts[-1]
    val = getattr(obj, attr)
    container_qual = f"{obj.__module__}.{getattr(obj, '__qualname__', obj.__class__.__name__)}" if hasattr(obj, "__module__") else repr(obj)
    return obj, val, container_qual, attr

# -------------
# core guard api
# -------------

class PatchTrap:
    # all comments in lowercase.
    def __init__(self, targets: List[str], auto_restore: bool = True, interval: float = 0.0):
        self.targets = targets
        self.auto_restore = auto_restore
        self.interval = max(0.0, float(interval))
        self.baseline: Dict[str, Dict[str, Any]] = {}   # dotted -> fingerprint
        self.originals: Dict[str, Any] = {}             # dotted -> original object
        self.meta_path0 = list(sys.meta_path)
        self.env0 = dict(os.environ)
        self.alerts: List[Dict[str, Any]] = []
        self.report: Dict[str, Any] = {}

    def seal(self):
        # compute baseline fingerprints and store originals for restoration
        for dotted in self.targets:
            container, val, container_qual, attr = _resolve_dotted(dotted)
            self.originals[dotted] = val
            self.baseline[dotted] = {
                "fp": _fingerprint_callable(val),
                "container": container_qual,
                "attr": attr,
            }

    def _scan_once(self):
        # check each target for changes
        for dotted in self.targets:
            try:
                container, current, container_qual, attr = _resolve_dotted(dotted)
            except Exception as e:
                self.alerts.append({"kind": "resolve_error", "target": dotted, "error": repr(e)})
                continue
            base = self.baseline.get(dotted)
            if not base:
                continue
            fp_now = _fingerprint_callable(current)
            if fp_now["hash"] != base["fp"]["hash"]:
                # record alert
                self.alerts.append({
                    "kind": "replaced",
                    "target": dotted,
                    "before": base["fp"],
                    "after": fp_now,
                })
                # optional auto-restore
                if self.auto_restore:
                    try:
                        setattr(container, attr, self.originals[dotted])
                        self.alerts.append({"kind": "restore", "target": dotted, "status": "ok"})
                    except Exception as e:
                        self.alerts.append({"kind": "restore", "target": dotted, "status": "fail", "error": repr(e)})

        # check meta_path integrity (import hooks)
        mp_now = list(sys.meta_path)
        if [type(x).__name__ for x in mp_now] != [type(x).__name__ for x in self.meta_path0]:
            self.alerts.append({
                "kind": "meta_path_changed",
                "before": [type(x).__name__ for x in self.meta_path0],
                "after": [type(x).__name__ for x in mp_now],
            })

        # check environment changes
        env_now = dict(os.environ)
        added = sorted(set(env_now) - set(self.env0))
        removed = sorted(set(self.env0) - set(env_now))
        changed = sorted(k for k in set(env_now).intersection(self.env0) if env_now[k] != self.env0[k])
        if added or removed or changed:
            self.alerts.append({
                "kind": "env_changed",
                "added": {k: env_now[k] for k in added},
                "removed": {k: self.env0[k] for k in removed},
                "changed": {k: {"before": self.env0[k], "after": env_now[k]} for k in changed},
            })

    def run(self, target_path: str, args_line: str = "") -> int:
        # prepare argv and run the script under guard
        old_argv = sys.argv[:]
        sys.argv = [target_path] + (args_line.split() if args_line else [])
        rc = 0
        start = time.time()
        try:
            print(f"[patchtrap] sealed {len(self.targets)} targets, meta_path=ok, env=baseline saved")
            print(f"[patchtrap] run begin: {os.path.abspath(target_path)}")
            # periodic scan during run, if interval > 0
            if self.interval > 0:
                # crude cooperative scanning: interleave short sleeps while running the script
                # we run the script in the same thread; so we do a pre-scan, run, then post-scan
                self._scan_once()
                runpy.run_path(target_path, run_name="__main__")
                time.sleep(self.interval)
                self._scan_once()
            else:
                runpy.run_path(target_path, run_name="__main__")
                self._scan_once()
            print("[patchtrap] run end: status=ok")
        except SystemExit as e:
            # capture exit code from target
            rc = int(getattr(e, "code", 0) or 0)
            print(f"[patchtrap] run end: SystemExit({rc})")
        except Exception as e:
            rc = 1
            self.alerts.append({"kind": "exception", "error": repr(e)})
            print("[patchtrap] run end: status=exception")
        finally:
            sys.argv = old_argv
            dur = round(time.time() - start, 3)
            self.report = {
                "duration_sec": dur,
                "auto_restore": self.auto_restore,
                "targets": self.targets,
                "alerts": self.alerts,
            }
            with open("patchtrap_report.json", "w", encoding="utf-8") as f:
                json.dump(self.report, f, indent=2, sort_keys=True)
            print("[patchtrap] report saved: patchtrap_report.json")
        # return rc for cli
        return rc

# -------------
# simple cli
# -------------

def main():
    p = argparse.ArgumentParser(description="patchtrap: live monkey-patch & tamper detector (auto-restore optional)")
    sub = p.add_subparsers(dest="cmd", required=True)

    prun = sub.add_parser("run", help="run a target script under patchtrap")
    prun.add_argument("target", help="path to script, e.g., suspicious.py")
    prun.add_argument("--args", default="", help="arguments passed to the target as a single string")
    prun.add_argument("--watch", default="builtins.open,socket.socket,subprocess.Popen,random.random",
                      help="comma-separated dotted names to watch")
    prun.add_argument("--auto-restore", type=int, default=1, help="1 to restore originals on tamper")
    prun.add_argument("--interval", type=float, default=0.0, help="scan interval seconds (0 = scan after run)")

    args = p.parse_args()

    if args.cmd == "run":
        targets = [x.strip() for x in args.watch.split(",") if x.strip()]
        guard = PatchTrap(targets=targets, auto_restore=bool(args.auto_restore), interval=args.interval)
        guard.seal()
        rc = guard.run(args.target, args_line=args.args)
        sys.exit(rc)

if __name__ == "__main__":
    main()