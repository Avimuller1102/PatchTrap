# PatchTrap — live monkey-patch & tamper detector (with auto-restore)

**PatchTrap** is a tiny Python wrapper that **runs any script under a tamper alarm**.

It **seals** sensitive functions (e.g., `builtins.open`, `socket.socket`, `subprocess.Popen`, `random.random`, plus your own targets), then **detects** if they get replaced or hooked at runtime (monkey-patched). When it sees tampering, PatchTrap **logs it** and can **restore** the original function automatically.

- **no code changes** to the target script
- **no OS hooks** or admin privileges
- **single file**, pure Python

---

## Why?

Attackers and test harnesses often **monkey-patch** functions at runtime to intercept or change behavior (e.g., to bypass checks, re-route I/O, or hide activity). This is powerful—but also a risk in untrusted or complex environments.

**PatchTrap** gives you a lightweight **counter-measure**: detect and optionally **undo** monkey-patching in real time.


**What it detects**

function replacement / monkey-patching
Compares fingerprints of watched callables before/after execution.

import-hook tampering
Detects changes to sys.meta_path composition.

environment changes
Reports added/removed/changed os.environ keys.

optionally self-heals
Puts originals back for replaced targets (--auto-restore 1).

**How it works (short)**

sealing: computes a stable fingerprint for each watched object
(for Python functions: bytecode + consts + names; for builtins/classes: identity & type signature).

guarded run: executes the target via runpy.run_path while periodically re-fingerprinting and also doing a final check.

alerts: diffs fingerprints; if changed → alert, and optionally restore the original object reference.

report: JSON file with all alerts and a summary.

**Why it's different from existing tools** 

pytest monkeypatch focuses on testing utilities, not runtime detection and auto-restore.

PEP 578 runtime audit hooks provide event streams, but PatchTrap is a minimal guard you can drop in without event plumbing.

anti-debug / anti-tamper repos exist, but typically tie into debugging detection, obfuscation, or platform specifics; PatchTrap is a single-file, learning-friendly detector + self-healer you can wrap around any script.



**Limitations**
PatchTrap can’t stop every form of runtime manipulation. Extremely crafty code can patch between checks.

Fingerprints of builtins are identity-based; if your script intentionally rebinds modules or proxies, you’ll get alerts (by design).

This is an educational tool; for high-assurance environments, combine with audit hooks, process isolation, and strict policy.



---

## Quick Start

```bash
# run a script with patchtrap guarding core functions
python patchtrap.py run path/to/target.py --watch builtins.open,socket.socket,subprocess.Popen,random.random --auto-restore 1

# just scan your own functions (add dotted names)
python patchtrap.py run myapp.py --watch mypkg.secure.validate,mypkg.db.connect --auto-restore 1

# dry-run scan: seal, run, report, but don't restore
python patchtrap.py run suspicious.py --watch builtins.open --auto-restore 0





Output example:

[patchtrap] sealed 6 targets, meta_path=ok, env=baseline saved
[patchtrap] run begin: /abs/path/suspicious.py
[patchtrap][alert] target replaced: builtins.open  =>  restored (auto)
[patchtrap][alert] env changed: added FOO=bar
[patchtrap] run end: status=ok
[patchtrap] report saved: patchtrap_report.json

