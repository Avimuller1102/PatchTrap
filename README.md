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

---

## Quick Start

```bash
# run a script with patchtrap guarding core functions
python patchtrap.py run path/to/target.py --watch builtins.open,socket.socket,subprocess.Popen,random.random --auto-restore 1

# just scan your own functions (add dotted names)
python patchtrap.py run myapp.py --watch mypkg.secure.validate,mypkg.db.connect --auto-restore 1

# dry-run scan: seal, run, report, but don't restore
python patchtrap.py run suspicious.py --watch builtins.open --auto-restore 0
