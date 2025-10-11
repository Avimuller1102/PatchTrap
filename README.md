# PatchTrap — live monkey-patch & tamper detector (with auto-restore & tamper-evident report)

פאצ'טראפ הוא "שומר ראש" לתוכניות פייתון: מריץ סקריפט תחת השגחה, מזהה בזמן אמת החלפות/הוקינג של פונקציות חשובות (כמו open, socket.socket, subprocess.Popen) ומסוגל להחזיר את המקור מייד. בנוסף, הוא מייצר דוח חסין-שינוי (Merkle + שרשרת מצטברת), ויכול לחתום עליו.

PatchTrap is a tiny Python wrapper that runs any script under a tamper alarm.
It seals sensitive functions (e.g., builtins.open, socket.socket, subprocess.Popen, random.random, plus your own targets), then detects if they get replaced or hooked at runtime (monkey-patched). When it sees tampering, PatchTrap logs it and can restore the original function automatically. It also emits a tamper-evident report (canonical JSON with Merkle root and cumulative chain tip) and supports optional signing (HMAC or Ed25519).

no code changes to the target script

no OS hooks or admin privileges

single file, pure Python (Ed25519 signing optional via cryptography)

# Why?

Attackers and test harnesses often monkey-patch functions at runtime to intercept or change behavior (e.g., bypass checks, re-route I/O, or hide activity). This is powerful—but risky in untrusted or complex environments.

PatchTrap gives you a lightweight counter-measure: detect and optionally undo monkey-patching in real time, and leave a tamper-evident audit trail.

# What it detects

function replacement / monkey-patching – compares fingerprints of watched callables before/after execution

import-hook tampering – detects changes to sys.meta_path composition

environment changes – reports added/removed/changed os.environ keys

optional modules churn – (opt-in) reports deltas in sys.modules

optionally self-heals – restores originals for replaced targets (--auto-restore 1)

tamper-evident report – canonical JSON with Merkle root & chain tip

optional signing – HMAC-SHA256 (stdlib) or Ed25519 (cryptography)

policy (allow/deny) – pattern-based enforcement with optional fail-closed

# How it works (short)

sealing: computes a stable fingerprint for each watched target (for Python functions: bytecode + consts + names + filename + firstlineno; for builtins/classes: identity & type signature).

guarded run: executes the target via runpy.run_path, scanning pre/during/post based on settings.

alerts: if a fingerprint changes → record an alert; optionally restore the original reference.

report: writes canonical JSON with all alerts + a summary containing the Merkle root and chain tip.

signing (optional): sign the report file with HMAC or Ed25519.

# Quick Start
# run a script with PatchTrap guarding core functions
python patchtrap_mil.py run path/to/target.py \
  --watch builtins.open,socket.socket,subprocess.Popen,random.random \
  --auto-restore 1

# just scan your own functions (add dotted names)
python patchtrap_mil.py run myapp.py \
  --watch mypkg.secure.validate,mypkg.db.connect \
  --auto-restore 1

# dry-run scan: seal, run, report, but don't restore
python patchtrap_mil.py run suspicious.py --watch builtins.open --auto-restore 0

# enforce allow/deny policy and fail closed on violations
python patchtrap_mil.py run app.py \
  --watch builtins.open,socket.socket \
  --policy-allow "builtins.*" --policy-deny "socket.*" \
  --policy-enforce 1 --fail-closed 1

# include a during-scan window (pre/during/post) with interval
python patchtrap_mil.py run app.py --interval 0.3 --scan-during 1

# verify Merkle root & chain tip of a report
python patchtrap_mil.py verify patchtrap_report.json

# sign a report (choose one)
python patchtrap_mil.py sign --file patchtrap_report.json --hmac-key "supersecret"

python patchtrap_mil.py sign --file patchtrap_report.json --ed25519-priv ed25519-key.pem

# verify signature (choose one)
python patchtrap_mil.py verify-sign --file patchtrap_report.json --hmac-key "supersecret"

python patchtrap_mil.py verify-sign --file patchtrap_report.json --ed25519-pub ed25519-pub.pem

# Output example
[patchtrap] sealed 6 targets; env/meta_path baselined
[patchtrap] run begin: /abs/path/suspicious.py
[patchtrap][alert] target replaced: builtins.open  =>  restored (auto)
[patchtrap][alert] env changed: added FOO=bar
[patchtrap] run end: status=ok
[patchtrap] report saved: patchtrap_report.json

# Files & deps

Single file: patchtrap_mil.py

Optional dependency for Ed25519 signing: cryptography

HMAC signing is stdlib-only, no external deps.
