# PatchTrap 🛡️

[![CI](https://github.com/Avimuller1102/PatchTrap/actions/workflows/ci.yml/badge.svg)](https://github.com/Avimuller1102/PatchTrap/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Single File](https://img.shields.io/badge/architecture-single__file-success)](#)

פאצ'טראפ הוא "שומר ראש" לתוכניות פייתון: מריץ סקריפט תחת השגחה, מזהה בזמן אמת החלפות/הוקינג של פונקציות חשובות ומסוגל להחזיר את המקור מייד.

**PatchTrap** is a production-ready, 100% user-space **Anti-Tamper & Auto-Heal** mechanism for Python. It seals sensitive functions, detects monkey-patching in real-time, instantly restores the original functions, and generates a tamper-evident cryptographic report (Merkle tree + cumulative hash chain).

---

## 🏛️ Architecture

```text
 +-------------------------------------------------------------------------+
 |                            PATCHTRAP MIL                                |
 |                                                                         |
 |  1. SEALING:             2. GUARDED RUN:             3. AUTO-HEAL:      |
 |  [Target Functions]      [User Script]               [Tamper Detected!] |
 |  (bytecode + env)        | (executes normally)       |                  |
 |         |                |         |                 |                  |
 |         v                v         v                 v                  |
 |  +---------------+   +-----------------+     +----------------------+   |
 |  | Fingerprint   |   | Periodic Scans  |     | 🚨 Alert Logged      |   |
 |  | Baseline      |-->| (Pre/During/Post|---->| 🔄 Original Restored |   |
 |  +---------------+   +-----------------+     +----------------------+   |
 |                                |                                        |
 +--------------------------------|----------------------------------------+
                                  v
                       +----------------------+
                       |  TAMPER-EVIDENT LOG  |
                       | (Merkle Root + HMAC) |
                       +----------------------+
```

## 💼 Investor & Business Use Cases

**1. Enterprise AI Agents (LLM Guards)**
AI agents execute dynamically generated Python code. PatchTrap acts as a safety harness, ensuring the agent cannot monkey-patch `subprocess`, `os`, or `socket` to escape its sandbox or exfiltrate data, all while generating an immutable audit trail for compliance.

**2. FinTech & Zero-Trust Infrastructure**
Financial transaction processors rely on standard cryptographic libraries. PatchTrap ensures no malicious dependency has quietly hooked `builtins.open` or RNGs in memory to steal keys or manipulate transaction hashes.

**3. DevSecOps & Forensic Auditing**
When a breach occurs, discovering *how* a script was tampered with in-memory is nearly impossible. PatchTrap provides an immutable, cryptographically signed (`Ed25519` or `HMAC`) report proving exactly what was hooked, when, and by what, facilitating immediate forensic analysis.

---

## 🚀 Key Features

*   **Zero Instrumentation:** No code changes to your target script. Works in user-space without OS-level hooks or root privileges.
*   **Deterministic Fingerprinting:** Uses bytecode, constants, and variable names to detect *logical* modifications, not just memory address changes.
*   **Instant Self-Healing:** Instantly restores original functions when tampering is detected (`--auto-restore 1`).
*   **Cryptographic Reporting:** Emits canonical JSON reports secured by a **Merkle Tree** and **Cumulative Hash Chain**.
*   **Policy Enforcement:** Define allow/deny lists. Fail-closed on violations.
*   **No Hard Dependencies:** 100% standard library (except optional `cryptography` for Ed25519 signatures).

---

## 📦 Installation

PatchTrap is packaged using modern PEP 621 standards.

```bash
# Clone the repository
git clone https://github.com/Avimuller1102/PatchTrap.git
cd PatchTrap

# Install standard (HMAC signing only)
pip install -e .

# Install with Ed25519 cryptographic signing support
pip install -e .[signing]
```

---

## ⚡ Quick Start

```bash
# 1. Run a script and guard core builtins, auto-restoring them if hacked
patchtrap run app.py --watch builtins.open,socket.socket,subprocess.Popen --auto-restore 1

# 2. Strict policy mode: fail immediately if policy is violated
patchtrap run app.py --policy-allow "builtins.*" --policy-deny "socket.*" --policy-enforce 1 --fail-closed 1

# 3. Verify the cryptographic integrity of the resulting report
patchtrap verify patchtrap_report.json

# 4. Sign the report cryptographically
patchtrap sign --file patchtrap_report.json --hmac-key "supersecret"
```

## 🧪 Testing

PatchTrap includes a comprehensive test suite (100% pass, ~80% coverage) verifying Merkle structures, auto-healing, and policy engines.

```bash
pip install pytest pytest-cov
pytest tests/ -v
```

---
*Built for Zero-Trust Python environments.*
