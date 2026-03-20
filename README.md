# 🛡️ File Integrity Monitor (FIM)

> A professional-grade cybersecurity tool that detects unauthorized file changes using SHA-256 cryptographic hashing — built for educational purposes and system security monitoring.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![No Dependencies](https://img.shields.io/badge/Dependencies-None-orange?style=flat-square)

---

## ⚠️ Disclaimer

> This tool is built for **educational purposes** and **legitimate system security monitoring only**.
> Use only on systems **you own** or have **explicit written permission** to monitor.
> The author assumes no liability for misuse.

---

## 📖 About

**File Integrity Monitor (FIM)** is a Python cybersecurity tool inspired by enterprise tools like **Tripwire** and **AIDE**. It creates a cryptographic baseline of your files using SHA-256 hashing and alerts you whenever any file is:

- 🚨 **Modified** — content tampered with
- ⚠️ **Deleted** — file removed from the system
- 🆕 **Added** — new unexpected file appeared

This type of tool is used in real-world security operations to detect malware infections, insider threats, and unauthorized configuration changes.

---

## ✨ Features

- ✅ SHA-256 cryptographic file hashing
- ✅ Baseline creation with full directory scanning
- ✅ One-time integrity check mode
- ✅ Continuous watch mode with configurable intervals
- ✅ Detailed JSON reports for audit trails
- ✅ Full event logging to file
- ✅ File metadata tracking (size, timestamps, permissions)
- ✅ Zero external dependencies — pure Python stdlib
- ✅ Works on Linux, Windows, and macOS
- ✅ Full unit test suite included

---

## 📸 Sample Output

```
╔══════════════════════════════════════════════════════════╗
║   File Integrity Monitor   Version 1.0.0                 ║
╚══════════════════════════════════════════════════════════╝

2024-01-15 10:32:01  [INFO]    Creating baseline for: ./test_files
2024-01-15 10:32:01  [INFO]    Baseline created: 5 files hashed
2024-01-15 10:32:01  [INFO]    Saved to: baseline.json

──────────────────────────────────────────────────────────
INTEGRITY CHECK RESULTS
Time   : 2024-01-15T10:35:22
Target : ./test_files
──────────────────────────────────────────────────────────
  Total files checked : 5
  ✅ Unchanged        : 3
  🆕 New files        : 1
  ⚠️  Deleted         : 0
  🚨 Modified         : 1
──────────────────────────────────────────────────────────
  STATUS: 🚨  ALERT — 1 suspicious change(s) detected!

  MODIFIED FILES (possible tampering):
    → /home/user/test_files/config.txt
```

---

## ⚙️ Installation

### Requirements
- Python 3.8 or higher
- No external packages needed!

### Clone the repository

```bash
git clone https://github.com/Kuldeep6474/file-integrity-monitor.git
cd file-integrity-monitor
```

---

## 🚀 Usage

### Step 1 — Create a baseline (do this when files are SAFE)

```bash
python fim.py --init --path ./folder_to_monitor
```

### Step 2 — Run an integrity check

```bash
python fim.py --check --path ./folder_to_monitor
```

### Step 3 — Continuous monitoring (every 30 seconds)

```bash
python fim.py --watch --path ./folder_to_monitor --interval 30
```

### View the last report

```bash
python fim.py --report
```

### All available options

```
usage: fim.py [-h] (--init | --check | --watch | --report)
              [--path PATH] [--interval INTERVAL]

options:
  --init              Create a new baseline
  --check             Run a one-time integrity check
  --watch             Start continuous real-time monitoring
  --report            Display the last saved report
  --path PATH         Directory to monitor (default: .)
  --interval INT      Seconds between checks in watch mode (default: 60)
  --version           Show version number
```

---

## 🗂️ Project Structure

```
file-integrity-monitor/
│
├── fim.py                  ← Main program
├── requirements.txt        ← No external deps needed
├── README.md               ← This file
├── LICENSE                 ← MIT License
│
├── baseline.json           ← Created when you run --init
│
├── logs/
│   └── fim.log             ← Event log (auto-created)
│
├── reports/
│   └── report.json         ← Latest check report (auto-created)
│
└── tests/
    └── test_fim.py         ← Unit tests
```

---

## 🧠 How It Works

1. **Baseline Phase** — FIM scans every file in the target directory and computes its SHA-256 hash. These hashes are stored in `baseline.json`. This snapshot represents the "trusted state."

2. **Check Phase** — FIM rescans every file and recomputes hashes. It compares each new hash against the stored baseline.

3. **Detection** — Any file whose hash has changed is flagged as **MODIFIED**. Missing files are **DELETED**. New files not in the baseline are **NEW**.

4. **Reporting** — All events are logged to `logs/fim.log` and a JSON report is written to `reports/report.json`.

> **Why SHA-256?** It's a cryptographic hash — changing even one byte of a file produces a completely different 64-character hash. This makes it impossible for an attacker to modify a file without detection.

---

## 🧪 Running Tests

```bash
python tests/test_fim.py
```

Expected output:
```
Running FIM Test Suite...

test_clean_result ... ok
test_create_baseline ... ok
test_detect_deleted_file ... ok
test_detect_modified_file ... ok
test_detect_new_file ... ok
test_sha256_consistent ... ok
test_sha256_different_files ... ok
test_sha256_nonexistent_file ... ok

Ran 8 tests in 0.042s — OK
```

---

## 🔐 Real-World Security Context

This tool is similar to how enterprise security tools work:

| Tool | What it does |
|------|-------------|
| **Tripwire** | Enterprise FIM used in banks and hospitals |
| **AIDE** | Linux open-source FIM |
| **OSSEC** | Open-source HIDS with file integrity checking |
| **This FIM** | Educational Python implementation of the same concept |

FIM is a core component of **PCI-DSS**, **HIPAA**, and **ISO 27001** compliance — making this a highly relevant skill for cybersecurity careers.

---

## 👤 Author

**[Your Name]** — Cybersecurity Student

- LinkedIn: [linkedin.com/in/kuldeep-trapasiya-6474t06](https://www.linkedin.com/in/kuldeep-trapasiya-6474t06/)
- GitHub: [@Kuldeep6474](https://github.com/Kuldeep6474)

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

⭐ If this project helped you learn, please give it a star!
