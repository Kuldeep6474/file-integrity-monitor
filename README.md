# 🔐 File Integrity Monitor (FIM)

> A Python-based cybersecurity tool that monitors files using **SHA-256 hashing** to detect unauthorized changes, deletions, or additions in real time.

---

## 👨‍💻 About the Developer

**Kuldeep** — B.Sc Cyber Security Student  
🔐 Ethical Hacking & Network Security Enthusiast  
🛠️ Learning Kali Linux • Metasploit • Wireshark • Python

---

## 📌 What is File Integrity Monitor?

A **File Integrity Monitor (FIM)** is a cybersecurity tool that saves the **"digital fingerprint" (hash)** of your files and alerts you whenever a file is:

- 📝 **Modified** — content changed
- ❌ **Deleted** — file removed
- ➕ **Added** — new unknown file appeared

> 💡 **Real-life analogy:** Imagine taking a photo of your bank locker key. Next day you compare the key with the photo — if it looks different, someone changed it! FIM does exactly this with your files.

---

## 🧠 How It Works — SHA-256 Hashing

The heart of this tool is **SHA-256 Hashing**.

| Concept | Details |
|--------|---------|
| SHA | Secure Hash Algorithm |
| Output | Always exactly **64 characters** |
| Unique | Every file gets a unique hash |
| One-way | Hash cannot be reversed |

```
Original File  →  SHA-256  →  a3f5c7d8e9b1...  (64 char hash)
Modified File  →  SHA-256  →  z9x8y7w6v5u4...  (completely different!)
```

If hash changes → **File was tampered!** 🚨

---

## ⚙️ Tool Modes

| Mode | Description |
|------|-------------|
| 🔵 Baseline | Scan and save original file hashes |
| 🟢 Monitor | Compare current files with saved hashes |
| 🔴 Alert | Show which files were changed/deleted/added |
| 📄 Report | Export results to JSON report |

---

## 🛠️ Requirements

- Python 3.x (No external libraries needed!)
- Only uses **Python Standard Library**:
  - `hashlib` — for SHA-256 hashing
  - `os` — for file system access
  - `json` — for saving/loading reports
  - `datetime` — for timestamps

---

## 🚀 How to Use This Project

### Step 1 — Clone the Repository
```bash
git clone https://github.com/YourUsername/file-integrity-monitor.git
cd file-integrity-monitor
```

### Step 2 — Run the Tool
```bash
python fim.py
```

### Step 3 — Create Baseline (First Time)
```bash
python fim.py --baseline /path/to/folder
```
This scans the folder and saves all file hashes.

### Step 4 — Monitor Files
```bash
python fim.py --monitor /path/to/folder
```
This compares current files with the saved baseline.

### Step 5 — View Report
```bash
python fim.py --report
```
Opens the JSON report showing all changes detected.

---

## 📊 Sample Output

```
[✅] clean       →  passwords.txt      (No changes)
[🚨] MODIFIED    →  config.sys         (Hash mismatch!)
[❌] DELETED     →  secret.txt         (File missing!)
[➕] NEW FILE    →  malware.exe        (Unknown file added!)
```

---

## 🌍 Real World Use Cases

This tool is similar to enterprise-level FIM tools used in real industry:

| This Project | Enterprise Tool | Used By |
|-------------|----------------|---------|
| `fim.py` | Tripwire | Banks, Hospitals |
| `fim.py` | AIDE | Linux Servers |
| `fim.py` | OSSEC | SOC Teams |
| `fim.py` | Wazuh | Cloud Security |

> ✅ FIM is required by **PCI-DSS**, **HIPAA**, and **ISO 27001** compliance standards — used in real security jobs!

---

## 🔒 Security Concepts Covered

- **Attacker View:** Hackers modify system files first — install malware, create backdoors, delete logs. FIM detects this.
- **Defender View:** Security engineers check FIM reports daily. Unexpected changes = start incident response.
- **Evidence:** JSON report can be used as **proof in court** for cybercrime cases.

---

## ⚠️ Limitations

- ✅ Detects file changes
- ❌ Does NOT prevent changes (detection only)

### 🚀 Future Improvements
- [ ] Email alerts on detection
- [ ] Telegram bot notifications
- [ ] Database logging
- [ ] Auto quarantine suspicious files
- [ ] Dashboard UI

---

## 📚 Skills Demonstrated

> After building this project you can confidently say in interviews:
> **"I have implemented cryptographic hashing (SHA-256) for tamper detection."** 💪

Useful for: `CCNA Security` • `CEH Exam` • `Cybersecurity Interviews`

---

## 📄 License

This project is licensed under the **MIT License**.

---

⭐ **If you found this useful, give it a star!**
