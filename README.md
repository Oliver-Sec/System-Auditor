# 🛡️ System Auditor v1.0
### An Educational Cybersecurity Tool for Beginners

> **Built by:** Oliver-Sec | **Language:** Python 3 | **Platform:** Windows

---

## 📖 What Is This Project?

**System Auditor** is a command-line security tool that inspects your own Windows PC for suspicious activity. It was built as a learning project to understand how real penetration testers and malware analysts investigate a compromised system.

It does three things:
1. **Lists the top 10 most memory-hungry processes** — useful for spotting programs hogging your RAM.
2. **Lists all active network connections** — shows everything your PC is currently "talking" to on the internet.
3. **Detects "Ghost" connections** — flags any network connection that is *not* from a known web browser, which is a classic red flag for hidden malware.

---

## 🚀 How to Run It

### Step 1 — Install Python
Make sure you have Python 3 installed. Download it from [python.org](https://www.python.org/downloads/).

### Step 2 — Install the one required library
Open your terminal (PowerShell or Command Prompt) and run:
```bash
pip install psutil
```

### Step 3 — Run the auditor
```bash
python auditor.py
```

You'll see a hacker-style ASCII table in your terminal, and a file called `audit_log.txt` will be saved in the same folder.

---

## 🧠 Beginner Explainer: `psutil.process_iter()`

This is the most important function in the whole script. Here's how it works in plain English:

### The Office Building Analogy

Imagine your computer is a giant **office building**. Every program running on your PC is an **office worker** doing their job. Your operating system (Windows) is the **building manager** that keeps track of every worker.

`psutil.process_iter()` is like a **security guard** doing a floor-by-floor walkthrough of the building. For each worker they find, the guard writes down:

| What the guard writes | What it means in Python |
|---|---|
| The worker's **badge number** | `PID` (Process ID — a unique number for each program) |
| The worker's **name** | `name` (e.g., `chrome.exe`, `svchost.exe`) |
| How many **office supplies** they're using | `memory_info` (RAM usage in bytes) |

### The Code, Explained Line by Line

```python
for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
```
- `process_iter()` walks through **every single running process**, one at a time.
- The list `['pid', 'name', 'memory_info']` tells it: *"Only grab me these three facts"*. This is faster than asking for everything.

```python
    try:
        pid  = proc.info['pid']
        name = proc.info['name']
        ram_mb = proc.info['memory_info'].rss / (1024 * 1024)
```
- `proc.info` is like reading the guard's clipboard for that one worker.
- `.rss` stands for **Resident Set Size** — the actual amount of RAM the process is actively using *right now* (not virtual memory).
- We divide by `1024 * 1024` to convert **bytes → megabytes** (MB), which is a more human-readable number.

```python
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
```
- Some processes are **protected by Windows** (like core system processes). If we try to read them and get blocked, we just skip them and move on. This is called **exception handling** — it stops your script from crashing when it hits a wall.

---

## 🔍 How a Penetration Tester Uses This to Find "Persistence"

### What is "Persistence"?

In cybersecurity, **persistence** is the ability of malware to **survive a reboot**. When a hacker breaks into a computer, their first goal is usually to install a program that keeps running — even after the victim restarts their PC. This is called establishing persistence.

Examples of persistence techniques:
- **Startup folder:** Malware places itself in `C:\Users\...\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
- **Registry run keys:** Malware adds an entry to the Windows Registry so it launches at login.
- **Scheduled tasks:** Malware creates a Windows task that re-runs it every hour.
- **Service installation:** Malware disguises itself as a Windows service (like `svchost.exe`).

### How This Tool Helps Find It

A penetration tester (a security expert hired to *ethically* hack a system to find weaknesses) would use a tool like this as a first step — called **enumeration**. Here's the workflow:

```
STEP 1: Run System Auditor
       ↓
STEP 2: Look at the Process List
       ↓
   → Is there a process you don't recognise?
   → Is a process using far more RAM than it should?
   → Is a system-sounding name (like "svch0st.exe") slightly misspelled?
       ↓
STEP 3: Look at the Network Connections
       ↓
   → Is any unknown process ESTABLISHED to a foreign IP?
   → Is a process connecting out on an unusual port (not 80/443)?
       ↓
STEP 4: Check the Ghost Detector output
       ↓
   → Every process flagged there is worth investigating further.
```

### A Real-World Example

Imagine the Ghost Detector flags this:

```
╔══════════════════════════════════════════════════════════╗
║           ⚠  GHOST CONNECTIONS DETECTED  ⚠              ║
╟──────────────────────────────────────────────────────────╢
║ PID  │ PROCESS         │ REMOTE ADDR      │ FLAG         ║
╟──────────────────────────────────────────────────────────╢
║ 4821 │ updater32.exe   │ 185.220.101.5:4444 │ ⚠ GHOST?  ║
╚══════════════════════════════════════════════════════════╝
```

Red flags here:
- **`updater32.exe`** sounds like a legitimate Windows updater — but you've never seen it before.
- **Port `4444`** is the *default port* for Metasploit (a famous hacking tool). Legitimate software almost never uses port 4444.
- **`185.220.101.5`** — a pen tester would paste this into [VirusTotal](https://www.virustotal.com) or [AbuseIPDB](https://www.abuseipdb.com) to check if it's a known malicious IP.

This is exactly how real incident responders start their investigations.

---

## 📁 Output Files

| File | Description |
|---|---|
| `auditor.py` | The main script |
| `audit_log.txt` | A text file with the full audit results, auto-generated each run |

---

## 📄 License

This project is licensed under the **MIT License** — see the [`LICENSE`](LICENSE) file for details.

---

## ⚠️ Legal & Ethical Notice

> This tool is designed to run **only on your own computer**. Running security tools against computers you don't own or don't have written permission to test is **illegal** in most countries under laws like the Computer Fraud and Abuse Act (USA) or the Computer Misuse Act (UK).
>
> **Always hack ethically. Always get permission first.**

---

## 🛠️ Technologies Used

| Library | Why We Use It |
|---|---|
| `psutil` | Cross-platform library for reading process and system info |
| `socket` | Built into Python; used for network address lookups |
| `datetime` | Built into Python; used for timestamping the log |

---

## 💡 Ideas to Extend This Project

Once you're comfortable with this script, here are some ways to level it up:

- [ ] **Add VirusTotal API integration** — automatically check flagged IPs against a threat database.
- [ ] **Export to HTML** — generate a nice browser-viewable report instead of a text file.
- [ ] **Add a whitelist config file** — let users define their own trusted processes via a `.json` file.
- [ ] **Schedule it with Task Scheduler** — run the audit every hour automatically and alert you by email if a Ghost connection appears.
- [ ] **Add hashing** — check the MD5/SHA256 hash of flagged `.exe` files against VirusTotal.

---

## 📚 Further Learning

- [TryHackMe](https://tryhackme.com) — Free, beginner-friendly cybersecurity labs
- [Hack The Box](https://www.hackthebox.com) — Intermediate/advanced practice machines
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) — The most common web security risks
- [psutil Documentation](https://psutil.readthedocs.io) — Everything `psutil` can do

---

*Happy hacking (ethically)! 🚀*


