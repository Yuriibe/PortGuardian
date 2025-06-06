# 🔐 PortGuardian - Suspicious Outbound Connection Watchdog

PortGuardian is a lightweight Python-based tool that monitors your system for **suspicious outbound network connections** and alerts you when connections to **untrusted or known-malicious services** are detected.

---

## 🚀 Features

- Monitors **live TCP/UDP connections** using `psutil`
- Resolves and watches IPs of domains like `pastebin.com`, `ngrok.io`, `discord.com`, `raw.githubusercontent.com`, etc.
- Flags any outbound connection to suspicious IPs
- Checks against a list of **trusted processes** to reduce false positives
- Simple JSON-based configuration for trusted processes

---

## 🛠️ Requirements

- Python 3.12
- Install dependencies:

```bash
pip install -r requirements.txt
```

**Dependencies:**
- `psutil` – to inspect active network connections
- `dnspython` – to resolve domain names to IPs

---

## 🧠 How it Works

1. Suspicious domains are resolved to their latest IP addresses using DNS A-records.
2. A loop continuously inspects system-level network connections.
3. Each remote IP is checked against the known suspicious IP list.
4. If a match is found and the process is **not trusted**, a warning is displayed.

---

## 📁 Files

- `port_watchdog.py` – main script that runs the watchdog
- `trusted_process.json` – list of process names to ignore (e.g., `["chrome.exe", "code.exe"]`)

---

## ✅ Example Output

```
🚨 Watching for suspicious outbound connections...

⚠️ Suspicious Connection Detected!
  → IP: 185.199.111.133
  → Domain: raw.githubusercontent.com
  → Process: python.exe (PID: 12345)
  → Status: ESTABLISHED
```

---

## ⚙️ Configuration

To add trusted processes (which you don't want to alert on):

**trusted_process.json**
```json
[
  "chrome.exe",
  "code.exe",
  "explorer.exe"
]
```

To add more suspicious domains:

Inside `SUSPICIOUS_IPS` dictionary in `port_watchdog.py`:
```python
SUSPICIOUS_IPS = {
    "example.com": "example.com"
}
```

---

## ⚠️ Disclaimer

This tool is meant for educational and monitoring purposes. It **does not block connections**, only reports them. Use it responsibly on systems you own or are authorized to monitor.

---

## 📬 Contact

Feel free to open an issue or pull request if you have improvements or suggestions!
