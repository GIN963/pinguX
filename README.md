# 🐧 pinGuX  
**pinGuX** — your chill little auditor with sharp security claws 🐧🛡️  
> A modular, extensible, and beginner-friendly Linux security auditing tool.

---

## 🚀 Overview

**pinGuX** is a security audit script for Linux systems. It performs deep checks on system configuration, firewall rules, listening ports, users and permissions, and more — all in a clean, modular structure.

Whether you're securing a production server or learning Linux hardening, pinGuX helps you spot misconfigurations before attackers do.

---

## 📋 Features

- ✅ Checks SSH configuration and weak authentication directives
- 🔐 Analyzes password aging and `/etc/shadow` policies
- 🧍 Detects UID/GID duplicates and misconfigured users
- 📁 Verifies critical file and directory permissions
- 📜 Scans cron jobs for dangerous commands or scripts
- 🧱 Audits firewall rules (UFW or nftables)
- 🌐 Compares listening ports to firewall exposure
- 📦 Detects insecure or banned packages
- 🧠 Auto-detects server roles based on active processes
- 🧾 Logs everything to `pingux.log` for full traceability

---

## 🛠️ Installation

```bash
git clone https://github.com/yourname/pingux.git
cd pingux
chmod +x pinGuX.py

