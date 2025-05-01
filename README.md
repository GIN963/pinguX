# 🐧 pinguX

**pinguX** — your chill little auditor with sharp security claws 🐧🛡️

> A modular, extensible, and beginner-friendly Linux security auditing tool.

---

## 🚀 Overview

**pinguX** is a security audit script for Linux systems. It performs deep checks on system configuration, firewall rules, listening ports, users and permissions, and more — all in a clean, modular structure.

Whether you're securing a production server or learning Linux hardening, pinGuX helps you spot **misconfigurations** before attackers do.

---

## 📋 Features

- Checks SSH configuration and weak authentication directives  
- Analyzes password aging and `/etc/shadow` policies  
- Detects UID/GID duplicates and misconfigured users  
- Verifies critical file and directory permissions  
- Scans cron jobs for dangerous commands or scripts  
- Audits firewall rules (`UFW` or `nftables`)  
- Compares listening ports to firewall exposure  
- Detects insecure or banned packages  
- Auto-detects server roles based on active processes  
- Logs everything to `pingux.log` for full traceability  

---

## 🛠️ Installation

```bash
git clone https://github.com/GIN963/pinguX.git
cd pinguX
chmod +x pinguX.py
```

Make sure you're running as **root**:

```bash
sudo ./pinguX.py
```

---

## ⚙️ Options

| Option              | Description                                 |
|---------------------|---------------------------------------------|
| `--output txt`      | Save audit report in `.txt` format          |
| `--output json`     | Save audit report in `.json` format         |
| `-v`, `--verbose`   | Print audit results to the console          |
| `-q`, `--quiet`     | Silent mode — no console output             |

**Example**:

```bash
sudo ./pinguX.py --output txt --verbose
```

---

## 📁 Output

- Audit report: `pingux_report_<timestamp>.txt` or `.json`
- Full audit logs: `pingux.log`  
> _(These files are ignored by Git via `.gitignore`)_

---

## 🔍 Module Breakdown

| Module              | Description                                          |
|---------------------|------------------------------------------------------|
| `check_ssh`         | Audit of SSH configuration and auth mechanisms      |
| `check_users_groups`| Full user/group integrity and password policy        |
| `check_logs_n_perms`| Lastlog, faillog, permission checks                  |
| `check_crontab`     | Scheduled tasks, script audits, frequency checks     |
| `check_packages`    | Detection of dangerous packages via dpkg             |
| `check_sysctl`      | Hardening of sysctl kernel parameters                |
| `check_nft / check_ufw` | Firewall configuration (auto-detected)          |
| `check_ports`       | Comparison between open ports and firewall rules     |
| `check_services`    | Audit of risky or legacy services                    |

---

## 🧪 Example Output (TXT)

```
[OK] SSH service is active
[WARNING] PermitRootLogin is enabled — should be disabled
[FAIL] /etc/shadow is world-readable!
[OK] Fail2Ban is active and running
[WARNING] Port 8080/tcp is open but not allowed by firewall — potential exposure
```

---

## 🤝 Contributing

Contributions, suggestions, or bug reports are welcome!  
Just fork the repo, submit a PR, or open an issue :)

---

## ⚠️ Disclaimer

This tool is for educational and **defensive** purposes only.  
Use responsibly and **always with permission** on target systems.
