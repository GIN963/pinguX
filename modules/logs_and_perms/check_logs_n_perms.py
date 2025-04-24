import os
import subprocess
import re
from ung_util import *
from perms_config import *

def scan_logs_n_perms():
    
    report = []

    # Check permissions for critical files and dirs
    for file, file_data in SENSITIVE_FILES.items():
        check_file_perms(file_data["path"], file_data["expected"], file_data["success_msg"], file_data["error_msg"], report)

    for dir, dir_data in SENSITIVE_DIRS.items():
        check_dir_perms(dir_data["path"], dir_data["expected"], dir_data["success_msg"], dir_data["error_msg"], report)
    
    # Parse last login data using 'lastlog' command
    # /var/log/lastlog is a binary file → we use the command to get a readable version
    lastlog_com = subprocess.run(['lastlog'], capture_output=True, text=True)
    lines = lastlog_com.stdout.strip().splitlines()[1:]  # Skip header

    check_config_directive(
        lines,
        r'^\s*(\S+)\s+\S+\s+\S+\s+(.*\d{4})$',  # Extract the last login date
        2,
        report,
        check_func=check_last_login,
        success_msg_func=lambda d: f"✅ Last login was at {d} (OK)",
        fail_msg_func=lambda d: f"❌ Last login was at {d} → account might be inactive for too long",
        missing_msg="❌ No lastlog data found",
        warning_func=warn_last_login,
        warning_msg_func=lambda d: f"⚠️ Last login was at {d} → user is becoming inactive"
    )

    # Analyze failed login attempts using 'faillog'
    faillog_com = subprocess.run(['faillog'], capture_output=True, text=True)
    lines = faillog_com.stdout.strip().splitlines()[1:]  # Skip header

    for line in lines:
        match = re.search(r'^\s*(\S+)\s+(\d+)\s+(.*)$', line)
        if match:
            user = match.group(1)
            fails = match.group(2)
            optional = match.group(3)

            # No failures
            if fails == "0":
                if optional.strip() == "":
                    report.append(f"✅ No recent failed login record found for user '{user}'")
                else:
                    report.append(f"✅ User '{user}' has no failed login attempts (last failure was at {optional.strip()})")

            # 1 to 5 failures → warning
            elif 1 <= int(fails) <= 5:
                report.append(f"⚠️ User '{user}' has {fails} failed login attempt(s) → monitor the account")

            # More than 5 failures → critical
            elif int(fails) > 5:
                report.append(f"❌ User '{user}' has {fails} failed login attempts → potential brute-force or suspicious activity")

            # Parsing issue
            else:
                report.append(f"❌ Unable to determine failure count for user '{user}'")

    # Check if Fail2Ban is active using systemctl
    fail2ban_com = subprocess.run(['systemctl', 'is-active', 'fail2ban'], capture_output=True, text=True)
    status = fail2ban_com.stdout.strip()

    if status == 'active':
        report.append("✅ Fail2Ban is active and running.")
    else:
        report.append("❌ Fail2Ban is not active or not installed.")

    return report











        
    