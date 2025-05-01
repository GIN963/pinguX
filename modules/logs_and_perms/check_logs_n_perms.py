import os
import subprocess
import re
import shutil
import logging
from utils.ung_util import *
from utils.dictionaries.perms_config import *
from utils.perms_util import *

logger = logging.getLogger(__name__)

def scan_logs_n_perms():
    report = []

    logger.info("=== Starting Log and Permissions Audit ===")

    # Check permissions for critical files and dirs
    logger.info("Checking critical files permissions...")
    for file, file_data in SENSITIVE_FILES.items():
        logger.info(f"Checking file: {file_data['path']}")
        check_file_perms(file_data["path"], file_data["expected"], file_data["success_msg"], file_data["error_msg"], report)

    logger.info("Checking critical directories permissions...")
    for dir, dir_data in SENSITIVE_DIRS.items():
        logger.info(f"Checking directory: {dir_data['path']}")
        check_dir_perms(dir_data["path"], dir_data["expected"], dir_data["success_msg"], dir_data["error_msg"], report)

    # Parse last login data using 'lastlog'
    logger.info("Parsing last login data using 'lastlog' command...")

    if not shutil.which("lastlog"):
        logger.error("'lastlog' command not found.")
        report.append("[FAIL] 'lastlog' command not found.")
    else:
        try:
            lastlog_com = subprocess.run(['lastlog'], capture_output=True, text=True, check=True)
            lines = lastlog_com.stdout.strip().splitlines()[1:]

            check_config_directive(
                lines,
                r'^\s*(\S+)\s+\S+\s+\S+\s+(.*\d{4})$',
                2,
                report,
                check_func=check_last_login,
                success_msg_func=lambda d: f"[OK] Last login was at {d} (OK)",
                fail_msg_func=lambda d: f"[FAIL] Last login was at {d} → account might be inactive for too long",
                missing_msg="[FAIL] No lastlog data found",
                warning_func=warn_last_login,
                warning_msg_func=lambda d: f"[WARNING] Last login was at {d} → user is becoming inactive"
            )
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to run 'lastlog' command: {e}")
            report.append(f"[FAIL] Failed to run 'lastlog' command: {e}")

    # Analyze failed login attempts using 'faillog'
    logger.info("Analyzing failed login attempts with 'faillog' command...")

    if not shutil.which("faillog"):
        logger.error("'faillog' command not found.")
        report.append("[FAIL] 'faillog' command not found.")
    else:
        try:
            faillog_com = subprocess.run(['faillog'], capture_output=True, text=True, check=True)
            lines = faillog_com.stdout.strip().splitlines()[1:]

            for line in lines:
                match = re.search(r'^\s*(\S+)\s+(\d+)\s+(.*)$', line)
                if match:
                    user = match.group(1)
                    fails = match.group(2)
                    optional = match.group(3)

                    if fails == "0":
                        if optional.strip() == "":
                            report.append(f"[OK] No recent failed login record found for user '{user}'")
                            logger.info(f"[OK] No recent failed login record found for user '{user}'")
                        else:
                            report.append(f"[OK] User '{user}' has no failed login attempts (last failure was at {optional.strip()})")
                            logger.info(f"[OK] User '{user}' has no failed login attempts (last failure was at {optional.strip()})")

                    elif 1 <= int(fails) <= 5:
                        report.append(f"[WARNING] User '{user}' has {fails} failed login attempt(s) → monitor the account")
                        logger.warning(f"[WARNING] User '{user}' has {fails} failed login attempt(s) → monitor the account")

                    elif int(fails) > 5:
                        report.append(f"[WARNING] User '{user}' has {fails} failed login attempts → potential brute-force or suspicious activity")
                        logger.error(f"[WARNING] User '{user}' has {fails} failed login attempts → potential brute-force or suspicious activity")

                    else:
                        report.append(f"[FAIL] Unable to determine failure count for user '{user}'")
                        logger.error(f"[FAIL] Unable to determine failure count for user '{user}'")

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to run 'faillog' command: {e}")
            report.append(f"[FAIL] Failed to run 'faillog' command: {e}")

    # Check if Fail2Ban is active
    logger.info("Checking Fail2Ban service status...")
    try:
        fail2ban_com = subprocess.run(['systemctl', 'is-active', 'fail2ban'], capture_output=True, text=True, check=True)
        status = fail2ban_com.stdout.strip()

        if status == 'active':
            logger.info("[OK] Fail2Ban is active and running.")
            report.append("[OK] Fail2Ban is active and running.")
        else:
            logger.warning("[FAIL] Fail2Ban is not active or not installed.")
            report.append("[FAIL] Fail2Ban is not active or not installed.")

    except subprocess.CalledProcessError as e:
        logger.error(f"[FAIL] Failed to check Fail2Ban status: {e}")
        report.append(f"[FAIL] Failed to check Fail2Ban status: {e}")

    report.append("[DETAILS] Detailed logs saved to pingux.log")
    logger.info("=== Log and Permissions Audit Completed ===")
    return report





        
    