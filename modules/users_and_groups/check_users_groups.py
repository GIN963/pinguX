import subprocess
import re
import os
import grp
import pwd
import logging
from collections import Counter
from utils.ung_util import *
from utils.perms_util import check_file_perms
from utils.dictionaries.usersgroups_shells import *

logger = logging.getLogger(__name__)

def scan_users_groups():
    report = []

    logger.info("=== Starting Users & Groups Audit ===")

    # Parse /etc/passwd to retrieve users, UIDs, home directories, and shells
    try:
        users_com = subprocess.run(['cat', '/etc/passwd'], capture_output=True, text=True, check=True)
        users = users_com.stdout.strip().splitlines()
        logger.info("Parsed /etc/passwd successfully.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to parse /etc/passwd: {e}")
        report.append(f"[FAIL] Failed to read /etc/passwd: {e}")
        return report

    # Analyze each user line from /etc/passwd
    for line in users:
        match = re.search(r'^([^:]+):[^:]*:(\d+):[^:]*:[^:]*:([^:]*):([^:]+)', line)
        if match:
            username = match.group(1)
            uid = int(match.group(2))
            home_dir = match.group(3)
            shell = match.group(4)

            # UID 0 must only be assigned to 'root'
            if username != "root" and uid == 0:
                report.append(f"[FAIL] User '{username}' has UID 0 but is not named 'root' → potential privilege escalation risk")
                logger.warning(f"UID 0 assigned to non-root user: {username}")

            # System accounts (UID < 1000) should use non-interactive shells
            if uid < 1000 and shell not in non_interactive_shells:
                report.append(f"[FAIL] System account '{username}' has shell '{shell}' → should be non-interactive")
                logger.warning(f"System account '{username}' has an interactive shell: {shell}")

            # Normal users (UID ≥ 1000) should have valid home and shell
            elif uid >= 1000:
                if not home_dir or shell not in valid_shells:
                    report.append(f"[FAIL] User '{username}' has UID ≥ 1000 but no valid home directory or shell → might be misconfigured")
                    logger.warning(f"User '{username}' misconfigured: home='{home_dir}', shell='{shell}'")
                else:
                    report.append(f"[OK] User '{username}' has valid shell and home directory")
                    logger.info(f"User '{username}' configuration is valid")

            # Check home directory existence
            if os.path.isdir(home_dir):
                report.append(f"{home_dir} exists and is accessible")
                logger.info(f"Home directory exists for user '{username}': {home_dir}")
            else:
                report.append(f"[FAIL] {home_dir} does not exist ! Bad configuration")
                logger.warning(f"Home directory missing for user '{username}': {home_dir}")

            # Check shell binary presence
            if os.path.exists(shell):
                report.append(f"[OK] {shell} exists and is valid")
                logger.info(f"Shell exists for user '{username}': {shell}")
            else: 
                report.append(f"[FAIL] {shell} is not found on the system")
                logger.warning(f"Shell not found for user '{username}': {shell}")

    logger.info("Checking for duplicate UIDs and usernames...")

    # Detect duplicate UIDs and usernames using the pwd module
    users = pwd.getpwall()
    uids = [user.pw_uid for user in users]
    uid_counts = Counter(uids)

    user_names = [user.pw_name for user in users]
    user_name_counts = Counter(user_names)

    for uid, count in uid_counts.items():
        if count > 1:
            report.append(f"[WARNING] UID {uid} is duplicated {count} times")
            logger.warning(f"Duplicate UID detected: {uid} ({count} times)")

    for user_name, count in user_name_counts.items():
        if count > 1:
            report.append(f"[WARNING] Username {user_name} is duplicated {count} times")
            logger.warning(f"Duplicate username detected: {user_name} ({count} times)")

    logger.info("Checking for duplicate GIDs and group names...")

    # Detect duplicate GIDs and group names using the grp module
    groups = grp.getgrall()
    gids = [group.gr_gid for group in groups]
    gid_counts = Counter(gids)

    group_names = [group.gr_name for group in groups]
    group_name_counts = Counter(group_names)

    for gid, count in gid_counts.items():
        if count > 1:
            report.append(f"[WARNING] GID {gid} is duplicated {count} times")
            logger.warning(f"Duplicate GID detected: {gid} ({count} times)")

    for name, count in group_name_counts.items():
        if count > 1:
            report.append(f"[WARNING] Name {name} is duplicated {count} times")
            logger.warning(f"Duplicate group name detected: {name} ({count} times)")

    logger.info("Checking password policies in /etc/shadow...")

    # Parse /etc/shadow to perform password aging policy checks
    try:
        with open('/etc/shadow', 'r') as f:
            lines = f.readlines()
    except Exception as e:
        logger.error(f"Failed to open /etc/shadow: {e}")
        report.append(f"[FAIL] Failed to read /etc/shadow: {e}")
        return report

    for line in lines:
        fields = line.strip().split(":")
        username = fields[0]

        # Use check_shadow utility to validate each password field
        check_shadow('password_hash', fields[1], lambda x : True,
            f"[OK] {username} has got a password",
            f"[WARNING] There is no password for {username}", report)

        check_shadow('last_changed', fields[2], lambda x : int(x) <= 90,
            f"[OK] Last changed : {fields[2]} (within acceptable range)",
            f"[WARNING] Last password change was over 90 days ago for user {username}", report)

        check_shadow('min_days', fields[3], lambda x: int(x) >= 1,
            f"[OK] Minimum days between password changes is set to {fields[3]} (OK)",
            f"[WARNING] Minimum days between password changes is {fields[3]}", report)

        check_shadow('max_days', fields[4], lambda x: int(x) <= 90,
            f"[OK] Maximum days between password changes is set to {fields[4]} (secure)",
            f"[WARNING] Maximum days between password changes is {fields[4]}", report)

        check_shadow('warn_days', fields[5], lambda x: int(x) >= 7,
            f"[OK] Warning days before password expiration is {fields[5]}",
            f"[WARNING] {fields[5]} warning days → users may not have enough time to react", report)

        check_shadow('inactive_days', fields[6], lambda x: int(x) <= 30,
            f"[OK] Inactive days after expiration is {fields[6]}",
            f"[WARNING] Inactive period after expiration is too long ({fields[6]})", report)

        check_shadow('expire', fields[7], lambda x: int(x) <= 99999,
            f"[OK] Account expiration is set to day {fields[7]}",
            f"[WARNING] Account expiration ({fields[7]}) is far in the future or never", report) 
    
    report.append("[DETAILS] Detailed logs saved to pingux.log")
    logger.info("=== Users & Groups Audit Completed ===")
    return report


 