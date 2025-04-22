from collections import Counter
from ung_utile import *
from perms_util import check_file_perms
import subprocess
import re
import os
import grp
import pwd

def check_users_groups():
    report = []

    # List of valid interactive shells for regular users
    valid_shells = [
        '/bin/bash', '/bin/sh', '/bin/zsh', '/usr/bin/bash', '/usr/bin/sh',
        '/usr/bin/zsh', '/bin/ksh', '/usr/bin/ksh', '/bin/dash',
        '/usr/bin/dash', '/bin/fish', '/usr/bin/fish',
    ]

    # List of non-interactive shells typically used for system accounts
    non_interactive_shells = [
        '/usr/sbin/nologin', '/bin/false', '/sbin/nologin', '/bin/nologin',
        '/usr/bin/nologin', '/usr/bin/false', '/dev/null', ''
    ]

    # Parse /etc/passwd manually for shell, UID and home directory checks
    users_com = subprocess.run(['cat', '/etc/passwd'], capture_output=True, text=True)
    users = users_com.stdout
    lines = users.strip().splitlines()

    for line in lines:
        # Extract username, UID, home directory, shell
        match = re.search(r'^([^:]+):[^:]*:(\d+):[^:]*:[^:]*:([^:]*):([^:]+)', line)
        if match:
            username = match.group(1)
            uid = int(match.group(2))
            home_dir = match.group(3)
            shell = match.group(4)

            # UID 0 should only be assigned to root
            if username != "root" and uid == 0:
                report.append(f"❌ User '{username}' has UID 0 but is not named 'root' → potential privilege escalation risk")

            # System accounts should have non-interactive shells
            if uid < 1000 and shell not in non_interactive_shells:
                report.append(f"❌ System account '{username}' has shell '{shell}' → should be non-interactive")
            
            # Normal users should have valid shell and home directory
            elif uid >= 1000:
                if not home_dir or shell not in valid_shells:
                    report.append(f"❌ User '{username}' has UID ≥ 1000 but no valid home directory or shell → might be misconfigured")
                else:
                    report.append(f"✅ User '{username}' has valid shell and home directory")

            # Check if home directory exists
            if os.path.isdir(home_dir):
                report.append(f"{home_dir} exists and is accessible")
            else:
                report.append(f"❌ {home_dir} does not exist ! Bad configuration")

            # Check if shell exists
            if os.path.exists(shell):
                report.append(f"✅ {shell} exists and is valid")
            else: 
                report.append(f"❌ {shell} is not found on the system")

    # Check for duplicate UIDs and usernames using pwd module
    users = pwd.getpwall()
    uids = [user.pw_uid for user in users]
    uid_counts = Counter(uids)

    user_names = [user.pw_name for user in users]
    user_name_counts = Counter(user_names)

    for uid, count in uid_counts.items():
        if count > 1:
            report.append(f"❌ UID {uid} is duplicated {count} times")

    for user_name, count in user_name_counts.items():
        if count > 1:
            report.append(f"❌ Username {user_name} is duplicated {count} times")

    # Check for duplicate GIDs and group names using grp module
    groups = grp.getgrall()
    gids = [group.gr_gid for group in groups]
    gid_counts = Counter(gids)

    group_names = [group.gr_name for group in groups]
    group_name_counts = Counter(group_names)

    for gid, count in gid_counts.items():
        if count > 1:
            report.append(f"❌ GID {gid} is duplicated {count} times")

    for name, count in group_name_counts.items():
        if count > 1:
            report.append(f"❌ Name {name} is duplicated {count} times")

    # Permissions for shadow file are now handled in check_logs_n_perms.py

    # Parse the shadow file line by line
    with open('/etc/shadow', 'r') as f:
        lines = f.readlines()

    for line in lines:
        fields = line.strip().split(":")
        username = fields[0]

        # Password-related security checks using a generic helper (check_shadow from ung_utile.py)
        check_shadow('password_hash', fields[1], lambda x : True,
            f"✅ {username} has got a password",
            f"❌ There is no password for {username}", report)

        check_shadow('last_changed', fields[2], lambda x : int(x) <= 90,
            f"✅ Last changed : {fields[2]} (within acceptable range)",
            f"❌ Last password change was over 90 days ago for user {username}", report)

        check_shadow('min_days', fields[3], lambda x: int(x) >= 1,
            f"✅ Minimum days between password changes is set to {fields[3]} (OK)",
            f"⚠️ Minimum days between password changes is {fields[3]}", report)

        check_shadow('max_days', fields[4], lambda x: int(x) <= 90,
            f"✅ Maximum days between password changes is set to {fields[4]} (secure)",
            f"❌ Maximum days between password changes is {fields[4]}", report)

        check_shadow('warn_days', fields[5], lambda x: int(x) >= 7,
            f"✅ Warning days before password expiration is {fields[5]}",
            f"⚠️ Only {fields[5]} warning days → users may not have enough time to react", report)

        check_shadow('inactive_days', fields[6], lambda x: int(x) <= 30,
            f"✅ Inactive days after expiration is {fields[6]}",
            f"⚠️ Inactive period after expiration is too long ({fields[6]})", report)

        check_shadow('expire', fields[7], lambda x: int(x) <= 99999,
            f"✅ Account expiration is set to day {fields[7]}",
            f"⚠️ Account expiration ({fields[7]}) is far in the future or never", report) 
    
    return report




 