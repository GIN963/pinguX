import subprocess
import re
import os
import grp
import pwd
from collections import Counter

def check_users_groups():
    report = []

    # Run the command to read the contents of /etc/passwd
    users_com = subprocess.run(['cat', '/etc/passwd'], capture_output=True, text=True)
    users = users_com.stdout
    lines = users.strip().splitlines()

    for line in lines:
        # Extract: username, UID, home directory, shell using regex
        match = re.search(r'^([^:]+):[^:]*:(\d+):[^:]*:[^:]*:([^:]*):([^:]+)', line)
        if match:
            username = match.group(1)
            uid = int(match.group(2))
            home_dir = match.group(3)
            shell = match.group(4)

            # Security check: UID 0 should only be used by 'root'
            if username != "root" and uid == 0:
                report.append(f"❌ User '{username}' has UID 0 but is not named 'root' → potential privilege escalation risk")

            # System accounts (UID < 1000) should not have interactive shells
            if uid < 1000 and shell not in ['/usr/sbin/nologin', '/bin/false']:
                report.append(f"❌ System account '{username}' has shell '{shell}' → should be non-interactive")
            
            # Normal users (UID ≥ 1000) should have a valid shell and home directory
            elif uid >= 1000:
                if not home_dir or shell not in ['/bin/bash', '/bin/zsh']:
                    report.append(f"❌ User '{username}' has UID ≥ 1000 but no valid home directory or shell → might be misconfigured")
                else:
                    report.append(f"✅ User '{username}' has valid shell and home directory")
            
            if os.path.isdir(home_dir):
                report.append(f"{home_dir} exists and is accessible")
            else:
                report.append(f"❌ {home_dir} does not exist ! Bad configuration")

            if os.path.exists(shell):
                report.append(f"✅ {shell} exists and is valid")
            else: 
                report.append(f"❌ {shell} is not found on the system")

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

    check_file_perms('/etc/shadow',
    "600", "✅ {path} permissions are correct",
    "❌ {path} should be {expected} but is {actual}",
    report
    )

    with open('/etc/shadow', 'r') as f:
        lines = f.readlines()

    for line in lines:
        fields = line.strip.split(":")
        username = fields[0]
        hash = fields[1]
        last_changed = fields[2]
        max_days = fields[3]
        min_days = fields[4]
        warn = fields[5]
        inactive = fields[6]
        expire = fields[7]







    return report



 