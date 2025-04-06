import subprocess
import re
import os
import grp
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
                report.append("donne moi le message")
            else:
                report.append(f"❌ {home_dir} does not exist ! Bad configuration")

            if os.path.exists(shell):
                report.append("donne le message")
            else: 
                report.append("donne le message")

    groups = grp.getgrall()

    gids = [group.gr_gid for group in groups]
    gid_counts = Counter(gids)

    group_names = [group.gr_name for group in groups]
    group_name_counts = Counter(groups_name)


    return report


       
       
       
    '''
       uid en double
       gid en double

       '''


 