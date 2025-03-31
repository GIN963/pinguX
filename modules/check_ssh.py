import argparse
import os
import subprocess
import re

#----- SSH -----
def check_ssh():

    report = []
    ssh_state_com = subprocess.run(['systemctl','is-active','ssh'], capture_output = True, text = True)
    ssh_state = ssh_state_com.stdout

    if ssh_state_com.returncode != 0:
        report.append("❌ Command failed, (possibly not installed):")
        report.append(ssh_state_com.stderr.strip())

    else:
        ssh_state = ssh_state_com.stdout
        if 'inactive' in ssh_state:
            report.append("❌ SSH is inactive")
        else:
            report.append("✅ SSH is active")
            ssh_config_com = subprocess.run(['cat','/etc/ssh/sshd_config'], capture_output = True, text = True)
            ssh_config = ssh_config_com.stdout
            lines = ssh_config.strip().splitlines()
            
            check_ssh_directive(lines, '^Port\s+(\d+)', 1, report, lambda x : x != "22", lambda port : f"✅ SSH on port {port}", 
            lambda port : f"❌ Port number {port} can be targeted by scanners and bots, change it (ex: 2022)",
            "❌ Port directive not found: SSH will use port 22 by default, which is commonly targeted by bots. Consider specifying a different port.")

            check_ssh_directive(lines, '^PermitRootLogin\s+(\S+)', 1, report, lambda x : x == "no", lambda value : f'✅ PermitRootLogin is set to {value}',
            lambda value : f'❌ PermitRootLogin is not set to {value}" (recommended: "no")', "❌ PermitRootLogin directive not found (default may allow root login)")

            check_ssh_directive(lines,'^MaxAuthTries\s+(\d+)', 1, report, lambda x : x <= 3, lambda nb : f"✅ MaxAuthTries is set to {nb}",
            lambda nb : f"❌ MaxAuthTries is set to {nb} (recommended: 3 or less)", "❌ MaxAuthTries directive not found (default is 6, which is too high)")

            psswdAuthFlag = False
            keyAuthFlag = False
            psswdValue = None
            keyValue = None

            for line in lines:
                match1 = re.search(r'^PasswordAuthentication\s+(\S+)', line)
                match2 = re.search(r'^PubkeyAuthentication\s+(\S+)', line)

                if match1:
                    psswdValue = match1.group(1)
                    psswdAuthFlag = True

                if match2:
                    keyValue = match2.group(1)
                    keyAuthFlag = True

            analyze_auth_methods(psswdValue, keyValue, report)

            if not psswdAuthFlag:
                report.append("❌ PasswordAuthentication directive not found")
            if not keyAuthFlag:
                report.append("⚠️ PubkeyAuthentication directive not found")
            
            emptyPassFlag = False

            for line in lines:
                match = re.search(r'^PermitEmptyPasswords\s+(\S+)', line)
                if match:
                    value = match.group(1)
                    emptyPassFlag = True

                    if value == "no":
                        report.append("✅ Empty password logins are disabled")
                    else:
                        report.append("❌ Empty password logins are allowed (set PermitEmptyPasswords to no)")

            if emptyPassFlag == False:
                report.append("❌ PermitEmptyPasswords directive not found")