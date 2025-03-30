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

            for port_numb in lines:
                match = re.search('^Port\s+(\d+)',port_numb)
                if match:
                    port = match.group(1)
                    
                    if port == "22":
                        report.append(f"❌ Port number #{port} ca be targeted by scanners and bots, change it (ex: 2022)")
                    else:
                        report.append(f"✅ SSH on port #{port}")
            break

            rootLogFlag = False

            for root_log in lines:
                match = re.search('^PermitRootLogin\s+(\S+)', root_log)
                if match:
                    value = match.group(1)
                    rootLogFlag = True
                    if value == "no":
                        report.append('✅ PermitRootLogin is set to "no"')
                    else:
                        report.append('❌ PermitRootLogin is not set to "no" (recommended: "no")')

            if rootLogFlag == False:
                report.append("❌ PermitRootLogin directive not found (default may allow root login)")

            maxTriesFlag = False
            for tries in lines:
                match = re.search('^MaxAuthTries\s+(\d+)', tries)
                if match:
                   nb = int(match.group(1))
                   maxTriesFlag = True

                   if nb > 3:
                    report.append("❌ MaxAuthTries is set too high (recommended: 3 or less)")
                   else:
                    report.append(f"✅ MaxAuthTries is set to {nb}")
            
            if maxTriesFlag == False:
                report.append("❌ MaxAuthTries directive not found (default is 6, which is too high)")

            psswdAuthFlag = False

            for psswdAuth in lines:
                match = re.search('^PasswordAuthentication\s+(\S+)', psswdAuth)
                if match:
                    value = match.group(1)
                    psswdAuthFlag = True

                    if value == "no":
                        report.append("✅ Password authentication is disabled")
                    else:
                        report.append("❌ Password authentication is enabled (recommended: use public key authentication)")

            if psswdAuthFlag == False:
                report.append("❌ PasswordAuthentication directive not found")
            
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