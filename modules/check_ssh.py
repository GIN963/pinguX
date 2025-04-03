from utiles.ssh_utiles import *
import argparse
import os
import subprocess
import re

#----- SSH -----
def check_ssh():

    directives = {
        "PasswordAuthentication": {
            "regex": r'^PasswordAuthentication\s+(\S+)',
            "value": None,
            "found": False
        },
        "PubkeyAuthentication": {
            "regex": r'^PubkeyAuthentication\s+(\S+)',
            "value": None,
            "found": False
        },
        "PermitEmptyPasswords": {
            "regex": r'^PermitEmptyPasswords\s+(\S+)',
            "value": None,
            "found": False
        }      
    }

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

            check_ssh_directive(lines, "^LoginGraceTime\s+(\S+)", 1, report, lambda x: convert_to_seconds(x) <= 30, lambda v: f"✅ LoginGraceTime is set to {v} (secure)",
            lambda v: f"❌ LoginGraceTime is set to {v}, which is too long (recommended: 30s or less)", "❌ LoginGraceTime directive not found")

            for line in lines:
                for directive, data in directives.items():
                    match = re.search(data["regex"], line)
                    if match:
                        data["value"] = match.group(1)
                        data["found"] = True
                    
            analyze_auth_methods(directives["PasswordAuthentication"].value, directives["PubkeyAuthentication"].value, report, context = "PasswordAuthentication")
            analyze_auth_methods(directives["PermitEmptyPasswords"].value, directives["PubkeyAuthentication"].value, report, context = "PermitEmptyPasswords")

            for directive, data in directives.items():
                if not data["found"]:
                    report.append(f"❌ {directive} directive not found")
            
