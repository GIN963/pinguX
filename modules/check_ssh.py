from utils.config_directive_checker import check_config_directive
from utils.dictionaries.ssh_directives_config import SSH_DIRECTIVES
import argparse
import os
import subprocess
import re

#----- SSH -----
def check_ssh():
    # Initialize the directives to be cross-analyzed with PubkeyAuthentication
    directives = {
        "PasswordAuthentication": {
            "regex": r'^PasswordAuthentication\s+(\S+)',  # Match PasswordAuthentication directive
            "value": None,     # Will hold the matched value
            "found": False     # Indicates if the directive was found
        },
        "PubkeyAuthentication": {
            "regex": r'^PubkeyAuthentication\s+(\S+)',     # Match PubkeyAuthentication directive
            "value": None,
            "found": False
        },
        "PermitEmptyPasswords": {
            "regex": r'^PermitEmptyPasswords\s+(\S+)',      # Match PermitEmptyPasswords directive
            "value": None,
            "found": False
        }      
    }

    report = []

    # Check whether the SSH service is active
    ssh_state_com = subprocess.run(['systemctl','is-active','ssh'], capture_output = True, text = True)
    ssh_state = ssh_state_com.stdout

    if ssh_state_com.returncode != 0:
        # Command failed, SSH may not be installed
        report.append("❌ Command failed, (possibly not installed):")
        report.append(ssh_state_com.stderr.strip())
    else:
        if 'inactive' in ssh_state:
            # SSH service is installed but not running
            report.append("❌ SSH is inactive")
        else:
            # SSH is active
            report.append("✅ SSH is active")

            # Read sshd_config
            with open('etc/ssh/sshd_config') as f:
                lines = f.readlines()

            # Loop on every directive of the ssh directives dictionary
            for directive in SSH_DIRECTIVES.values():
                check_config_directive(
                lines,
                directive["regex"],
                directive["group_index"],
                report,
                directive["check_func"],
                directive["success_msg_func"],
                directive["fail_msg_func"],
                directive["missing_msg"],
                directive.get("warning_func"),
                directive.get("warning_msg_func")
                )

            # Extract values from each directive for cross-checks
            for line in lines:
                for directive, data in directives.items():
                    match = re.search(data["regex"], line)
                    if match:
                        data["value"] = match.group(1)
                        data["found"] = True
            
            # Cross-analyze primary directives with PubkeyAuthentication
            analyze_auth_methods(
                directives["PasswordAuthentication"]["value"],
                directives["PubkeyAuthentication"]["value"],
                report,
                context = "PasswordAuthentication"
            )
            analyze_auth_methods(
                directives["PermitEmptyPasswords"]["value"],
                directives["PubkeyAuthentication"]["value"],
                report,
                context = "PermitEmptyPasswords"
            )

            # Check for missing directives
            for directive, data in directives.items():
                if not data["found"]:
                    report.append(f"❌ {directive} directive not found")

        # Check ~/.ssh directory permissions (should be 700)
        check_dir_perms(
            os.path.expanduser("~/.ssh"), "700",
            "✅ {path} permissions are correct",
            "❌ {path} should be {expected} but is {actual}",
            report
        )

        # Check ~/.ssh/authorized_keys file permissions (should be 600)
        check_file_perms(
            os.path.expanduser("~/.ssh/authorized_keys"), "600",
            "✅ {path} permissions are correct",
            "❌ {path} should be {expected} but is {actual}",
            report
        )
