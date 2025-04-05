from utiles.ssh_utile import *
from utiles.perms_utile import *
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

            # Read sshd_config file
            ssh_config_com = subprocess.run(['cat','/etc/ssh/sshd_config'], capture_output = True, text = True)
            ssh_config = ssh_config_com.stdout
            lines = ssh_config.strip().splitlines()  # Split file into individual lines

            # Check individual directives with reusable logic
            check_ssh_directive(
                lines, '^Port\s+(\d+)', 1, report,
                lambda x : x != "22",
                lambda port : f"✅ SSH on port {port}", 
                lambda port : f"❌ Port number {port} can be targeted by scanners and bots, change it (ex: 2022)",
                "❌ Port directive not found: SSH will use port 22 by default, which is commonly targeted by bots. Consider specifying a different port."
            )

            check_ssh_directive(
                lines, '^PermitRootLogin\s+(\S+)', 1, report,
                lambda x : x == "no",
                lambda value : f'✅ PermitRootLogin is set to {value}',
                lambda value : f'❌ PermitRootLogin is not set to {value}" (recommended: "no")',
                "❌ PermitRootLogin directive not found (default may allow root login)"
            )

            check_ssh_directive(
                lines, '^MaxAuthTries\s+(\d+)', 1, report,
                lambda x : int(x) <= 3,
                lambda nb : f"✅ MaxAuthTries is set to {nb}",
                lambda nb : f"❌ MaxAuthTries is set to {nb} (recommended: 3 or less)",
                "❌ MaxAuthTries directive not found (default is 6, which is too high)"
            )

            check_ssh_directive(
                lines, '^LoginGraceTime\s+(\S+)', 1, report,
                lambda x: convert_to_seconds(x) <= 30,
                lambda v: f"✅ LoginGraceTime is set to {v} (secure)",
                lambda v: f"❌ LoginGraceTime is set to {v}, which is too long (recommended: 30s or less)",
                "❌ LoginGraceTime directive not found"
            )

            check_ssh_directive(
                lines, '^ChallengeResponseAuthentication\s+(\S+)', 1, report,
                lambda x : x == "no",
                lambda value : f"✅ ChallengeResponseAuthentication is set to {value}",
                lambda value : f"❌ ChallengeResponseAuthentication is set to {value}",
                "❌ ChallengeResponseAuthentication directive not found"
            )

            check_ssh_directive(
                lines, '^AllowUsers\s+(.+)$', 1, report,
                lambda x : len(x.strip().split()) > 0,
                lambda v: f"✅ AllowUsers is not empty ({v})",
                lambda v : "❌ AllowUsers is defined but empty → all users might be allowed",
                "⚠️ AllowUsers directive not found → by default, all users are allowed unless restricted elsewhere"
            )

            check_ssh_directive(
                lines, '^AllowGroups\s+(.+)$', 1, report,
                lambda x : len(x.strip().split()) > 0,
                lambda v: f"✅ AllowGroups is not empty ({v})",
                lambda v : "❌ AllowGroups is defined but empty → all groups might be allowed",
                "⚠️ AllowGroups directive not found → by default, all groups are allowed unless restricted elsewhere"
            )

            check_ssh_directive(
                lines, '^LogLevel\s+(\S+)', 1, report,
                lambda x: x.lower() == "info",
                lambda level: f"✅ LogLevel is set to {level} (recommended)",
                lambda level: f"❌ LogLevel is set to {level} (recommended: INFO)",
                "❌ LogLevel directive not found (default is INFO, but it's safer to set it explicitly)"
            )

            check_ssh_directive(
                lines, '^ClientAliveInterval\s+(\d+)', 1, report,
                lambda x: int(x) <= 300,
                lambda v: f"✅ ClientAliveInterval is set to {v} seconds (secure)",
                lambda v: f"❌ ClientAliveInterval is set to {v} seconds (too high, recommended: 300s or less)",
                "❌ ClientAliveInterval directive not found (default is 0, which disables keep-alive checks)"
            )

            check_ssh_directive(
                lines, '^ClientAliveCountMax\s+(\d+)', 1, report,
                lambda x: int(x) <= 3,
                lambda v: f"✅ ClientAliveCountMax is set to {v} (secure)",
                lambda v: f"❌ ClientAliveCountMax is set to {v} (too high, recommended: 3 or less)",
                "❌ ClientAliveCountMax directive not found (default is 3, but should be set explicitly)"
            )

            check_ssh_directive(
                lines, '^IgnoreRhosts\s+(\S+)', 1, report,
                lambda x: x.lower() == "yes",
                lambda val: f"✅ IgnoreRhosts is set to {val} (recommended)",
                lambda val: f"❌ IgnoreRhosts is set to {val} (recommended: yes)",
                "❌ IgnoreRhosts directive not found (recommended: yes)"
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
