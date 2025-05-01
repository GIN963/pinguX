from utils.config_checker import check_config_directive
from utils.dictionaries.ssh_directives_config import *
from utils.ssh_util import analyze_auth_methods
import argparse
import os
import subprocess
import re
import logging

logger = logging.getLogger(__name__)

# ----- SSH Scanner -----
def scan_ssh():
    report = []
    
    logger.info("=== Starting Listenning Ports Scan ===")

    try:
        # Check SSH service status
        ssh_state_com = subprocess.run(['systemctl', 'is-active', 'ssh'], capture_output=True, text=True)
        ssh_state = ssh_state_com.stdout.strip()

        if ssh_state_com.returncode != 0:
            report.append("[FAIL] SSH command failed (possibly not installed):")
            report.append(ssh_state_com.stderr.strip())
            logging.error(f"[FAIL] SSH check failed: {ssh_state_com.stderr.strip()}")
            return report

        if ssh_state == 'inactive':
            report.append("[FAIL] SSH service is inactive")
            logging.warning("[WARNING] SSH is installed but not running")
        else:
            report.append("[OK] SSH service is active")
            logging.info("[OK] SSH is active")

            # Read sshd_config
            try:
                with open('/etc/ssh/sshd_config') as f:
                    lines = f.readlines()
                logging.info("[OK] sshd_config file loaded successfully")
            except Exception as e:
                report.append(f"[FAIL] Could not read sshd_config: {e}")
                logging.error(f"[FAIL] Failed to read sshd_config: {e}")
                return report

            # Check directives from dictionary
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

            # Extract actual values for cross-analysis
            for line in lines:
                for directive_name, data in directives.items():
                    match = re.search(data["regex"], line)
                    if match:
                        data["value"] = match.group(1)
                        data["found"] = True

            # Cross-checking authentication methods
            try:
                analyze_auth_methods(
                    directives["PasswordAuthentication"]["value"],
                    directives["PubkeyAuthentication"]["value"],
                    report,
                    context="PasswordAuthentication"
                )
                analyze_auth_methods(
                    directives["PermitEmptyPasswords"]["value"],
                    directives["PubkeyAuthentication"]["value"],
                    report,
                    context="PermitEmptyPasswords"
                )
                logging.info("[CROSS-CHECK] SSH authentication cross-checks completed")
            except Exception as e:
                report.append(f"[FAIL] Error during SSH cross-checks: {e}")
                logging.error(f"[FAIL] SSH directive analysis failed: {e}")

            # Check for missing directives
            for directive_name, data in directives.items():
                if not data["found"]:
                    report.append(f"[FAIL] {directive_name} directive not found")
                    logging.warning(f"[WARNING] Missing directive: {directive_name}")

    except Exception as e:
        report.append(f"[FAIL] Unexpected error while scanning SSH: {e}")
        logging.critical(f"[FAIL] Unexpected failure in scan_ssh(): {e}")

    report.append("[DETAILS] Detailed logs saved to pingux.log")
    logging.info("=== SSH Audit Completed ===")
    return report

