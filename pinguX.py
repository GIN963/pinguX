#!/usr/bin/env python3

import os
import sys
import argparse
import json
import logging
from datetime import datetime
from modules.ports_and_services.check_services import scan_services
from modules.ssh.check_ssh import scan_ssh
from modules.users_and_groups.check_users_groups import scan_users_groups
from modules.logs_and_perms.check_logs_n_perms import scan_logs_n_perms
from modules.crontab.check_crontab import scan_crontab
from modules.packages.check_packages import scan_packages
from modules.kernel_config.check_sysctl import scan_sysctl
from modules.firewall.check_nft import scan_nftables
from modules.firewall.check_ufw import scan_ufw
from modules.firewall.check_ports_vs_firewall import scan_ports_vs_firewall
from modules.ports_and_services.check_listening_ports import scan_listening_ports

# Check root privileges
if os.geteuid() != 0:
    print("[FAIL] This script must be run as root. Try using 'sudo'.")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    filename='pingux.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("pingux")

# Argument parsing
parser = argparse.ArgumentParser(description="PinguX - Linux Security Audit Tool")
parser.add_argument('--output', choices=['txt', 'json'], help='Output format: txt or json')
parser.add_argument('-v', '--verbose', action='store_true', help='Verbose mode (print everything)')
parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode (no console output)')
args = parser.parse_args()

def display(message):
    if not args.quiet:
        print(message)

def run_audit():
    full_report = []

    display("[+] Scanning services...")
    services_report, _ = scan_services()
    full_report.extend(services_report)

    display("[+] Scanning SSH...")
    full_report.extend(scan_ssh())

    display("[+] Scanning users & groups...")
    full_report.extend(scan_users_groups())

    display("[+] Scanning logs & file permissions...")
    full_report.extend(scan_logs_n_perms())

    display("[+] Scanning scheduled tasks (cron)...")
    full_report.extend(scan_crontab())

    display("[+] Scanning installed packages...")
    full_report.extend(scan_packages())

    display("[+] Scanning sysctl kernel config...")
    full_report.extend(scan_sysctl())

    # Try nftables first, fallback to ufw
    display("[+] Scanning firewall configuration...")
    nft_report, allowed_ports = scan_nftables()
    if not nft_report or any("command not found" in r for r in nft_report):
        firewall_report = scan_ufw()
        allowed_ports = set()  # UFW doesn't give direction info
    else:
        firewall_report = nft_report
    full_report.extend(firewall_report)

    display("[+] Scanning listening ports...")
    full_report.extend(scan_listening_ports())

    display("[+] Comparing firewall rules vs open ports...")
    full_report.extend(scan_ports_vs_firewall())

    return full_report

def export_report(report):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if args.output == "txt":
        filename = f"pingux_report_{timestamp}.txt"
        with open(filename, "w") as f:
            for line in report:
                f.write(line + "\n")
        print(f"\n[+] TXT report saved to {filename}")
    elif args.output == "json":
        filename = f"pingux_report_{timestamp}.json"
        with open(filename, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] JSON report saved to {filename}")

if __name__ == "__main__":
    logger.info("=== Starting PinguX audit ===")
    try:
        report = run_audit()
        if args.verbose and not args.quiet:
            print("\n".join(report))
        export_report(report) if args.output else None
        logger.info("=== Audit completed successfully ===")
    except Exception as e:
        logger.critical(f"Unexpected failure in pingux.py: {e}")
        print(f"[FAIL] An unexpected error occurred: {e}")
