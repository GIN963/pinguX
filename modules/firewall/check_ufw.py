import argparse
import os
import subprocess
import re
from utls.whitelist_comparator import compare_firewall_rules
from utils.dictionaries.firewall_whitelist import NFT_WHITELIST

# ----- UFW -----
def scan_ufw():
    report = []
    allowed_ports = set()

    # Run "ufw status verbose" command and capture the output
    ufw_com = subprocess.run(['ufw', 'status', 'verbose'], capture_output=True, text=True)
    ufw_result = ufw_com.stdout
    lines = ufw_result.strip().splitlines()

    # (With regex) Extract the default policy values (incoming/outgoing/routed) in one line
    for line in lines:
        match = re.search(
            r"Default:\s*(\w+)\s+\(incoming\),\s*(\w+)\s+\(outgoing\),\s*(\w+)\s+\(routed\)",
            line
        )
        if match:
            incoming_policy = match.group(1)
            outgoing_policy = match.group(2)
            routed_policy = match.group(3)

            if incoming_policy == "deny" and outgoing_policy == "deny" and routed_policy == "disabled":
                report.append("✅ Default policy is secure (deny incoming, deny outgoing, routed disabled)")
            else:
                report.append("⚠️ Default policy is not secure:")
                if incoming_policy != "deny":
                    report.append(f"❌ Incoming policy is '{incoming_policy}', expected 'deny'")
                if outgoing_policy != "deny":
                    report.append(f"❌ Outgoing policy is '{outgoing_policy}', expected 'deny'")
                if routed_policy != "disabled":
                    report.append(f"❌ Routed policy is '{routed_policy}', expected 'disabled'")
            break

    # Extract all ALLOW rules with port/protocol/direction
    for line in lines:
        match = re.search(r"(\d+)/(tcp|udp)\s+ALLOW\s+Anywhere(?:\s+\(?(in|out)\)?)?", line)
        if match:
            port = match.group(1)
            proto = match.group(2)
            direction = match.group(3) or "in"
            allowed_ports.add((port, proto, direction))

    comparison_report = compare_firewall_rules(NFT_WHITELIST,allowed_ports)
    report.extend(comparison_report)

    return report
