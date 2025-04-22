import argparse
import os
import subprocess
import re

# ----- nftables -----
def check_nftables():
    report = []
    allowed_ports = set()

    # Define allowed rules (whitelist)
    whitelist = {
        ('22', 'tcp', 'in'),      # SSH
        ('80', 'tcp', 'in'),      # HTTP
        ('443', 'tcp', 'in'),     # HTTPS
        ('53', 'udp', 'in'),      # DNS
        ('123', 'udp', 'in'),     # NTP
        ('icmp', None, 'in')      # Ping (ICMP)
    }

    # Run the nft command to get the current ruleset
    nft_com = subprocess.run(['nft', 'list', 'ruleset'], capture_output=True, text=True)
    nft_result = nft_com.stdout
    lines = nft_result.strip().splitlines()

    # Check if the 'inet filter' table exists
    filter_found = False
    for line in lines:
        if re.search(r"^table\s+inet\s+filter\s*{", line):
            filter_found = True
            report.append("✅ 'inet filter' table found")
            break

    if not filter_found:
        report.append("❌ 'inet filter' table not found")

    # Check the default policies for input/output/forward hooks
    for chain in lines:
        match = re.search(r"type\s+filter\s+hook\s+(input|output|forward)\s+priority\s+\d+;\s+policy\s+(\w+);", chain)
        if match:
            hook = match.group(1)
            policy = match.group(2)

            if policy == "drop":
                report.append(f"✅ {hook} policy is secure: drop")
            else:
                report.append(f"⚠️ {hook} policy is '{policy}', expected 'drop'")

    # Extract accepted rules (TCP/UDP ports and ICMP)
    for rule in lines:
        # Match TCP/UDP port accept rules
        match = re.search(r"(tcp|udp)\s+dport\s+(\d+)\s+accept", rule)
        if match:
            proto = match.group(1)
            port = match.group(2)
            allowed_ports.add((port, proto, "in"))

        # Match ICMP accept rules
        if re.search(r"ip\s+protocol\s+icmp\s+accept", rule):
            allowed_ports.add(("icmp", None, "in"))

    # Check for missing expected rules
    for rule in whitelist:
        if rule not in allowed_ports:
            report.append(f"⚠️ Rule {rule} is missing from current config")

    # Check for unauthorized rules
    for rule in allowed_ports:
        if rule not in whitelist:
            report.append(f"⚠️ Unauthorized rule: {rule}")
        else:
            report.append(f"✅ Authorized rule: {rule}")

    return report




