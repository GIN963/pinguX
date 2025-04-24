import argparse
import os
import subprocess
import re
from utls.whitelist_comparator import compare_firewall_rules
from utils.dictionaries.firewall_whitelist import NFT_WHITELIST

# ----- nftables -----
def scan_nftables():
    report = []
    allowed_ports = set()

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

    comparison_report = compare_firewall_rules(NFT_WHITELIST,allowed_ports)
    report.extend(comparison_report)

    return report




