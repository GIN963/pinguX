import argparse
import os
import subprocess
import re

#----- nft -----
def check_nftables():
    report = []
    allowed_ports = set()

    whitelist = {
        ('22', 'tcp', 'in'),      # SSH
        ('80', 'tcp', 'in'),      # HTTP
        ('443', 'tcp', 'in'),     # HTTPS
        ('53', 'udp', 'in'),      # DNS
        ('123', 'udp', 'in'),     # NTP
        ('icmp', None, 'in')      # Ping
    }

    nft_com = subprocess.run(['nft', 'list', 'ruleset'], capture_output=True, text=True)

    # If the command failed: nft is not installed or not available
    if nft_com.returncode != 0:
        report.append("❌ nftables command failed (possibly not installed):")
        report.append(nft_com.stderr.strip())
    else:
        nft_result = nft_com.stdout
        lines = nft_result.strip().splitlines()

        if not lines:
            report.append("❌ nftables is not active (no ruleset found)")
        else:
            filter_found = False

            for line in lines:
                match = re.search(r"^table\s+inet\s+filter\s*{", line)
                if match:
                    filter_found = True
                    report.append("✅ 'inet filter' table found")
                    break

            if not filter_found:
                report.append("❌ 'inet filter' table not found")

            for chain in lines:
                match = re.search(r"type\s+filter\s+hook\s+(input|output|forward)\s+priority\s+\d+;\s+policy\s+(\w+);", chain)
                if match:
                    hook = match.group(1)
                    policy = match.group(2)

                    if policy == "drop":
                        report.append(f"✅ {hook} policy is secure: drop")
                    else:
                        report.append(f"⚠️ {hook} policy is '{policy}', expected 'drop'")

            for rule in lines:
                # TCP/UDP rules with dport
                match = re.search(r"(tcp|udp)\s+dport\s+(\d+)\s+accept", rule)
                if match:
                    proto = match.group(1)
                    port = match.group(2)
                    allowed_ports.add((port, proto, "in"))  # Direction assumed "in"

                # ICMP rule
                if re.search(r"ip\s+protocol\s+icmp\s+accept", rule):
                    allowed_ports.add(("icmp", None, "in"))

            # Compare to whitelist
            for rule in whitelist:
                if rule not in allowed_ports:
                    report.append(f"⚠️ Rule {rule} is missing from current config")

            for rule in allowed_ports:
                if rule not in whitelist:
                    report.append(f"⚠️ Unauthorized rule: {rule}")
                else:
                    report.append(f"✅ Authorized rule: {rule}")

    return report



