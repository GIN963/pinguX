import argparse
import os
import subprocess
import re

parser = argparse.ArgumentParser(description="Linux machine scanner")

parser.add_argument('--output-format txt', action='store_true', help='Generates a report in .txt format.')
parser.add_argument('--output-format json', action='store_true', help='Generates a report in .json format.')
parser.add_argument('-v', '--verbose', action='store_true', help='Print detailed audit progress and results to the console.')
parser.add_argument('-q', '--quiet', action='store_true', help='Silent mode. No information is displayed during the scan.')

args = parser.parse_args()

#----- UFW -----
def check_ufw():
    
    report = []
    
    allowed_ports = set()

    whitelist = {
        ('22', 'tcp', 'in'),
        ('80', 'tcp', 'in'),
        ('443', 'tcp', 'in'),
        ('53', 'udp', 'out'),
        ('80', 'tcp', 'out'),
        ('443', 'tcp', 'out'),
        ('123', 'udp', 'out'),
        ('icmp', None, 'out')  # ping
    }

    # Run "ufw status verbose" command and capture the output
    ufw_com = subprocess.run(['ufw', 'status', 'verbose'], capture_output=True, text=True)

    # If the command failed: so ufw may not be installed
    if ufw_com.returncode != 0:
        report.append("❌ UFW command failed (possibly not installed):")
        report.append(ufw_com.stderr.strip())

    else:
        ufw_result = ufw_com.stdout
        lines = ufw_result.strip().splitlines()

        if "Status: active" in ufw_result:
            report.append("✅ UFW is active")

            # (With regex) Extract the default policy values (incoming/outgoing/routed) in one line
            # Uses capture groups to isolate the 3 keywords in this exact pattern
            for line in lines:
                match = re.search(r"Default:\s*(\w+)\s+\(incoming\),\s*(\w+)\s+\(outgoing\),\s*(\w+)\s+\(routed\)", line)
                if match:
                    incoming_policy = match.group(1)
                    outgoing_policy = match.group(2)
                    routed_policy = match.group(3)

                    # Checking if the default policies match expected secure values
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

            # Extract all ALLOW rules with port/protocol/direction, adding them to allowed_ports to compare with the whitelist
            for line in lines:
                match = re.search(r"(\d+)/(tcp|udp)\s+ALLOW\s+Anywhere(?:\s+\(?(in|out)\)?)?", line)
                if match:
                    port = match.group(1)
                    proto = match.group(2)
                    direction = match.group(3) or "in"
                    allowed_ports.add((port, proto, direction))

            # Checking which allowed rules are unauthorized (not in whitelist)
            for rule in allowed_ports:
                if rule not in whitelist:
                    report.append(f"⚠️ Unauthorized rule: {rule}")
                else:
                    report.append(f"✅ Authorized rule: {rule}")

            # Checking which whitelist rules are missing from current config
            for rule in whitelist:
                if rule not in allowed_ports:
                    report.append(f"⚠️ Rule {rule} is missing")

        else:
            report.append("❌ UFW is not active")

    return report

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


      


      
'''
disable remote ssh authentification with the root account

                   




'''
