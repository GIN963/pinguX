import subprocess
import re

def scan_ports_vs_firewall():
    report = []
    listening_ports = set()
    firewall_ports = set()

    # Step 1: Extract listening ports using ss
    ss_cmd = subprocess.run(['ss', '-tuln'], capture_output=True, text=True)
    ss_lines = ss_cmd.stdout.strip().splitlines()

    for line in ss_lines:
        if line.startswith("Netid"):
            continue

        parts = re.split(r'\s+', line)
        if len(parts) < 5:
            continue

        proto = parts[0]
        local_address = parts[4]

        if ':' not in local_address:
            continue

        _, port = local_address.rsplit(':', 1)
        listening_ports.add((port, proto.lower()))

    # Step 2: Extract firewall-allowed ports from nftables
    nft_cmd = subprocess.run(['nft', 'list', 'ruleset'], capture_output=True, text=True)
    nft_lines = nft_cmd.stdout.strip().splitlines()

    for line in nft_lines:
        match = re.search(r'(tcp|udp)\s+dport\s+(\d+)\s+accept', line)
        if match:
            proto = match.group(1).lower()
            port = match.group(2)
            firewall_ports.add((port, proto))

    # Step 3: Compare sets
    # Ports that are listening but not allowed by firewall
    for port_proto in listening_ports:
        if port_proto in firewall_ports:
            report.append(f"✅ Port {port_proto[0]}/{port_proto[1]} is open and allowed by firewall")
        else:
            report.append(f"❌ Port {port_proto[0]}/{port_proto[1]} is open but not allowed by firewall — potential exposure")

    # Ports allowed by firewall but nothing is listening on them
    for port_proto in firewall_ports:
        if port_proto not in listening_ports:
            report.append(f"⚠️ Firewall allows port {port_proto[0]}/{port_proto[1]} but no service is listening — unused rule")

    return report
