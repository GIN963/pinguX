import subprocess
import re
import logging
import shutil
from utils.whitelist_comparator import compare_firewall_rules
from utils.dictionaries.firewall_whitelist import NFT_WHITELIST

# ----- Setup logging -----
logging.basicConfig(
    filename='pingux.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)

# ----- nftables -----
def scan_nftables():
    report = []
    allowed_ports = set()

    if not shutil.which("nft"):
        report.append("❌ 'nft' command not found. Is nftables installed?")
        logging.error("❌ 'nft' command not found. Is nftables installed?")
        return report, allowed_ports

    try:
        logging.info("🔍 Starting nftables scan...")

        # Run the nft command to get the current ruleset
        nft_com = subprocess.run(['nft', 'list', 'ruleset'], capture_output=True, text=True, check=True)
        nft_result = nft_com.stdout
        lines = nft_result.strip().splitlines()
        logging.info("✅ nftables ruleset retrieved")

        # Check if the 'inet filter' table exists
        filter_found = False
        for line in lines:
            if re.search(r"^table\s+inet\s+filter\s*{", line):
                filter_found = True
                report.append("✅ 'inet filter' table found")
                logging.info("✅ 'inet filter' table found")
                break

        if not filter_found:
            report.append("❌ 'inet filter' table not found")
            logging.warning("❌ 'inet filter' table not found")
            return report

        # Check the default policies for input/output/forward hooks
        for chain in lines:
            match = re.search(r"type\s+filter\s+hook\s+(input|output|forward)\s+priority\s+\d+;\s+policy\s+(\w+);", chain)
            if match:
                hook = match.group(1)
                policy = match.group(2)

                if policy == "drop":
                    report.append(f"✅ {hook} policy is secure: drop")
                    logging.info(f"✅ {hook} policy is secure: drop")
                else:
                    report.append(f"⚠️ {hook} policy is '{policy}', expected 'drop'")
                    logging.warning(f"⚠️ {hook} policy is '{policy}', expected 'drop'")

        # Extract accepted rules (TCP/UDP ports and ICMP)
        for rule in lines:
            match = re.search(r"(tcp|udp)\s+dport\s+(\d+)\s+accept", rule)
            if match:
                proto = match.group(1)
                port = match.group(2)
                allowed_ports.add((port, proto, "in"))
                logging.info(f"✅ Allowed port found: {port}/{proto}")

            # Match ICMP accept rules
            if re.search(r"ip\s+protocol\s+icmp\s+accept", rule):
                allowed_ports.add(("icmp", None, "in"))
                logging.info(f"✅ ICMP accept rule found")

        # Compare allowed rules to whitelist
        logging.info("🔍 Comparing nftables rules to whitelist...")
        comparison_report = compare_firewall_rules(NFT_WHITELIST, allowed_ports)
        report.extend(comparison_report)

    except subprocess.CalledProcessError as e:
        report.append("❌ Error retrieving nftables status. Check pingux.log for more details.")
        logging.error(f"❌ nftables command failed: {e}")

    report.append("📄 Detailed logs saved to pingux.log")
    logging.info("✅ nftables scan completed.")
    return report, allowed_ports





