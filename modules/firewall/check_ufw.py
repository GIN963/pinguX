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

# ----- UFW -----
def scan_ufw():
    report = []
    allowed_ports = set()

    if not shutil.which("ufw"):
        report.append("❌ 'ufw' command not found. Is nftables installed?")
        logging.error("❌ 'ufw' command not found. Is nftables installed?")
        return report

    try:
        logging.info("🔍 Starting UFW scan...")

        # Run "ufw status verbose" command
        ufw_com = subprocess.run(['ufw', 'status', 'verbose'], capture_output=True, text=True, check=True)
        ufw_result = ufw_com.stdout
        lines = ufw_result.strip().splitlines()
        logging.info("✅ UFW status retrieved")

        # Check default policies
        for line in lines:
            match = re.search(r"Default:\s*(\w+)\s+\(incoming\),\s*(\w+)\s+\(outgoing\),\s*(\w+)\s+\(routed\)", line)
            if match:
                incoming_policy, outgoing_policy, routed_policy = match.groups()
                logging.info(f"🔍 Default policies found - Incoming: {incoming_policy}, Outgoing: {outgoing_policy}, Routed: {routed_policy}")

                if incoming_policy == "deny" and outgoing_policy == "deny" and routed_policy == "disabled":
                    report.append("✅ Default policy is secure (deny incoming, deny outgoing, routed disabled)")
                    logging.info("✅ Default policies are secure")
                else:
                    report.append("⚠️ Default policy is not secure:")
                    logging.warning("⚠️ Default policy is not secure")
                    if incoming_policy != "deny":
                        report.append(f"❌ Incoming policy is '{incoming_policy}', expected 'deny'")
                        logging.warning(f"❌ Incoming policy incorrect: {incoming_policy}")
                    if outgoing_policy != "deny":
                        report.append(f"❌ Outgoing policy is '{outgoing_policy}', expected 'deny'")
                        logging.warning(f"❌ Outgoing policy incorrect: {outgoing_policy}")
                    if routed_policy != "disabled":
                        report.append(f"❌ Routed policy is '{routed_policy}', expected 'disabled'")
                        logging.warning(f"❌ Routed policy incorrect: {routed_policy}")
                break

        # Extract ALLOW rules
        for line in lines:
            match = re.search(r"(\d+)/(tcp|udp)\s+ALLOW\s+Anywhere(?:\s+\(?(in|out)\)?)?", line)
            if match:
                port, proto, direction = match.groups()
                direction = direction or "in"
                allowed_ports.add((port, proto, direction))
                logging.info(f"✅ Found allowed port: {port}/{proto} {direction}")

        # Compare to whitelist
        logging.info("🔍 Comparing UFW allowed ports with whitelist...")
        comparison_report = compare_firewall_rules(NFT_WHITELIST, allowed_ports)
        report.extend(comparison_report)

    except subprocess.CalledProcessError as e:
        report.append("❌ Error retrieving UFW status. Check pingux.log for more details.")
        logging.error(f"❌ UFW command failed: {e}")

    report.append("📄 Detailed logs saved to pingux.log")
    logging.info("✅ UFW scan completed.")
    return report

