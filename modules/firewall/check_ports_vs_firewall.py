import subprocess
import re
import logging
from modules.check_nft import scan_nftables

# ----- Setup logging -----
logging.basicConfig(
    filename='pingux.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)

# ----- Compare Listening Ports vs Firewall -----
def scan_ports_vs_firewall():
    report = []
    listening_ports = set()

    try:
        logging.info("🔍 Starting listening ports scan using ss...")

        # Step 1: Extract listening ports using ss
        ss_cmd = subprocess.run(['ss', '-tuln'], capture_output=True, text=True, check=True)
        ss_lines = ss_cmd.stdout.strip().splitlines()
        logging.info("✅ Listening ports retrieved via ss")

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
            logging.info(f"✅ Detected listening port: {port}/{proto.lower()}")

        # Step 2: Get firewall allowed ports from nftables
        logging.info("🔍 Retrieving allowed ports from nftables...")
        nft_report, firewall_ports_full = scan_nftables()
        firewall_ports = {(port, proto) for (port, proto, direction) in firewall_ports_full if direction == "in"}
        logging.info("✅ Allowed ports from firewall retrieved")

        # Step 3: Compare sets
        for port_proto in listening_ports:
            if port_proto in firewall_ports:
                report.append(f"✅ Port {port_proto[0]}/{port_proto[1]} is open and allowed by firewall")
                logging.info(f"✅ Port {port_proto[0]}/{port_proto[1]} is correctly open and allowed")
            else:
                report.append(f"❌ Port {port_proto[0]}/{port_proto[1]} is open but not allowed by firewall — potential exposure")
                logging.warning(f"❌ Port {port_proto[0]}/{port_proto[1]} is open but not allowed by firewall")

        for port_proto in firewall_ports:
            if port_proto not in listening_ports:
                report.append(f"⚠️ Firewall allows port {port_proto[0]}/{port_proto[1]} but no service is listening — unused rule")
                logging.warning(f"⚠️ Firewall allows {port_proto[0]}/{port_proto[1]} but nothing is listening")

    except subprocess.CalledProcessError as e:
        report.append("❌ Error retrieving listening ports. Check pingux.log for more details.")
        logging.error(f"❌ ss command failed: {e}")

    report.append("📄 Detailed logs saved to pingux.log")
    logging.info("✅ scan_ports_vs_firewall completed.")
    return report

