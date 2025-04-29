import subprocess
import re
import logging
from utils.dictionaries.firewall_rules_config import WHITELIST, GREYLIST, BLACKLIST
from utils.dictionaries.server_roles_config import ROLE_PROCESS_MAP, DEFAULT_ACCEPTED_SERVICES
from utils.detect_server_role import detect_server_roles
from utils.get_process_list import get_process_list

# ----- Setup logging -----
logging.basicConfig(
    filename='pingux.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

def scan_listening_ports():
    report = []
    processes_found = set()
    listening_entries = []

    logger.info("=== Starting Listenning Ports Scan ===")

    try:
        # Get running processes globally (not only bound to ports)
        all_processes = set(get_process_list())

        # Get listening ports from ss
        ss_cmd = subprocess.run(['ss', '-tulpen'], capture_output=True, text=True, check=True)
        lines = ss_cmd.stdout.strip().splitlines()

        if not lines:
            report.append("[OK] No active listening services detected.")
            return report

        for line in lines:
            if line.startswith("Netid") or not line.strip():
                continue

            parts = re.split(r'\s+', line)
            if len(parts) < 6:
                continue

            proto = parts[0]
            local_address = parts[4]
            process_info = parts[-1]

            if ':' not in local_address:
                continue

            ip, port = local_address.rsplit(':', 1)
            try:
                port_int = int(port)
            except ValueError:
                continue

            match = re.search(r'"([^"]+)",pid=\d+', process_info)
            process_name = match.group(1) if match else "unknown"
            processes_found.add(process_name)

            rule = (port, proto, process_name)

            if rule in WHITELIST:
                report.append(f"[OK] {process_name} listening on {ip}:{port} ({proto}) — Whitelisted")
            elif process_name in BLACKLIST or ip == "0.0.0.0" or port_int > 40000:
                report.append(f"[WARNING] {process_name} listening on {ip}:{port} ({proto}) — Suspicious or dangerous")
            elif process_name in GREYLIST or ip == "127.0.0.1":
                report.append(f"[WARNING] {process_name} listening on {ip}:{port} ({proto}) — Acceptable but not whitelisted")
            elif process_name in DEFAULT_ACCEPTED_SERVICES:
                report.append(f"[WARNING] {process_name} listening on {ip}:{port} ({proto}) — Known but not role-specific")
            else:
                report.append(f"[WARNING] {process_name} listening on {ip}:{port} ({proto}) — Unknown service")

            listening_entries.append((process_name, ip, port, proto))

        # Detect server roles based on all running processes
        roles, unknown_procs = detect_server_roles(all_processes)

        report.append(f"\n[INFO] Detected server roles: {', '.join(roles)}")
        if unknown_procs:
            report.append(f"[WARNING] Unrecognized processes: {', '.join(unknown_procs)}")

        # Check if services match the declared roles
        known_role_services = set()
        for role in roles:
            known_role_services |= ROLE_PROCESS_MAP.get(role, set())

        for process_name in processes_found:
            if process_name in DEFAULT_ACCEPTED_SERVICES:
                continue
            if process_name in known_role_services:
                continue
            for role, allowed in ROLE_PROCESS_MAP.items():
                if process_name in allowed and role not in roles:
                    report.append(f"[WARNING] {process_name} is active, but the server is not a '{role}' server")
                    break

    except subprocess.CalledProcessError as e:
        report.append("[FAIL] Failed to retrieve listening ports using ss. Check pingux.log for more details.")
        logger.error(f"Failed to run ss command: {e}")

    except Exception as e:
        report.append("[FAIL] Unexpected error while scanning listening ports. Check pingux.log for more details.")
        logger.error(f"Unexpected error in scan_listening_ports: {e}")

    report.append("[INFO] Detailed logs are available in pingux.log")
    logger.info("=== Listenning Ports Audit Completed ===")
    return report
