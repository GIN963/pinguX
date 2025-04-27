import os
import shlex
import logging
from modules.crontab.crontab_scripts_audit import audit_script
from modules.crontab.detect_dangerous_commands import check_dangerous_command
from modules.crontab.check_frequency import check_frequency

# ----- Setup logging -----
logging.basicConfig(
    filename='pingux.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)

def scan_crontab():
    report = []

    cron_dir = "/var/spool/cron/"
    logging.info("🔍 Starting crontab scan...")

    if not os.path.exists(cron_dir):
        report.append(f"[❌] Cron directory not found: {cron_dir}")
        logging.error(f"❌ Cron directory not found: {cron_dir}")
        return report

    for filename in os.listdir(cron_dir):
        user = filename
        filepath = os.path.join(cron_dir, user)
        logging.info(f"🔍 Scanning cron jobs for user: {user}")

        try:
            with open(filepath, "r") as f:
                cron_lines = f.readlines()
            logging.info(f"✅ Cron file loaded for {user}")
        except Exception as e:
            report.append(f"[⚠️] Cannot read cron file for {user}: {e}")
            logging.warning(f"⚠️ Failed to read {filepath}: {e}")
            continue

        for line in cron_lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split()
            if len(parts) < 6:
                logging.warning(f"⚠️ Invalid cron line for {user}: {line}")
                continue  # invalid cron line

            minute, hour, dom, month, dow = parts[:5]
            command = " ".join(parts[5:])

            try:
                cmd_parts = shlex.split(command)
            except ValueError as e:
                report.append(f"[⚠️] Invalid cron line for {user}: {command} ({e})")
                logging.warning(f"⚠️ Error parsing command for {user}: {command} ({e})")
                continue

            if not cmd_parts:
                continue

            cmd_path = cmd_parts[0]
            logging.info(f"🔍 Analyzing cron command: {command} for {user}")

            try:
                # Check frequency of the cron job
                freq_alerts = check_frequency(minute, hour, user, command)
                if freq_alerts:
                    report.extend(freq_alerts)
                    logging.info(f"⚠️ Suspicious frequency detected for {command} ({user})")

                # Check for dangerous commands in the cron job
                dangerous_alerts = check_dangerous_command(command, user)
                if dangerous_alerts:
                    report.extend(dangerous_alerts)
                    logging.warning(f"❌ Dangerous command detected: {command} ({user})")

                # Audit the script or binary being executed
                report.append(f"[🕵️‍♂️] Checking script in cron for user '{user}': {cmd_path}")
                logging.info(f"🕵️‍♂️ Auditing script {cmd_path} for {user}")
                script_report = audit_script(cmd_path)
                report.extend(script_report)

            except Exception as e:
                report.append(f"[⚠️] Error analyzing cron job '{command}' for {user}: {e}")
                logging.error(f"❌ Error analyzing cron job '{command}' for {user}: {e}")

    report.append("📄 Detailed logs saved to pingux.log")
    logging.info("✅ scan_crontab completed.")
    return report





