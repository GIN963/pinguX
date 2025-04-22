import os
import shlex
from modules.crontab.crontab_scripts_audit import audit_script
from modules.crontab.detect_dangerous_commands import check_dangerous_command
from modules.crontab.check_frequency import check_frequency

def check_crontab():
    report = []

    cron_dir = "/var/spool/cron/"

    for filename in os.listdir(cron_dir):
        user = filename
        filepath = os.path.join(cron_dir, user)

        with open(filepath, "r") as f:
            cron_lines = f.readlines()

        for line in cron_lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split()
            if len(parts) < 6:
                continue  # invalid cron line

            minute, hour, dom, month, dow = parts[:5]
            command = " ".join(parts[5:])
            cmd_parts = shlex.split(command)

            if not cmd_parts:
                continue

            cmd_path = cmd_parts[0]

            # Check frequency of the cron job
            freq_alerts = check_frequency(minute, hour, user, command)
            if freq_alerts:
                report.extend(freq_alerts)

            # Check for dangerous commands in the cron job
            dangerous_alerts = check_dangerous_command(command, user)
            if dangerous_alerts:
                report.extend(dangerous_alerts)

            # Audit the script or binary being executed
            report.append(f"[🕵️‍♂️] Checking script in cron for user '{user}': {cmd_path}")
            script_report = audit_script(cmd_path)
            report.extend(script_report)

    return report




