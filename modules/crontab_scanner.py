import os
import shlex

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

            # Ignore empty lines and comments
            if not line or line.startswith("#"):
                continue

            parts = line.split()
            if len(parts) < 6:
                continue  # invalid cron line

            command = " ".join(parts[5:])
            cmd_parts = shlex.split(command)

            if not cmd_parts:
                continue

            cmd_path = cmd_parts[0]

            report.append(f"[🕵️‍♂️] Checking script in cron for user '{user}': {cmd_path}")
            script_report = audit_script(cmd_path)
            report.extend(script_report)

    return report



