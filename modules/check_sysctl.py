import subprocess
from utiles.dictionaries.sysctl_config import SYSCTL_HARDENING_RULES

def check_sysctl():
    sysctl_output = {}
    report = []

    # Run sysctl -a to get active kernel values
    sysctl_com = subprocess.run(['sysctl', '-a'], capture_output=True, text=True)
    lines = sysctl_com.stdout.strip().splitlines()

    # Parse sysctl -a output into a dictionary
    for line in lines:
        if "=" in line:
            key, value = line.split("=", 1)
            sysctl_output[key.strip()] = value.strip()

    # Load sysctl.conf once for persistence checks
    with open('/etc/sysctl.conf') as f:
        sysctl_conf_lines = f.readlines()

    # Audit each expected sysctl directive
    for rule, expected_value in SYSCTL_HARDENING_RULES.items():
        if rule in sysctl_output:
            actual_value = sysctl_output[rule]  # ← fix ici (== → =)
            if actual_value == expected_value:
                report.append(f"✅ {rule} = {actual_value} (kernel) — OK")
            else:
                report.append(f"❌ {rule} = {actual_value} (kernel), expected {expected_value}")
        else:
            report.append(f"⚠️ {rule} not found in sysctl -a — checking sysctl.conf...")

        # Always check persistence in sysctl.conf
        found_in_file = False
        for line in sysctl_conf_lines:
            if rule in line:
                found_in_file = True
                if line.strip().startswith("#"):
                    report.append(f"⚠️ {rule} is commented in sysctl.conf — should be uncommented")
                elif f"{rule}={expected_value}" not in line.replace(" ", ""):
                    report.append(f"❌ {rule} found in sysctl.conf but has wrong value")
                else:
                    report.append(f"✅ {rule} is correctly configured in sysctl.conf")
        if not found_in_file:
            report.append(f"❌ {rule} is missing from sysctl.conf — should be added")

    return report

 