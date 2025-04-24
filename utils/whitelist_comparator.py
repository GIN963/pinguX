from utils.dictionaries.firewall_whitelist import *

def compare_firewall_rules(whitelist,allowed_ports):
    report = []
        # Check for missing expected rules
    for rule in whitelist:
        if rule not in allowed_ports:
            report.append(f"⚠️ Rule {rule} is missing from current config")

    # Check for unauthorized rules
    for rule in allowed_ports:
        if rule not in whitelist:
            report.append(f"⚠️ Unauthorized rule: {rule}")
        else:
            report.append(f"✅ Authorized rule: {rule}")

    return report