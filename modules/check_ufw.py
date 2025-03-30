import argparse
import os
import subprocess
import re

#----- UFW -----
def check_ufw():
    
    report = []
    
    allowed_ports = set()

    whitelist = {
        ('22', 'tcp', 'in'),
        ('80', 'tcp', 'in'),
        ('443', 'tcp', 'in'),
        ('53', 'udp', 'out'),
        ('80', 'tcp', 'out'),
        ('443', 'tcp', 'out'),
        ('123', 'udp', 'out'),
        ('icmp', None, 'out')  # ping
    }

    # Run "ufw status verbose" command and capture the output
    ufw_com = subprocess.run(['ufw', 'status', 'verbose'], capture_output=True, text=True)

    # If the command failed: so ufw may not be installed
    if ufw_com.returncode != 0:
        report.append("❌ UFW command failed (possibly not installed):")
        report.append(ufw_com.stderr.strip())

    else:
        ufw_result = ufw_com.stdout
        lines = ufw_result.strip().splitlines()

        if "Status: active" in ufw_result:
            report.append("✅ UFW is active")

            # (With regex) Extract the default policy values (incoming/outgoing/routed) in one line
            # Uses capture groups to isolate the 3 keywords in this exact pattern
            for line in lines:
                match = re.search(r"Default:\s*(\w+)\s+\(incoming\),\s*(\w+)\s+\(outgoing\),\s*(\w+)\s+\(routed\)", line)
                if match:
                    incoming_policy = match.group(1)
                    outgoing_policy = match.group(2)
                    routed_policy = match.group(3)

                    # Checking if the default policies match expected secure values
                    if incoming_policy == "deny" and outgoing_policy == "deny" and routed_policy == "disabled":
                        report.append("✅ Default policy is secure (deny incoming, deny outgoing, routed disabled)")
                    else:
                        report.append("⚠️ Default policy is not secure:")
                        if incoming_policy != "deny":
                            report.append(f"❌ Incoming policy is '{incoming_policy}', expected 'deny'")
                        if outgoing_policy != "deny":
                            report.append(f"❌ Outgoing policy is '{outgoing_policy}', expected 'deny'")
                        if routed_policy != "disabled":
                            report.append(f"❌ Routed policy is '{routed_policy}', expected 'disabled'")
                    break

            # Extract all ALLOW rules with port/protocol/direction, adding them to allowed_ports to compare with the whitelist
            for line in lines:
                match = re.search(r"(\d+)/(tcp|udp)\s+ALLOW\s+Anywhere(?:\s+\(?(in|out)\)?)?", line)
                if match:
                    port = match.group(1)
                    proto = match.group(2)
                    direction = match.group(3) or "in"
                    allowed_ports.add((port, proto, direction))

            # Checking which allowed rules are unauthorized (not in whitelist)
            for rule in allowed_ports:
                if rule not in whitelist:
                    report.append(f"⚠️ Unauthorized rule: {rule}")
                else:
                    report.append(f"✅ Authorized rule: {rule}")

            # Checking which whitelist rules are missing from current config
            for rule in whitelist:
                if rule not in allowed_ports:
                    report.append(f"⚠️ Rule {rule} is missing")

        else:
            report.append("❌ UFW is not active")

    return report