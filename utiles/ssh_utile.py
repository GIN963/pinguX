import argparse
import os
import subprocess
import re

def check_ssh_directive(lines, regex, group_index, report, check_func, success_msg_func, fail_msg_func, missing_msg):

            # Flag to track if the directive was found in the config file
            flag = False
            for thing in lines:
                # Try to match the line with the given regex
                match = re.search(regex,thing)
                if match:
                    # If match found, extract the value using the group index
                    var = match.group(group_index)
                    flag = True
                    # Check the extracted value with the user-defined function
                    if check_func(var):
                        report.append(success_msg_func(var))
                    else:
                        report.append(fail_msg_func(var))
            
            if not flag:
              report.append(missing_msg)

def analyze_auth_methods(primary_value, key_value, report, context):

    # Case 1: the main directive (PasswordAuth or PermitEmptyPasswords) is disabled
    # and PubkeyAuthentication is enabled → Secure setup
    if primary_value == "no" and key_value == "yes":
        report.append(f"✅ {context} is disabled & PubkeyAuthentication is enabled")

    # Case 2: the main directive is disabled, but public key auth is not set or disabled
    # → Login might be impossible (no method available)
    elif primary_value == "no" and (key_value is None or key_value == "no"):
        report.append(f"⚠️ {context} is disabled, but PubkeyAuthentication is either disabled or not configured → SSH login might be impossible.")

    # Case 3: any other case (e.g. password auth still enabled)
    # → Setup needs to be hardened
    else:
        report.append(f"❌ Make sure to disable {context} and enable PubkeyAuthentication")