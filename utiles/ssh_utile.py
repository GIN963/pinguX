import os
import subprocess
import re

# Generic function to validate an SSH directive from sshd_config
# Parameters:
# - lines: list of lines from the SSH config file
# - regex: regex pattern to locate the directive (e.g., r'^Port\s+(\d+)')
# - group_index: the capture group index containing the directive value
# - report: the list where audit messages are appended
# - check_func: function that checks if the value is secure (returns True/False)
# - success_msg_func: function to generate success message (takes value as input)
# - fail_msg_func: function to generate fail message (takes value as input)
# - missing_msg: message to append if directive is not found at all
def check_ssh_directive(lines, regex, group_index, report, check_func, success_msg_func, fail_msg_func, missing_msg):
    
    # Flag to track if the directive was found in the config file
    flag = False

    for thing in lines:
        # Try to match the line with the given regex
        match = re.search(regex, thing)
        if match:
            # Extract the directive value from the specified capture group
            var = match.group(group_index)
            flag = True

            # Evaluate the value using the check function
            if check_func(var):
                report.append(success_msg_func(var))
            else:
                report.append(fail_msg_func(var))
    
    # If directive not found, append the missing directive warning
    if not flag:
        report.append(missing_msg)


# Function to analyze the combined state of a directive (e.g. PasswordAuthentication)
# and PubkeyAuthentication to determine if the SSH login setup is secure
# Parameters:
# - primary_value: the value of the main directive (e.g. 'no' for PasswordAuthentication)
# - key_value: the value of PubkeyAuthentication (expected: 'yes')
# - report: the list where messages are appended
# - context: a label (string) for the primary directive to show in messages
def analyze_auth_methods(primary_value, key_value, report, context):

    # Case 1: PasswordAuthentication or PermitEmptyPasswords is disabled
    # and PubkeyAuthentication is enabled → secure setup
    if primary_value == "no" and key_value == "yes":
        report.append(f"✅ {context} is disabled & PubkeyAuthentication is enabled")

    # Case 2: PasswordAuthentication or PermitEmptyPasswords is disabled
    # but PubkeyAuthentication is not configured or is disabled
    # → no login method available → risk of lockout
    elif primary_value == "no" and (key_value is None or key_value == "no"):
        report.append(
            f"⚠️ {context} is disabled, but PubkeyAuthentication is either disabled or not configured → SSH login might be impossible."
        )

    # Case 3: One or both are enabled → security hardening needed
    else:
        report.append(f"❌ Make sure to disable {context} and enable PubkeyAuthentication")
