import os
import subprocess
import re

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
