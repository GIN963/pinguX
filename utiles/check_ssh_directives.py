import argparse
import os
import subprocess
import re

def check_ssh_directive(lines, regex, group_index, report, check_func, success_msg_func, fail_msg_func, missing_msg):

            flag = False
            for thing in lines:
                match = re.search(regex,thing)
                if match:
                    var = match.group(group_index)
                    flag = True
                    
                    if check_func(var):
                        report.append(success_msg_func(var))
                    else:
                        report.append(fail_msg_func(var))
            
            if not flag:
              report.append(missing_msg)
            

def analyze_auth_methods(psswd_value, key_value, report):
    
    if psswd_value == "no" and key_value == "yes":
        report.append("✅ Password authentication is disabled & public key authentication is enabled")
    elif psswd_value == "no" and (key_value is None or key_value == "no"):
        report.append("⚠️ PasswordAuthentication is disabled, but PubkeyAuthentication is either disabled or not configured → SSH login might be impossible.")
    else:
        report.append("❌ Make sure to disable password authentication and enable public key authentication")


