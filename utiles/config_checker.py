import os
import subprocess
import re

def check_config_directive(
    lines,
    regex,
    group_index,
    report,
    check_func,
    success_msg_func,
    fail_msg_func,
    missing_msg,
    warning_func=None,
    warning_msg_func=None
):
    """
    Generic helper to validate a configuration directive from a config file.
    This function is reusable for any config audit where directives are stored line by line.

    Parameters:
    - lines (list): list of config lines (e.g., from a config file like sshd_config)
    - regex (str): regular expression to extract the directive's value
    - group_index (int): index of the capturing group in the regex (1-based)
    - report (list): list where all messages (success, fail, missing) are appended
    - check_func (function): main condition to evaluate the directive (returns True/False)
    - success_msg_func (function): generates a success message when check_func is True
    - fail_msg_func (function): generates a fail message when check_func and warning_func are False
    - missing_msg (str): message to append if the directive is not found at all
    - warning_func (function, optional): secondary check to emit a warning (not fail)
    - warning_msg_func (function, optional): generates the warning message if warning_func is True
    """

    # Tracks whether the directive has been found in the config
    flag = False

    for line in lines:
        # Search for the directive using the provided regex
        match = re.search(regex, line)
        if match:
            # Extract the value from the regex capture group
            var = match.group(group_index)
            flag = True

            # Check for secure configuration
            if check_func(var):
                report.append(success_msg_func(var))
            # If a warning threshold exists, check it
            elif warning_func and warning_func(var):
                report.append(warning_msg_func(var))
            # Otherwise, it's a misconfiguration
            else:
                report.append(fail_msg_func(var))
    
    # If directive was never found in the file
    if not flag:
        report.append(missing_msg)


def check_config_service(
    service_name, 
    report, 
    success_active_msg, 
    fail_active_msg, 
    success_enabled_msg, 
    fail_enabled_msg, 
    error_msg):
    
    """
    Check whether a service is correctly installed, active, and enabled at boot.
    Returns True if the service is installed and active, False otherwise.

    Parameters:
    - service_name: Name of the service to check (e.g. "ssh")
    - report: List to append the results of the check
    - success_active_msg: Message to show if service is active
    - fail_active_msg: Message to show if service is inactive
    - success_enabled_msg: Message to show if service is enabled at boot
    - fail_enabled_msg: Message to show if service is not enabled at boot
    - error_msg: Message to show if the service is not found or status command fails
    """

    is_active_flag = False
    
    # Check if the service is installed / recognized
    service_status = subprocess.run(["systemctl", "status", service_name], capture_output=True, text=True)
    if service_status.returncode == 0:
        # Check if service is active
        is_active = subprocess.run(["systemctl", "is-active", service_name], capture_output=True, text=True)
        if is_active.stdout.strip() == "active":
            report.append(success_active_msg)
            is_active_flag = True
        else:
            report.append(fail_active_msg)

        # Check if service is enabled at startup
        is_enabled = subprocess.run(["systemctl", "is-enabled", service_name], capture_output=True, text=True)
        if is_enabled.stdout.strip() == "enabled":
            report.append(success_enabled_msg)
        else:
            report.append(fail_enabled_msg)
    else:
        report.append(error_msg)
        
    return is_active_flag
