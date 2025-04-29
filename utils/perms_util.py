import os

"""
Checks the permissions of a directory and appends the result to the report.

Parameters:
- path (str): Full path to the directory to check.
- expected_perms (str): The permission string to expect (e.g., "700").
- success_msg (str): Message template if the permission is correct. Use {path} to inject path.
- error_msg (str): Message template if the permission is incorrect. Use {path}, {expected}, {actual}.
- report (list): The list that accumulates audit messages.
"""

def check_dir_perms(path, expected_perms, success_msg, error_msg, report):
    if os.path.isdir(path):
        stat_info = os.stat(path)  # Get metadata about the directory
        permissions = oct(stat_info.st_mode)[-3:]  # Extract the last 3 digits (e.g., '700')

        if permissions != expected_perms:
            # If permissions don't match, append an error with details
            report.append(error_msg.format(path=path, expected=expected_perms, actual=permissions))
        else:
            # Permissions are correct
            report.append(success_msg.format(path=path))
    else:
        # Directory not found
        report.append(f"⚠️ {path} directory not found")


"""
Checks the permissions of a directory and appends the result to the report.

Parameters:
- path (str): Full path to the directory to check.
- expected_perms (str): The permission string to expect (e.g., "700").
- success_msg (str): Message template if the permission is correct. Use {path} to inject path.
- error_msg (str): Message template if the permission is incorrect. Use {path}, {expected}, {actual}.
- report (list): The list that accumulates audit messages.
"""

def check_file_perms(path, expected_perms, success_msg, error_msg, report):
    if os.path.isfile(path):
        stat_info = os.stat(path)  # Get metadata about the file
        permissions = oct(stat_info.st_mode)[-3:]  # Extract permission bits

        if permissions != expected_perms:
            # Incorrect permissions
            report.append(error_msg.format(path=path, expected=expected_perms, actual=permissions))
        else:
            # Correct permissions
            report.append(success_msg.format(path=path))
    else:
        # File not found
        report.append(f"[FAIL] {path} file not found")

