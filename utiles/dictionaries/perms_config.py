# =============================================================
# Dictionaries: SENSITIVE_FILES and SENSITIVE_DIRS
# Description:
# These dictionaries define critical files and directories that must
# be protected with strict permissions for security reasons.
#
# - SENSITIVE_FILES: lists sensitive system and user-level files such as
#   /etc/shadow, /var/log/faillog, ~/.ssh/authorized_keys, etc.
#
# - SENSITIVE_DIRS: lists sensitive directories such as ~/.ssh
#
# Each entry contains:
#   - path: absolute or user-relative path to the file/directory
#   - expected: expected permission in octal format (as string)
#   - success_msg: message displayed when permissions are correct
#   - error_msg: message displayed when permissions are incorrect
#
# Usage:
# These dictionaries are meant to be used with check_file_perms()
# and check_dir_perms() to validate secure access control.
# Example:
#   check_file_perms(SENSITIVE_FILES["Shadow"]["path"], ...)
#   check_dir_perms(SENSITIVE_DIRS[".ssh"]["path"], ...)
# =============================================================

SENSITIVE_FILES = {
    "Shadow": {
        "path": "/etc/shadow",
        "expected": "600",
        "success_msg": "✅ {path} permissions are correct",
        "error_msg": "❌ {path} should be {expected} but is {actual}"
    },
    "Faillog": {
        "path": "/var/log/faillog",
        "expected": "600",
        "success_msg": "✅ {path} permissions are correct",
        "error_msg": "❌ {path} should be {expected} but is {actual}"
    },
    "Auth.log": {
        "path": "/var/log/auth.log",
        "expected": "600",
        "success_msg": "✅ {path} permissions are correct",
        "error_msg": "❌ {path} should be {expected} but is {actual}"
    },
    "Lastlog": {
        "path": "/var/log/lastlog",
        "expected": "600",
        "success_msg": "✅ {path} permissions are correct",
        "error_msg": "❌ {path} should be {expected} but is {actual}"
    },
    "Authorized_keys": {
        "path": "~/.ssh/authorized_keys",
        "expected": "600",
        "success_msg": "✅ {path} permissions are correct",
        "error_msg": "❌ {path} should be {expected} but is {actual}"
    }
}

SENSITIVE_DIRS = {
    ".ssh": {
        "path": "~/.ssh",
        "expected": "700",
        "success_msg": "✅ {path} permissions are correct",
        "error_msg": "❌ {path} should be {expected} but is {actual}"
    }
}

