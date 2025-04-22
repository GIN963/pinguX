from datetime import datetime
from dateutil import parser

# Dictionary defining each relevant field in the /etc/shadow file
# Each entry contains:
# - index: the position of the field in the colon-separated line
# - empty_msg: the message to display when the field is empty

shadow_fields = {
    "password_hash": {
        "index": 1,
        "empty_msg": "❌ No password hash found → the account might not require a password (disabled or misconfigured)."
    },
    "last_changed": {
        "index": 2,
        "empty_msg": "⚠️ Last password change date is empty → the system may not be tracking password changes."
    },
    "min_days": {
        "index": 3,
        "empty_msg": "⚠️ Minimum days between password changes not set → users might change passwords too frequently."
    },
    "max_days": {
        "index": 4,
        "empty_msg": "⚠️ Maximum days between password changes not set → passwords might never expire."
    },
    "warn_days": {
        "index": 5,
        "empty_msg": "⚠️ Warning days before password expiration not set → users won’t be alerted before expiry."
    },
    "inactive_days": {
        "index": 6,
        "empty_msg": "⚠️ Inactivity period after password expiration not set → expired accounts may stay active indefinitely."
    },
    "expire": {
        "index": 7,
        "empty_msg": "⚠️ Account expiration date is empty → the account may never expire."
    }
}

# Generic function to evaluate shadow file fields (e.g., password aging policy)
# Parameters:
# - field_name: the key from the shadow_fields dict (used to get the empty message)
# - field_value: the actual string value extracted from the shadow file
# - check_func: lambda or function to evaluate the value
# - success_msg: message to append to report if check passes
# - fail_msg: message to append if the check fails
# - report: the shared list collecting audit results

def check_shadow(field_name, field_value, check_func, success_msg, fail_msg, report):
    if field_value is None or field_value == "":
        # If field is missing or empty, append the associated warning
        report.append(f"{shadow_fields[field_name]['empty_msg']}")
    elif check_func(field_value):
        # If check function passes, add success message
        report.append(success_msg)
    else:
        # If check fails, add fail message
        report.append(fail_msg)


def check_last_login(date_str):
    if date_str == "Never logged in":
        return False
    try:
        login_date = parser.parse(date_str)
        delta = (datetime.now() - login_date).days
        return delta <= 60
    except:
        return False

def warn_last_login(date_str):
    if date_str == "Never logged in":
        return False
    try:
        login_date = parser.parse(date_str)
        delta = (datetime.now() - login_date).days
        return 60 < delta <= 90
    except:
        return False

