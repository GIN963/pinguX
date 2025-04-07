
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

def check_shadow(field_name, field_value, check_func, success_msg, fail_msg, report):
    if field_value is None or field_value == "":
        report.append(f"{shadow_fields[field_name]['empty_msg']}")
    elif check_func(field_value):
        report.append(success_msg)
    else:
        report.append(fail_msg)
