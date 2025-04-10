LASTLOG_CONFIG = {
    "inactive_days": {
        "regex": ...,  # ton regex pour extraire la date
        "group_index": 1,
        "check_func": lambda days: days < 60,
        "warning_func": lambda days: 60 <= days <= 90,
        "success_msg": lambda days: f"✅ Last login was {days} days ago",
        "warning_msg": lambda days: f"⚠️ Last login was {days} days ago (getting old)",
        "fail_msg": lambda days: f"❌ User hasn't logged in for over {days} days → account might be inactive",
        "missing_msg": "⚠️ Could not find last login information"
    }
}
