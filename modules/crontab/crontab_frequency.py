def scan_frequency(minute, hour, user, command):
    """
    Check if the cron job runs too frequently.

    Parameters:
    - minute: Minute field of the cron schedule.
    - hour: Hour field of the cron schedule.
    - user: The user owning the cron job.
    - command: The command scheduled.

    """
    alerts = []

    if (minute == "*" and hour == "*") or (minute.startswith("*/") and hour == "*" and int(minute[2:]) <= 5):
        alerts.append(f"⚠️ Cron job for user '{user}' runs very frequently: '{minute} {hour} ...' — {command}")

    return alerts
