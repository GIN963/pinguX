from utils.dictionaries.dangerous_commands import DANGEROUS_COMMAND_PATTERNS

def scan_dangerous_command(command, user):
    alerts = []

    # Convert the command to lowercase for case-insensitive matching
    cmd_lower = command.lower()

    for pattern in DANGEROUS_COMMAND_PATTERNS:
        # If the pattern is found in the command
        if pattern in cmd_lower:
            # Add an alert with the user and the pattern detected
            alerts.append(f"[WARNING] Dangerous pattern detected for user '{user}': '{pattern}' in command '{command}'")

    return alerts

