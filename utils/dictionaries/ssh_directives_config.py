# ==============================================================================
# SSH_DIRECTIVES - Dictionary containing SSH hardening checks
# ------------------------------------------------------------------------------
# Each entry corresponds to an SSH configuration directive to audit.
# Structure of each directive:
#   - 'regex': Regex pattern to extract the directive's value from sshd_config.
#   - 'group': The regex group index that contains the value.
#   - 'check': A lambda to determine if the value is secure.
#   - 'success': Function (or lambda) returning the success message.
#   - 'fail': Function (or lambda) returning the failure message.
#   - 'missing': Message if the directive is not found in sshd_config.
#   - (optional) 'warning': A lambda to detect a weak but not critical value.
#   - (optional) 'warning_msg': Function returning a warning message.
# ------------------------------------------------------------------------------
# This dictionary is used by check_config_directive() to automate validation
# of sshd_config settings in a modular and maintainable way.
# ==============================================================================

SSH_DIRECTIVES = {
    "Port": {
        "regex": r"^Port\\s+(\\d+)",
        "group": 1,
        "check_func": lambda x: x != "22",
        "success_msg": lambda x: f"[OK] SSH on port {x}",
        "fail_msg": lambda x: f"[WARNING] Port number {x} can be targeted by scanners and bots, change it (ex: 2022)",
        "missing_msg": "[FAIL] Port directive not found: SSH will use port 22 by default, which is commonly targeted by bots. Consider specifying a different port."
    },
    "PermitRootLogin": {
        "regex": r"^PermitRootLogin\\s+(\\S+)",
        "group": 1,
        "check_func": lambda x: x == "no",
        "success_msg": lambda x: f"[OK] PermitRootLogin is set to {x}",
        "fail_msg": lambda x: f"[WARNING] PermitRootLogin is not set to {x} (recommended: \"no\")",
        "missing_msg": "[FAIL] PermitRootLogin directive not found (default may allow root login)"
    },
    "MaxAuthTries": {
        "regex": r"^MaxAuthTries\\s+(\\d+)",
        "group": 1,
        "check_func": lambda x: int(x) <= 3,
        "success_msg": lambda x: f"[OK] MaxAuthTries is set to {x}",
        "fail_msg": lambda x: f"[WARNING] MaxAuthTries is set to {x} (recommended: 3 or less)",
        "missing_msg": "[FAIL] MaxAuthTries directive not found (default is 6, which is too high)"
    },
    "LoginGraceTime": {
        "regex": r"^LoginGraceTime\\s+(\\S+)",
        "group": 1,
        "check_func": lambda x: convert_to_seconds(x) <= 30,
        "success_msg": lambda x: f"[OK] LoginGraceTime is set to {x} (secure)",
        "fail_msg": lambda x: f"[WARNING] LoginGraceTime is set to {x}, which is too long (recommended: 30s or less)",
        "missing_msg": "[FAIL] LoginGraceTime directive not found"
    },
    "ChallengeResponseAuthentication": {
        "regex": r"^ChallengeResponseAuthentication\\s+(\\S+)",
        "group": 1,
        "check_func": lambda x: x == "no",
        "success_msg": lambda x: f"[OK] ChallengeResponseAuthentication is set to {x}",
        "fail_msg": lambda x: f"[WARNING] ChallengeResponseAuthentication is set to {x}",
        "missing_msg": "[FAIL] ChallengeResponseAuthentication directive not found"
    },
    "AllowUsers": {
        "regex": r"^AllowUsers\\s+(.+)$",
        "group": 1,
        "check_func": lambda x: len(x.strip().split()) > 0,
        "success_msg": lambda x: f"[OK] AllowUsers is not empty ({x})",
        "fail_msg": lambda x: "[WARNING] AllowUsers is defined but empty → all users might be allowed",
        "missing_msg": "[FAIL] AllowUsers directive not found → by default, all users are allowed unless restricted elsewhere"
    },
    "AllowGroups": {
        "regex": r"^AllowGroups\\s+(.+)$",
        "group": 1,
        "check_func": lambda x: len(x.strip().split()) > 0,
        "success_msg": lambda x: f"[OK] AllowGroups is not empty ({x})",
        "fail_msg": lambda x: "[WARNING] AllowGroups is defined but empty → all groups might be allowed",
        "missing_msg": "[FAIL] AllowGroups directive not found → by default, all groups are allowed unless restricted elsewhere"
    },
    "LogLevel": {
        "regex": r"^LogLevel\\s+(\\S+)",
        "group": 1,
        "check_func": lambda x: x.lower() == "info",
        "success_msg": lambda x: f"[OK] LogLevel is set to {x} (recommended)",
        "fail_msg": lambda x: f"[WARNING] LogLevel is set to {x} (recommended: INFO)",
        "missing_msg": "[FAIL] LogLevel directive not found (default is INFO, but it's safer to set it explicitly)"
    },
    "ClientAliveInterval": {
        "regex": r"^ClientAliveInterval\\s+(\\d+)",
        "group": 1,
        "check_func": lambda x: int(x) <= 300,
        "success_msg": lambda x: f"[OK] ClientAliveInterval is set to {x} seconds (secure)",
        "fail_msg": lambda x: f"[WARNING] ClientAliveInterval is set to {x} seconds (too high, recommended: 300s or less)",
        "missing_msg": "[FAIL] ClientAliveInterval directive not found (default is 0, which disables keep-alive checks)"
    },
    "ClientAliveCountMax": {
        "regex": r"^ClientAliveCountMax\\s+(\\d+)",
        "group": 1,
        "check_func": lambda x: int(x) <= 3,
        "success_msg": lambda x: f"[OK] ClientAliveCountMax is set to {x} (secure)",
        "fail_msg": lambda x: f"[WARNING] ClientAliveCountMax is set to {x} (too high, recommended: 3 or less)",
        "missing_msg": "[FAIL] ClientAliveCountMax directive not found (default is 3, but should be set explicitly)"
    },
    "IgnoreRhosts": {
        "regex": r"^IgnoreRhosts\\s+(\\S+)",
        "group": 1,
        "check_func": lambda x: x.lower() == "yes",
        "success_msg": lambda x: f"[OK] IgnoreRhosts is set to {x} (recommended)",
        "fail_msg": lambda x: f"[WARNING] IgnoreRhosts is set to {x} (recommended: yes)",
        "missing_msg": "[FAIL] IgnoreRhosts directive not found (recommended: yes)"
    }
}

# Initialize the directives to be cross-analyzed with PubkeyAuthentication
directives = {
    "PasswordAuthentication": {
        "regex": r'^PasswordAuthentication\s+(\S+)',  # Match PasswordAuthentication directive
        "value": None,     # Will hold the matched value
        "found": False     # Indicates if the directive was found
    },
    "PubkeyAuthentication": {
        "regex": r'^PubkeyAuthentication\s+(\S+)',     # Match PubkeyAuthentication directive
        "value": None,
        "found": False
    },
    "PermitEmptyPasswords": {
        "regex": r'^PermitEmptyPasswords\s+(\S+)',      # Match PermitEmptyPasswords directive
        "value": None,
        "found": False
    }      
}
