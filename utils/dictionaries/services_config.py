SENSITIVE_SERVICES = {
    "ufw": {
        "description": "Uncomplicated Firewall - frontend for iptables",
        "criticality": "high",
        "active_msg": "[OK] UFW is active.",
        "inactive_msg": "[FAIL] UFW is not active.",
        "enabled_msg": "[OK] UFW is enabled at boot.",
        "disabled_msg": "[FAIL] UFW is not enabled at boot.",
        "not_found_msg": "[ERROR] UFW is not installed or the command failed.",
        "recommendation": "[RECOMMENDATION] If UFW is used, ensure it is enabled with secure default policies and restricted access rules."
    },
    "nftables": {
        "description": "Linux packet filtering framework replacing iptables",
        "criticality": "high",
        "active_msg": "[OK] nftables is active (ruleset found).",
        "inactive_msg": "[FAIL] nftables is not active (no ruleset found).",
        "enabled_msg": "[OK] nftables is enabled at boot.",
        "disabled_msg": "[FAIL] nftables is not enabled at boot.",
        "not_found_msg": "[ERROR] nftables is not installed or the command failed.",
        "recommendation": "[RECOMMENDATION] Ensure nftables has a proper 'inet filter' table with strict hook policies and minimal allowed traffic."
    },
    "telnet": {
        "description": "Unencrypted remote access service",
        "criticality": "high",
        "active_msg": "[FAIL] 'telnet' service is active. This is a security risk.",
        "inactive_msg": "[OK] 'telnet' service is not active.",
        "enabled_msg": "[FAIL] 'telnet' service is enabled at boot.",
        "disabled_msg": "[OK] 'telnet' service is not enabled at boot.",
        "not_found_msg": "[ERROR] 'telnet' service is missing or systemctl failed.",
        "recommendation": "[RECOMMENDATION] Disable Telnet immediately and use SSH instead."
    },
    "ftp": {
        "description": "Unsecured file transfer protocol",
        "criticality": "high",
        "active_msg": "[FAIL] 'ftp' service is active. FTP transmits data in cleartext.",
        "inactive_msg": "[OK] 'ftp' service is not active.",
        "enabled_msg": "[FAIL] 'ftp' service is enabled at boot.",
        "disabled_msg": "[OK] 'ftp' service is not enabled at boot.",
        "not_found_msg": "[ERROR] 'ftp' service is missing or systemctl failed.",
        "recommendation": "[RECOMMENDATION] Use SFTP or SCP instead of FTP."
    },
    "rsh": {
        "description": "Remote Shell - unencrypted remote access",
        "criticality": "high",
        "active_msg": "[FAIL] 'rsh' service is active.",
        "inactive_msg": "[OK] 'rsh' service is not active.",
        "enabled_msg": "[FAIL] 'rsh' service is enabled at boot.",
        "disabled_msg": "[OK] 'rsh' service is not enabled at boot.",
        "not_found_msg": "[ERROR] 'rsh' service is missing.",
        "recommendation": "[RECOMMENDATION] Remove RSH and use SSH instead."
    },
    "rlogin": {
        "description": "Remote login - unencrypted access via rlogin",
        "criticality": "high",
        "active_msg": "[FAIL] 'rlogin' service is active.",
        "inactive_msg": "[OK] 'rlogin' service is not active.",
        "enabled_msg": "[FAIL] 'rlogin' service is enabled at boot.",
        "disabled_msg": "[OK] 'rlogin' service is not enabled at boot.",
        "not_found_msg": "[ERROR] 'rlogin' service is missing.",
        "recommendation": "[RECOMMENDATION] Disable rlogin and use SSH with key-based authentication."
    },
    "apache2": {
        "description": "Apache web server",
        "criticality": "medium",
        "active_msg": "[OK] 'apache2' service is active.",
        "inactive_msg": "[FAIL] 'apache2' service is not active.",
        "enabled_msg": "[OK] 'apache2' service is enabled at boot.",
        "disabled_msg": "[FAIL] 'apache2' service is not enabled at boot.",
        "not_found_msg": "[ERROR] 'apache2' service is missing.",
        "recommendation": "[RECOMMENDATION] Enable HTTPS, configure security headers, and keep the server updated."
    },
    "nginx": {
        "description": "Nginx web server",
        "criticality": "medium",
        "active_msg": "[OK] 'nginx' service is active.",
        "inactive_msg": "[FAIL] 'nginx' service is not active.",
        "enabled_msg": "[OK] 'nginx' service is enabled at boot.",
        "disabled_msg": "[FAIL] 'nginx' service is not enabled at boot.",
        "not_found_msg": "[ERROR] 'nginx' service is missing.",
        "recommendation": "[RECOMMENDATION] Enable HTTPS, configure security headers, and keep the server updated."
    },
    "vsftpd": {
        "description": "Secure FTP server (vsftpd)",
        "criticality": "high",
        "active_msg": "[FAIL] 'vsftpd' service is active.",
        "inactive_msg": "[OK] 'vsftpd' service is not active.",
        "enabled_msg": "[FAIL] 'vsftpd' service is enabled at boot.",
        "disabled_msg": "[OK] 'vsftpd' service is not enabled at boot.",
        "not_found_msg": "[ERROR] 'vsftpd' service is missing.",
        "recommendation": "[RECOMMENDATION] If using vsftpd, enable TLS and restrict users. Prefer SFTP if possible."
    },
    "smb": {
        "description": "Windows file sharing service (Samba/SMB)",
        "criticality": "medium",
        "active_msg": "[OK] 'smb' service is active.",
        "inactive_msg": "[FAIL] 'smb' service is not active.",
        "enabled_msg": "[OK] 'smb' service is enabled at boot.",
        "disabled_msg": "[FAIL] 'smb' service is not enabled at boot.",
        "not_found_msg": "[ERROR] 'smb' service is missing.",
        "recommendation": "[RECOMMENDATION] Limit public shares, use SMBv3 with encryption, and restrict access by IP or user."
    },
    "cups": {
        "description": "Network printing service (CUPS)",
        "criticality": "low",
        "active_msg": "[OK] 'cups' service is active.",
        "inactive_msg": "[FAIL] 'cups' service is not active.",
        "enabled_msg": "[OK] 'cups' service is enabled at boot.",
        "disabled_msg": "[FAIL] 'cups' service is not enabled at boot.",
        "not_found_msg": "[ERROR] 'cups' service is missing.",
        "recommendation": "[RECOMMENDATION] Disable CUPS if not needed, especially on servers."
    },
    "mysql": {
        "description": "MySQL or MariaDB database server",
        "criticality": "medium",
        "active_msg": "[OK] 'mysql' service is active.",
        "inactive_msg": "[FAIL] 'mysql' service is not active.",
        "enabled_msg": "[OK] 'mysql' service is enabled at boot.",
        "disabled_msg": "[FAIL] 'mysql' service is not enabled at boot.",
        "not_found_msg": "[ERROR] 'mysql' service is missing.",
        "recommendation": "[RECOMMENDATION] Limit access to localhost and change all default passwords."
    },
    "postgresql": {
        "description": "PostgreSQL database server",
        "criticality": "medium",
        "active_msg": "[OK] 'postgresql' service is active.",
        "inactive_msg": "[FAIL] 'postgresql' service is not active.",
        "enabled_msg": "[OK] 'postgresql' service is enabled at boot.",
        "disabled_msg": "[FAIL] 'postgresql' service is not enabled at boot.",
        "not_found_msg": "[ERROR] 'postgresql' service is missing.",
        "recommendation": "[RECOMMENDATION] Restrict network access, use certificate-based auth, and apply security updates."
    },
    "docker": {
        "description": "Docker container engine",
        "criticality": "high",
        "active_msg": "[OK] 'docker' service is active.",
        "inactive_msg": "[FAIL] 'docker' service is not active.",
        "enabled_msg": "[OK] 'docker' service is enabled at boot.",
        "disabled_msg": "[FAIL] 'docker' service is not enabled at boot.",
        "not_found_msg": "[ERROR] 'docker' service is missing.",
        "recommendation": "[RECOMMENDATION] Restrict docker group access and avoid privileged containers if possible."
    },
    "ssh": {
        "description": "Secure remote access service (SSH)",
        "criticality": "high",
        "active_msg": "[OK] 'ssh' service is active.",
        "inactive_msg": "[FAIL] 'ssh' service is not active. Enable it to allow remote access.",
        "enabled_msg": "[OK] 'ssh' service is enabled at boot.",
        "disabled_msg": "[FAIL] 'ssh' service is not enabled at boot.",
        "not_found_msg": "[ERROR] 'ssh' service is missing.",
        "recommendation": "[RECOMMENDATION] Secure SSH: disable root login, restrict users, use key authentication."
    },
    "x11": {
        "description": "X11 graphical display server",
        "criticality": "medium",
        "active_msg": "[FAIL] 'x11' service is active.",
        "inactive_msg": "[OK] 'x11' service is not active.",
        "enabled_msg": "[FAIL] 'x11' service is enabled at boot.",
        "disabled_msg": "[OK] 'x11' service is not enabled at boot.",
        "not_found_msg": "[ERROR] 'x11' service is missing.",
        "recommendation": "[RECOMMENDATION] X11 should not be active on a server. Remove it if unused."
    }
}

