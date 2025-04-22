# ==============================================================================
# BANNED_PACKAGES - Known insecure, obsolete or dangerous packages
# ------------------------------------------------------------------------------
# This list is used to detect potentially risky software installed on the system.
# Each entry maps the package name to a short description of the associated risk.
# ==============================================================================

BANNED_PACKAGES = {
    "telnet": "insecure protocol — transmits credentials in clear text",
    "ftp": "insecure file transfer protocol",
    "rsh": "remote shell without authentication",
    "rlogin": "unsecure remote login",
    "rcp": "unsecure remote copy protocol",

    "talk": "obsolete user communication service",
    "ntalk": "obsolete and insecure network chat",
    "finger": "can expose user account info",
    "rwho": "discloses logged-in users over the network",
    "xinetd": "legacy super-server — often unused & vulnerable",

    "hydra": "password brute-force tool",
    "nmap": "network scanner and host discovery",
    "netcat": "can be used to open reverse shells",
    "socat": "flexible port forwarder — powerful but dangerous",
    "john": "password cracker",
    "nikto": "web server scanner",
    "metasploit-framework": "exploitation framework",
    "aircrack-ng": "Wi-Fi cracking toolset",

    "gcc": "compiler — not needed in production",
    "make": "build utility — shouldn't be installed on production servers",
    "build-essential": "developer toolkit — increases attack surface",
    "python-dev": "development headers — often unnecessary",

    "tcpdump": "packet sniffer — powerful but must be justified",
    "wireshark": "GUI network sniffer — shouldn't be on a server",
    "ettercap": "MITM attack tool",

    "tftp": "trivial file transfer protocol — unencrypted",
    "snmpd": "SNMP daemon — often misconfigured and noisy",
    "apache2-utils": "contains brute-force tools like `ab` and `htpasswd`"
}
