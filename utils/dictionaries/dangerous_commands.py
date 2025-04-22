# ==============================================================================
# DANGEROUS_COMMAND_PATTERNS - Extensive blacklist of dangerous command patterns
# ------------------------------------------------------------------------------
# This expanded list includes patterns used in reverse shells, obfuscated code,
# data exfiltration, privilege escalation, and harmful system manipulation.
# ==============================================================================

DANGEROUS_COMMAND_PATTERNS = [
    # Reverse shells (bash, netcat, socat, etc.)
    "bash -i >& /dev/tcp/",
    "bash -c",
    "/dev/tcp/",
    "/dev/udp/",
    "nc ",
    "ncat ",
    "socat ",
    "telnet ",
    
    # Download & Execute (via HTTP, FTP)
    "curl ",
    "wget ",
    "| bash",
    "| sh",
    "| python",
    "| perl",
    "ftp ",
    "tftp ",
    "scp ",
    "rsync ",
    
    # Scripting languages (execution of code)
    "python -c",
    "python3 -c",
    "perl -e",
    "php -r",
    "ruby -e",
    "node -e",
    
    # Obfuscation / Encoding
    "eval ",
    "base64 -d",
    "xxd ",
    "hexdump ",
    "od ",
    
    # System manipulation / Destruction
    "rm -rf /",
    "dd if=",
    "mkfs.ext",
    "chmod 777 ",
    "chown ",
    "nohup ",
    "killall ",
    "pkill ",
    
    # Privilege escalation / Persistence
    "sudo ",
    "su ",
    "chattr ",
    "setenforce 0",
    "passwd ",
    
    # Network scanning / Enumeration
    "nmap ",
    "whois ",
    "dig ",
    "host ",
    "netstat ",
    "ss ",
    "tcpdump ",
    "strace ",
    
    # Logs clearing
    ">/dev/null",
    "> /dev/null",
    "2>&1",
    "history -c",
    "unset HISTFILE",
    
    # Miscellaneous
    "sleep ",
    "watch ",
    "while true",
    "nohup ",
    "screen ",
    "tmux "
]
