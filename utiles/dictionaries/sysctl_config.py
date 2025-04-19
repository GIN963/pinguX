# ==============================================================================
# SYSCTL_HARDENING_RULES - Security-related sysctl directives and their expected values
# ------------------------------------------------------------------------------
# Each key is a sysctl directive to audit, and the value is the expected secure setting.
# ==============================================================================

SYSCTL_HARDENING_RULES = {
    "net.ipv4.ip_forward": "0",
    "net.ipv4.conf.all.send_redirects": "0",
    "net.ipv4.conf.default.send_redirects": "0",
    "net.ipv4.conf.all.accept_redirects": "0",
    "net.ipv4.conf.default.accept_redirects": "0",
    "net.ipv4.icmp_ignore_bogus_error_responses": "1",
    "net.ipv4.tcp_syncookies": "1",
    "net.ipv4.tcp_max_syn_backlog": "2048",
    "net.ipv4.tcp_synack_retries": "3",
    "net.ipv4.netfilter.ip_conntrack_tcp_timeout_syn_recv": "45",
    "net.ipv4.conf.all.rp_filter": "1",                # Anti-spoofing
    "net.ipv4.conf.default.rp_filter": "1",
    "net.ipv4.conf.all.log_martians": "1",             # Log abnormal packets
}
