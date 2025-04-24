# ==============================================================================
# FIREWALL_WHITELIST - Whitelisted firewall rules for nftables and UFW
# ------------------------------------------------------------------------------
# This module defines accepted network rules (services/ports/protocols).
#
# These rules are shared between nftables and UFW in most environments,
# but nftables might require finer control (e.g., interface, chains, hooks).
# ==============================================================================

# General whitelist used for both nftables and UFW
SHARED_WHITELIST = {
    ('22', 'tcp', 'in'),      # SSH
    ('80', 'tcp', 'in'),      # HTTP
    ('443', 'tcp', 'in'),     # HTTPS
    ('53', 'udp', 'in'),      # DNS (if DNS server)
    ('123', 'udp', 'in'),     # NTP (if NTP server)
    ('53', 'udp', 'out'),     # DNS client queries
    ('80', 'tcp', 'out'),     # HTTP outbound
    ('443', 'tcp', 'out'),    # HTTPS outbound
    ('123', 'udp', 'out'),    # NTP client
    ('icmp', None, 'in'),     # ICMP inbound (ping)
    ('icmp', None, 'out')     # ICMP outbound
}

# Specific whitelist for nftables 
NFT_WHITELIST = SHARED_WHITELIST

# Specific whitelist for UFW 
UFW_WHITELIST = SHARED_WHITELIST
