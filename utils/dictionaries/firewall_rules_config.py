# ==============================================================================
# FIREWALL_RULES_CONFIG - Rules to classify listening ports and services
# ------------------------------------------------------------------------------
# WHITELIST contains exact triplets (port, protocol, process) considered safe.
# GREYLIST contains known non-critical but acceptable services.
# BLACKLIST includes known suspicious tools or reverse shells.
# ==============================================================================

WHITELIST = {
    ('22', 'tcp', 'sshd'),
    ('80', 'tcp', 'nginx'),
    ('443', 'tcp', 'nginx'),
    ('5432', 'tcp', 'postgres'),
    ('3306', 'tcp', 'mysqld')
}

GREYLIST = {
    'gunicorn', 'node', 'vault', 'grafana', 'prometheus', 'python3', 'php-fpm'
}

BLACKLIST = {
    'nc', 'ncat', 'bash', 'python', 'perl', 'java', 'socat', 'netcat', 'php'
}
