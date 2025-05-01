# ==============================================================================
# ROLES_CONFIG - Mapping of process names to functional server roles
# ------------------------------------------------------------------------------
# ROLE_PROCESS_MAP is used to guess the server's role based on running processes.
# DEFAULT_ACCEPTED_SERVICES is a global whitelist of services we consider safe.
# ==============================================================================

ROLE_PROCESS_MAP = {
    "web": {"nginx", "apache2", "httpd", "php-fpm", "gunicorn", "lighttpd", "caddy"},
    "db": {"mysqld", "postgres", "mariadbd", "mongod", "redis-server", "couchdb", "influxd"},
    "mail": {"postfix", "dovecot", "exim", "sendmail", "mail", "fetchmail", "procmail"},
    "bastion": {"sshd"}  # only if it's the only one
}

DEFAULT_ACCEPTED_SERVICES = {
    "sshd", "nginx", "apache2", "php-fpm", "gunicorn", "lighttpd", "caddy",
    "mysqld", "postgres", "mariadbd", "mongod", "redis-server", "couchdb", "influxd",
    "postfix", "dovecot", "exim", "sendmail", "mail", "fetchmail", "procmail",
    "systemd", "cron", "rsyslogd", "dbus-daemon", "NetworkManager", "polkitd"
}
