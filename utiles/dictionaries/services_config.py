# ==============================================================================
# SENSITIVE_SERVICES - Dictionary containing critical or sensitive services
# ------------------------------------------------------------------------------
# Each entry corresponds to a service to audit on the system.
# Structure of each service:
#   - 'description'      : Brief explanation of the service's purpose.
#   - 'criticality'      : Security impact level ("low", "medium", "high").
#   - 'active_msg'       : Message if the service is running.
#   - 'inactive_msg'     : Message if the service is not running.
#   - 'enabled_msg'      : Message if the service is enabled at boot.
#   - 'disabled_msg'     : Message if the service is not enabled at boot.
#   - 'not_found_msg'    : Message if the service is not found or systemctl fails.
#   - 'recommendation'   : Security advice related to this service.
# ------------------------------------------------------------------------------
# This dictionary is used by audit_sensitive_services() and check_config_service()
# to automate system service auditing in a modular and maintainable way.
# ==============================================================================

SENSITIVE_SERVICES = {
    "ufw": {
        "description": "Uncomplicated Firewall - frontend for iptables",
        "criticality": "high",
        "active_msg": "[✔] UFW is active.",
        "inactive_msg": "[✘] UFW is not active.",
        "enabled_msg": "[✔] UFW is enabled at boot.",
        "disabled_msg": "[✘] UFW is not enabled at boot.",
        "not_found_msg": "[❌] UFW is not installed or the command failed.",
        "recommendation": "🛡️ If you're using UFW, make sure it's enabled and properly configured with secure default policies and limited access rules."
    },
    "nftables": {
        "description": "Linux packet filtering framework replacing iptables",
        "criticality": "high",
        "active_msg": "[✔] nftables is active (ruleset found).",
        "inactive_msg": "[✘] nftables is not active (no ruleset found).",
        "enabled_msg": "[✔] nftables is enabled at boot.",
        "disabled_msg": "[✘] nftables is not enabled at boot.",
        "not_found_msg": "[❌] nftables is not installed or the command failed.",
        "recommendation": "🛡️ Ensure nftables is properly configured with 'inet filter' table, secure hook policies, and minimal allowed traffic."
    },
    "telnet": {
        "description": "Service d'accès distant non chiffré",
        "criticality": "high",
        "active_msg": "[✘] Le service 'telnet' est actif. Cela représente un risque de sécurité.",
        "inactive_msg": "[✔] Le service 'telnet' n'est pas actif.",
        "enabled_msg": "[✘] Le service 'telnet' est activé au démarrage.",
        "disabled_msg": "[✔] Le service 'telnet' n'est pas activé au démarrage.",
        "not_found_msg": "[❌] Le service 'telnet' est introuvable ou systemctl a échoué.",
        "recommendation": "❗ Désactivez immédiatement Telnet et utilisez SSH à la place."
    },
    "ftp": {
        "description": "Protocole de transfert de fichiers non sécurisé",
        "criticality": "high",
        "active_msg": "[✘] Le service 'ftp' est actif. FTP transmet les données en clair.",
        "inactive_msg": "[✔] Le service 'ftp' n'est pas actif.",
        "enabled_msg": "[✘] Le service 'ftp' est activé au démarrage.",
        "disabled_msg": "[✔] Le service 'ftp' n'est pas activé au démarrage.",
        "not_found_msg": "[❌] Le service 'ftp' est introuvable ou systemctl a échoué.",
        "recommendation": "❗ Utilisez SFTP ou SCP à la place de FTP."
    },
    "rsh": {
        "description": "Remote Shell, accès distant sans chiffrement",
        "criticality": "high",
        "active_msg": "[✘] Le service 'rsh' est actif.",
        "inactive_msg": "[✔] Le service 'rsh' n'est pas actif.",
        "enabled_msg": "[✘] Le service 'rsh' est activé au démarrage.",
        "disabled_msg": "[✔] Le service 'rsh' n'est pas activé au démarrage.",
        "not_found_msg": "[❌] Le service 'rsh' est introuvable.",
        "recommendation": "❗ Supprimez RSH et utilisez SSH à la place."
    },
    "rlogin": {
        "description": "Connexion distante non sécurisée via rlogin",
        "criticality": "high",
        "active_msg": "[✘] Le service 'rlogin' est actif.",
        "inactive_msg": "[✔] Le service 'rlogin' n'est pas actif.",
        "enabled_msg": "[✘] Le service 'rlogin' est activé au démarrage.",
        "disabled_msg": "[✔] Le service 'rlogin' n'est pas activé au démarrage.",
        "not_found_msg": "[❌] Le service 'rlogin' est introuvable.",
        "recommendation": "❗ Désactivez rlogin et utilisez SSH avec clés d'authentification."
    },
    "apache2": {
        "description": "Serveur web Apache",
        "criticality": "medium",
        "active_msg": "[✔] Le service 'apache2' est actif.",
        "inactive_msg": "[✘] Le service 'apache2' n'est pas actif.",
        "enabled_msg": "[✔] Le service 'apache2' est activé au démarrage.",
        "disabled_msg": "[✘] Le service 'apache2' n'est pas activé au démarrage.",
        "not_found_msg": "[❌] Le service 'apache2' est introuvable.",
        "recommendation": "🔍 Vérifiez que HTTPS est activé, que les headers de sécurité sont bien configurés, et que le service est à jour."
    },
    "nginx": {
        "description": "Serveur web Nginx",
        "criticality": "medium",
        "active_msg": "[✔] Le service 'nginx' est actif.",
        "inactive_msg": "[✘] Le service 'nginx' n'est pas actif.",
        "enabled_msg": "[✔] Le service 'nginx' est activé au démarrage.",
        "disabled_msg": "[✘] Le service 'nginx' n'est pas activé au démarrage.",
        "not_found_msg": "[❌] Le service 'nginx' est introuvable.",
        "recommendation": "🔍 Activez le HTTPS, configurez les headers de sécurité, et appliquez les dernières mises à jour."
    },
    "vsftpd": {
        "description": "Serveur FTP sécurisé (vsftpd)",
        "criticality": "high",
        "active_msg": "[✘] Le service 'vsftpd' est actif.",
        "inactive_msg": "[✔] Le service 'vsftpd' n'est pas actif.",
        "enabled_msg": "[✘] Le service 'vsftpd' est activé au démarrage.",
        "disabled_msg": "[✔] Le service 'vsftpd' n'est pas activé au démarrage.",
        "not_found_msg": "[❌] Le service 'vsftpd' est introuvable.",
        "recommendation": "⚠️ Activez TLS si vous utilisez vsftpd et restreignez les utilisateurs. Préférez SFTP si possible."
    },
    "smb": {
        "description": "Partages de fichiers Windows (Samba/SMB)",
        "criticality": "medium",
        "active_msg": "[✔] Le service 'smb' est actif.",
        "inactive_msg": "[✘] Le service 'smb' n'est pas actif.",
        "enabled_msg": "[✔] Le service 'smb' est activé au démarrage.",
        "disabled_msg": "[✘] Le service 'smb' n'est pas activé au démarrage.",
        "not_found_msg": "[❌] Le service 'smb' est introuvable.",
        "recommendation": "🔒 Limitez les partages publics, utilisez SMBv3 avec chiffrement, et filtrez par adresse IP ou utilisateur."
    },
    "cups": {
        "description": "Service d'impression réseau (CUPS)",
        "criticality": "low",
        "active_msg": "[✔] Le service 'cups' est actif.",
        "inactive_msg": "[✘] Le service 'cups' n'est pas actif.",
        "enabled_msg": "[✔] Le service 'cups' est activé au démarrage.",
        "disabled_msg": "[✘] Le service 'cups' n'est pas activé au démarrage.",
        "not_found_msg": "[❌] Le service 'cups' est introuvable.",
        "recommendation": "📄 Désactivez CUPS si l'impression réseau n'est pas nécessaire, surtout sur un serveur."
    },
    "mysql": {
        "description": "Serveur de base de données MySQL ou MariaDB",
        "criticality": "medium",
        "active_msg": "[✔] Le service 'mysql' est actif.",
        "inactive_msg": "[✘] Le service 'mysql' n'est pas actif.",
        "enabled_msg": "[✔] Le service 'mysql' est activé au démarrage.",
        "disabled_msg": "[✘] Le service 'mysql' n'est pas activé au démarrage.",
        "not_found_msg": "[❌] Le service 'mysql' est introuvable.",
        "recommendation": "🔐 Limitez l'écoute à localhost et changez tous les mots de passe par défaut."
    },
    "postgresql": {
        "description": "Serveur de base de données PostgreSQL",
        "criticality": "medium",
        "active_msg": "[✔] Le service 'postgresql' est actif.",
        "inactive_msg": "[✘] Le service 'postgresql' n'est pas actif.",
        "enabled_msg": "[✔] Le service 'postgresql' est activé au démarrage.",
        "disabled_msg": "[✘] Le service 'postgresql' n'est pas activé au démarrage.",
        "not_found_msg": "[❌] Le service 'postgresql' est introuvable.",
        "recommendation": "🔐 Limitez l'accès réseau, utilisez l'authentification par certificat, et tenez le système à jour."
    },
    "docker": {
        "description": "Moteur de conteneurisation Docker",
        "criticality": "high",
        "active_msg": "[✔] Le service 'docker' est actif.",
        "inactive_msg": "[✘] Le service 'docker' n'est pas actif.",
        "enabled_msg": "[✔] Le service 'docker' est activé au démarrage.",
        "disabled_msg": "[✘] Le service 'docker' n'est pas activé au démarrage.",
        "not_found_msg": "[❌] Le service 'docker' est introuvable.",
        "recommendation": "⚠️ Restreignez les utilisateurs du groupe docker et désactivez les conteneurs avec privilèges si possible."
    },
    "ssh": {
        "description": "Service d'accès distant sécurisé (SSH)",
        "criticality": "high",
        "active_msg": "[✔] Le service 'ssh' est actif.",
        "inactive_msg": "[✘] Le service 'ssh' n'est pas actif. Activez-le pour permettre les connexions distantes.",
        "enabled_msg": "[✔] Le service 'ssh' est activé au démarrage.",
        "disabled_msg": "[✘] Le service 'ssh' n'est pas activé au démarrage.",
        "not_found_msg": "[❌] Le service 'ssh' est introuvable.",
        "recommendation": "🛡️ Sécurisez SSH : désactivez root login, limitez les utilisateurs, utilisez des clés d'authentification."
    },
    "x11": {
        "description": "Serveur d'affichage graphique X11",
        "criticality": "medium",
        "active_msg": "[✘] Le service 'x11' est actif.",
        "inactive_msg": "[✔] Le service 'x11' n'est pas actif.",
        "enabled_msg": "[✘] Le service 'x11' est activé au démarrage.",
        "disabled_msg": "[✔] Le service 'x11' n'est pas activé au démarrage.",
        "not_found_msg": "[❌] Le service 'x11' est introuvable.",
        "recommendation": "📉 X11 ne devrait pas être activé sur un serveur. Supprimez-le si non utilisé."
    }
}

