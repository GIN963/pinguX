from utiles.dictionaries.roles_config import ROLE_PROCESS_MAP

def detect_server_roles(processes):
    """
    Detect the roles of a server based on the active processes.

    Parameters:
        processes (list or set): A list or set of running process names.

    Returns:
        roles (list): Detected roles such as 'web', 'db', 'mail', etc.
        unknown_procs (list): Processes not associated with any known role.
    """
    roles = []
    process_set = set(processes)

    for role, known_procs in ROLE_PROCESS_MAP.items():
        # Special case: if only sshd is running, the server is considered a 'bastion'
        if role == "bastion":
            if process_set == {"sshd"}:
                roles.append("bastion")
        # Otherwise, if any known process matches this role, we add it
        elif process_set & known_procs:
            roles.append(role)

    # Flatten all known process names into one set
    known_all = set().union(*ROLE_PROCESS_MAP.values())

    # Detect any unknown processes (not listed in ROLE_PROCESS_MAP)
    unknown_procs = sorted(process_set - known_all)

    if unknown_procs:
        roles.append("other")

    return roles, unknown_procs
