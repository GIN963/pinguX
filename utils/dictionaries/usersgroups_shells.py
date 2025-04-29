valid_shells = [
        '/bin/bash', '/bin/sh', '/bin/zsh', '/usr/bin/bash', '/usr/bin/sh',
        '/usr/bin/zsh', '/bin/ksh', '/usr/bin/ksh', '/bin/dash',
        '/usr/bin/dash', '/bin/fish', '/usr/bin/fish',
]

non_interactive_shells = [
        '/usr/sbin/nologin', '/bin/false', '/sbin/nologin', '/bin/nologin',
        '/usr/bin/nologin', '/usr/bin/false', '/dev/null', ''
]