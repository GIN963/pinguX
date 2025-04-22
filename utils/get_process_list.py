import subprocess

def get_process_list():
    """
    Returns a list of unique process names currently running on the system.
    Useful for global role detection even outside of ss output.
    """
    result = subprocess.run(["ps", "-eo", "comm"], capture_output=True, text=True)
    lines = result.stdout.strip().split("\n")[1:]
    return list(set(line.strip() for line in lines if line.strip()))
