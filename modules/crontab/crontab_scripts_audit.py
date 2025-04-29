import os

def audit_script(path):
    report = []

    # 1. Check if the file exists
    if not os.path.exists(path):
        report.append(f"[FAIL] Script not found: {path}")
        return report

    # 2. Check if the file is executable
    if not os.access(path, os.X_OK):
        report.append(f"[WARNING] Script exists but is not executable: {path}")

    # 3. Check for shebang (#!)
    try:
        with open(path, "r") as f:
            first_line = f.readline().strip()
            if not first_line.startswith("#!"):
                report.append(f"[WARNING] No shebang found in script: {path}")
    except Exception as e:
        report.append(f"[WARNING] Unable to read script: {path} ({e})")

    # 4. Check file permissions (world-writable or group-writable)
    file_stat = os.stat(path)
    file_mode = oct(file_stat.st_mode)[-3:]

    if file_mode[-1] in ['6', '7']:  # World-writable
        report.append(f"[WARNING] Script is world-writable: {path}")
    elif file_mode[-2] in ['6', '7']:  # Group-writable
        report.append(f"[WARNING] Script is group-writable: {path}")

    # 5. All good
    if not report:
        report.append(f"[OK] Script is secure and properly configured: {path}")

    return report