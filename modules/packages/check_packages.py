import subprocess
from utils.dictionaries.banned_packages import BANNED_PACKAGES

def check_packages():
    report = []

    # Get list of installed packages
    dpkg_com = subprocess.run(['dpkg-query', '-W', '-f=${binary:Package}\n'], capture_output=True, text=True)
    packages = dpkg_com.stdout.strip().splitlines()

    # Check for banned packages
    for pkg in packages:
        if pkg in BANNED_PACKAGES:
            report.append(f"❌ {pkg} is installed — {BANNED_PACKAGES[pkg]}")

    # Summary
    if not any(pkg in BANNED_PACKAGES for pkg in packages):
        report.append("✅ No dangerous packages detected")
    else:
        report.append("🔍 Scan completed — dangerous packages listed above")

    return report
