import subprocess
import logging
from utils.dictionaries.banned_packages import BANNED_PACKAGES

# ----- Setup logging -----
logging.basicConfig(
    filename='pingux.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)

logger = logging.getLogger(__name__)

def scan_packages():
    report = []

    logger.info("=== Starting Package Scan ===")

    # Get list of installed packages
    try:
        dpkg_com = subprocess.run(['dpkg-query', '-W', '-f=${binary:Package}\n'], capture_output=True, text=True, check=True)
        packages = dpkg_com.stdout.strip().splitlines()
        logger.info(f"Found {len(packages)} installed packages.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to list installed packages: {e}")
        report.append(f"[❌] Failed to list installed packages: {e}")
        return report

    # Check for banned packages
    banned_found = False
    for pkg in packages:
        if pkg in BANNED_PACKAGES:
            report.append(f"❌ {pkg} is installed — {BANNED_PACKAGES[pkg]}")
            logger.warning(f"❌ {pkg} is installed — {BANNED_PACKAGES[pkg]}")
            banned_found = True

    # Summary
    if not banned_found:
        report.append("✅ No dangerous packages detected")
        logger.info("✅ No dangerous packages detected")
    else:
        report.append("🔍 Scan completed — dangerous packages listed above")
        logger.info("🔍 Scan completed — dangerous packages listed above")

    report.append("📄 Detailed logs saved to pingux.log")
    logger.info("=== Package Scan Completed ===")
    return report
