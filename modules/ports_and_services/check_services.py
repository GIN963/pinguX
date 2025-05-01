import os
import subprocess
import re
import logging
from utils.dictionaries.services_config import SENSITIVE_SERVICES
from utils.config_checker import check_config_service

logger = logging.getLogger(__name__)

def scan_services():
    report = []
    service_status = {}

    logger.info("=== Starting Services Scan ===")

    for service, service_data in SENSITIVE_SERVICES.items():
        description = service_data["description"]
        recommendation = service_data["recommendation"]

        report.append(f"\n[INFO] Checking service '{service}': {description}")

        try:
            is_active = check_config_service(
                service_name=service,
                report=report,
                success_active_msg=service_data["active_msg"],
                fail_active_msg=service_data["inactive_msg"],
                success_enabled_msg=service_data["enabled_msg"],
                fail_enabled_msg=service_data["disabled_msg"],
                error_msg=service_data["not_found_msg"]
            )
            service_status[service] = is_active
        except Exception as e:
            logger.error(f"[ERROR] Failed to check service '{service}': {e}")
            report.append(f"[FAIL] Unexpected error while checking service '{service}' — see pingux.log for details")
            service_status[service] = False

        report.append(f"[RECOMMENDATION] {recommendation}")

    report.append("[INFO] Detailed logs are available in pingux.log")
    logger.info("=== Services Audit Completed ===")
    return report, service_status

