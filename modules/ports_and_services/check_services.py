import os
import subprocess
import re
from utils.dictionaries.services_config import SENSITIVE_SERVICES
from utils.config_checker import *

def check_services():
    report = []
    service_status = {}

    for service, service_data in SENSITIVE_SERVICES.items():
        description = service_data["description"]
        recommendation = service_data["recommendation"]

        report.append(f"\n[🔍] Vérification du service '{service}' : {description}")

        is_active = check_config_service(
            service_name=service,
            report=report,
            success_active_msg=service_data["active_msg"],
            fail_active_msg=service_data["inactive_msg"],
            success_enabled_msg=service_data["enabled_msg"],
            fail_enabled_msg=service_data["disabled_msg"],
            error_msg=service_data["not_found_msg"]
        )

        report.append(f"[💡 Recommandation] {recommendation}")
        service_status[service] = is_active

    return report, service_status 
