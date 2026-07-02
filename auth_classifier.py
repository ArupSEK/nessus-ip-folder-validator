from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional


@dataclass(frozen=True)
class AuthFinding:
    plugin_id: str
    plugin_name: str
    plugin_output: str = ""
    risk: str = ""
    scan_protocol: str = ""


# Tenable troubleshooting / auth summary plugins commonly used for credential status.
# The classifier is intentionally evidence based. It preserves raw plugin output in the report.
SUCCESS_PLUGIN_IDS = {
    "141118",  # Integration Credential Status by Authentication Protocol - Valid Credentials Provided
    "110095",  # Integration Credential Status by Authentication Protocol - No Issues Found
}
LIMITED_PLUGIN_IDS = {
    "110385",  # Insufficient privilege
    "117885",  # Intermittent authentication failure
}
FAILURE_PLUGIN_IDS = {
    "104410",  # Failure for provided credentials
    "122503",  # Common auth failure in some integrations
    "21745",   # Authentication Failure - Local Checks Not Run
    "24786",   # Windows scan not performed with admin privileges
    "10428",   # SMB registry not fully accessible
    "26917",   # Cannot access Windows registry
    "91822",   # Database authentication failure
    "11149",   # HTTP login failure
}
NO_CREDS_PLUGIN_IDS = {
    "110723",  # No credentials provided
}
INFO_PLUGIN_IDS = {
    "19506",   # Nessus Scan Information; look for Credentialed Checks: yes/no in output
}

AUTH_RELATED_IDS = SUCCESS_PLUGIN_IDS | LIMITED_PLUGIN_IDS | FAILURE_PLUGIN_IDS | NO_CREDS_PLUGIN_IDS | INFO_PLUGIN_IDS


def _clean(text: object, max_len: int = 300) -> str:
    if text is None:
        return ""
    value = str(text).replace("\r", " ").replace("\n", " ").strip()
    while "  " in value:
        value = value.replace("  ", " ")
    return value[:max_len]


def is_auth_related(plugin_id: object, plugin_name: object = "") -> bool:
    pid = str(plugin_id or "").strip()
    name = str(plugin_name or "").lower()
    if pid in AUTH_RELATED_IDS:
        return True
    keywords = [
        "credential", "authenticated", "authentication failure", "local checks", "not run",
        "insufficient privilege", "login failure", "smb registry", "registry access",
    ]
    return any(k in name for k in keywords)


def classify_auth(findings: Iterable[AuthFinding]) -> dict[str, str]:
    """Classify a host's authentication state from evidence plugin rows."""
    findings = list(findings)
    if not findings:
        return {
            "auth_status": "Unknown",
            "auth_reason": "No authentication evidence found in API/export data",
            "auth_plugin": "",
            "auth_plugin_output": "",
            "protocol_summary": "",
            "confidence": "Low",
        }

    def first(ids: set[str]) -> Optional[AuthFinding]:
        for f in findings:
            if str(f.plugin_id).strip() in ids:
                return f
        return None

    # Plugin 19506 fallback: parse the common Credentialed Checks line if output is available.
    scan_info = first(INFO_PLUGIN_IDS)
    scan_info_yes = False
    scan_info_no = False
    if scan_info:
        blob = f"{scan_info.plugin_name}\n{scan_info.plugin_output}".lower()
        if "credentialed checks" in blob and "yes" in blob:
            scan_info_yes = True
        if "credentialed checks" in blob and "no" in blob:
            scan_info_no = True

    failure = first(FAILURE_PLUGIN_IDS)
    limited = first(LIMITED_PLUGIN_IDS)
    no_creds = first(NO_CREDS_PLUGIN_IDS)
    success = first(SUCCESS_PLUGIN_IDS)

    if failure:
        status = "Failed"
        confidence = "High"
        chosen = failure
    elif limited:
        status = "Valid with limitations"
        confidence = "High"
        chosen = limited
    elif success:
        status = "Authenticated"
        confidence = "High"
        chosen = success
    elif scan_info_yes:
        status = "Authenticated"
        confidence = "Medium"
        chosen = scan_info
    elif no_creds:
        status = "No credentials"
        confidence = "High"
        chosen = no_creds
    elif scan_info_no:
        status = "No credentials / Not credentialed"
        confidence = "Medium"
        chosen = scan_info
    else:
        status = "Unknown"
        confidence = "Low"
        chosen = findings[0]

    protocol_bits = []
    for f in findings:
        name_out = f"{f.plugin_name} {f.plugin_output}".lower()
        if "ssh" in name_out:
            proto = "SSH"
        elif "smb" in name_out or "windows" in name_out:
            proto = "SMB/Windows"
        elif "http" in name_out:
            proto = "HTTP"
        elif "database" in name_out or "oracle" in name_out or "sql" in name_out:
            proto = "DB"
        else:
            proto = "General"
        part = f"{proto}: {f.plugin_id}"
        if part not in protocol_bits:
            protocol_bits.append(part)

    reason = _clean(chosen.plugin_output) or _clean(chosen.plugin_name) or "Authentication evidence plugin found"
    return {
        "auth_status": status,
        "auth_reason": reason,
        "auth_plugin": f"{chosen.plugin_id} - {_clean(chosen.plugin_name, 120)}".strip(" -"),
        "auth_plugin_output": _clean(chosen.plugin_output, 1000),
        "protocol_summary": "; ".join(protocol_bits[:6]),
        "confidence": confidence,
    }
