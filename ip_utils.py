from __future__ import annotations

import ipaddress
import re
from typing import Optional

IPV4_CANDIDATE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")


def normalize_ip(value: object) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip().strip('"').strip("'")
    if not text or text.lower() in {"nan", "none", "null"}:
        return None
    try:
        return str(ipaddress.ip_address(text.split("/")[0].strip()))
    except Exception:
        pass
    for match in IPV4_CANDIDATE.findall(text):
        try:
            return str(ipaddress.ip_address(match))
        except Exception:
            continue
    return None
