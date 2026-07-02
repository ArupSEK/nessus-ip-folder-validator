from __future__ import annotations

import ipaddress
import re
from typing import Iterable, Optional, Set

IPV4_CANDIDATE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")


def normalize_ip(value: object) -> Optional[str]:
    """Return a canonical IP string or None."""
    if value is None:
        return None
    text = str(value).strip().strip('"').strip("'")
    if not text or text.lower() in {"nan", "none", "null"}:
        return None

    # Direct parse first.
    try:
        return str(ipaddress.ip_address(text))
    except Exception:
        pass

    # Extract first valid IPv4 from mixed host text such as "host / 10.0.0.1".
    for match in IPV4_CANDIDATE.findall(text):
        try:
            return str(ipaddress.ip_address(match))
        except Exception:
            continue
    return None


def extract_ips_from_text(value: object) -> Set[str]:
    """Extract all valid IPs from a free text field."""
    out: Set[str] = set()
    if value is None:
        return out
    text = str(value)
    direct = normalize_ip(text)
    if direct:
        out.add(direct)
    for match in IPV4_CANDIDATE.findall(text):
        try:
            out.add(str(ipaddress.ip_address(match)))
        except Exception:
            pass
    return out


def normalize_ip_list(values: Iterable[object]) -> list[str]:
    ips: list[str] = []
    seen: set[str] = set()
    for value in values:
        ip = normalize_ip(value)
        if ip and ip not in seen:
            ips.append(ip)
            seen.add(ip)
    return ips
