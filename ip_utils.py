from __future__ import annotations

import ipaddress
import re
from typing import Iterable, Optional, Set

IPV4_CANDIDATE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")


def _parse_direct(text: str) -> Optional[str]:
    candidates = [text]
    if text.startswith("[") and "]" in text:
        candidates.append(text[1 : text.index("]")])
    if text.count(":") == 1 and "." in text:
        host, port = text.rsplit(":", 1)
        if port.isdigit():
            candidates.append(host)

    for candidate in candidates:
        try:
            return str(ipaddress.ip_address(candidate))
        except Exception:
            pass
        try:
            return str(ipaddress.ip_interface(candidate).ip)
        except Exception:
            pass
    return None


def normalize_ip(value: object) -> Optional[str]:
    """Return a canonical IP string or None.

    Supports plain IPs, /32 or /128 notation, bracketed IPv6, IPv4:port, and
    mixed text containing an IPv4 address.
    """
    if value is None:
        return None
    text = str(value).strip().strip('"').strip("'")
    if not text or text.lower() in {"nan", "none", "null"}:
        return None

    direct = _parse_direct(text)
    if direct:
        return direct

    for match in IPV4_CANDIDATE.findall(text):
        try:
            return str(ipaddress.ip_address(match))
        except Exception:
            continue

    # Best-effort mixed-text IPv6 parsing without accepting arbitrary words.
    for token in re.split(r"[\s,;|(){}<>]+", text):
        token = token.strip().strip('"\'').strip("[]")
        if ":" not in token:
            continue
        direct = _parse_direct(token)
        if direct:
            return direct
    return None


def extract_ips_from_text(value: object) -> Set[str]:
    """Extract all valid IPs from a free-text field."""
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

    for token in re.split(r"[\s,;|(){}<>]+", text):
        token = token.strip().strip('"\'').strip("[]")
        if ":" not in token:
            continue
        parsed = _parse_direct(token)
        if parsed:
            out.add(parsed)
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
