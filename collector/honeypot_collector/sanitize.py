"""Make attacker-controlled strings safe to publish.

Everything that reaches stats.json from Cowrie (usernames, passwords, commands,
client banners) was typed by an attacker. These helpers strip what a public page
should never carry: full IP addresses, clickable URLs, control characters and
unbounded length. Rendering safety (HTML escaping) is the dashboard's job; this
module is about what gets published at all.
"""

from __future__ import annotations

import ipaddress
import re

# Dotted quads, with a lookaround so we do not chew version strings like 1.2.3.4.5.
_IPV4 = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])")
# Loose IPv6 match: at least three hextet groups with colons. Validated before redacting.
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
_URL_SCHEME = re.compile(r"\b(https?|ftp|tftp)://", re.IGNORECASE)
_URL_HOST = re.compile(r"(hxxps?|fxp|tfxp)://([^/\s'\"`;|&)]+)", re.IGNORECASE)
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏ -‮⁦-⁩]")
_WS = re.compile(r"\s+")

_DEFANG = {"http": "hxxp", "https": "hxxps", "ftp": "fxp", "tftp": "tfxp"}


def truncate_ip(ip: str) -> str | None:
    """Return the /24 (IPv4) or /48 (IPv6) network for an address, or None if invalid."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    prefix = 24 if addr.version == 4 else 48
    return str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False))


def _redact_v4(match: re.Match[str]) -> str:
    octets = match.groups()
    if any(int(o) > 255 for o in octets):
        return match.group(0)
    return f"{octets[0]}.{octets[1]}.{octets[2]}.x"


def _redact_v6(match: re.Match[str]) -> str:
    text = match.group(0)
    try:
        ipaddress.IPv6Address(text)
    except ValueError:
        return text
    return "[ipv6]"


def _defang_host(match: re.Match[str]) -> str:
    return f"{match.group(1)}://{match.group(2).replace('.', '[.]')}"


def clean_text(value: object, max_len: int) -> str:
    """Strip control characters, collapse whitespace and cap length."""
    text = value if isinstance(value, str) else str(value)
    text = _CONTROL.sub("", text)
    text = _WS.sub(" ", text).strip()
    if len(text) > max_len:
        text = text[: max_len - 1].rstrip() + "…"
    return text


def sanitize_command(value: object, max_len: int = 160) -> str:
    """Clean a shell command for publication.

    IPv4 addresses keep their /24 (last octet becomes x), IPv6 addresses are
    removed, URLs are defanged (hxxp://host[.]tld) so nothing on the page is a
    live link to attacker infrastructure.
    """
    text = clean_text(value, max_len=4096)
    # Redact addresses before defanging: once dots become [.] the IP regex no longer matches.
    text = _IPV4.sub(_redact_v4, text)
    text = _IPV6.sub(_redact_v6, text)
    text = _URL_SCHEME.sub(lambda m: _DEFANG[m.group(1).lower()] + "://", text)
    text = _URL_HOST.sub(_defang_host, text)
    return clean_text(text, max_len=max_len)


def sanitize_credential(value: object, max_len: int = 48) -> str:
    """Clean a username or password. Empty strings are shown as (empty)."""
    text = clean_text(value, max_len=max_len)
    text = _IPV4.sub(_redact_v4, text)
    return text if text else "(empty)"
