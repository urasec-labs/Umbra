"""Networking helpers: DNS, CIDR checks, tool detection."""
from __future__ import annotations

import ipaddress
import shutil
import socket
import subprocess

import dns.exception
import dns.resolver

TOOLS = ["nmap", "subfinder", "gitleaks", "trivy", "pip-audit", "lynis", "git"]


def tool_status() -> dict[str, bool]:
    return {t: shutil.which(t) is not None for t in TOOLS}


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def run_cmd(cmd: list[str], timeout: int = 300) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except OSError as e:
        return 127, "", str(e)


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def in_cidrs(ip: str, cidrs: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in cidrs:
        try:
            if addr in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


def _resolver(timeout: float) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout = timeout
    r.lifetime = timeout
    return r


def resolve(host: str, rtype: str = "A", timeout: float = 4.0) -> list[str]:
    """Return record strings; [] on NXDOMAIN/no answer/error."""
    if rtype in ("A", "AAAA") and is_ip(host):
        return [host]
    try:
        ans = _resolver(timeout).resolve(host, rtype)
        return [r.to_text().strip('"') for r in ans]
    except (dns.exception.DNSException, OSError):
        pass
    if rtype == "A":  # fall back to the system resolver (hosts file, split DNS)
        try:
            return sorted({i[4][0] for i in socket.getaddrinfo(host, None, socket.AF_INET)})
        except OSError:
            return []
    return []


def is_nxdomain(host: str, timeout: float = 4.0) -> bool:
    try:
        _resolver(timeout).resolve(host, "A")
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except dns.exception.DNSException:
        return False
