"""Exposed-service detection on your own IPs, compared against policy.allowed_ports."""
from __future__ import annotations

import socket
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

from core.plugin_base import Module
from utils import net

RISKY = {  # port: (label, severity)
    21: ("FTP", "high"), 23: ("Telnet", "critical"), 25: ("SMTP", "low"), 110: ("POP3", "medium"),
    111: ("rpcbind", "high"), 135: ("MS-RPC", "high"), 139: ("NetBIOS", "high"), 143: ("IMAP", "medium"),
    445: ("SMB", "critical"), 1433: ("MSSQL", "critical"), 1521: ("Oracle DB", "critical"),
    2049: ("NFS", "high"), 2375: ("Docker API (unauthenticated)", "critical"), 3306: ("MySQL", "critical"),
    3389: ("RDP", "critical"), 5432: ("PostgreSQL", "critical"), 5601: ("Kibana", "high"),
    5672: ("AMQP", "high"), 5900: ("VNC", "critical"), 6379: ("Redis", "critical"),
    9200: ("Elasticsearch", "critical"), 9300: ("Elasticsearch transport", "high"),
    11211: ("Memcached", "critical"), 15672: ("RabbitMQ management", "high"), 27017: ("MongoDB", "critical"),
    22: ("SSH", "medium"),
}


def _service(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


class Ports(Module):
    name = "ports"
    description = "Find open TCP ports on your own IPs and flag those outside policy"
    category = "network"
    produces = ("port",)
    requires_tools = ("nmap",)

    def run(self, ctx):
        cfg = ctx.cfg
        skip = cfg.get("scan.skip_cidrs", [])
        targets: dict[str, list[str]] = {}
        for ip, hosts in ctx.ip_hosts().items():
            if ip in ctx.excluded or net.in_cidrs(ip, skip):
                ctx.log.info("ports: skipping %s (excluded or shared CDN range)", ip)
                continue
            targets[ip] = hosts
        for h in ctx.hosts:
            if net.is_ip(h) and h not in targets and h not in ctx.excluded and not net.in_cidrs(h, skip):
                targets[h] = [h]
        ports = sorted(set(cfg.get("scan.ports", [])))
        timeout = min(cfg.get("scan.timeout", 6), 3)
        open_map = self._nmap(targets, ports, ctx) if (cfg.get("scan.port_mode") == "nmap" and net.have("nmap")) \
            else self._connect(targets, ports, timeout, cfg.get("scan.threads", 32))
        ctx.ports_scanned = True

        allowed_global = set(cfg.get("policy.allowed_ports", []))
        overrides = cfg.get("policy.host_ports", {}) or {}
        for ip, plist in open_map.items():
            names = targets.get(ip, [ip])
            allowed = set(allowed_global)
            for n in names + [ip]:
                allowed |= set(overrides.get(n, []))
            for port, banner in plist:
                a = ctx.add_asset("port", f"{ip}:{port}", "portscan", ip=ip, port=port,
                                  service=_service(port), hosts=",".join(sorted(names))[:120], banner=banner[:80])
                if port in allowed:
                    continue
                label, sev = RISKY.get(port, (_service(port), "medium"))
                ctx.add_finding(
                    rule=f"ports.unexpected.{port}" if port in RISKY else "ports.unexpected",
                    module=self.name, severity=sev, asset=a.key,
                    title=f"Unexpected open port {port}/tcp ({label})",
                    description=f"{ip}:{port} is reachable but not in policy.allowed_ports. Exposed management and database services are a common breach path.",
                    evidence=f"hosts: {', '.join(names)}" + (f"; banner: {banner[:60]}" if banner else ""),
                    remediation=("Block the port at the firewall/security group, bind the service to localhost or a private "
                                 "network, or — if it is intentional — accept it with `umbra baseline accept`."),
                    fix_snippet=(f"# ufw\nsudo ufw deny {port}/tcp\n# iptables\nsudo iptables -A INPUT -p tcp --dport {port} -j DROP\n"
                                 f"# or allow only your admin IP\nsudo ufw allow from <ADMIN_IP> to any port {port} proto tcp"),
                    references=["CIS Controls v8: 4.4, 12.2"])

    @staticmethod
    def _connect(targets, ports, timeout, threads):
        def probe(args):
            ip, port = args
            try:
                with socket.create_connection((ip, port), timeout=timeout) as s:
                    s.settimeout(0.6)
                    banner = ""
                    try:
                        banner = s.recv(80).decode("latin-1", "replace").strip().replace("\n", " ")
                    except OSError:
                        pass
                    return ip, port, banner
            except OSError:
                return None
        jobs = [(ip, p) for ip in targets for p in ports]
        out: dict[str, list] = {}
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for r in ex.map(probe, jobs):
                if r:
                    out.setdefault(r[0], []).append((r[1], r[2]))
        return out

    @staticmethod
    def _nmap(targets, ports, ctx):
        out: dict[str, list] = {}
        plist = ",".join(map(str, ports))
        for ip in targets:
            rc, xml, err = net.run_cmd(["nmap", "-Pn", "-sT", "-sV", "--version-light", "-T3", "-p", plist,
                                        "-oX", "-", ip], timeout=600)
            if rc != 0:
                ctx.log.warning("nmap failed for %s: %s", ip, err[:100])
                continue
            try:
                for p in ET.fromstring(xml).iter("port"):
                    if p.find("state").get("state") == "open":
                        svc = p.find("service")
                        banner = " ".join(filter(None, [svc.get("product"), svc.get("version")])) if svc is not None else ""
                        out.setdefault(ip, []).append((int(p.get("portid")), banner))
            except ET.ParseError:
                ctx.log.warning("nmap output unparsable for %s", ip)
        return out
