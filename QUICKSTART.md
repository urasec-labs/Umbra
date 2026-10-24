# Umbra — Quick Start

**Author:** Uras AKAS | urasakas.com

## 1. Install
```bash
cd umbra
python3 -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Optional defensive tools (Umbra uses them automatically when present)
# sudo apt install nmap lynis git
# gitleaks, trivy, subfinder: see their release pages;  pip install pip-audit
python umbra.py tools          # shows what is available
```

## 2. First scan
```bash
python umbra.py init                                   # creates config/umbra.yaml (edit scope + alerts)
python umbra.py scan -d example.com                    # quick profile: discovery, tls, headers
python umbra.py scan -d example.com --host 203.0.113.10 --path ~/code/app -p full
python umbra.py modules                                # list modules
```
Reports: `data/reports/*.html|pdf|json` · Dashboard: `python umbra.py dashboard`

## 3. Continuous monitoring + alerts
```bash
export UMBRA_DISCORD_WEBHOOK="https://discord.com/api/webhooks/..."
python umbra.py notify-test
python umbra.py monitor -d example.com --interval 3600
```

## 4. Taking control
```bash
python umbra.py baseline accept -d example.com --key port:203.0.113.10:8080 --note "internal tool"
python umbra.py suppress <fingerprint> --reason "false positive" -d example.com
python umbra.py scan -d example.com -p full --fail-on high     # CI gate (exit code 2)
```

## 5. Profiles
| Profile   | Modules |
|-----------|---------|
| `quick`   | discovery, tls, headers |
| `full`    | discovery, dns_hygiene, ports, tls, headers, exposure, secrets, ext_tools |
| `monitor` | discovery, ports, tls, secrets |
| `code`    | secrets, ext_tools |

Only monitor assets you own or are authorized to assess — see `DISCLAIMER.md`.
