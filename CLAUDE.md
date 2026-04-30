# MailFlow Sentinel — Project Context

## Stack
- FastAPI + Jinja2, Python 3.11
- Two systemd services on ports 8000 and 8001
- nginx reverse proxy + SSL (Let's Encrypt)
- VPS: 144.202.103.114 (Vultr)
- GitHub: siirila-bit/mailflow-sentinel

## Project files
- app.py — main FastAPI application
- probe_server.py — SMTP probe service (port 8001)

## Checks implemented
SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT, SMTP probe, open relay, subdomain scan, PDF export, rate limiting

## Current dev priority
Parallel probe execution — probes currently run sequentially, need asyncio.gather() pattern

## Conventions
- Never touch nginx config without asking
- Don't restart systemd services mid-session
- Rate limiting logic lives in app.py — flag before touching
