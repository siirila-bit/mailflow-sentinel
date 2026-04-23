from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import FileResponse
from fastapi.templating import Jinja2Templates
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import dns.resolver
import urllib.request
import urllib.parse
import ssl
import asyncio
import json
import re
import uuid
import os
from datetime import datetime, timezone

PROBE_URL = "http://144.202.103.114:8001/probe"
REPORTS_DIR = "/opt/mailflow/reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
templates = Jinja2Templates(directory="templates")


def extract_domain(value: str) -> str:
    value = value.strip().lower()
    if "@" in value:
        return value.split("@", 1)[1]
    return value


def get_mx(domain: str):
    try:
        answers = dns.resolver.resolve(domain, "MX")
        records = sorted(
            [(r.preference, str(r.exchange).rstrip(".")) for r in answers],
            key=lambda x: x[0]
        )
        return [host for _, host in records]
    except Exception:
        return []


def get_txt_records(name: str):
    try:
        answers = dns.resolver.resolve(name, "TXT")
        records = []
        for r in answers:
            txt = "".join(
                part.decode() if isinstance(part, bytes) else str(part)
                for part in r.strings
            )
            records.append(txt)
        return records
    except Exception:
        return []


def get_cname(hostname: str) -> str | None:
    try:
        answers = dns.resolver.resolve(hostname, "CNAME")
        return str(answers[0].target).rstrip(".")
    except Exception:
        return None


def get_spf(domain: str):
    txt_records = get_txt_records(domain)
    for record in txt_records:
        if record.lower().startswith("v=spf1"):
            return record
    return None


def get_dmarc(domain: str):
    records = get_txt_records(f"_dmarc.{domain}")
    for record in records:
        if record.lower().startswith("v=dmarc1"):
            return record
    return None


def get_bimi(domain: str):
    records = get_txt_records(f"default._bimi.{domain}")
    for record in records:
        if record.lower().startswith("v=bimi1"):
            return record
    return None


def get_dkim_record(selector: str, domain: str):
    try:
        name = f"{selector}._domainkey.{domain}"
        records = get_txt_records(name)
        for record in records:
            upper = record.upper()
            lower = record.lower()
            if "V=DKIM1" in upper or "k=rsa" in lower or "p=" in lower:
                return record
        return None
    except Exception:
        return None


def estimate_dkim_bits(record: str | None):
    if not record:
        return None
    lower = record.lower()
    if "p=" not in lower:
        return None
    try:
        p_value = lower.split("p=", 1)[1]
        p_value = p_value.split(";", 1)[0]
        p_value = "".join(p_value.split())
        key_len = len(p_value)
        if key_len >= 300:
            return 2048
        if key_len >= 150:
            return 1024
        return None
    except Exception:
        return None


def check_common_dkim(domain: str):
    selectors = [
        "selector1", "selector2", "default", "dkim", "s1", "s2",
        "mail", "email", "smtp", "mta", "google", "k1", "k2", "key1", "key2",
    ]
    results = []
    for selector in selectors:
        record = get_dkim_record(selector, domain)
        host = f"{selector}._domainkey.{domain}"
        if selector == "selector1":
            label = "Microsoft 365 (Primary)"
        elif selector == "selector2":
            label = "Microsoft 365 (Secondary)"
        elif selector == "google":
            label = "Google"
        elif selector in ["s1", "s2"]:
            label = "SendGrid"
        else:
            label = "Common Selector"
        bits = estimate_dkim_bits(record)
        results.append({
            "selector": selector,
            "host": host,
            "label": label,
            "found": bool(record),
            "record": record,
            "bits": bits,
            "weak": bool(record) and bits == 1024,
        })
    return results


async def check_common_dkim_async(domain: str) -> list:
    selectors = [
        "selector1", "selector2", "default", "dkim", "s1", "s2",
        "mail", "email", "smtp", "mta", "google", "k1", "k2", "key1", "key2",
    ]

    async def _lookup(selector: str) -> dict:
        record = await asyncio.to_thread(get_dkim_record, selector, domain)
        host = f"{selector}._domainkey.{domain}"
        if selector == "selector1":
            label = "Microsoft 365 (Primary)"
        elif selector == "selector2":
            label = "Microsoft 365 (Secondary)"
        elif selector == "google":
            label = "Google"
        elif selector in ["s1", "s2"]:
            label = "SendGrid"
        else:
            label = "Common Selector"
        bits = estimate_dkim_bits(record)
        return {
            "selector": selector,
            "host": host,
            "label": label,
            "found": bool(record),
            "record": record,
            "bits": bits,
            "weak": bool(record) and bits == 1024,
        }

    return list(await asyncio.gather(*[_lookup(s) for s in selectors]))


def detect_msft_dkim(dkim_results):
    selector1_found = any(item["selector"] == "selector1" and item["found"] for item in dkim_results)
    selector2_found = any(item["selector"] == "selector2" and item["found"] for item in dkim_results)
    return {
        "enabled": selector1_found or selector2_found,
        "selector1": selector1_found,
        "selector2": selector2_found,
    }


def infer_dkim_signing_authority(vendor: str, dkim_results, msft_dkim):
    google_found = any(item["selector"] == "google" and item["found"] for item in dkim_results)
    sendgrid_found = any(item["selector"] in ["s1", "s2"] and item["found"] for item in dkim_results)

    if msft_dkim["enabled"]:
        return {
            "status": "Inferred",
            "authority": "Microsoft 365",
            "detail": "Microsoft 365 selectors were detected. Microsoft 365 is likely acting as a signing authority.",
        }
    if google_found:
        return {
            "status": "Inferred",
            "authority": "Google Workspace",
            "detail": "Google DKIM selector was detected. Google Workspace is likely acting as a signing authority.",
        }
    if sendgrid_found:
        return {
            "status": "Inferred",
            "authority": "SendGrid",
            "detail": "SendGrid DKIM selectors were detected. SendGrid is likely signing at least some mail streams.",
        }
    if vendor.lower() == "barracuda":
        return {
            "status": "Unknown",
            "authority": "Header analysis required",
            "detail": "DNS confirms DKIM-related records may exist, but the true signing domain requires header analysis (d= value).",
        }
    return {
        "status": "Unknown",
        "authority": "Header analysis required",
        "detail": "The actual DKIM signing domain cannot be proven from DNS alone. Email header analysis is required.",
    }


def count_spf_lookups(spf_record: str | None) -> int:
    """
    Recursively resolve SPF includes and redirects via DNS and return the
    exact number of DNS-lookup-consuming mechanisms encountered.

    RFC 7208 §4.6.4 caps evaluation at 10 such lookups; this function returns
    the real count so the caller can flag anything over 10 as permerror.
    """
    def _resolve(record: str, visited: set, depth: int) -> int:
        if depth > 12:  # hard guard against malformed/adversarial chains
            return 0
        total = 0
        for token in record.split():
            t = token.lower()
            if t.startswith("include:"):
                target = token[8:]
                total += 1
                if target not in visited:
                    visited.add(target)
                    fetched = get_spf(target)
                    if fetched:
                        total += _resolve(fetched, visited, depth + 1)
            elif t.startswith("redirect="):
                target = token[9:]
                total += 1
                if target not in visited:
                    visited.add(target)
                    fetched = get_spf(target)
                    if fetched:
                        total += _resolve(fetched, visited, depth + 1)
                break  # redirect= replaces the rest of the record
            elif t in ("a", "mx", "ptr") or any(
                t.startswith(x) for x in ("a:", "mx:", "ptr:", "exists:")
            ):
                total += 1
            if total > 10:  # stop early once the RFC limit is already exceeded
                break
        return total

    if not spf_record:
        return 0

    return _resolve(spf_record, set(), 0)


# ── Third-party sender detection ─────────────────────────────────────────────

_ESP_PATTERNS: dict[str, list[str]] = {
    "HubSpot":          [r"hubspot\.com", r"hs-sites\.com", r"hsmai", r"hubspotemail\.net"],
    "SendGrid":         [r"sendgrid\.net", r"sendgrid\.com"],
    "Mailchimp":        [r"mailchimp\.com", r"mcsv\.net", r"list-manage\.com"],
    "Klaviyo":          [r"klaviyo\.com", r"klaviyomail\.com"],
    "Salesforce MC":    [r"exacttarget\.com", r"sfmc"],
    "Marketo":          [r"marketo\.com", r"mktomail\.com"],
    "Postmark":         [r"postmarkapp\.com"],
    "Amazon SES":       [r"amazonses\.com"],
    "Mailgun":          [r"mailgun\.org", r"mailgun\.net"],
    "Braze":            [r"braze\.com", r"appboy"],
    "Iterable":         [r"iterable\.com"],
    "ActiveCampaign":   [r"activecampaign\.com"],
    "Constant Contact": [r"constantcontact\.com", r"ctct\.net"],
}

_DKIM_SELECTORS = [
    "s1", "s2", "hs1", "hs2",
    "selector1", "selector2",
    "google", "k1", "k2",
    "mail", "default", "dkim", "smtp", "mta",
]


def _match_esps(text: str) -> list[str]:
    return [name for name, patterns in _ESP_PATTERNS.items()
            if any(re.search(p, text, re.IGNORECASE) for p in patterns)]


def _expand_spf_includes(spf_record: str | None, depth: int = 0) -> list[str]:
    """Return all include: domains, following one level of redirect=."""
    if not spf_record or depth > 3:
        return []
    includes = []
    for token in spf_record.split():
        t = token.lower()
        if t.startswith("include:"):
            includes.append(token[8:])
        elif t.startswith("redirect=") and depth == 0:
            redirected = get_spf(token[9:])
            if redirected:
                includes += _expand_spf_includes(redirected, depth + 1)
    return includes


def detect_email_senders(domain: str, spf: str | None) -> list[dict]:
    seen: dict[str, dict] = {}

    def _add(esp_name: str, signal: str):
        if esp_name not in seen:
            seen[esp_name] = {"name": esp_name, "signals": []}
        if signal not in seen[esp_name]["signals"]:
            seen[esp_name]["signals"].append(signal)

    # SPF includes (with redirect= following)
    for inc in _expand_spf_includes(spf):
        for esp in _match_esps(inc):
            _add(esp, f"SPF include:{inc}")

    # DKIM selector CNAMEs
    for sel in _DKIM_SELECTORS:
        name = f"{sel}._domainkey.{domain}"
        cname = get_cname(name)
        if cname:
            for esp in _match_esps(cname):
                _add(esp, f"{name} → {cname}")

    return list(seen.values())


# ─────────────────────────────────────────────────────────────────────────────

def detect_vendor(mx_records):
    joined = " ".join(mx_records).lower()
    if "barracuda" in joined:
        return "Barracuda"
    if "mimecast" in joined:
        return "Mimecast"
    if "proofpoint" in joined:
        return "Proofpoint"
    if "google" in joined or "aspmx" in joined:
        return "Google Workspace"
    if "mail.protection.outlook.com" in joined:
        return "Microsoft 365"
    return "Unknown"


def get_mta_sts_dns(domain: str):
    records = get_txt_records(f"_mta-sts.{domain}")
    for record in records:
        if record.lower().startswith("v=stsv1"):
            return record
    return None


def get_tls_rpt(domain: str):
    records = get_txt_records(f"_smtp._tls.{domain}")
    for record in records:
        if record.lower().startswith("v=tlsrptv1"):
            return record
    return None


def check_mta_sts_policy(domain: str):
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(url, timeout=5, context=ctx) as response:
            body = response.read().decode("utf-8", errors="replace")
            if "version: STSv1" in body:
                return {"found": True, "url": url, "body": body}
            return {"found": False, "url": url, "body": body}
    except Exception:
        return {"found": False, "url": url, "body": None}


def build_probe_stages(data):
    stage = data.get("stage")
    code = data.get("smtp_code")
    response = (data.get("smtp_response") or "").strip()
    host = (data.get("host") or data.get("eop_host", "")).strip()
    status = data.get("status", "")
    error = (data.get("error") or "").strip()

    stages = []
    if status in ("Timeout", "DNS Error", "Error") or not stage:
        stages.append({"stage": "Connect", "code": "—", "response": error or "Connection failed"})
        return {"host": host, "stages": stages}

    stages.append({"stage": "Connect + EHLO + STARTTLS", "code": "220 / 250", "response": "TLS negotiated"})
    if stage == "mail_from":
        stages.append({"stage": "MAIL FROM", "code": str(code) if code else "—", "response": response[:150] or "—"})
    elif stage == "rcpt_to":
        stages.append({"stage": "MAIL FROM", "code": "250", "response": "OK"})
        stages.append({"stage": "RCPT TO", "code": str(code) if code else "—", "response": response[:200] or "—"})
    return {"host": host, "stages": stages}


def evaluate_direct_send(domain, vendor, mx_records, dmarc, msft_dkim):
    """
    Hybrid direct send evaluation:
    1. DNS inference as primary signal
    2. Live SMTP probe as confirmation
    """
    mx_string = " ".join(mx_records).lower()
    is_microsoft = "mail.protection.outlook.com" in mx_string
    gateway_vendors = ["barracuda", "proofpoint", "mimecast"]
    has_gateway = any(v in vendor.lower() for v in gateway_vendors)

    # DNS inference baseline
    if is_microsoft and not has_gateway:
        dns_status = "Not Protected"
        dns_severity = "high"
    elif has_gateway and is_microsoft:
        dns_status = "Not Protected"
        dns_severity = "medium"
    elif has_gateway:
        dns_status = "Protected"
        dns_severity = "low"
    else:
        dns_status = "Unknown"
        dns_severity = "low"

    def _reason(status, severity):
        if status == "Protected":
            return f"A {vendor} secure email gateway is detected in the MX routing path. Mail must pass through the gateway before reaching the destination server, preventing unauthorized direct delivery."
        if status == "Not Protected" and severity == "high":
            return "Microsoft 365 MX records are publicly reachable with no gateway detected. No connector restriction has been confirmed from external signals — direct delivery to the EOP endpoint may be possible."
        if status == "Not Protected" and severity == "medium":
            return "A gateway is present in DNS but Microsoft 365 also appears in the routing path. Connector restrictions have not been confirmed — direct delivery bypass to the M365 endpoint may still be possible."
        return "Unable to determine direct send exposure from DNS alone."

    # Try live probe for confirmation
    try:
        url = f"{PROBE_URL}?domain={urllib.parse.quote(domain)}"
        with urllib.request.urlopen(url, timeout=12) as resp:
            data = json.loads(resp.read().decode())

        probe_status = data.get("status", "Unknown")
        smtp_response = (data.get("smtp_response") or "").strip()
        smtp_code = data.get("smtp_code")
        probe_detail = build_probe_stages(data)

        # Confirmed connector block via 5.7.68 TenantInboundAttribution
        if probe_status == "Protected" and ("5.7.68" in smtp_response or "TenantInboundAttribution" in smtp_response):
            return {
                "status": "Protected",
                "severity": "low",
                "reason": f"Microsoft 365 rejected the connection at RCPT TO with {smtp_code or '550'} 5.7.68 TenantInboundAttribution. Connector enforcement is active — only mail from authorized sources will be accepted by this tenant.",
                "validation": f"Live probe confirmed: {smtp_response[:150]}",
                "probe": "confirmed",
                "probe_detail": probe_detail,
            }

        # Probe returned 250
        if probe_status == "Exposed":
            if not has_gateway:
                # No gateway in MX — 250 confirms direct delivery to M365 is possible
                eop_host = (data.get("host") or data.get("eop_host", "the M365 EOP endpoint")).strip()
                return {
                    "status": "Not Protected",
                    "severity": "high",
                    "reason": f"Microsoft 365 accepted the SMTP envelope at RCPT TO (250 OK) from an external, unauthenticated source at {eop_host}. No connector-level restriction was detected.",
                    "validation": "Live SMTP probe returned 250 at RCPT TO. Transport rule-based blocking is not detectable externally — additional protection may still be in place post-DATA.",
                    "probe": "confirmed",
                    "probe_detail": probe_detail,
                }
            else:
                # Gateway present — probe 250 is inconclusive (probe IP hits M365 directly, bypassing the gateway path)
                return {
                    "status": "Protected",
                    "severity": "low",
                    "reason": _reason("Protected", "low"),
                    "validation": "Live SMTP probe returned 250, but this is inconclusive — the probe connects directly to the M365 EOP endpoint from an external IP, bypassing the gateway. Gateway detection is the authoritative signal.",
                    "probe": "dns_primary",
                    "probe_detail": probe_detail,
                }

        # Probe not applicable or inconclusive — use DNS inference with definitive reason
        return {
            "status": dns_status,
            "severity": dns_severity,
            "reason": _reason(dns_status, dns_severity),
            "validation": f"Live SMTP probe status: {probe_status}. DNS inference is the primary signal.",
            "probe": "dns_primary",
            "probe_detail": probe_detail,
        }

    except Exception:
        return {
            "status": dns_status,
            "severity": dns_severity,
            "reason": _reason(dns_status, dns_severity),
            "validation": "DNS inference only — live SMTP probe was unavailable.",
            "probe": "dns",
            "probe_detail": None,
        }


def evaluate_catch_all(domain: str) -> dict:
    try:
        url = f"http://144.202.103.114:8001/catchall?domain={urllib.parse.quote(domain)}"
        with urllib.request.urlopen(url, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        return {
            "status": data.get("status", "Unknown"),
            "reason": data.get("reason", ""),
            "smtp_code": data.get("smtp_code"),
            "smtp_response": data.get("smtp_response", ""),
            "mx_tested": data.get("mx_tested", ""),
        }
    except Exception:
        return {
            "status": "Unavailable",
            "reason": "Catch-all check unavailable.",
            "smtp_code": None,
            "smtp_response": "",
            "mx_tested": "",
        }


def generate_recommendations(spf, dmarc, mta_sts_record, tls_rpt_record, direct_send, catch_all, msft_dkim, vendor="", dkim_results=None):
    fixes = []
    if not spf:
        fixes.append("Add an SPF record to define authorized sending sources.")
    if not dmarc:
        fixes.append("Publish a DMARC record to monitor and enforce authentication.")
    elif "p=none" in dmarc.lower():
        fixes.append("Move DMARC from p=none to quarantine or reject for stronger spoof protection.")
    vendor_lower = vendor.lower()
    if not msft_dkim["enabled"] and ("microsoft" in vendor_lower or "365" in vendor_lower):
        fixes.append("Enable Microsoft 365 DKIM if Microsoft 365 is used for primary user mail.")
    if not mta_sts_record:
        fixes.append("Add an MTA-STS record and publish a valid policy file.")
    if not tls_rpt_record:
        fixes.append("Publish a TLS-RPT record to receive transport security failure reports.")
    if direct_send["status"] == "Not Protected":
        if direct_send.get("severity") == "high":
            fixes.append("Restrict Microsoft 365 so it only accepts mail from approved gateway or connector sources.")
        else:
            fixes.append("Validate Microsoft 365 connector configuration — a gateway is present but direct delivery bypass should be confirmed.")
    if catch_all["status"] == "Catch-All Enabled":
        fixes.append("Disable catch-all to prevent email harvesting and reduce spam exposure.")
    if dkim_results and any(item.get("weak") for item in dkim_results):
        fixes.append("Rotate DKIM keys from 1024-bit to 2048-bit for stronger cryptographic protection.")
    return fixes


def build_score_summary(score, spf, dmarc, dkim_present, mta_sts_record, direct_send_status, findings):
    if score >= 90:
        if not findings:
            return "Authentication stack is fully deployed and enforced. No critical gaps detected from external DNS signals."
        gaps = " and ".join([f.lower().rstrip(".") for f in findings[:2]])
        return f"Strong authentication posture. Minor gaps detected: {gaps}."
    elif score >= 75:
        parts = []
        if dmarc and "reject" in dmarc.lower():
            parts.append("DMARC is enforced at reject")
        if dkim_present:
            parts.append("DKIM is active")
        if not mta_sts_record:
            parts.append("transport security (MTA-STS) is missing")
        if direct_send_status == "Not Protected":
            parts.append("direct send requires validation")
        return "Good baseline posture. " + ("; ".join(parts) + "." if parts else "Some gaps remain.")
    elif score >= 50:
        issues = []
        if not spf:
            issues.append("SPF is missing")
        if not dmarc or "p=none" in (dmarc or "").lower():
            issues.append("DMARC is not enforced")
        if not dkim_present:
            issues.append("DKIM is not configured")
        if direct_send_status == "Not Protected":
            issues.append("direct send is exposed")
        return "Moderate risk. " + (", ".join(issues) + "." if issues else "Multiple gaps present.")
    else:
        critical = []
        if not spf:
            critical.append("no SPF")
        if not dmarc:
            critical.append("no DMARC")
        if not dkim_present:
            critical.append("no DKIM")
        if direct_send_status == "Not Protected":
            critical.append("direct send exposed")
        return "High risk. This domain is vulnerable to spoofing: " + (", ".join(critical) + "." if critical else "multiple critical controls missing.")


def calculate_score(spf, dmarc, spf_lookups, mta_sts_record, tls_rpt_record, direct_send_status, msft_dkim, catch_all_status, dkim_results=None):
    score = 100
    findings = []

    if not spf:
        score -= 25
        findings.append("SPF record missing")
    elif spf_lookups > 10:
        score -= 15
        findings.append("SPF exceeds the 10 DNS lookup limit")
    elif spf_lookups >= 8:
        score -= 5
        findings.append("SPF lookup count is getting high")

    if not dmarc:
        score -= 25
        findings.append("DMARC record missing")
    elif "p=none" in dmarc.lower():
        score -= 18
        findings.append("DMARC is monitor-only (p=none)")

    if not msft_dkim["enabled"]:
        score -= 15
        findings.append("Microsoft 365 DKIM not detected")

    if dkim_results and any(item.get("weak") for item in dkim_results):
        score -= 8
        findings.append("Weak DKIM key — one or more active keys are 1024-bit")

    if direct_send_status == "Not Protected":
        score -= 20
        findings.append("Direct send — Microsoft 365 endpoint may be reachable without connector restrictions")

    if not mta_sts_record:
        score -= 6
        findings.append("MTA-STS record missing")

    if not tls_rpt_record:
        score -= 4
        findings.append("TLS-RPT record missing")

    if catch_all_status == "Catch-All Enabled":
        score -= 10
        findings.append("Catch-all enabled — domain accepts email to any address")

    score = max(score, 0)

    if score >= 85:
        risk_level = "Low"
        score_label = "Protected (Improvements Recommended)"
    elif score >= 65:
        risk_level = "Medium"
        score_label = "Strong (Gaps Identified)"
    else:
        risk_level = "High"
        score_label = "At Risk"

    return score, risk_level, score_label, findings


def _probe_relay(domain: str) -> dict:
    result = {"status": "Unknown", "reason": "", "mx_tested": [], "tls_versions": [], "banners": []}
    try:
        relay_url = f"http://144.202.103.114:8001/relay?domain={urllib.parse.quote(domain)}"
        with urllib.request.urlopen(relay_url, timeout=20) as resp:
            relay_data = json.loads(resp.read().decode())
        result["status"] = relay_data.get("status", "Unknown")
        result["reason"] = relay_data.get("reason", "")
        result["mx_tested"] = relay_data.get("mx_tested", [])
        for r in relay_data.get("results", []):
            if r.get("tls_version"):
                result["tls_versions"].append(r["tls_version"])
            if r.get("banner"):
                result["banners"].append(r["banner"])
    except Exception:
        result["status"] = "Unavailable"
        result["reason"] = "Open relay check unavailable."
    return result


def _probe_subdomains(domain: str) -> dict:
    try:
        sub_url = f"http://144.202.103.114:8001/subdomains?domain={urllib.parse.quote(domain)}"
        with urllib.request.urlopen(sub_url, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return {"subdomains_found": 0, "open_relays_found": 0, "open_relay_hosts": [], "results": []}


@app.get("/robots.txt")
def robots():
    return FileResponse("/opt/mailflow/robots.txt")


@app.get("/")
def home(request: Request):
    return templates.TemplateResponse(request=request, name="index.html", context={})


@app.get("/about")
def about(request: Request):
    return templates.TemplateResponse(request=request, name="about.html", context={})


@app.post("/share")
@limiter.limit("10/minute")
async def share(request: Request):
    data = await request.json()
    report_id = str(uuid.uuid4())
    path = os.path.join(REPORTS_DIR, f"{report_id}.json")
    with open(path, "w") as f:
        json.dump(data, f)
    return {"url": f"/r/{report_id}"}


@app.get("/r/{report_id}")
def shared_report(request: Request, report_id: str):
    try:
        uuid.UUID(report_id)
    except ValueError:
        raise HTTPException(status_code=404)
    path = os.path.join(REPORTS_DIR, f"{report_id}.json")
    if not os.path.exists(path):
        raise HTTPException(status_code=404)
    with open(path) as f:
        data = json.load(f)
    return templates.TemplateResponse(request=request, name="share.html", context=data)


@app.get("/analyze")
@limiter.limit("10/minute")
async def analyze(request: Request, domain: str):
    original_input = domain
    domain = extract_domain(domain)

    # Phase 1: all independent DNS lookups in parallel (6 TXT/MX + 15 DKIM selectors)
    mx, spf, dmarc, bimi_record, mta_sts_record, tls_rpt_record, dkim_results = await asyncio.gather(
        asyncio.to_thread(get_mx, domain),
        asyncio.to_thread(get_spf, domain),
        asyncio.to_thread(get_dmarc, domain),
        asyncio.to_thread(get_bimi, domain),
        asyncio.to_thread(get_mta_sts_dns, domain),
        asyncio.to_thread(get_tls_rpt, domain),
        check_common_dkim_async(domain),
    )

    vendor = detect_vendor(mx)
    dkim_present = any(item["found"] for item in dkim_results)
    msft_dkim = detect_msft_dkim(dkim_results)
    dkim_signing_authority = infer_dkim_signing_authority(vendor, dkim_results, msft_dkim)

    # Phase 2: all slow I/O in parallel (SPF recursion, MTA-STS fetch, 5 probe calls)
    (
        spf_lookups,
        mta_sts_policy,
        direct_send,
        catch_all,
        email_senders,
        open_relay,
        subdomain_data,
    ) = await asyncio.gather(
        asyncio.to_thread(count_spf_lookups, spf),
        asyncio.to_thread(check_mta_sts_policy, domain),
        asyncio.to_thread(evaluate_direct_send, domain, vendor, mx, dmarc, msft_dkim),
        asyncio.to_thread(evaluate_catch_all, domain),
        asyncio.to_thread(detect_email_senders, domain, spf),
        asyncio.to_thread(_probe_relay, domain),
        asyncio.to_thread(_probe_subdomains, domain),
    )

    recommended_fixes = generate_recommendations(
        spf, dmarc, mta_sts_record, tls_rpt_record,
        direct_send, catch_all, msft_dkim, vendor, dkim_results,
    )

    if open_relay["status"] == "Open Relay":
        recommended_fixes.insert(0, "CRITICAL: Open relay detected — your mail server will forward email for anyone. Restrict relay immediately.")

    if subdomain_data.get("open_relays_found", 0) > 0:
        recommended_fixes.insert(0, f"CRITICAL: Open relay detected on mail subdomain(s): {', '.join(subdomain_data['open_relay_hosts'])}. Restrict relay immediately.")

    # Build mail server fingerprint from open relay probe data
    fingerprint = {
        "banners": open_relay.get("banners", []),
        "tls_versions": open_relay.get("tls_versions", []),
        "mx_hosts": open_relay.get("mx_tested", []),
        "vendor": vendor,
    }
    fingerprint["server_software"] = ""
    if fingerprint["banners"]:
        banner = fingerprint["banners"][0]
        match = re.search(r'(?:ESMTP|SMTP)\s+([^\s(]+)', banner, re.IGNORECASE)
        if match:
            fingerprint["server_software"] = match.group(1)
    fingerprint["tls_secure"] = all("TLSv1.2" in t or "TLSv1.3" in t for t in fingerprint["tls_versions"]) if fingerprint["tls_versions"] else None

    score, risk_level, score_label, findings = calculate_score(
        spf, dmarc, spf_lookups, mta_sts_record,
        tls_rpt_record, direct_send["status"], msft_dkim, catch_all["status"], dkim_results,
    )

    score_summary = build_score_summary(
        score, spf, dmarc, dkim_present, mta_sts_record, direct_send["status"], findings
    )

    report_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    share_data = {
        "domain": domain, "input_value": original_input, "mx": mx, "vendor": vendor,
        "spf": spf, "dmarc": dmarc, "bimi_record": bimi_record,
        "dkim_results": dkim_results, "dkim_present": dkim_present,
        "msft_dkim": msft_dkim, "dkim_signing_authority": dkim_signing_authority,
        "spf_lookups": spf_lookups, "mta_sts_record": mta_sts_record,
        "tls_rpt_record": tls_rpt_record, "mta_sts_policy": mta_sts_policy,
        "direct_send": direct_send, "catch_all": catch_all,
        "email_senders": email_senders, "recommended_fixes": recommended_fixes,
        "score": score, "risk_level": risk_level, "score_label": score_label,
        "findings": findings, "score_summary": score_summary,
        "report_date": report_date, "open_relay": open_relay,
        "fingerprint": fingerprint, "subdomain_data": subdomain_data,
    }
    scan_data_json = json.dumps(share_data).replace("</", r"</")

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "input_value": original_input,
            "domain": domain,
            "mx": mx,
            "vendor": vendor,
            "spf": spf,
            "dmarc": dmarc,
            "bimi_record": bimi_record,
            "dkim_results": dkim_results,
            "dkim_present": dkim_present,
            "msft_dkim": msft_dkim,
            "dkim_signing_authority": dkim_signing_authority,
            "spf_lookups": spf_lookups,
            "mta_sts_record": mta_sts_record,
            "tls_rpt_record": tls_rpt_record,
            "mta_sts_policy": mta_sts_policy,
            "direct_send": direct_send,
            "catch_all": catch_all,
            "email_senders": email_senders,
            "recommended_fixes": recommended_fixes,
            "score": score,
            "risk_level": risk_level,
            "score_label": score_label,
            "findings": findings,
            "score_summary": score_summary,
            "report_date": report_date,
            "open_relay": open_relay,
            "fingerprint": fingerprint,
            "subdomain_data": subdomain_data,
            "scan_data_json": scan_data_json,
        }
    )
