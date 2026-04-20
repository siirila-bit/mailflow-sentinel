from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.templating import Jinja2Templates
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import dns.resolver
import urllib.request
import urllib.parse
import ssl
import json
import asyncio
import httpx
from datetime import datetime, timezone

PROBE_URL = "http://144.202.103.114:8001/probe"

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
        results.append({
            "selector": selector,
            "host": host,
            "label": label,
            "found": bool(record),
            "record": record,
            "bits": estimate_dkim_bits(record),
        })
    return results


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


def count_spf_lookups(spf_record):
    if not spf_record:
        return 0
    parts = spf_record.split()
    count = 0
    for part in parts:
        lowered = part.lower()
        if any(lowered.startswith(x) for x in ["include:", "exists:", "redirect="]):
            count += 1
        elif lowered in ["a", "mx", "ptr"] or any(lowered.startswith(x) for x in ["a:", "mx:", "ptr:"]):
            count += 1
    return count


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


def get_cname(name: str) -> str | None:
    try:
        answers = dns.resolver.resolve(name, "CNAME")
        return str(answers[0].target).rstrip(".")
    except Exception:
        return None


ESP_DEFS = [
    {
        "name": "SendGrid",
        "spf": ["sendgrid.net"],
        "cname": ["sendgrid.net"],
        "selectors": ["s1", "s2"],
    },
    {
        "name": "Mailchimp",
        "spf": ["servers.mcsv.net", "spf.mandrillapp.com"],
        "cname": ["mcsv.net", "mcdlv.net", "list-manage.com", "mandrillapp.com"],
        "selectors": ["k1", "k2"],
    },
    {
        "name": "HubSpot",
        "spf": ["_spf.hubspot.com"],
        "cname": ["hubspot.com", "hubspotemail.net"],
        "selectors": ["hs1", "hs2"],
    },
    {
        "name": "Klaviyo",
        "spf": ["klaviyo.com"],
        "cname": ["klaviyo.com"],
        "selectors": ["pd"],
    },
    {
        "name": "Constant Contact",
        "spf": ["spf.constantcontact.com"],
        "cname": ["constantcontact.com", "isnotspam.com"],
        "selectors": [],
    },
    {
        "name": "Brevo",
        "spf": ["sendinblue.com", "mail.sendinblue.com"],
        "cname": ["sendinblue.com", "brevo.com"],
        "selectors": ["mail"],
    },
    {
        "name": "Postmark",
        "spf": ["spf.mtasv.net"],
        "cname": ["mtasv.net"],
        "selectors": ["pm"],
    },
    {
        "name": "Salesforce Marketing Cloud",
        "spf": ["exacttarget.com", "cust-spf.exacttarget.com"],
        "cname": ["exacttarget.com", "s.exacttarget.com"],
        "selectors": [],
    },
]


def detect_email_senders(domain: str, spf: str | None) -> list[dict]:
    detected: dict[str, dict] = {}

    # Check SPF includes
    if spf:
        spf_lower = spf.lower()
        for esp in ESP_DEFS:
            for inc in esp["spf"]:
                if inc in spf_lower:
                    detected.setdefault(esp["name"], {"name": esp["name"], "signals": []})
                    detected[esp["name"]]["signals"].append(f"SPF include:{inc}")
                    break

    # Check DKIM selectors for CNAMEs pointing to known ESP infrastructure
    for esp in ESP_DEFS:
        for selector in esp["selectors"]:
            cname = get_cname(f"{selector}._domainkey.{domain}")
            if cname and any(t in cname for t in esp["cname"]):
                detected.setdefault(esp["name"], {"name": esp["name"], "signals": []})
                detected[esp["name"]]["signals"].append(
                    f"DKIM CNAME {selector}._domainkey.{domain} → {cname}"
                )

    # Check common tracking/sending subdomains for CNAMEs
    tracking_subs = ["em", "em1", "em2", "email", "bounce", "click", "track", "links", "news", "go", "sg", "hub"]
    for sub in tracking_subs:
        cname = get_cname(f"{sub}.{domain}")
        if not cname:
            continue
        for esp in ESP_DEFS:
            if any(t in cname for t in esp["cname"]):
                detected.setdefault(esp["name"], {"name": esp["name"], "signals": []})
                signal = f"CNAME {sub}.{domain} → {cname}"
                if signal not in detected[esp["name"]]["signals"]:
                    detected[esp["name"]]["signals"].append(signal)

    return list(detected.values())


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


async def evaluate_direct_send(domain, vendor, mx_records, dmarc, msft_dkim, email_senders=None):
    """
    Hybrid direct send evaluation:
    1. DNS inference as primary signal
    2. Live SMTP probe as confirmation only
       - 5.7.68 = upgrade to Confirmed Protected
       - 250 = don't downgrade — stay with DNS inference
       - Not Applicable = domain not on M365
    """
    mx_string = " ".join(mx_records).lower()
    is_microsoft = "mail.protection.outlook.com" in mx_string
    gateway_vendors = ["barracuda", "proofpoint", "mimecast"]
    has_gateway = any(v in vendor.lower() for v in gateway_vendors)

    # DNS inference baseline
    if is_microsoft and not has_gateway:
        dns_status = "At Risk"
        dns_reason = "Microsoft 365 appears to be receiving mail directly with no gateway detected."
    elif has_gateway and is_microsoft:
        dns_status = "Potential Exposure"
        dns_reason = "A gateway is visible but Microsoft 365 also appears in the routing path. Connector restrictions should be validated."
    elif has_gateway:
        dns_status = "Likely Protected"
        dns_reason = "A secure email gateway is detected in front of the mail system. Direct send risk is reduced."
    else:
        dns_status = "Unknown"
        dns_reason = "Unable to determine direct send exposure from DNS alone."

    # When M365 is the inbound handler and ESPs are detected, note the outbound/inbound split.
    # ESPs handle outbound only — they have no bearing on whether M365's inbound MX
    # can be reached directly by an unauthenticated sender.
    esp_context = None
    if is_microsoft and email_senders:
        esp_names = [e["name"] for e in email_senders]
        names_str = ", ".join(esp_names)
        esp_context = (
            f"Outbound mail appears split: {names_str} "
            f"{'handles' if len(esp_names) == 1 else 'handle'} outbound sending while "
            "Microsoft 365 handles inbound. ESP configuration does not reduce direct send "
            "bypass risk — an attacker can still deliver spoofed mail directly to the M365 "
            "MX endpoint, bypassing the outbound ESP entirely."
        )

    # Try live probe for confirmation
    try:
        url = f"{PROBE_URL}?domain={urllib.parse.quote(domain)}"
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, timeout=12)
            data = resp.json()

        probe_status = data.get("status", "Unknown")
        smtp_response = data.get("smtp_response", "")

        # Only upgrade on definitive 5.7.68 connector block
        if probe_status == "Protected" and ("5.7.68" in (smtp_response or "") or "TenantInboundAttribution" in (smtp_response or "")):
            return {
                "status": "Likely Protected",
                "severity": "low",
                "reason": dns_reason,
                "validation": f"Live SMTP probe confirmed connector-level block: {smtp_response[:120] if smtp_response else '5.7.68 TenantInboundAttribution'}",
                "probe": "confirmed",
                "esp_context": esp_context,
            }

        # 250 from probe is inconclusive — transport rules may still block post-DATA
        # Stay with DNS inference result
        return {
            "status": dns_status,
            "severity": "high" if dns_status == "At Risk" else "medium" if dns_status == "Potential Exposure" else "low",
            "reason": dns_reason,
            "validation": "Live SMTP probe returned 250 at RCPT TO. Note: transport rule-based blocking is not detectable externally — full protection may still be in place internally.",
            "probe": "dns_primary",
            "esp_context": esp_context,
        }

    except Exception:
        # Probe unavailable — fall back to DNS only
        return {
            "status": dns_status,
            "severity": "high" if dns_status == "At Risk" else "medium" if dns_status == "Potential Exposure" else "low",
            "reason": dns_reason,
            "validation": "DNS inference only. A live SMTP probe provides additional confirmation.",
            "probe": "dns",
            "esp_context": esp_context,
        }


async def evaluate_catch_all(domain: str) -> dict:
    try:
        url = f"http://144.202.103.114:8001/catchall?domain={urllib.parse.quote(domain)}"
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, timeout=15)
            data = resp.json()
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


async def probe_open_relay(domain: str) -> dict:
    result = {"status": "Unknown", "reason": "", "mx_tested": [], "tls_versions": [], "banners": []}
    try:
        relay_url = f"http://144.202.103.114:8001/relay?domain={urllib.parse.quote(domain)}"
        async with httpx.AsyncClient() as client:
            resp = await client.get(relay_url, timeout=20)
            relay_data = resp.json()
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


async def probe_subdomains(domain: str) -> dict:
    try:
        sub_url = f"http://144.202.103.114:8001/subdomains?domain={urllib.parse.quote(domain)}"
        async with httpx.AsyncClient() as client:
            resp = await client.get(sub_url, timeout=10)
            return resp.json()
    except Exception:
        return {"subdomains_found": 0, "open_relays_found": 0, "open_relay_hosts": [], "results": []}


def generate_recommendations(spf, dmarc, mta_sts_record, tls_rpt_record, direct_send, catch_all, msft_dkim):
    fixes = []
    if not spf:
        fixes.append("Add an SPF record to define authorized sending sources.")
    if not dmarc:
        fixes.append("Publish a DMARC record to monitor and enforce authentication.")
    elif "p=none" in dmarc.lower():
        fixes.append("Move DMARC from p=none to quarantine or reject for stronger spoof protection.")
    if not msft_dkim["enabled"]:
        fixes.append("Enable Microsoft 365 DKIM if Microsoft 365 is used for primary user mail.")
    if not mta_sts_record:
        fixes.append("Add an MTA-STS record and publish a valid policy file.")
    if not tls_rpt_record:
        fixes.append("Publish a TLS-RPT record to receive transport security failure reports.")
    if direct_send["status"] == "At Risk":
        fixes.append("Restrict Microsoft 365 so it only accepts mail from approved gateway or connector sources.")
    if direct_send["status"] == "Potential Exposure":
        fixes.append("Validate direct send exposure with a live SMTP probe against the Microsoft 365 endpoint.")
    if catch_all["status"] == "Catch-All Enabled":
        fixes.append("Disable catch-all to prevent email harvesting and reduce spam exposure.")
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
        if direct_send_status == "Potential Exposure":
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
        if direct_send_status == "At Risk":
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
        if direct_send_status == "At Risk":
            critical.append("direct send exposed")
        return "High risk. This domain is vulnerable to spoofing: " + (", ".join(critical) + "." if critical else "multiple critical controls missing.")


def calculate_score(spf, dmarc, spf_lookups, mta_sts_record, tls_rpt_record, direct_send_status, msft_dkim, catch_all_status):
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

    if direct_send_status == "At Risk":
        score -= 20
        findings.append("Direct send exposure appears likely")
    elif direct_send_status == "Potential Exposure":
        score -= 10
        findings.append("Direct send exposure requires validation")

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


@app.get("/robots.txt")
def robots():
    return FileResponse("/opt/mailflow/robots.txt")


@app.get("/")
def home(request: Request):
    return templates.TemplateResponse(request=request, name="index.html", context={})


@app.get("/analyze")
@limiter.limit("10/minute")
async def analyze(request: Request, domain: str):
    original_input = domain
    domain = extract_domain(domain)

    mx = get_mx(domain)
    vendor = detect_vendor(mx)
    spf = get_spf(domain)
    dmarc = get_dmarc(domain)
    bimi_record = get_bimi(domain)

    dkim_results = check_common_dkim(domain)
    dkim_present = any(item["found"] for item in dkim_results)
    msft_dkim = detect_msft_dkim(dkim_results)
    dkim_signing_authority = infer_dkim_signing_authority(vendor, dkim_results, msft_dkim)

    spf_lookups = count_spf_lookups(spf)
    email_senders = detect_email_senders(domain, spf)
    mta_sts_record = get_mta_sts_dns(domain)
    tls_rpt_record = get_tls_rpt(domain)
    mta_sts_policy = check_mta_sts_policy(domain)

    direct_send, catch_all, open_relay, subdomain_data = await asyncio.gather(
        evaluate_direct_send(domain, vendor, mx, dmarc, msft_dkim, email_senders),
        evaluate_catch_all(domain),
        probe_open_relay(domain),
        probe_subdomains(domain),
    )

    recommended_fixes = generate_recommendations(
        spf, dmarc, mta_sts_record, tls_rpt_record,
        direct_send, catch_all, msft_dkim,
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
    # Parse banner for software info
    fingerprint["server_software"] = ""
    if fingerprint["banners"]:
        banner = fingerprint["banners"][0]
        import re
        match = re.search(r'(?:ESMTP|SMTP)\s+([^\s(]+)', banner, re.IGNORECASE)
        if match:
            fingerprint["server_software"] = match.group(1)
    fingerprint["tls_secure"] = all("TLSv1.2" in t or "TLSv1.3" in t for t in fingerprint["tls_versions"]) if fingerprint["tls_versions"] else None

    score, risk_level, score_label, findings = calculate_score(
        spf, dmarc, spf_lookups, mta_sts_record,
        tls_rpt_record, direct_send["status"], msft_dkim, catch_all["status"],
    )

    score_summary = build_score_summary(
        score, spf, dmarc, dkim_present, mta_sts_record, direct_send["status"], findings
    )

    report_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

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
            "email_senders": email_senders,
        }
    )
