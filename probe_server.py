from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
import socket
import ssl
import dns.resolver
from datetime import datetime, timezone

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://mailflowsentinel.com", "http://mailflowsentinel.com"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

PROBE_HELO = "probe.mailflowsentinel.com"
PROBE_FROM = "probe@mailflowsentinel.com"
TIMEOUT = 10


def resolve_eop_host(domain: str) -> str:
    return f"{domain.replace('.', '-')}.mail.protection.outlook.com"


def eop_host_resolves(eop_host: str) -> bool:
    try:
        dns.resolver.resolve(eop_host, "A")
        return True
    except Exception:
        try:
            dns.resolver.resolve(eop_host, "AAAA")
            return True
        except Exception:
            return False


def get_mx_hosts(domain: str) -> list:
    try:
        answers = dns.resolver.resolve(domain, "MX")
        records = sorted(
            [(r.preference, str(r.exchange).rstrip(".")) for r in answers],
            key=lambda x: x[0]
        )
        return [host for _, host in records]
    except Exception:
        return []


def smtp_connect(host: str) -> tuple:
    """Open SMTP connection, return (sock, banner, ehlo_response)"""
    sock = socket.create_connection((host, 25), timeout=TIMEOUT)
    banner = sock.recv(1024).decode(errors="replace")

    sock.sendall(f"EHLO {PROBE_HELO}\r\n".encode())
    ehlo_resp = sock.recv(4096).decode(errors="replace")

    if "STARTTLS" in ehlo_resp:
        sock.sendall(b"STARTTLS\r\n")
        starttls_resp = sock.recv(1024).decode(errors="replace")
        if starttls_resp.startswith("220"):
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.sendall(f"EHLO {PROBE_HELO}\r\n".encode())
            ehlo_resp = sock.recv(4096).decode(errors="replace")

    return sock, banner, ehlo_resp


def smtp_probe_direct_send(eop_host: str, domain: str) -> dict:
    """Probe EOP endpoint for direct send exposure."""
    result = {
        "host": eop_host,
        "status": "Inconclusive",
        "smtp_code": None,
        "smtp_response": None,
        "stage": None,
        "error": None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    try:
        sock, banner, ehlo_resp = smtp_connect(eop_host)
        result["stage"] = "ehlo_tls"

        sock.sendall(f"MAIL FROM:<{PROBE_FROM}>\r\n".encode())
        mail_resp = sock.recv(1024).decode(errors="replace")
        result["stage"] = "mail_from"

        if not mail_resp.startswith("250"):
            result["status"] = "Inconclusive"
            result["smtp_code"] = int(mail_resp[:3]) if mail_resp[:3].isdigit() else None
            result["smtp_response"] = mail_resp.strip()
            sock.close()
            return result

        test_recipient = f"probe-test@{domain}"
        sock.sendall(f"RCPT TO:<{test_recipient}>\r\n".encode())
        rcpt_resp = sock.recv(1024).decode(errors="replace")
        result["stage"] = "rcpt_to"
        result["smtp_response"] = rcpt_resp.strip()

        code = int(rcpt_resp[:3]) if rcpt_resp[:3].isdigit() else None
        result["smtp_code"] = code

        if code == 550 and ("5.7.68" in rcpt_resp or "TenantInboundAttribution" in rcpt_resp):
            result["status"] = "Protected"
        elif code == 550 and "5.7.64" in rcpt_resp:
            result["status"] = "Protected"
        elif code == 250:
            result["status"] = "Exposed"
        elif code == 550:
            result["status"] = "Exposed"
        else:
            result["status"] = "Inconclusive"

        sock.sendall(b"QUIT\r\n")
        sock.close()

    except socket.timeout:
        result["status"] = "Timeout"
        result["error"] = "Connection timed out"
    except socket.gaierror as e:
        result["status"] = "DNS Error"
        result["error"] = str(e)
    except Exception as e:
        result["status"] = "Error"
        result["error"] = str(e)

    return result


def smtp_probe_open_relay(mx_host: str, domain: str) -> dict:
    """
    Test if a mail server is an open relay.
    An open relay will accept mail FROM an external domain TO an external domain
    without authentication.
    
    Test: MAIL FROM external → RCPT TO external (neither is the target domain)
    If accepted = open relay confirmed.
    """
    result = {
        "host": mx_host,
        "status": "Unknown",
        "smtp_code": None,
        "smtp_response": None,
        "stage": None,
        "tls_version": None,
        "banner": None,
        "ehlo_capabilities": [],
        "error": None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    try:
        sock, banner, ehlo_resp = smtp_connect(mx_host)
        result["banner"] = banner.strip()
        result["stage"] = "connected"

        # Extract TLS version if available
        if hasattr(sock, "version"):
            result["tls_version"] = sock.version()

        # Extract EHLO capabilities
        caps = []
        for line in ehlo_resp.splitlines():
            if line.startswith("250-") or line.startswith("250 "):
                cap = line[4:].strip()
                if cap and cap != PROBE_HELO:
                    caps.append(cap)
        result["ehlo_capabilities"] = caps

        # Open relay test:
        # From: external address (not the target domain)
        # To: another external address (not the target domain)
        relay_from = "test@example-probe-check.com"
        relay_to = "relay-check@mailflowsentinel-test.com"

        sock.sendall(f"MAIL FROM:<{relay_from}>\r\n".encode())
        mail_resp = sock.recv(1024).decode(errors="replace")
        result["stage"] = "mail_from"

        mail_code = int(mail_resp[:3]) if mail_resp[:3].isdigit() else None

        if mail_code != 250:
            # Server rejected MAIL FROM — not an open relay
            result["status"] = "Not Open Relay"
            result["smtp_code"] = mail_code
            result["smtp_response"] = mail_resp.strip()
            sock.sendall(b"QUIT\r\n")
            sock.close()
            return result

        sock.sendall(f"RCPT TO:<{relay_to}>\r\n".encode())
        rcpt_resp = sock.recv(1024).decode(errors="replace")
        result["stage"] = "rcpt_to"
        result["smtp_response"] = rcpt_resp.strip()

        rcpt_code = int(rcpt_resp[:3]) if rcpt_resp[:3].isdigit() else None
        result["smtp_code"] = rcpt_code

        if rcpt_code == 250:
            result["status"] = "Open Relay"
        elif rcpt_code in [550, 554, 553, 551, 552]:
            result["status"] = "Not Open Relay"
        else:
            result["status"] = "Inconclusive"

        sock.sendall(b"QUIT\r\n")
        sock.close()

    except socket.timeout:
        result["status"] = "Timeout"
        result["error"] = "Connection timed out"
    except socket.gaierror as e:
        result["status"] = "DNS Error"
        result["error"] = str(e)
    except Exception as e:
        result["status"] = "Error"
        result["error"] = str(e)

    return result


@app.get("/probe")
def probe(domain: str = Query(..., description="Domain to probe for direct send")):
    domain = domain.strip().lower()
    eop_host = resolve_eop_host(domain)

    if not eop_host_resolves(eop_host):
        return {
            "domain": domain,
            "eop_host": eop_host,
            "status": "Not Applicable",
            "reason": "No Microsoft 365 EOP endpoint found for this domain.",
            "smtp_code": None,
            "smtp_response": None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    result = smtp_probe_direct_send(eop_host, domain)
    result["domain"] = domain

    if result["status"] == "Protected":
        result["reason"] = (
            "Microsoft 365 rejected the connection with a TenantInboundAttribution block. "
            "Direct send is not allowed from unauthorized sources."
        )
    elif result["status"] == "Exposed":
        result["reason"] = (
            "Microsoft 365 accepted the SMTP connection without a connector restriction block. "
            "Note: transport rule-based blocking may still be in place internally."
        )
    elif result["status"] == "Timeout":
        result["reason"] = "Connection to the EOP endpoint timed out."
    else:
        result["reason"] = result.get("error", "Unknown error during probe.")

    return result


@app.get("/relay")
def relay(domain: str = Query(..., description="Domain to test for open relay")):
    """
    Test the domain's MX servers for open relay misconfiguration.
    An open relay will forward email from external senders to external recipients
    without authentication — enabling spam, phishing, and BEC attacks.
    """
    domain = domain.strip().lower()
    mx_hosts = get_mx_hosts(domain)

    if not mx_hosts:
        return {
            "domain": domain,
            "status": "No MX Records",
            "reason": "No MX records found for this domain.",
            "results": [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    results = []
    overall_status = "Not Open Relay"

    for mx_host in mx_hosts[:2]:  # Test top 2 MX hosts
        probe_result = smtp_probe_open_relay(mx_host, domain)
        results.append(probe_result)

        if probe_result["status"] == "Open Relay":
            overall_status = "Open Relay"

    # Build summary reason
    if overall_status == "Open Relay":
        reason = (
            "One or more MX servers accepted relay of mail from an external sender "
            "to an external recipient without authentication. This server can be used "
            "to send spam or phishing email impersonating this domain."
        )
    else:
        reason = "MX servers rejected external-to-external relay attempts. No open relay detected."

    return {
        "domain": domain,
        "status": overall_status,
        "reason": reason,
        "mx_tested": [r["host"] for r in results],
        "results": results,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/catchall")
def catchall(domain: str = Query(..., description="Domain to test for catch-all")):
    domain = domain.strip().lower()
    mx_hosts = get_mx_hosts(domain)

    if not mx_hosts:
        return {
            "domain": domain,
            "status": "No MX Records",
            "reason": "No MX records found.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    result = {
        "domain": domain,
        "status": "Unknown",
        "smtp_code": None,
        "smtp_response": None,
        "mx_tested": mx_hosts[0],
        "reason": "",
        "error": None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    try:
        sock, banner, ehlo_resp = smtp_connect(mx_hosts[0])

        sock.sendall(f"MAIL FROM:<{PROBE_FROM}>\r\n".encode())
        mail_resp = sock.recv(1024).decode(errors="replace")

        if not mail_resp.startswith("250"):
            result["status"] = "Inconclusive"
            result["reason"] = "Server rejected MAIL FROM during catch-all test."
            sock.close()
            return result

        random_addr = f"zxqj8472catchalltest9183@{domain}"
        sock.sendall(f"RCPT TO:<{random_addr}>\r\n".encode())
        rcpt_resp = sock.recv(1024).decode(errors="replace")

        code = int(rcpt_resp[:3]) if rcpt_resp[:3].isdigit() else None
        result["smtp_code"] = code
        result["smtp_response"] = rcpt_resp.strip()

        if code == 250:
            result["status"] = "Catch-All Enabled"
            result["reason"] = (
                "The mail server accepted delivery to a nonexistent address. "
                "This domain accepts all incoming email regardless of whether the mailbox exists. "
                "Attackers can use this for email harvesting, phishing infrastructure, and BEC reconnaissance."
            )
        elif code in [550, 551, 552, 553, 554]:
            result["status"] = "No Catch-All"
            result["reason"] = "Server rejected the nonexistent address. Catch-all is not configured."
        elif code == 451:
            result["status"] = "Inconclusive"
            result["reason"] = "Server returned a temporary error. May be rate limiting or greylisting."
        else:
            result["status"] = "Inconclusive"
            result["reason"] = f"Unexpected SMTP response code {code}."

        sock.sendall(b"QUIT\r\n")
        sock.close()

    except socket.timeout:
        result["status"] = "Timeout"
        result["error"] = "Connection timed out"
    except Exception as e:
        result["status"] = "Error"
        result["error"] = str(e)

    return result


@app.get("/subdomains")
def subdomains(domain: str = Query(..., description="Domain to check mail subdomains")):
    """
    Test common mail-related subdomains for open SMTP ports and relay misconfiguration.
    Subdomains like mail., smtp., webmail. are often forgotten and left misconfigured.
    """
    domain = domain.strip().lower()
    prefixes = ["mail", "smtp", "webmail", "mx", "mx1", "mx2", "relay", "mailhost", "exchange"]
    
    results = []
    
    for prefix in prefixes:
        subdomain = f"{prefix}.{domain}"
        result = {
            "subdomain": subdomain,
            "resolves": False,
            "smtp_open": False,
            "banner": None,
            "tls_version": None,
            "open_relay": None,
            "error": None,
        }
        
        # Check if subdomain resolves
        try:
            dns.resolver.resolve(subdomain, "A")
            result["resolves"] = True
        except Exception:
            results.append(result)
            continue
        
        # Try SMTP connection
        try:
            sock, banner, ehlo_resp = smtp_connect(subdomain)
            result["smtp_open"] = True
            result["banner"] = banner.strip()
            
            if hasattr(sock, "version"):
                result["tls_version"] = sock.version()
            
            # Quick relay test
            sock.sendall(f"MAIL FROM:<{PROBE_FROM}>\r\n".encode())
            mail_resp = sock.recv(1024).decode(errors="replace")
            
            if mail_resp.startswith("250"):
                relay_to = "relay-check@mailflowsentinel-test.com"
                sock.sendall(f"RCPT TO:<{relay_to}>\r\n".encode())
                rcpt_resp = sock.recv(1024).decode(errors="replace")
                code = int(rcpt_resp[:3]) if rcpt_resp[:3].isdigit() else None
                result["open_relay"] = (code == 250)
            
            sock.sendall(b"QUIT\r\n")
            sock.close()
            
        except socket.timeout:
            result["error"] = "Timeout"
        except Exception as e:
            result["error"] = str(e)[:80]
        
        results.append(result)
    
    # Only return subdomains that resolve
    found = [r for r in results if r["resolves"]]
    open_relays = [r["subdomain"] for r in found if r["open_relay"]]
    
    return {
        "domain": domain,
        "subdomains_found": len(found),
        "open_relays_found": len(open_relays),
        "open_relay_hosts": open_relays,
        "results": found,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
