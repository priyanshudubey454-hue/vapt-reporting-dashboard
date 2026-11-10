"""Local-only mitmproxy addon for the VAPT Reporting Dashboard.

Writes redacted flow metadata to a small JSON queue because mitmproxy's
Windows installer uses a standalone Python runtime without sqlite3.
"""
from datetime import datetime, timezone
from http.cookies import SimpleCookie
import ipaddress
import json
import os
from pathlib import Path
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from mitmproxy import http

BASE_DIR = Path(__file__).resolve().parent
QUEUE_DIR = BASE_DIR / "proxy-queue"
SCOPE_FILE = BASE_DIR / "proxy_scope.json"
SENSITIVE_PARTS = ("authorization", "cookie", "token", "secret", "api-key", "apikey", "password", "referer", "location")
SENSITIVE_QUERY_PARTS = ("token", "secret", "key", "password", "auth", "session", "code")


def safe_url(raw_url):
    parts = urlsplit(raw_url)
    hostname = parts.hostname or ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    try:
        netloc = hostname + (f":{parts.port}" if parts.port else "")
    except ValueError:
        netloc = hostname
    safe_query = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if any(part in key.lower() for part in SENSITIVE_QUERY_PARTS):
            value = "[REDACTED]"
        safe_query.append((key, value))
    return urlunsplit((parts.scheme, netloc, parts.path, urlencode(safe_query), ""))[:1800]


def safe_headers(headers):
    result = []
    for name, value in list(headers.items())[:60]:
        key = str(name)
        if any(part in key.lower() for part in SENSITIVE_PARTS):
            value = "[REDACTED]"
        result.append([key[:120], str(value)[:500]])
    return result


def approved_private_hosts():
    try:
        data = json.loads(SCOPE_FILE.read_text(encoding="utf-8"))
        return {str(host).lower() for host in data.get("hosts", [])}
    except (OSError, json.JSONDecodeError, AttributeError):
        return set()


def allowed_host(host):
    candidate = host.lower().rstrip(".")
    if candidate not in approved_private_hosts():
        return False
    if candidate == "localhost":
        return True
    try:
        address = ipaddress.ip_address(candidate)
        return (address.is_private or address.is_loopback or address.is_link_local) and not address.is_multicast and not address.is_unspecified
    except ValueError:
        return False


def passive_alerts(flow):
    headers = {str(name).lower(): str(value) for name, value in flow.response.headers.items()}
    alerts = []
    checks = {
        "content-security-policy": ("Content-Security-Policy", "Review whether this application needs a Content-Security-Policy."),
        "x-content-type-options": ("X-Content-Type-Options", "Consider setting nosniff where appropriate."),
        "x-frame-options": ("X-Frame-Options", "Review framing policy to reduce clickjacking risk."),
        "referrer-policy": ("Referrer-Policy", "Review how much referrer information the site should send."),
        "permissions-policy": ("Permissions-Policy", "Review whether browser features should be restricted."),
    }
    for key, (label, recommendation) in checks.items():
        if key not in headers:
            alerts.append({"check": label, "severity": "Review", "detail": "Response header is missing.", "recommendation": recommendation})
    if flow.request.scheme == "https" and "strict-transport-security" not in headers:
        alerts.append({"check": "HSTS", "severity": "Review", "detail": "HTTPS response did not include HSTS.", "recommendation": "Review HSTS after confirming every relevant route is HTTPS-only."})
    if flow.request.scheme == "http" and not (flow.response.status_code in (301, 302, 303, 307, 308) and headers.get("location", "").lower().startswith("https://")):
        alerts.append({"check": "HTTP to HTTPS", "severity": "Review", "detail": "No HTTPS redirect was observed for this response.", "recommendation": "Review the deployment's HTTPS redirect policy."})
    for raw in flow.response.headers.get_all("set-cookie"):
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except Exception:
            continue
        for name, item in cookie.items():
            for flag in ("httponly", "samesite"):
                if not item[flag]:
                    alerts.append({"check": f"Cookie {name}: {flag.title()}", "severity": "Review", "detail": "Cookie flag is absent; confirm the application's requirements.", "recommendation": f"Review whether this cookie should set {flag.title()}."})
            if flow.request.scheme == "https" and not item["secure"]:
                alerts.append({"check": f"Cookie {name}: Secure", "severity": "Review", "detail": "HTTPS response set a cookie without Secure.", "recommendation": "Set Secure on cookies that should only travel over HTTPS."})
    return alerts


class LabHistory:
    def __init__(self):
        self.records = {}

    def save(self, record):
        QUEUE_DIR.mkdir(parents=True, exist_ok=True)
        safe_id = re.sub(r"[^A-Za-z0-9_-]", "", record["flow_id"])
        destination = QUEUE_DIR / f"{safe_id}.json"
        temporary = QUEUE_DIR / f"{safe_id}.tmp"
        temporary.write_text(json.dumps(record, ensure_ascii=True), encoding="utf-8")
        os.replace(temporary, destination)

    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.host.lower().rstrip(".")
        approved = allowed_host(host)
        record = {
            "flow_id": flow.id,
            "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "host": host[:255],
            "method": flow.request.method[:20],
            "url": safe_url(flow.request.pretty_url),
            "request_headers": safe_headers(flow.request.headers),
            "response_status": None,
            "response_headers": [],
            "request_size": len(flow.request.raw_content or b""),
            "response_size": 0,
            "alerts": [],
            "blocked_by_scope": not approved,
        }
        self.records[flow.id] = record
        if not approved:
            record["response_status"] = 403
            record["response_headers"] = [["Content-Type", "text/plain; charset=utf-8"]]
            record["alerts"] = [{"check": "Scope", "severity": "Blocked", "detail": "Host is outside the approved private lab scope.", "recommendation": "Use a localhost/private lab host listed in assessment scope."}]
            self.save(record)
            flow.response = http.Response.make(
                403, b"Blocked: host is not a private IP/localhost listed in dashboard assessment scope.",
                {"Content-Type": "text/plain; charset=utf-8"},
            )

    def response(self, flow: http.HTTPFlow) -> None:
        record = self.records.get(flow.id)
        if record is None:
            return
        record["response_status"] = flow.response.status_code
        record["response_headers"] = safe_headers(flow.response.headers)
        record["response_size"] = len(flow.response.raw_content or b"")
        try:
            record["alerts"].extend(passive_alerts(flow))
        except Exception as exc:
            record["alerts"].append({"check": "Passive analysis", "severity": "Info", "detail": str(exc)[:240], "recommendation": "Review the response manually."})
        self.save(record)
        self.records.pop(flow.id, None)

    def error(self, flow: http.HTTPFlow) -> None:
        record = self.records.get(flow.id)
        if record is None:
            return
        message = (flow.error.msg if flow.error else "Connection error")[:300]
        record["alerts"] = [{"check": "Connection", "severity": "Info", "detail": message, "recommendation": "Check that the lab target is running and listed in scope."}]
        self.save(record)
        self.records.pop(flow.id, None)


addons = [LabHistory()]
