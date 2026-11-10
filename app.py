from contextlib import contextmanager
from datetime import datetime, timezone
from hmac import compare_digest
from io import BytesIO
import ipaddress
import json
import os
from pathlib import Path
from secrets import token_urlsafe
import re
import socket
import ssl
import sqlite3
import subprocess
import textwrap
from http.cookies import SimpleCookie
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from flask import Flask, abort, flash, redirect, render_template, request, send_file, session, url_for

app = Flask(__name__)
app.secret_key = "local-learning-key-change-before-deployment"
BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "vapt_dashboard.db"
PROXY_SCOPE_FILE = BASE_DIR / "proxy_scope.json"
PROXY_QUEUE = BASE_DIR / "proxy-queue"
SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")
STATUSES = ("Open", "In Progress", "Fixed", "Retest")


@contextmanager
def db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db():
    with db_connection() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                asset TEXT NOT NULL,
                severity TEXT NOT NULL,
                cvss REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open',
                description TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                evidence TEXT NOT NULL DEFAULT '',
                retest_notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        existing = {row["name"] for row in db.execute("PRAGMA table_info(vulnerabilities)")}
        migrations = {
            "evidence": "TEXT NOT NULL DEFAULT ''",
            "retest_notes": "TEXT NOT NULL DEFAULT ''",
            "updated_at": "TEXT NOT NULL DEFAULT ''",
        }
        for column, definition in migrations.items():
            if column not in existing:
                db.execute(f"ALTER TABLE vulnerabilities ADD COLUMN {column} {definition}")
        db.execute("""
            UPDATE vulnerabilities SET severity = CASE
                WHEN cvss >= 9 THEN 'Critical'
                WHEN cvss >= 7 THEN 'High'
                WHEN cvss >= 4 THEN 'Medium'
                WHEN cvss > 0 THEN 'Low'
                ELSE 'Informational'
            END
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS assessment (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                title TEXT NOT NULL DEFAULT 'VAPT Assessment',
                organization TEXT NOT NULL DEFAULT '',
                assessor TEXT NOT NULL DEFAULT '',
                scope TEXT NOT NULL DEFAULT '',
                authorization TEXT NOT NULL DEFAULT '',
                assessment_window TEXT NOT NULL DEFAULT '',
                methodology TEXT NOT NULL DEFAULT 'OWASP Testing Guide / authorized lab review',
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.execute("INSERT OR IGNORE INTO assessment (id) VALUES (1)")
        db.execute("""
            CREATE TABLE IF NOT EXISTS scan_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                results_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS proxy_flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flow_id TEXT NOT NULL UNIQUE,
                captured_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                host TEXT NOT NULL,
                method TEXT NOT NULL,
                url TEXT NOT NULL,
                request_headers_json TEXT NOT NULL DEFAULT '[]',
                response_status INTEGER,
                response_headers_json TEXT NOT NULL DEFAULT '[]',
                request_size INTEGER NOT NULL DEFAULT 0,
                response_size INTEGER NOT NULL DEFAULT 0,
                alerts_json TEXT NOT NULL DEFAULT '[]',
                blocked_by_scope INTEGER NOT NULL DEFAULT 0
            )
        """)


def hosts_in_scope(scope):
    hosts = {"localhost"} if re.search(r"\blocalhost\b", scope, re.I) else set()
    for candidate in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", scope):
        try:
            address = ipaddress.ip_address(candidate)
            if address.is_private or address.is_loopback or address.is_link_local:
                hosts.add(address.compressed)
        except ValueError:
            continue
    return sorted(hosts)


def sync_proxy_scope():
    scope = get_assessment()["scope"]
    temporary = PROXY_SCOPE_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps({"hosts": hosts_in_scope(scope)}), encoding="utf-8")
    temporary.replace(PROXY_SCOPE_FILE)


def import_proxy_queue():
    if not PROXY_QUEUE.exists():
        return
    pending = []
    for path in PROXY_QUEUE.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("flow_id") and data.get("host") and data.get("url"):
                pending.append((path, data))
        except (OSError, json.JSONDecodeError):
            continue
    if not pending:
        return
    with db_connection() as db:
        for _, data in pending:
            db.execute("""
                INSERT OR REPLACE INTO proxy_flows
                (flow_id, captured_at, host, method, url, request_headers_json, response_status,
                 response_headers_json, request_size, response_size, alerts_json, blocked_by_scope)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                data["flow_id"], data.get("captured_at") or "", data["host"], data.get("method", "GET"),
                data["url"], json.dumps(data.get("request_headers", [])), data.get("response_status"),
                json.dumps(data.get("response_headers", [])), int(data.get("request_size", 0)),
                int(data.get("response_size", 0)), json.dumps(data.get("alerts", [])),
                int(bool(data.get("blocked_by_scope", False))),
            ))
    for path, _ in pending:
        try:
            path.unlink()
        except OSError:
            pass


def get_findings(search="", severity="", status=""):
    sql = "SELECT * FROM vulnerabilities WHERE 1=1"
    params = []
    if search:
        sql += " AND (title LIKE ? OR asset LIKE ? OR description LIKE ?)"
        pattern = f"%{search}%"
        params.extend((pattern, pattern, pattern))
    if severity in SEVERITIES:
        sql += " AND severity = ?"
        params.append(severity)
    if status in STATUSES:
        sql += " AND status = ?"
        params.append(status)
    sql += " ORDER BY id DESC"
    with db_connection() as db:
        return db.execute(sql, params).fetchall()


def get_finding(finding_id):
    with db_connection() as db:
        return db.execute("SELECT * FROM vulnerabilities WHERE id = ?", (finding_id,)).fetchone()


def get_assessment():
    with db_connection() as db:
        return db.execute("SELECT * FROM assessment WHERE id = 1").fetchone()


def severity_for_score(score):
    """Map a CVSS v3.x score to its standard severity band."""
    if score == 0:
        return "Informational"
    if score < 4:
        return "Low"
    if score < 7:
        return "Medium"
    if score < 9:
        return "High"
    return "Critical"


def validate_finding(form):
    title = form.get("title", "").strip()
    asset = form.get("asset", "").strip()
    description = form.get("description", "").strip()
    recommendation = form.get("recommendation", "").strip()
    evidence = form.get("evidence", "").strip()
    retest_notes = form.get("retest_notes", "").strip()
    status = form.get("status", "Open")
    try:
        cvss = float(form.get("cvss", ""))
    except ValueError:
        cvss = -1

    if not all((title, asset, description, recommendation)):
        return None, "Title, asset, description and remediation are required."
    if status not in STATUSES:
        return None, "Choose a valid remediation status."
    if not 0 <= cvss <= 10:
        return None, "CVSS score must be between 0 and 10."
    values = (title, asset, severity_for_score(cvss), cvss, status, description, recommendation, evidence, retest_notes)
    return values, None


def run_safe_web_scan(target):
    """One non-following GET and a TLS handshake against a private lab address."""
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Enter a full http:// or https:// lab URL without login credentials.")
    if parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise ValueError("For safety, scan only the target site's base URL without a path, query, or fragment.")
    try:
        try:
            ip = ipaddress.ip_address(parsed.hostname)
            addresses = {ip.compressed}
        except ValueError:
            if parsed.hostname.lower() != "localhost":
                raise ValueError("Use localhost or a private lab IP address, such as 192.168.56.101.")
            addresses = {item[4][0] for item in socket.getaddrinfo("localhost", parsed.port or 80, type=socket.SOCK_STREAM)}
        for address in addresses:
            ip = ipaddress.ip_address(address.split("%", 1)[0])
            if not (ip.is_private or ip.is_loopback or ip.is_link_local) or ip.is_multicast or ip.is_unspecified:
                raise ValueError("Scanner only allows localhost or private lab IP addresses.")
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve localhost: {exc}") from exc

    observation = {
        "target": target,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "http_status": None,
        "findings": [],
    }
    req = Request(target, headers={"User-Agent": "VAPT-Lab-Scanner/1.0", "Accept": "text/html,*/*;q=0.5"}, method="GET")

    class StopRedirects(HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, new_url):
            return None

    opener = build_opener(ProxyHandler({}), StopRedirects)
    headers = {}
    set_cookies = []
    try:
        try:
            response = opener.open(req, timeout=6)
        except HTTPError as exc:
            response = exc
        with response:
            observation["http_status"] = response.getcode()
            headers = {key.lower(): value for key, value in response.headers.items()}
            set_cookies = response.headers.get_all("Set-Cookie") or []
    except (URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise ValueError(f"Could not reach the lab target: {reason}") from exc

    if parsed.scheme == "http":
        location = headers.get("location", "")
        if observation["http_status"] in (301, 302, 303, 307, 308) and location.lower().startswith("https://"):
            observation["findings"].append({"check": "HTTP to HTTPS", "severity": "pass", "detail": "HTTP response redirects to HTTPS (redirect was not followed)."})
        else:
            observation["findings"].append({"check": "HTTP to HTTPS", "severity": "review", "detail": "No HTTPS redirect was observed from this response. Review the intended deployment policy."})

    header_advice = {
        "strict-transport-security": ("HSTS", "Consider HSTS after confirming the site is HTTPS-only."),
        "content-security-policy": ("Content-Security-Policy", "Review whether a Content-Security-Policy suits this application."),
        "x-content-type-options": ("X-Content-Type-Options", "Consider setting nosniff."),
        "x-frame-options": ("X-Frame-Options", "Review framing policy to reduce clickjacking risk."),
        "referrer-policy": ("Referrer-Policy", "Review how much referrer information the site should send."),
        "permissions-policy": ("Permissions-Policy", "Review whether browser features should be restricted."),
    }
    for key, (label, advice) in header_advice.items():
        value = headers.get(key)
        observation["findings"].append({
            "check": label,
            "severity": "pass" if value else "review",
            "detail": "Header is present." if value else f"Header missing. {advice}",
        })

    cookie_values = []
    for raw_cookie in set_cookies:
        parsed_cookie = SimpleCookie()
        try:
            parsed_cookie.load(raw_cookie)
        except Exception:
            continue
        for name, cookie in parsed_cookie.items():
            flags = [key for key in ("Secure", "HttpOnly", "SameSite") if cookie[key.lower()]]
            missing = [key for key in ("Secure", "HttpOnly", "SameSite") if key not in flags]
            cookie_values.append({"name": name, "flags": flags, "missing": missing})
    observation["cookies"] = cookie_values
    for cookie in cookie_values:
        for flag in cookie["missing"]:
            observation["findings"].append({"check": f"Cookie {cookie['name']}: {flag}", "severity": "review", "detail": f"Cookie may need the {flag} attribute; confirm the app's requirements."})

    if parsed.scheme == "https":
        try:
            context = ssl.create_default_context()
            with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=6) as connection:
                with context.wrap_socket(connection, server_hostname=parsed.hostname) as tls:
                    certificate = tls.getpeercert()
                    version = tls.version()
            expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(certificate["notAfter"]), timezone.utc)
            days_left = (expires - datetime.now(timezone.utc)).days
            observation["tls"] = {"version": version, "expires_at": expires.isoformat(), "days_until_expiry": days_left}
            observation["findings"].append({"check": "TLS certificate", "severity": "pass" if days_left >= 21 else "review", "detail": f"TLS {version}; certificate expires in {days_left} days."})
        except Exception as exc:
            observation["findings"].append({"check": "TLS certificate", "severity": "review", "detail": f"Could not verify certificate: {exc}"})
    else:
        observation["findings"].append({"check": "TLS certificate", "severity": "info", "detail": "Target URL uses HTTP; no TLS certificate was checked."})
    return observation


@app.before_request
def protect_post_requests():
    token = session.setdefault("_csrf_token", token_urlsafe(32))
    if request.method == "POST":
        submitted = request.form.get("_csrf_token", "")
        if not compare_digest(token, submitted):
            abort(400, description="Form token is missing or expired. Reload the page and try again.")


@app.context_processor
def inject_template_values():
    return {"csrf_token": session.get("_csrf_token", "")}


@app.route("/")
def index():
    search = request.args.get("q", "").strip()
    severity = request.args.get("severity", "")
    status = request.args.get("status", "")
    findings = get_findings(search, severity, status)
    with db_connection() as db:
        counts = {row["severity"]: row["n"] for row in db.execute(
            "SELECT severity, COUNT(*) AS n FROM vulnerabilities GROUP BY severity"
        )}
        statuses = {row["status"]: row["n"] for row in db.execute(
            "SELECT status, COUNT(*) AS n FROM vulnerabilities GROUP BY status"
        )}
    stats = {
        "total": sum(counts.values()),
        "critical": counts.get("Critical", 0),
        "high": counts.get("High", 0),
        "medium": counts.get("Medium", 0),
        "low": counts.get("Low", 0),
        "informational": counts.get("Informational", 0),
        "open": statuses.get("Open", 0),
        "in_progress": statuses.get("In Progress", 0),
        "fixed": statuses.get("Fixed", 0),
        "retest": statuses.get("Retest", 0),
    }
    return render_template(
        "index.html", project_name="Mini Web VAPT Workbench", findings=findings,
        stats=stats, statuses=STATUSES, severities=SEVERITIES,
        filters={"q": search, "severity": severity, "status": status},
        assessment=get_assessment(),
    )


@app.route("/demo-data", methods=["POST"])
def load_demo_data():
    """Add clearly labeled fictional findings for a guided screen-recording demo."""
    samples = [
        (
            "DEMO ONLY — Missing browser security headers", "127.0.0.1:5055", "Medium", 5.3, "Open",
            "Illustrative training record based on the local scanner's header review. This is sample data, not a confirmed vulnerability.",
            "Review and configure an appropriate Content-Security-Policy, X-Content-Type-Options, Referrer-Policy, and framing policy for the real application.",
            "Demo evidence: local scanner reported selected response headers missing. Validate each header against application requirements before treating this as a real finding.", "",
        ),
        (
            "DEMO ONLY — HTTP used by local learning app", "127.0.0.1:5055", "Low", 3.1, "In Progress",
            "Illustrative training record. The development dashboard is served over HTTP on loopback; this does not establish risk for a production deployment.",
            "For a deployed environment, terminate TLS at a trusted reverse proxy and redirect HTTP to HTTPS. Keep the development server local.",
            "Demo evidence: local URL begins with http://. Sample record only; review actual deployment architecture.", "",
        ),
        (
            "DEMO ONLY — Review cookie security flags", "127.0.0.1:5055", "Informational", 0.0, "Retest",
            "Illustrative checklist entry to demonstrate remediation tracking. The scanner's cookie observations require manual validation.",
            "For session cookies, evaluate Secure, HttpOnly, and SameSite attributes based on the application's transport and login flow.",
            "Demo evidence: training placeholder; no real user session or secret is recorded.", "Retest the cookie flags after applying an approved configuration change.",
        ),
    ]
    with db_connection() as db:
        for sample in samples:
            exists = db.execute("SELECT 1 FROM vulnerabilities WHERE title = ?", (sample[0],)).fetchone()
            if not exists:
                db.execute("""INSERT INTO vulnerabilities
                    (title, asset, severity, cvss, status, description, recommendation, evidence, retest_notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""", sample)
    flash("Clearly labeled demo records are ready. They are fictional examples, not confirmed findings.", "success")
    return redirect(url_for("index"))


@app.route("/scanner", methods=["GET", "POST"])
def scanner():
    latest = None
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        if request.form.get("authorized") != "yes":
            flash("Confirm that you own or have written permission to assess this lab target.", "error")
        else:
            host = urlparse(target).hostname or ""
            assessment_scope = get_assessment()["scope"]
            if not host or host.casefold() not in assessment_scope.casefold():
                flash("Add this exact host or IP to Assessment details → authorized scope before scanning.", "error")
            else:
                try:
                    result = run_safe_web_scan(target)
                except ValueError as exc:
                    flash(str(exc), "error")
                else:
                    with db_connection() as db:
                        cursor = db.execute(
                            "INSERT INTO scan_runs (target, results_json) VALUES (?, ?)",
                            (target, json.dumps(result)),
                        )
                        scan_id = cursor.lastrowid
                    return redirect(url_for("scanner_result", scan_id=scan_id))
    return render_template("scanner.html", latest=latest)


@app.route("/scanner/<int:scan_id>")
def scanner_result(scan_id):
    with db_connection() as db:
        scan = db.execute("SELECT * FROM scan_runs WHERE id = ?", (scan_id,)).fetchone()
    if scan is None:
        abort(404)
    result = json.loads(scan["results_json"])
    return render_template("scanner.html", latest=result, scan=scan)


@app.route("/security-lab", methods=["GET", "POST"])
def security_lab():
    results = None
    target = "http://127.0.0.1:3000"
    if request.method == "POST":
        mode = request.form.get("mode", "")
        if mode not in ("vulnerable", "fixed"):
            abort(400, description="Choose a practice scenario.")
        vulnerable = mode == "vulnerable"
        results = [
            {
                "name": "SQL injection (SQLi)",
                "outcome": "FAIL — simulated weakness detected" if vulnerable else "PASS — parameterized-query behavior",
                "evidence": "Training simulation: a crafted search condition returned unrelated sample records." if vulnerable else "Training simulation: the crafted search text was treated as data; no unrelated sample records were returned.",
                "fix": "Use parameterized SQL queries; never build SQL by joining user input into a query string.",
            },
            {
                "name": "IDOR / BOLA access control",
                "outcome": "FAIL — simulated unauthorized access" if vulnerable else "PASS — server-side ownership check",
                "evidence": "Training simulation: User B received User A's private sample record (HTTP 200)." if vulnerable else "Training simulation: User B was denied access to User A's private sample record (HTTP 403).",
                "fix": "Check the signed-in user's permission for every object on the server; do not rely on hidden buttons or unpredictable IDs.",
            },
        ]
        samples = [
            ("TRAINING SIMULATION — SQL injection in search", "High", 8.1,
             "The built-in fictional vulnerable scenario returned unrelated sample records for crafted search text. No real SQL injection was sent to any target.",
             "Use parameterized SQL queries and add regression tests for search input."),
            ("TRAINING SIMULATION — IDOR / BOLA object access", "High", 7.5,
             "The built-in fictional vulnerable scenario let User B read User A's sample record. No external API or account was accessed.",
             "Enforce object-level authorization on the server for every read and update, based on the authenticated user."),
        ]
        with db_connection() as db:
            for title, severity, cvss, description, recommendation in samples:
                row = db.execute("SELECT id FROM vulnerabilities WHERE title = ?", (title,)).fetchone()
                if vulnerable and not row:
                    db.execute("""INSERT INTO vulnerabilities
                        (title, asset, severity, cvss, status, description, recommendation, evidence, retest_notes)
                        VALUES (?, ?, ?, ?, 'Open', ?, ?, ?, '')""", (
                        title, "Built-in practice lab (simulated)", severity, cvss, description, recommendation,
                        "Training simulation only; fictional request/response behavior.",
                    ))
                elif vulnerable and row:
                    db.execute("UPDATE vulnerabilities SET status='Open', retest_notes='', updated_at=CURRENT_TIMESTAMP WHERE id=?", (row["id"],))
                elif not vulnerable and row:
                    db.execute("""UPDATE vulnerabilities SET status='Fixed', retest_notes=?, updated_at=CURRENT_TIMESTAMP
                        WHERE id=?""", ("Retest passed in the fixed built-in simulation; sample only, not a real system retest.", row["id"]))
    return render_template("security_lab.html", results=results, target=target)


def validate_juice_shop_target(target):
    parsed = urlparse(target)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "http" or not host or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("Use the HTTP base URL only, for example http://192.168.56.101:3000.")
    allowed = {item.lower() for item in hosts_in_scope(get_assessment()["scope"])}
    if host not in allowed:
        raise ValueError("First add this exact private lab IP to Assessment details → authorized scope.")
    try:
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError("The lab URL port must be between 1 and 65535.")
    except ValueError as exc:
        raise ValueError("Enter a valid port in the lab URL.") from exc
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if host != "localhost":
            raise ValueError("Use localhost or a private IPv4 address that is already in scope.")
    else:
        if not (ip.is_private or ip.is_loopback or ip.is_link_local) or ip.is_multicast or ip.is_unspecified:
            raise ValueError("Only localhost and private lab IP addresses are allowed.")
    return target.rstrip("/")


def juice_shop_request(url, method="GET", payload=None, token=None):
    headers = {"User-Agent": "VAPT-Workbench-Authorized-Lab/1.0", "Accept": "application/json,text/html;q=0.5"}
    body = None
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = Request(url, data=body, headers=headers, method=method)

    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, response_headers, new_url):
            return None

    opener = build_opener(ProxyHandler({}), NoRedirect)
    try:
        try:
            response = opener.open(req, timeout=8)
        except HTTPError as exc:
            response = exc
        with response:
            return response.getcode(), response.read(512 * 1024)
    except (URLError, TimeoutError, OSError) as exc:
        raise ValueError("Could not reach the scoped lab. Check that Juice Shop is running and the IP/port is correct.") from exc


def store_live_candidate(title, asset, cvss, description, recommendation, evidence):
    with db_connection() as db:
        exists = db.execute("SELECT id FROM vulnerabilities WHERE title=? AND asset=?", (title, asset)).fetchone()
        if not exists:
            db.execute("""INSERT INTO vulnerabilities
                (title, asset, severity, cvss, status, description, recommendation, evidence, retest_notes)
                VALUES (?, ?, ?, ?, 'Open', ?, ?, ?, '')""", (
                title, asset, severity_for_score(cvss), cvss, description, recommendation, evidence,
            ))


@app.route("/juice-shop", methods=["GET", "POST"])
def juice_shop_checks():
    results = None
    target_value = request.form.get("target", "http://127.0.0.1:3000").strip()
    if request.method == "POST":
        if request.form.get("authorized") != "yes":
            flash("Confirm that this is your own authorized Juice Shop lab.", "error")
        else:
            try:
                base = validate_juice_shop_target(target_value)
                test_type = request.form.get("test_type", "")
                if test_type == "sqli":
                    # A single read-only search request with a quote/semicolon checks for exposed SQL errors.
                    status, body = juice_shop_request(f"{base}/rest/products/search?q={quote(chr(39) + chr(59))}")
                    text = body.decode("utf-8", errors="replace")
                    sql_error = status >= 500 and any(marker in text.casefold() for marker in (
                        "sqlite_error", "sql syntax", "sequelize", "syntax error",
                    ))
                    results = [{
                        "name": "Product search SQL input check",
                        "outcome": "Candidate SQL error disclosure detected" if sql_error else "No SQL error signature observed",
                        "evidence": f"One read-only request; HTTP {status}. SQL response body was inspected for an error signature but was not saved.",
                        "fix": "Use parameterized queries and return generic errors; manually validate before confirming SQL injection.",
                        "result_class": "review" if sql_error else "info",
                    }]
                    if sql_error:
                        store_live_candidate(
                            "Candidate — SQL error from product search", base, 5.3,
                            "A single harmless quote/semicolon search probe caused a database-style server error. This is a candidate signal, not proof of data extraction or confirmed SQL injection.",
                            "Use parameterized queries and generic error handling; manually verify the affected code path.",
                            f"HTTP {status}; SQL error marker detected. Response body was not retained.",
                        )
                elif test_type == "idor":
                    owner_email = request.form.get("owner_email", "").strip()
                    owner_password = request.form.get("owner_password", "")
                    other_email = request.form.get("other_email", "").strip()
                    other_password = request.form.get("other_password", "")
                    if not all((owner_email, owner_password, other_email, other_password)) or owner_email.casefold() == other_email.casefold():
                        raise ValueError("Enter two different throwaway lab accounts and their passwords.")
                    owner_status, owner_body = juice_shop_request(f"{base}/rest/user/login", "POST", {"email": owner_email, "password": owner_password})
                    other_status, other_body = juice_shop_request(f"{base}/rest/user/login", "POST", {"email": other_email, "password": other_password})
                    try:
                        owner_auth = json.loads(owner_body).get("authentication", {})
                        other_auth = json.loads(other_body).get("authentication", {})
                    except (json.JSONDecodeError, AttributeError):
                        owner_auth, other_auth = {}, {}
                    owner_token, owner_bid = owner_auth.get("token"), owner_auth.get("bid")
                    other_token, other_bid = other_auth.get("token"), other_auth.get("bid")
                    if owner_status != 200 or other_status != 200 or not all((owner_token, owner_bid, other_token, other_bid)):
                        raise ValueError("A lab login did not succeed. Check both test accounts; credentials and tokens are not saved.")
                    if (not re.fullmatch(r"[A-Za-z0-9_.-]{1,8192}", str(owner_token))
                            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,8192}", str(other_token))
                            or not str(other_bid).isdigit() or len(str(other_bid)) > 12):
                        raise ValueError("The lab returned an unexpected login response. No result was saved.")
                    # Read the second account's basket once as its owner and once as the other account.
                    own_status, own_body = juice_shop_request(f"{base}/rest/basket/{other_bid}", token=other_token)
                    cross_status, cross_body = juice_shop_request(f"{base}/rest/basket/{other_bid}", token=owner_token)
                    try:
                        own_data = json.loads(own_body).get("data")
                        cross_data = json.loads(cross_body).get("data")
                        own_products = own_data.get("Products", []) if isinstance(own_data, dict) else own_data
                        cross_products = cross_data.get("Products", []) if isinstance(cross_data, dict) else cross_data
                        same_nonempty = bool(own_products) and json.dumps(own_products, sort_keys=True) == json.dumps(cross_products, sort_keys=True)
                    except (json.JSONDecodeError, AttributeError, TypeError):
                        own_products, cross_products, same_nonempty = [], [], False
                    confirmed_candidate = own_status == 200 and cross_status == 200 and same_nonempty
                    if own_status == 200 and cross_status in (401, 403):
                        outcome = "PASS — other account was denied"
                        result_class = "pass"
                    elif confirmed_candidate:
                        outcome = "Potential IDOR/BOLA — cross-account basket matched"
                        result_class = "review"
                        store_live_candidate(
                            "Candidate — cross-account basket access", base, 7.5,
                            "The second test account's non-empty basket matched when requested with the first test account's login. Review this IDOR/BOLA result and the application's intended access rules.",
                            "Enforce object ownership on the server for every basket request; derive the permitted object from the authenticated user.",
                            f"Owner request HTTP {own_status}; other-account request HTTP {cross_status}; matching non-empty item list ({len(own_products)} items). Response contents and credentials were not saved.",
                        )
                    else:
                        outcome = "INCONCLUSIVE — check accounts and add an item to the second account's basket"
                        result_class = "info"
                    results = [{
                        "name": "Read-only basket ownership check",
                        "outcome": outcome,
                        "evidence": f"Owner control HTTP {own_status}; cross-account request HTTP {cross_status}. Login credentials, tokens, and response bodies were used temporarily and not stored.",
                        "fix": "Deny cross-user access server-side. A pass or inconclusive result does not establish security for other endpoints.",
                        "result_class": result_class,
                    }]
                else:
                    raise ValueError("Choose the SQL input check or the basket access check.")
            except ValueError as exc:
                flash(str(exc), "error")
    return render_template("security_lab.html", results=results, target=target_value)


@app.route("/proxy", methods=["GET", "POST"])
def proxy_setup():
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        parsed = urlparse(target)
        hostname = (parsed.hostname or "").lower()
        allowed_hosts = {host.lower() for host in hosts_in_scope(get_assessment()["scope"])}
        if parsed.scheme != "http" or not hostname or parsed.username or parsed.password or hostname not in allowed_hosts:
            flash("Enter an HTTP URL whose exact localhost/private IP is already listed in Assessment details → scope.", "error")
        else:
            try:
                with socket.create_connection(("127.0.0.1", 8899), timeout=1):
                    pass
            except OSError:
                flash("Proxy is not running yet. Start it with start_proxy.bat, keep its window open, then try again.", "error")
            else:
                edge_candidates = [
                    Path(os.environ.get("PROGRAMFILES(X86)", "C:/Program Files (x86)")) / "Microsoft/Edge/Application/msedge.exe",
                    Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "Microsoft/Edge/Application/msedge.exe",
                ]
                edge = next((candidate for candidate in edge_candidates if candidate.is_file()), None)
                if edge is None:
                    flash("Microsoft Edge was not found in its usual Windows installation folder. Use open_lab_browser.bat instead.", "error")
                else:
                    try:
                        subprocess.Popen([
                            str(edge),
                            f"--user-data-dir={BASE_DIR / 'proxy-browser-profile-8899'}",
                            "--proxy-server=http://127.0.0.1:8899",
                            "--proxy-bypass-list=<-loopback>",
                            "--no-first-run",
                            target,
                        ], close_fds=True)
                    except OSError as exc:
                        flash(f"Could not open the isolated browser: {exc}", "error")
                    else:
                        flash("Isolated Edge opened through the lab proxy. Browse only the authorized target.", "success")
    return render_template("proxy.html")


@app.route("/proxy-history")
def proxy_history():
    import_proxy_queue()
    search = request.args.get("q", "").strip()
    with db_connection() as db:
        if search:
            pattern = f"%{search}%"
            rows = db.execute("""
                SELECT * FROM proxy_flows WHERE host LIKE ? OR url LIKE ? OR method LIKE ?
                ORDER BY id DESC LIMIT 200
            """, (pattern, pattern, pattern)).fetchall()
        else:
            rows = db.execute("SELECT * FROM proxy_flows ORDER BY id DESC LIMIT 200").fetchall()
    flows = []
    for row in rows:
        item = dict(row)
        try:
            item["alert_count"] = len(json.loads(item["alerts_json"]))
        except (TypeError, json.JSONDecodeError):
            item["alert_count"] = 0
        flows.append(item)
    return render_template("proxy_history.html", flows=flows, search=search)


@app.route("/proxy-flow/<int:flow_id>")
def proxy_flow_detail(flow_id):
    with db_connection() as db:
        flow = db.execute("SELECT * FROM proxy_flows WHERE id=?", (flow_id,)).fetchone()
    if flow is None:
        abort(404)
    details = dict(flow)
    details["request_headers"] = json.loads(flow["request_headers_json"])
    details["response_headers"] = json.loads(flow["response_headers_json"])
    details["alerts"] = json.loads(flow["alerts_json"])
    return render_template("proxy_flow.html", flow=details)


@app.route("/assessment", methods=["GET", "POST"])
def assessment_settings():
    if request.method == "POST":
        values = (
            request.form.get("title", "").strip(),
            request.form.get("organization", "").strip(),
            request.form.get("assessor", "").strip(),
            request.form.get("scope", "").strip(),
            request.form.get("authorization", "").strip(),
            request.form.get("assessment_window", "").strip(),
            request.form.get("methodology", "").strip(),
        )
        if not values[0] or not values[3] or not values[4]:
            flash("Assessment title, scope, and authorization note are required.", "error")
        else:
            with db_connection() as db:
                db.execute("""
                    UPDATE assessment SET title=?, organization=?, assessor=?, scope=?, authorization=?,
                    assessment_window=?, methodology=?, updated_at=CURRENT_TIMESTAMP WHERE id=1
                """, values)
            sync_proxy_scope()
            flash("Assessment details saved.", "success")
            return redirect(url_for("assessment_settings"))
    return render_template("assessment.html", assessment=get_assessment())


@app.route("/vulnerabilities/new", methods=["GET", "POST"])
def new_vulnerability():
    if request.method == "POST":
        values, error = validate_finding(request.form)
        if error:
            flash(error, "error")
        else:
            with db_connection() as db:
                db.execute("""
                    INSERT INTO vulnerabilities
                    (title, asset, severity, cvss, status, description, recommendation, evidence, retest_notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, values)
            flash("Finding saved. Severity was calculated from its CVSS score.", "success")
            return redirect(url_for("index"))
    return render_template("finding_form.html", finding=None, page_title="Add vulnerability", statuses=STATUSES)


@app.route("/vulnerabilities/<int:finding_id>/edit", methods=["GET", "POST"])
def edit_vulnerability(finding_id):
    finding = get_finding(finding_id)
    if finding is None:
        abort(404)
    if request.method == "POST":
        values, error = validate_finding(request.form)
        if error:
            flash(error, "error")
        else:
            with db_connection() as db:
                db.execute("""
                    UPDATE vulnerabilities SET title=?, asset=?, severity=?, cvss=?, status=?, description=?,
                    recommendation=?, evidence=?, retest_notes=?, updated_at=CURRENT_TIMESTAMP WHERE id=?
                """, (*values, finding_id))
            flash("Finding updated. Severity was recalculated from its CVSS score.", "success")
            return redirect(url_for("index"))
    return render_template("finding_form.html", finding=finding, page_title="Edit vulnerability", statuses=STATUSES)


@app.route("/vulnerabilities/<int:finding_id>/status", methods=["POST"])
def update_status(finding_id):
    status = request.form.get("status", "")
    if status not in STATUSES:
        flash("Choose a valid status.", "error")
    elif get_finding(finding_id) is None:
        abort(404)
    else:
        with db_connection() as db:
            db.execute("UPDATE vulnerabilities SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", (status, finding_id))
        flash("Remediation status updated.", "success")
    return redirect(url_for("index"))


def pdf_literal(value):
    """Encode text safely in a PDF literal string using the built-in WinAnsi font."""
    raw = str(value or "").encode("cp1252", errors="replace")
    output = []
    for byte in raw:
        if byte in (40, 41, 92):
            output.append("\\" + chr(byte))
        elif byte < 32 or byte > 126:
            output.append(f"\\{byte:03o}")
        else:
            output.append(chr(byte))
    return "(" + "".join(output) + ")"


def pdf_report_bytes(assessment, findings):
    """Build a compact multi-page PDF with standard-library PDF primitives."""
    lines = []

    def add(text="", font="F1", size=10, gap=14):
        for segment in str(text or "").splitlines() or [""]:
            wrapped = textwrap.wrap(segment, width=94, break_long_words=True, break_on_hyphens=False) or [""]
            for part in wrapped:
                lines.append((part, font, size, gap))

    add(assessment["title"], "F2", 19, 25)
    add("VULNERABILITY ASSESSMENT REPORT", "F2", 11, 20)
    add("Generated: " + datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), size=9, gap=17)
    add("ASSESSMENT DETAILS", "F2", 12, 19)
    for label, key in (("Organization", "organization"), ("Assessor", "assessor"), ("Authorized scope", "scope"),
                       ("Authorization reference", "authorization"), ("Assessment window", "assessment_window"), ("Methodology", "methodology")):
        add(f"{label}: {assessment[key] or 'Not recorded'}", size=9, gap=13)

    counts = {severity: sum(row["severity"] == severity for row in findings) for severity in SEVERITIES}
    open_count = sum(row["status"] in ("Open", "In Progress", "Retest") for row in findings)
    add("", gap=8)
    add("EXECUTIVE SUMMARY", "F2", 12, 19)
    add(f"Recorded findings: {len(findings)}. Open, in progress, or awaiting retest: {open_count}.", gap=15)
    add("Severity totals: " + " | ".join(f"{name}: {counts[name]}" for name in SEVERITIES), gap=20)
    add("FINDINGS AND REMEDIATION", "F2", 12, 19)
    if not findings:
        add("No vulnerabilities have been recorded yet.")
    for row in findings:
        add(f"{row['id']}. {row['title']}", "F2", 12, 18)
        add(f"Asset: {row['asset']}", size=9)
        add(f"Risk: {row['severity']} | CVSS {row['cvss']:.1f} | Status: {row['status']}", size=9)
        add("Description: " + row["description"], size=9, gap=13)
        add("Evidence: " + (row["evidence"] or "Not recorded"), size=9, gap=13)
        add("Remediation: " + row["recommendation"], size=9, gap=13)
        add("Retest notes: " + (row["retest_notes"] or "Not recorded"), size=9, gap=13)
        add("", gap=8)

    pages = []
    page = []
    remaining = 690
    for line in lines:
        if remaining < line[3] and page:
            pages.append(page)
            page = []
            remaining = 690
        page.append(line)
        remaining -= line[3]
    if page or not pages:
        pages.append(page)

    def make_stream(page_lines, page_number):
        commands = ["0.55 0.60 0.68 RG", "54 754 m 558 754 l S", "0 0 0 rg", "BT"]
        y = 733
        for text, font, size, gap in page_lines:
            commands.extend([f"/{font} {size} Tf", f"1 0 0 1 54 {y} Tm {pdf_literal(text)} Tj"])
            y -= gap
        commands.extend(["ET", "0.55 0.60 0.68 RG", "54 38 m 558 38 l S", "0 0 0 rg", "BT", "/F1 8 Tf", f"1 0 0 1 54 24 Tm {pdf_literal('VAPT Reporting Dashboard | Authorized assessment report')} Tj", f"1 0 0 1 520 24 Tm {pdf_literal(f'Page {page_number}')} Tj", "ET"])
        return "\n".join(commands).encode("cp1252", errors="replace")

    objects = [None, None]
    page_ids = []
    for number, page_lines in enumerate(pages, start=1):
        page_id = len(objects) + 1
        stream_id = page_id + 1
        page_ids.append(page_id)
        stream = make_stream(page_lines, number)
        page_obj = f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 {len(pages)*2+3} 0 R /F2 {len(pages)*2+4} 0 R >> >> /Contents {stream_id} 0 R >>".encode("ascii")
        stream_obj = f"<< /Length {len(stream)} >>\nstream\n".encode("ascii") + stream + b"\nendstream"
        objects.extend([page_obj, stream_obj])
    font_regular_id = len(objects) + 1
    font_bold_id = font_regular_id + 1
    objects[0] = b"<< /Type /Catalog /Pages 2 0 R >>"
    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    objects[1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode("ascii")
    objects.extend([b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>", b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"])

    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for object_number, body in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{object_number} 0 obj\n".encode("ascii"))
        output.extend(body)
        output.extend(b"\nendobj\n")
    xref_position = len(output)
    output.extend(f"xref\n0 {len(objects)+1}\n0000000000 65535 f \n".encode("ascii"))
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(f"trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref_position}\n%%EOF".encode("ascii"))
    return bytes(output)


@app.route("/report.pdf")
def download_report():
    assessment = get_assessment()
    findings = get_findings()
    buffer = BytesIO(pdf_report_bytes(assessment, findings))
    filename = "vapt-assessment-report.pdf"
    return send_file(buffer, mimetype="application/pdf", as_attachment=True, download_name=filename)


init_db()
sync_proxy_scope()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5055, debug=True)
