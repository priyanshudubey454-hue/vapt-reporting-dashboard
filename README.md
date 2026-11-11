# Mini Web VAPT Workbench

A learning project that combines a finding tracker with a local-only HTTP lab proxy and basic passive checks. Use it only on localhost or private lab systems that you own or have written authorization to assess.

## What it does

- Records assessment scope and permission notes
- Captures HTTP request/response metadata through an isolated Edge profile
- Shows request history, methods, URLs, statuses, and redacted headers
- Runs passive checks for common response headers and cookie flags
- Scans one localhost/private-IP base URL for headers and TLS expiry
- Includes a built-in SQLi and IDOR/BOLA behavior simulator and narrow, read-only Juice Shop lab checks
- Lets you manually validate findings, assign CVSS scores, track remediation/retest, and export a PDF report
- Blocks proxy requests to hosts outside the private-IP/localhost allowlist written in assessment scope

It does not crawl, exploit, brute force, modify or replay traffic, or scan public targets. Request/response bodies are not stored. Authorization, cookies, token-like headers, and sensitive query values are redacted. Passive observations are leads, not confirmed vulnerabilities.

## 1. Run the dashboard

From this folder in VS Code PowerShell:

```powershell
.\.venv\Scripts\python.exe app.py
```

Open `http://127.0.0.1:5055` and keep the terminal running. If setting up on another computer, install the Flask dependency listed in `requirements.txt` in a virtual environment first.

## 2. Set authorized scope

In the dashboard, open **Assessment details**. Enter the exact private lab IPv4 address or `localhost` in scope, and record the written permission note. The proxy allowlist reads those entries and refuses other hosts.

For a local demo, add `127.0.0.1` to scope. The dashboard itself can be used as the HTTP target.

## 2a. Start an OWASP Juice Shop practice target

If Docker Desktop is installed and running, double-click `start_juice_shop.bat`. It starts the official Juice Shop image bound only to this computer at `http://127.0.0.1:3000`; keep its window open. Add `127.0.0.1` to assessment scope. Alternatively, run Juice Shop in a private VMware lab, find its private IP, and add that exact IP to scope before using it. Do not expose the intentionally vulnerable app to a public network.

## 3. Start the local proxy

Install mitmproxy using its official Windows installer: https://docs.mitmproxy.org/stable/overview/installation/

Then double-click `start_proxy.bat` and leave its terminal open. It listens only on `127.0.0.1:8899`, keeps mitmproxy's local CA material in an ignored project folder, and defers upstream connections until the scope-checking addon has approved the host. The addon writes redacted metadata to a local JSON queue; the Flask dashboard imports that queue into SQLite when you open Request history.

## 4. Browse through the proxy

From **Proxy setup**, you can enter an authorized HTTP lab URL and click **Open isolated browser** after the proxy is running. It launches Edge with a separate browser profile and routes that profile through the proxy; other browser profiles are not changed. You can also double-click `open_lab_browser.bat`. The launcher routes loopback addresses through the proxy for localhost lab demos, while the addon enforces the documented private-host allowlist.

Browse the lab, then return to the dashboard and select **Request history**. Open a flow to see its request/response metadata and passive observations. Body contents are intentionally omitted to avoid storing passwords or tokens.

This starter uses HTTP lab URLs. Decrypting HTTPS requires trusting mitmproxy's CA. The included Edge profile isolates proxy settings but does not isolate certificate trust, so this project does not ask you to install the CA in the Windows trust store or click through certificate warnings. An isolated browser certificate profile can be added separately.

## 5. Validate and report

Treat each **Review** as a prompt to investigate. Verify the issue in the lab, then use **Add finding** to record evidence, a CVSS score, a remediation recommendation, and retest notes. The app maps CVSS v3.x score bands automatically:

- 0.0: Informational
- 0.1–3.9: Low
- 4.0–6.9: Medium
- 7.0–8.9: High
- 9.0–10.0: Critical

Use **Download PDF** for the assessment report. The app does not calculate CVSS from a vector and does not automatically turn passive observations into vulnerabilities.

## Record a video demo

1. Start the dashboard and open `http://127.0.0.1:5055`.
2. Open **Assessment details**. Set the title to `Local VAPT Learning Demo`, scope to `127.0.0.1`, and permission note to `Self-owned local learning application`. Save.
3. Select **Lab scanner**, enter `http://127.0.0.1:5055`, confirm authorization, and run the checks. Explain that “Review” means investigate, not confirmed vulnerability.
4. For traffic history, start `start_proxy.bat`, then `open_lab_browser.bat`; browse the dashboard in that isolated Edge window. Return to **Request history** and open a captured request. This optional portion needs mitmproxy installed and available on PATH.
5. Return to the dashboard and click **Load video demo records**. The three records are fictional examples, explicitly labeled `DEMO ONLY`; they demonstrate CVSS, workflow statuses, evidence notes, and remediation text. Do not present them as real scan results.
6. Open **SQLi / IDOR lab**. For the live SQL check, use the Juice Shop base URL and run the single read-only search syntax check. For IDOR, first create two throwaway accounts in Juice Shop and put a product in Account B's basket, then enter both accounts and run the read-only comparison. Explain that these checks cover only the named endpoints. The built-in simulator is available when no live lab is running.
7. Show the statistics and select **Download PDF** to finish.

The demo records button is safe to click again; it will not add duplicate sample entries. The scanner and proxy still require the target to be in the saved scope.

## Deploy a read-only portfolio demo on Render

This project also supports a restricted online showcase. Connect the GitHub repository as a Render **Web Service**, leave Root Directory blank, use `pip install -r requirements.txt` as the build command, and use `gunicorn app:app --bind 0.0.0.0:$PORT` as the start command. Set `PUBLIC_DEMO_MODE` to `true` in Environment Variables. In this mode, the app loads fictional demo findings, permits viewing the dashboard and downloading its PDF, and blocks all writes, scanner checks, Juice Shop checks, and proxy routes. Keep real lab testing on your own computer. The free service uses temporary storage, so any online data is recreated from the sample records after a restart; do not use it to store assessment results.

The local learning mode remains the default when `PUBLIC_DEMO_MODE` is unset or false.

For the SQLi/IDOR part, choose **SQLi / IDOR lab**. Add the Juice Shop private IP to scope first. The SQL input check sends one read-only search request with a quote/semicolon and only looks for database error signatures; it does not retrieve data. The IDOR check logs into two throwaway Juice Shop accounts, compares one basket as its owner and as the other user, and saves only status/item-count evidence. It does not change baskets. Credentials, tokens, and response bodies are not stored. A positive is a candidate that must be reviewed; no result covers other endpoints. **Simulate vulnerable example** remains available as a clearly labeled training simulator if no live lab is running.

## Safety and limitations

The proxy is loopback-only and its addon forwards only `localhost` or private IPv4 hosts explicitly listed in assessment scope. It records metadata, not bodies. The standalone scanner sends one ordinary GET request, does not follow redirects, and accepts only localhost/private lab IP base URLs. The Flask debug server is for local learning only; do not expose it to the internet.

MITMproxy's official docs describe the local proxy, browser routing, addons, and its CA requirements: https://docs.mitmproxy.org/stable/overview/getting-started/ · https://docs.mitmproxy.org/stable/addons/overview/ · https://docs.mitmproxy.org/stable/concepts/certificates/
