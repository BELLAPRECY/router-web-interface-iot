# Controlled CSRF Attack and Reporting Guide

This guide explains how to execute and document the three CSRF vectors against
the Django router interface in the isolated VirtualBox lab. It also records the
security configuration being evaluated.

> Authorization boundary: use these procedures only with the private OpenWrt
> VM and Django application that you own. Do not substitute public IP addresses
> or third-party systems. Vector V3 can reboot the real OpenWrt VM.

## 1. Lab addresses

Use three distinct roles:

| Role | Example address | Service |
|---|---|---|
| OpenWrt router | `192.168.56.2` | LuCI and ubus |
| Victim/Django host | `192.168.56.1:8000` | Router dashboard and target endpoints |
| Attacker VM | `192.168.56.3:8080` | Malicious page |

The attacker should have a different IP/hostname from Django. Different ports
on the same hostname are cross-origin, but browsers can still classify them as
the same *site* for SameSite cookies.

## 2. Current security configuration

### C0 — unprotected baseline

Start with:

```bash
cd router_web_interface_iot
./run_c0.sh
```

Active configuration:

```text
LAB_CONDITION=C0
CSRF token validation=disabled
Origin/Referer validation=disabled
SESSION_COOKIE_SAMESITE=False
SESSION_COOKIE_HTTPONLY=False
SESSION_COOKIE_SECURE=False
```

### C1 — combined defence

Start with:

```bash
cd router_web_interface_iot
./run_c1.sh
```

Active configuration:

```text
LAB_CONDITION=C1
CSRF token=128-bit, session-bound
Token idle lifetime=300 seconds
Token comparison=constant-time HMAC comparison
Origin validation=enabled
Referer fallback=enabled
Null Origin without Referer=blocked
SESSION_COOKIE_SAMESITE=Strict
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SECURE=False for HTTP development
```

For the final HTTPS C1 experiment, set `SESSION_COOKIE_SECURE=1`.

Confirm the runtime state:

```bash
curl http://127.0.0.1:8000/api/status
```

The response reports `condition`, router IP, reachability, authentication, and
the current experimental state.

## 3. Start the Django attack server

The attack launcher is a Django view at `/attack-lab/`. Run a second instance
on the attacker VM:

```bash
cd router_web_interface_iot
. .venv/bin/activate

DJANGO_ALLOWED_HOSTS=192.168.56.3,127.0.0.1,localhost \
ROUTER_STATUS_ENABLED=0 \
python manage.py runserver 0.0.0.0:8080
```

Open:

```text
http://192.168.56.3:8080/attack-lab/
```

Enter the victim origin:

```text
http://192.168.56.1:8000
```

The original static launcher remains available and can alternatively be served
with:

```bash
python3 -m http.server 8080 --directory attacks
```

## 4. Prepare each test

Use a clean browser profile for every condition:

1. Start C0 or C1 on the Django host.
2. Open `http://192.168.56.1:8000`.
3. Log in with the OpenWrt/LuCI router credentials.
4. Confirm the dashboard says `Router authenticated`.
5. Save the initial state from `/api/status`.
6. Open browser developer tools:
   - Network panel
   - Preserve log enabled
   - Disable cache enabled
7. Start a timer or performance capture.
8. Open the attack page from the separate attacker origin.

Give every execution a unique run ID so the server evidence is written to a
separate structured log:

```bash
LAB_RUN_ID=C0-V1-run01 ./run_c0.sh
```

After the run, summarize it with:

```bash
python manage.py summarize_performance logs/C0-V1-run01.jsonl \
  --json-output evidence/C0-V1-run01/performance-summary.json
```

The server's `duration_ms` measures Django processing time. A nested
`router_call` event measures OpenWrt network time. Use the browser HAR for
browser-to-server latency and for requests blocked before Django receives them.

Do not change multiple variables between C0 and C1. Use the same browser,
payloads, network, timing method, and router state.

## 5. V1 — hidden form DNS POST

### Objective

Test whether another origin can submit an authenticated request to `/dns`
without knowing a CSRF token.

### Payload

```text
POST /dns
dns=6.6.6.6
CSRF token omitted
```

### Procedure

1. Record the current `state.dns` value from `/api/status`.
2. Click **Launch V1** on the attacker page.
3. Capture the `/dns` request and response in browser developer tools.
4. Refresh `/api/status`.
5. Record whether `state.dns` changed to `6.6.6.6`.
6. Save the Django console log line and HTTP response code.

### Expected results

- C0: request can succeed if the browser sends the Django session cookie.
- C1: request should be rejected with `403` because the Origin is disallowed;
  SameSite should also withhold the session cookie on a genuinely cross-site
  request.

This endpoint changes experimental session state, not the real OpenWrt DNS.

## 6. V2 — password-event form POST

### Objective

Test an automatically constructed cross-origin form against `/passwd`.

### Payload

```text
POST /passwd
password=attacker-password
CSRF token omitted
```

### Procedure

1. Record `state.password_changes`.
2. Click **Launch V2**.
3. Capture the request, response, Origin, Referer, and Cookie headers.
4. Refresh `/api/status`.
5. Record whether `password_changes` increased.

### Expected results

- C0: the counter can increase when the authenticated cookie is attached.
- C1: the request should return `403`.

The submitted password is never retained and this vector does not change the
real OpenWrt password.

## 7. V3 — JavaScript fetch reboot

### Objective

Test whether cross-origin JavaScript can invoke the real `/reboot` router
command with the victim's authenticated session.

### Payload

```text
POST /reboot
credentials=include
mode=no-cors
CSRF token omitted
```

### Procedure

1. Ensure no other router users are active.
2. Confirm VirtualBox console access is available.
3. Record router reachability:

   ```bash
   ping 192.168.56.2
   ```

4. Click **Launch V3** and confirm the warning.
5. Capture the browser request and Django log.
6. Continue pinging the router.
7. Record whether replies stop and later resume.
8. Record the LuCI recovery time.

### Expected results

- C0: when the browser sends the authenticated Django session, Django can call
  the real OpenWrt `system.reboot` ubus method.
- C1: the cross-origin request should be rejected with `403` before the ubus
  call.

Browsers can block cross-origin `fetch`, third-party cookies, or private-network
access independently of Django. Record a browser-level block separately from a
Django defence rejection.

## 8. Evidence to collect for every attack

Create one evidence folder per run:

```text
evidence/
  C0-V1-run01/
  C0-V2-run01/
  C0-V3-run01/
  C1-V1-run01/
  C1-V2-run01/
  C1-V3-run01/
```

Collect:

- Screenshot of the active C0/C1 dashboard indicator
- Screenshot or saved JSON from `/api/status` before and after
- Browser network HAR file
- Request method, URL, Origin, Referer, Cookie presence, and payload
- HTTP response status and response body
- Relevant Django console lines
- Router ping or LuCI availability for V3
- CPU and memory measurements
- Browser name and exact version
- Timestamp and test operator

Do not include router passwords or live session tokens in the report. Redact
`Cookie`, `router_session`, `ubus_rpc_session`, and CSRF-token values.

## 9. Individual attack report template

Copy this section for every run:

```markdown
## Attack Run: [C0/C1]-[V1/V2/V3]-[run number]

### Identification
- Date and time:
- Operator:
- Condition:
- Vector:
- Browser and version:
- Django commit/version:
- Victim origin:
- Attacker origin:
- Router IP:

### Security configuration
- CSRF token:
- SameSite:
- Secure:
- HttpOnly:
- Origin validation:
- Referer fallback:

### Initial state
- Router reachable:
- Router authenticated:
- `/api/status` state:

### Request evidence
- Method and endpoint:
- Origin:
- Referer:
- Session cookie attached: Yes/No/Blocked by browser
- CSRF token attached: Yes/No
- Payload:

### Result
- HTTP status:
- Django response:
- State changed: Yes/No
- Actual router effect:
- Processing time:
- CPU measurement:
- Memory measurement:

### Classification
- Attack successful:
- Blocked by Django:
- Blocked by browser:
- Failed for another reason:

### Evidence files
- Before screenshot:
- After screenshot:
- HAR file:
- Server log:
- Router availability log:

### Notes and anomalies
-
```

## 10. Experiment summary report

Do not enter expected values as observed results. Complete this table only
after executing the experiments:

| Run | Condition | Vector | HTTP status | Cookie sent | State changed | Router effect | Blocked by | Latency |
|---|---|---|---:|---|---|---|---|---:|
| 01 | C0 | V1 | | | | DNS session state | | |
| 01 | C0 | V2 | | | | Password event counter | | |
| 01 | C0 | V3 | | | | Real router reboot | | |
| 01 | C1 | V1 | | | | None expected | | |
| 01 | C1 | V2 | | | | None expected | | |
| 01 | C1 | V3 | | | | None expected | | |

Recommended derived metrics:

```text
Attack success rate = successful attacks / total attempted attacks × 100
Defence effectiveness = blocked attacks / total attacks × 100
Mean latency = sum of request latencies / request count
Overhead = mean C1 latency - mean C0 latency
Relative overhead (%) = (mean C1 - mean C0) / mean C0 × 100
```

Report browser blocks separately. A request blocked before reaching Django does
not demonstrate that Django's middleware blocked it.

## 11. Interpreting server responses

| Status | Meaning |
|---:|---|
| `200` | Target handler processed the request |
| `401` | No authenticated Django router session |
| `403` | C1 rejected Origin/Referer or CSRF token |
| `405` | Wrong HTTP method |
| `502` | Django accepted the request but OpenWrt did not confirm the command |

Use the JSON error body and Django console log to distinguish causes.

## 12. Important validity notes

- A server-side Django HTTP client is not a CSRF attack. CSRF depends on a
  victim browser automatically attaching credentials.
- The Django attack view only serves malicious HTML/JavaScript. The victim
  browser performs the actual cross-origin request.
- Run the attack view from a genuinely separate origin.
- Clear cookies between C0 and C1.
- Keep the router and payload values constant between conditions.
- Never infer a successful reboot only from the browser response; verify loss
  and restoration of router reachability.
- Repeat each vector enough times for the study's statistical analysis.
