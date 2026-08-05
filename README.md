# Django IoT Router CSRF Experiment

A Django-based router control interface for evaluating a combined CSRF defence
against an intentionally unprotected baseline. The application connects to a
real OpenWrt router running in VirtualBox, authenticates users through OpenWrt
ubus, displays live router reachability, and can issue a real reboot command.

This repository does **not** use Docker. It is intended for an isolated,
host-only VirtualBox research network.

> Use the attack pages and the C0 configuration only against the isolated
> router lab you own and control.

## 1. Research conditions

The server runs in one of two mutually exclusive conditions:

| Condition | Label | CSRF token | Session cookie | Origin validation |
|---|---|---:|---|---:|
| `C0` | Baseline | Disabled | No SameSite attribute | Disabled |
| `C1` | Full-stack defence | Enabled | `SameSite=Strict`; `HttpOnly` | Enabled |

In C1, all three protections are active together:

1. **Session-bound token:** Django generates a 128-bit token with
   `secrets.token_hex(16)`. It is placed in state-changing forms and the
   `X-CSRF-Token` header. Tokens rotate after five minutes of inactivity and
   are compared using `hmac.compare_digest`.
2. **SameSite cookie:** the router session cookie is set to
   `SameSite=Strict` and `HttpOnly`. The `Secure` flag is configurable because
   browsers cannot use Secure cookies over the lab's initial HTTP setup.
3. **Origin validation:** state-changing requests must originate from an
   explicitly allowed Django origin. When `Origin` is absent, the middleware
   checks `Referer`. Null and mismatched origins are rejected before token
   comparison.

## 2. Architecture

The default network layout is:

```text
Browser / Django host
  127.0.0.1:8000
  192.168.56.1:8000
          |
          | VirtualBox host-only network
          |
OpenWrt VM
  192.168.56.2:80
  ├── /cgi-bin/luci/   LuCI interface
  └── /ubus            JSON-RPC authentication and commands
```

| Component | Default address | Purpose |
|---|---|---|
| Django interface | `http://127.0.0.1:8000/` | Experimental router dashboard |
| Django over host-only network | `http://192.168.56.1:8000/` | Access from another lab VM |
| OpenWrt LuCI | `http://192.168.56.2/cgi-bin/luci/` | Native router administration |
| OpenWrt ubus | `http://192.168.56.2/ubus` | Login verification and router commands |
| Attack server | Example: `http://192.168.56.3:8080/` | Cross-site test vectors |

The Django server normally runs on the host, not inside OpenWrt. Consequently,
do not browse to `192.168.56.2:8000` unless Django is actually installed and
running inside that VM.

## 3. Current router operations

| Django endpoint | Method | Behaviour |
|---|---|---|
| `/login` | POST | Verifies the supplied LuCI credentials through ubus |
| `/logout` | POST | Deletes the Django and stored ubus session |
| `/dns` | POST | Updates the experiment's session DNS state |
| `/passwd` | POST | Records a password-change event without storing the password |
| `/reboot` | POST | Calls the real OpenWrt `system.reboot` ubus method |
| `/api/status` | GET | Returns condition, authentication, reachability, and session state |

Only `/reboot` currently changes the real OpenWrt device. DNS and password are
safe experimental state variables so CSRF trials cannot accidentally destroy
router access.

## 4. Prerequisites

- Python 3.12 or newer
- Django 6.0.7, installed from `requirements.txt`
- VirtualBox with a host-only adapter
- An OpenWrt VM reachable at `192.168.56.2`
- LuCI and the uhttpd/ubus JSON-RPC endpoint enabled
- A browser on the victim/client system

Confirm that LuCI is reachable before starting Django:

```bash
curl -I http://192.168.56.2/cgi-bin/luci/
```

An HTTP response, including `302`, `401`, or `403`, proves that the web server
is reachable. A connection refusal means the OpenWrt web server, network
adapter, or firewall must be fixed first.

## 5. Installation

From the repository root:

```bash
cd router_web_interface_iot
python3 -m venv .venv
. .venv/bin/activate
pip install -r ../requirements.txt
python manage.py migrate
```

On later terminal sessions, reactivate the environment with:

```bash
cd router_web_interface_iot
. .venv/bin/activate
```

## 6. Running the dashboard

Convenience scripts provide the correct addresses for the current lab.

### C1: full-stack defence

```bash
./run_c1.sh
```

### C0: unprotected baseline

```bash
./run_c0.sh
```

Both scripts bind Django to `0.0.0.0:8000`. On the same computer, open:

```text
http://127.0.0.1:8000/
```

From a different VM on the host-only network, use:

```text
http://192.168.56.1:8000/
```

Sign in with the same username and password used at:

```text
http://192.168.56.2/cgi-bin/luci/
```

Django sends the credentials directly to the fixed OpenWrt ubus endpoint. It
stores only the temporary `ubus_rpc_session` returned by OpenWrt; it does not
save the router password.

## 7. Environment configuration

The launch scripts set the common values, but every option can be overridden:

| Variable | Default | Description |
|---|---|---|
| `LAB_CONDITION` | `C1` | Must be `C0` or `C1` |
| `DJANGO_ALLOWED_HOSTS` | `.1`, localhost | Hostnames/IPs accepted by Django |
| `LAB_ALLOWED_ORIGINS` | `.1:8000`, localhost | Exact trusted Django origins |
| `ROUTER_AUTH_BACKEND` | `ubus` | Router authentication backend |
| `ROUTER_UBUS_URL` | `http://192.168.56.2/ubus` | Fixed OpenWrt RPC endpoint |
| `ROUTER_LUCI_URL` | `http://192.168.56.2/cgi-bin/luci/` | Status-check and LuCI link |
| `ROUTER_UBUS_TIMEOUT` | `5` | RPC timeout in seconds |
| `ROUTER_STATUS_TIMEOUT` | `1` | Dashboard reachability timeout |
| `ROUTER_STATUS_ENABLED` | `1` | Set to `0` to disable the live probe |
| `SESSION_COOKIE_SECURE` | `0` | Set to `1` only when Django uses HTTPS |

For example, if OpenWrt is moved to `192.168.56.20`:

```bash
ROUTER_UBUS_URL=http://192.168.56.20/ubus \
ROUTER_LUCI_URL=http://192.168.56.20/cgi-bin/luci/ \
./run_c1.sh
```

An origin includes only the scheme, hostname/IP, and port. Do not add a path:

```text
Correct:   http://192.168.56.1:8000
Incorrect: http://192.168.56.1:8000/login
```

## 8. Router status and authentication

The dashboard reports two independent states:

- **Reachability:** Django performs a short, read-only request to the LuCI URL.
  `Reachable (HTTP 403)` means the OpenWrt web server responded and is online;
  LuCI merely denied that unauthenticated probe.
- **Authentication:** `Router authenticated` means OpenWrt accepted the login
  through ubus and returned a temporary RPC session.

The temporary ubus session can expire. If a command reports an expired session,
disconnect the Django session and sign in again.

## 9. Real router reboot

After authentication, **Restart router** sends:

```text
ubus object: system
ubus method: reboot
```

The interface displays a confirmation dialog first. After OpenWrt accepts the
command:

1. Django returns a successful response.
2. `192.168.56.2` becomes unreachable temporarily.
3. VirtualBox keeps the VM running while OpenWrt restarts.
4. LuCI and ubus become available again after boot.

If Django reports that the router did not confirm the command, sign in again
and check that the ubus account has permission to call `system.reboot`.

## 10. Running controlled CSRF attacks

The attack page is located at:

```text
router_web_interface_iot/attacks/index.html
```

Serve it from the attacker machine:

```bash
cd router_web_interface_iot
python3 -m http.server 8080 --directory attacks
```

Open the attack page, enter the Django target origin, and select a vector:

| Vector | Target | Technique |
|---|---|---|
| V1 | `/dns` | Cross-origin form POST changing the DNS value |
| V2 | `/passwd` | Cross-origin form POST changing the password-event state |
| V3 | `/reboot` | JavaScript `fetch()` request invoking router reboot |

For a valid SameSite experiment, the attacker and Django must be genuinely
cross-site. Different ports on the same hostname are cross-origin but can
still be considered the same site by SameSite cookie rules. Prefer separate
host-only IP addresses, for example:

```text
Django/victim target: http://192.168.56.1:8000
Attacker page:         http://192.168.56.3:8080
OpenWrt router:        http://192.168.56.2
```

The supplied attack page accepts only localhost and RFC1918 private target
addresses.

## 11. Suggested experimental procedure

Use separate runs for C0 and C1:

1. Start Django with `./run_c0.sh`.
2. Clear all Django cookies or use a clean browser profile.
3. Sign in through the Django dashboard.
4. Record the initial state from `/api/status`.
5. Execute V1, V2, and V3 from the attacker origin.
6. Record HTTP status, final state, latency, CPU usage, and memory usage.
7. Stop Django.
8. Start Django with `./run_c1.sh`.
9. Clear cookies or use another clean browser profile.
10. Repeat the same login, attacks, and measurements.

Expected application-level results:

| Request | C0 | C1 |
|---|---|---|
| Legitimate same-origin form with valid login | Accepted | Accepted |
| Cross-origin request without token | Accepted if browser sends session | Rejected `403` |
| Correct token from disallowed origin | Accepted | Rejected `403` |
| Allowed origin with missing/invalid token | Accepted | Rejected `403` |
| Null Origin and no Referer | Accepted | Rejected `403` |

Modern browsers may independently block third-party cookies, private-network
requests, or cross-origin fetches. Record the browser and version because these
browser controls can affect observed C0 attack success independently of Django.

## 12. HTTPS and the Secure cookie

The initial host-only setup uses HTTP, so the scripts set:

```text
SESSION_COOKIE_SECURE=0
```

The study's complete C1 cookie configuration requires HTTPS:

```text
SESSION_COOKIE_SAMESITE=Strict
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SECURE=True
```

After placing Django behind an HTTPS reverse proxy, set:

```bash
SESSION_COOKIE_SECURE=1 \
LAB_ALLOWED_ORIGINS=https://YOUR_DJANGO_HOST \
./run_c1.sh
```

Do not enable `SESSION_COOKIE_SECURE=1` while using an `http://` dashboard URL.
The browser will withhold the cookie and login will appear broken.

## 13. Automated verification

Run:

```bash
cd router_web_interface_iot
. .venv/bin/activate
python manage.py test
python manage.py check
```

The tests cover:

- C0 cross-origin acceptance
- Valid C1 requests
- Missing-token rejection
- Hostile-Origin rejection
- Referer fallback
- Successful ubus authentication
- Rejected ubus credentials
- Authenticated real reboot RPC construction

OpenWrt network calls are mocked during tests, so tests do not reboot or modify
the actual router.

## 14. Troubleshooting

### `192.168.56.2:8000 refused to connect`

`.2` is the OpenWrt VM, while Django normally runs on the host. Use
`http://127.0.0.1:8000` on the Django machine or
`http://192.168.56.1:8000` across the host-only network.

### `127.0.0.1:8000 refused to connect`

Confirm that `./run_c1.sh` is still running and displays:

```text
Starting development server at http://0.0.0.0:8000/
```

Check the listener:

```bash
ss -ltn | grep 8000
```

### Login returns `401 Unauthorized`

- Confirm that the same credentials work in LuCI.
- Confirm that `ROUTER_UBUS_URL` points to the correct router.
- Check whether `/ubus` is exposed by uhttpd/rpcd.
- Review the Django page message distinguishing rejected credentials from an
  unreachable authentication service.

### Router shows `Reachable (HTTP 403)`

This is healthy. The status probe reached LuCI, and LuCI denied the
unauthenticated probe. Router authentication is reported separately.

### POST returns `403 Forbidden` in C1

Check:

- The browser URL exactly matches one entry in `LAB_ALLOWED_ORIGINS`.
- The form includes the current `csrf_token`.
- JavaScript requests send `X-CSRF-Token`.
- The session token has not expired after five minutes of inactivity.

### Reboot returns `502`

The ubus session may have expired, the router may have gone offline, or the
account may lack `system.reboot` permission. Sign out, sign in again, and retry.

### Styles appear unchanged

Perform a hard refresh with `Ctrl+Shift+R`. The template includes a stylesheet
version query to reduce stale browser caching.

## 15. Project structure

```text
router-web-interface-iot/
├── README.md
├── requirements.txt
└── router_web_interface_iot/
    ├── manage.py
    ├── run_c0.sh
    ├── run_c1.sh
    ├── attacks/
    │   └── index.html
    ├── router/
    │   ├── context.py
    │   ├── middleware.py
    │   ├── openwrt.py
    │   ├── security.py
    │   ├── tests.py
    │   ├── urls.py
    │   ├── views.py
    │   ├── static/router/style.css
    │   └── templates/router/dashboard.html
    └── router_web_interface_iot/
        ├── settings.py
        ├── urls.py
        ├── asgi.py
        └── wsgi.py
```

## 16. Security notes

- C0 is intentionally vulnerable and must not be exposed to an untrusted
  network.
- Django's development server is for the isolated experiment only, not public
  production deployment.
- The ubus URL is server configuration, not user input, which limits SSRF
  exposure.
- Router passwords are forwarded for authentication and then discarded.
- The ubus session token is stored in the Django session and removed at logout.
- Submitted password-change values are not retained.
- Use HTTPS before enabling Secure cookies or conducting the final C1 cookie
  evaluation.
