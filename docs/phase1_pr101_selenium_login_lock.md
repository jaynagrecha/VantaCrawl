# Phase-1 PR #101 — Selenium login lock fix

**Branch:** `cursor/phase1-xss-gate-metrics-32cd`  
**Do not merge** until an independent final audit re-runs.  
**Do not begin Phase 2.**

## 1. Root cause

Production path `browser_fetch.apply_selenium_login` → `auth_login.selenium_login` performed shared WebDriver navigation and state extraction **without** holding `browser_fetch.selenium_driver_lock`. XSS eval, DOM-clobber, and `fetch_with_selenium` already used that RLock, so login could race the shared driver.

## 2. Old unprotected call path

```
web/worker/runner.py  (if config.use_selenium_login)
→ browser_fetch.apply_selenium_login
→ auth_login.selenium_login
→ driver_factory() = get_selenium_driver   # lock only during acquire
→ driver.get(login_url)                    # UNLOCKED
→ find_elements / clear / send_keys / click|submit
→ driver.current_url / driver.get_cookies  # UNLOCKED
→ cookie string returned; jar filled outside browser
```

Desktop `app.py` used the same `apply_selenium_login` entry.

## 3. Corrected lock boundary

```
apply_selenium_login
  [non-browser: chrome_available / UA pick]
  with selenium_driver_lock():          # process-global RLock
      selenium_login(...)               # fail-closed requires lock owned
          get_selenium_driver(...)      # re-entrant
          driver.get → form interact → cookies/URL
  [non-browser: SessionCookieStore materialization]
```

`auth_login._require_shared_selenium_lock()` fails closed if called without ownership (covers any alternate caller).

## 4. WebDriver operations covered

Under the held lock for the full login transaction:

- `driver.get` (login navigation)
- `find_elements` (username/password/submit)
- `clear` / `send_keys` (form fill)
- `click` / `submit`
- `driver.current_url` (redirect check)
- `driver.get_cookies` (session extract)

No `about:blank` / storage / screenshot ops in this path.

## 5. No bypassing entry point

| Caller | Lock |
|--------|------|
| `browser_fetch.apply_selenium_login` | acquires `selenium_driver_lock` |
| `web/worker/runner.py` | via `apply_selenium_login` only |
| `app.py` | via `apply_selenium_login` only |
| Direct `auth_login.selenium_login` | **RuntimeError** unless lock owned |

## 6. Files / functions changed

- `browser_fetch.apply_selenium_login` — wrap browser transaction in `selenium_driver_lock`
- `auth_login._require_shared_selenium_lock` / `selenium_login` — fail-closed ownership guard
- `tests/test_selenium_login_lock.py` — runtime lock-ownership proofs
- `tests/test_phase1_xss_browser_binding.py` — `auth_login` in production roots/closure

## Validation (filled after deploy + Lab)

| Field | Value |
|-------|-------|
| PR tip SHA | _(post-commit)_ |
| API deploy SHA | _(post-deploy)_ |
| Worker deploy SHA | _(post-deploy)_ |
| Fresh Lab scan ID | _(post-Lab)_ |
| Focused tests | see suite log |
| Full suite | see suite log |
| Closure | browser_fetch + auth_login; Horizon imports 0 |

## Remaining genuine Phase-1 gaps (non-blocking for this defect)

- Inventory `discovery_missing`: `/meta/azure`, `/meta/gcp` (2/39)
