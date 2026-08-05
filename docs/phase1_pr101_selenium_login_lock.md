# Phase-1 PR #101 — Selenium login lock fix

**Branch:** `cursor/phase1-xss-gate-metrics-32cd`  
**PR tip:** `2e4d2ca7c46599088c001c1e910f32c35a8429cf`  
**Do not merge** until an independent final audit re-runs after deploy+Lab.  
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

**WebDriver ops on the path:** `driver.get`, `find_elements`, `clear`, `send_keys`, `click`/`submit`, `current_url`, `get_cookies`. No about:blank / storage / screenshot in this path.

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

## 5. No bypassing entry point

| Caller | Lock |
|--------|------|
| `browser_fetch.apply_selenium_login` | acquires `selenium_driver_lock` |
| `web/worker/runner.py` | via `apply_selenium_login` only |
| `app.py` | via `apply_selenium_login` only |
| Direct `auth_login.selenium_login` | **RuntimeError** unless lock owned |

## 6. Files / functions changed

- `browser_fetch.apply_selenium_login`
- `auth_login._require_shared_selenium_lock` / `selenium_login`
- `tests/test_selenium_login_lock.py` (runtime ownership proofs)
- `tests/test_phase1_xss_browser_binding.py` (`auth_login` in roots/closure)

## 7–11. Local validation

| Check | Result |
|-------|--------|
| Focused login-lock + Phase-1 suites | **44 passed** |
| Full suite | **775 passed**, 0 failed, 0 skipped, 0 xfailed, 33 warnings, exit 0 |
| Closure size | 37 (includes `browser_fetch`, `auth_login`) |
| Horizon imports (direct/transitive) | **0** |
| Horizon host/path literals in production set | **0** |
| Missing roots / unresolved entries | **0** |
| Working tree after commit | clean |

## 12–15. Deploy / Lab

| Field | Value |
|-------|-------|
| PR tip SHA | `2e4d2ca7c46599088c001c1e910f32c35a8429cf` |
| API deploy SHA | **not updated this session** — Render MCP unauthorized; `RENDER_API_KEY` unset |
| Worker deploy SHA | **not updated this session** |
| Fresh Lab scan ID | **not run** (requires tip deploy) |

## 16. Remaining genuine Phase-1 gaps

- Inventory `discovery_missing`: `/meta/azure`, `/meta/gcp` (2/39) — pre-existing coverage debt
- Deploy + Lab revalidation blocked by missing Render credentials in this environment

## Verdict (this agent session)

**BLOCKED — unable to deploy PR tip `2e4d2ca7…` to API/worker (Render MCP unauthorized; RENDER_API_KEY unset); Lab regression therefore not re-run on the tip**

Code fix and deterministic lock-ownership tests are on the branch and green locally. Independent final audit after tip deploy + Lab remains required.
