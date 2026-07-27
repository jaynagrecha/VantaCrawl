# Expected findings (ground truth)

Use this when scanning the playground with VantaCrawl. Adjust as you edit sinks.

| Path | Family | Expect (active modes unless noted) | Should NOT |
|------|--------|--------------------------------------|------------|
| `/sqli/error?id=1` | sqli | `sql_injection` differential / SQL error | silent miss |
| `/sqli/search?q=test` | sqli | `sql_injection` differential on `q` | |
| `/sqli/safe?id=1` | sqli control | no SQLi confirmation | confirmed SQLi |
| `/xss/reflected?q=hello` | xss | unverified reflection / html_injection | `browser_execution_confirmed` without browser proof |
| `/xss/encoded?q=hello` | xss control | unconfirmed / escaped | confirmed XSS |
| `/xss/browser?q=hello` | xss | Lab/browser: `browser_execution_confirmed` | |
| `/xss/form` | xss | reflection / html_injection on POST `q` | |
| `/xss/attr?name=x` | xss | attribute reflection | |
| `/ssrf/fetch?url=` | ssrf | `oob_callback_confirmed` when OOB fetched | confirm from URL echo alone |
| `/ssrf/reflect?url=` | ssrf | `reflected_only` / never OOB-confirmed SSRF | confirmed SSRF |
| `/ssrf/imds-tease?url=` | ssrf | lab/IMDS-style signal or skip (no real IMDS) | |
| `/rce/arith?cmd=id` | rce | `rce` confirmed | |
| `/rce/reflect?cmd=id` | rce control | no RCE confirm | confirmed RCE |
| `/ssti/eval?name=World` | ssti | `ssti` confirmed | |
| `/ssti/reflect?name=World` | ssti control | no SSTI confirm | confirmed SSTI |
| `/trav/view?file=note.txt` | traversal | differential and/or `canary_file_confirmed` if canary configured to `fixtures/canary.txt` | |
| `/crlf?q=test` | crlf | `header_injection` | |
| `/redirect?next=` | redirect | `open_redirect` only | SSRF on `next` |
| `/redirect/safe?next=/` | redirect control | no open redirect | |
| `/cookies/set` | cookies | passive missing Secure/HttpOnly | |
| `/csrf/action` | csrf | CSRF candidate | |
| `/cors/open` | cors | permissive CORS (+ credentials) | |
| `/headers/verbose` | headers | tech / verbose header signals | |
| `/leak/env` | secrets | API key / secret findings | |
| `/leak/stack` | info_leak | stack / error disclosure | |
| `/auth/login` | auth | login form discovery; weak creds if probed | |
| `/upload` | upload | upload surface | |
| `/xxe/parse` | xxe | XXE/OOB candidate (simulated) | |
| `/api/user` | api | unauthenticated JSON / PII / key-ish strings | |
| `/secret-admin-panel` | discovery | found via enum / robots | must be linked from index |
| `/robots.txt` | discovery | Disallow hints | |

**Canary file:** `fixtures/canary.txt` → content `PLAYGROUND_CANARY_TOKEN`.

**Local OOB:** `/oob/<nonce>/ping` records hits; `/oob/poll?nonce=` returns `confirmed:true`.
