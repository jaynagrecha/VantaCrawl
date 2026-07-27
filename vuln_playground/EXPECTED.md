# Expected findings (ground truth) — expanded playground

Public site: Horizon Catalog. Machine catalog: `/catalog.json`.

## Core (original)
| Path | Expect |
|------|--------|
| `/sqli/error` | SQLi differential |
| `/xss/*` | reflection / browser / stored / DOM / SVG |
| `/ssrf/fetch`, `/webhook/fetch` | OOB SSRF when callback fetched |
| `/ssrf/reflect` | reflected_only — never OOB confirm |
| `/rce/arith`, `/ssti/eval`, `/el/eval` | confirmed eval sinks |
| `/trav/view` | canary / traversal |
| `/crlf`, `/redirect*` | header injection / open redirect |
| `/cookies/*`, `/csrf/action`, `/cors/*` | passive cookie/CSRF/CORS |

## Added families
| Family | Paths (examples) |
|--------|------------------|
| idor / access_control / mass_assignment / business_logic | `/idor/*`, `/bac/admin`, `/mass-assign/profile`, `/logic/*` |
| jwt / oauth / session | `/jwt/none`, `/jwt/weak`, `/oauth/callback`, `/auth/session-fixation`, `/auth/2fa-bypass`, `/auth/reset` |
| nosql / ldap / xpath / ssi / el / prototype_pollution / deserialization | `/nosql/login`, `/ldap/search`, `/xpath/user`, `/ssi/page`, `/el/eval`, `/proto/merge`, `/deser/pickle`, `/yaml/load` |
| graphql / jsonp / host_header / cache / smuggling / hpp | `/graphql`, `/jsonp`, `/host-header`, `/cache/poison`, `/smuggle/tease`, `/hpp/search` |
| backup / sourcemap / actuator / git / crypto / firebase / listing / cloud | `/backup/site.sql`, `/static/app.js.map`, `/actuator/env`, `/.git/HEAD`, `/keys/private.pem`, `/config/firebase.json`, `/listing`, `/k8s/token` |
| clickjacking / csp / email_injection / websocket / log4j / xmlrpc / race | `/clickjack`, `/csp/bypass`, `/email/draft`, `/websocket/info`, `/log4j/greet`, `/xmlrpc.php`, `/race/withdraw` |

**Canary:** `fixtures/canary.txt` → `PLAYGROUND_CANARY_TOKEN`  
**Local OOB:** `/oob/<nonce>/ping` + `/oob/poll?nonce=`
