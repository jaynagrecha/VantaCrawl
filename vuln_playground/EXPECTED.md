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

## Access / auth / logic
| Family | Paths (examples) |
|--------|------------------|
| idor / bac / mass_assignment / business_logic | `/idor/*`, `/bac/admin`, `/mass-assign/profile`, `/logic/*` |
| jwt / oauth / session / otp / saml | `/jwt/*`, `/oauth/callback`, `/auth/*`, `/otp/predictable`, `/saml/acs` |
| user_enumeration / timing / rate_limit / captcha / password_reset | `/enum/user`, `/auth/timing`, `/auth/norate`, `/captcha/bypass`, `/reset/poison` |

## Injection
| Family | Paths (examples) |
|--------|------------------|
| sqli (error/blind/time/second-order) | `/sqli/error`, `/sqli/blind`, `/sqli/time`, `/sqli/second-order` |
| nosql / ldap / xpath / ssi / el / cmdi | `/nosql/login`, `/ldap/*`, `/xpath/*`, `/ssi/page`, `/el/eval`, `/cmdi/ping` |
| ssti engines / spel / ognl | `/ssti/*`, `/tmpl/*`, `/spel/eval`, `/ognl/eval` |
| prototype_pollution / deserialization | `/proto/merge`, `/deser/*`, `/yaml/load` |
| lfi / rfi / null_byte / zip_slip / xxe | `/lfi/include`, `/rfi/fetch`, `/nullbyte/download`, `/zipslip/extract`, `/xxe/*` |

## Protocol / browser / client
| Family | Paths (examples) |
|--------|------------------|
| graphql / jsonp / host_header / cache / smuggling / hpp | `/graphql`, `/jsonp`, `/host-header`, `/cache/*`, `/smuggle/tease`, `/hpp/search` |
| method_override / put_upload / TRACE | `/method/override`, `/put/upload`, `/method/trace` |
| xss extras / css / tabnabbing / sri / client_storage | `/xss/*`, `/css/inject`, `/tabnabbing`, `/sri/missing`, `/cors/localstorage` |
| clickjacking / csp / email_injection / websocket | `/clickjack`, `/csp/bypass`, `/email/draft`, `/websocket/*` |

## Exposure / cloud / DoS teases
| Family | Paths (examples) |
|--------|------------------|
| backup / dotenv / git / actuator / sourcemap | `/backup/*`, `/.env`, `/.git/*`, `/actuator/env`, `/static/app.js.map` |
| firebase / crypto / listing / k8s / redis / elasticsearch | `/config/firebase.json`, `/keys/private.pem`, `/listing`, `/k8s/token`, `/redis/info`, `/_cat/indices` |
| server_status / debug / phpinfo | `/server-status`, `/debug/django`, `/phpinfo` |
| ssrf meta / log4j / xmlrpc / race / redos / csv | `/meta/*`, `/ssrf/*`, `/log4j/greet`, `/xmlrpc.php`, `/race/*`, `/redos/search`, `/csv/export` |
| type_juggling | `/typejuggling/login` |

**Canary:** `fixtures/canary.txt` → `PLAYGROUND_CANARY_TOKEN`  
**Local OOB:** `/oob/<nonce>/ping` + `/oob/poll?nonce=`
