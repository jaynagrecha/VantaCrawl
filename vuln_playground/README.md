# Vuln Playground — architecture & how to extend

Standalone **dirty playground** for scanning with VantaCrawl in prod-like setups.
This is **not** `acceptance_lab/` (frozen post-PR #81 baseline). Edit freely.

## Layout

```
vuln_playground/
  app.py              # HTTP server, index, local OOB callback/poll
  http_util.py        # request/response helpers
  registry.py         # @register decorator + catalog
  run.sh              # HOST/PORT launcher (default :9080)
  EXPECTED.md         # ground-truth cheat sheet for scan scoring
  fixtures/           # canary + sample secrets/files
  vulns/              # one module per vulnerability family
```

## Run

```bash
cd vuln_playground
./run.sh
# or
PORT=9080 python3 app.py
```

Open `http://127.0.0.1:9080/`. Machine-readable route list: `/catalog.json`.

Point VantaCrawl at that base URL (Safe / Extended / Lab as you prefer).
For local OOB SSRF confirmation without an external callback service, configure
the scanner callback/poll to this same origin:

- callback ping: `http://127.0.0.1:9080/oob/<nonce>/ping`
- poll: `http://127.0.0.1:9080/oob/poll?nonce=<nonce>`

(Exact wiring depends on your CrawlConfig callback fields — use the playground
host as the callback base when testing OOB on loopback.)

## Safety model

Sinks are **simulated** where dangerous (no real shell, no real IMDS fetch).
`/ssrf/fetch` does perform real outbound HTTP GETs — only run on networks you control.

## Add / modify a vulnerability

1. Create `vulns/my_thing.py` (or edit an existing family file).
2. Register a route:

```python
from http_util import page, send
from registry import register

@register(
    "/demo/ping",
    title="Demo ping",
    family="demo",
    expected="none — example route",
    tags=["active"],
    notes="Delete me when done.",
)
def demo_ping(handler, params, *, head_only=False):
    send(handler, 200, page("Ping", "<p>pong</p>"), head_only=head_only)
```

3. Restart `./run.sh`. The index and `/catalog.json` update automatically.

Disable index linking with `linked=False` (still reachable by URL / enum).

## Ground truth

See [EXPECTED.md](./EXPECTED.md) for what VantaCrawl *should* report per route.
Use that when judging prod scanner behavior (TP / FP / FN).
