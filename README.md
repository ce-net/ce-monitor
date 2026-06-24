# ce-watch

The operator's security console for CE — a light HTTP service that collects abuse flags from the
hub's detector and renders them in an admin-only "police HQ" dashboard.

It is intentionally minimal: axum + tokio + serde, no libp2p, no wasmtime, no database server. The
flag log is a durable, bounded, append-only JSONL file. ce-watch runs beside the relay and never
touches the `ce` node directly — the hub pushes flags to it over HTTP, and the operator reads them.

## What it does

1. **`POST /ingest`** — receives one `FlagEvent` from the hub's abuse detector. Gated by the header
   `x-ce-watch-token` matching `CE_WATCH_INGEST_TOKEN`. The event is appended durably (fsync) to
   `flags.jsonl` and the unseen counter is incremented.
2. **Admin console** — `GET /` (and `/admin`) serve a single-page dark "security console". It
   prompts once for the admin token, stores it in `localStorage`, and sends it as `x-ce-admin` on
   every data call. The page renders the flag log as a structured, filterable table:
   - **WHO** — `node_id` (Ed25519 pubkey hex, or `ip:<addr>` for unsigned nodes) + source `ip`
   - **WHERE** — chosen node / endpoint / func (pulled from the sample)
   - **WHEN** — timestamp, newest first
   - **WHY** — heuristic tag + human reason + severity
   - Filter by heuristic / severity / node. A **red unseen-count dot** pulses while there are
     unacknowledged flags and clears on **mark seen**.
3. **`GET /admin/flags?since=&heuristic=&severity=&node=`** — token-gated JSON feed powering the
   UI. `since` is an exclusive sequence cursor for incremental polling.
4. **`GET /admin/unseen`** / **`POST /admin/seen`** — read / clear the unseen watermark.

## Environment

| Var | Default | Purpose |
|---|---|---|
| `CE_WATCH_INGEST_TOKEN` | _(unset → /ingest rejects all)_ | Shared secret the hub sends as `x-ce-watch-token`. |
| `CE_WATCH_ADMIN_TOKEN` | _(unset → admin rejects all)_ | Operator token for the console (`x-ce-admin`). |
| `PORT` | `8971` | Listen port. |
| `CE_WATCH_DATA_DIR` | `./ce-watch-data` | Directory holding `flags.jsonl`. |

If a token is unset the corresponding surface refuses every request (fail-closed).

## Durability & bounds

- Flags are appended one JSON object per line to `flags.jsonl`, fsync'd on each write, and replayed
  on boot — so the log **survives restart**.
- The active log rotates to `flags.jsonl.1` (one generation kept) once it passes 16 MiB, keeping
  disk usage bounded. The most recent flags stay resident in memory for the admin feed.

## FlagEvent contract

```json
{
  "ts": 1700000000,
  "node_id": "<ed25519 pubkey hex, or 'ip:'+ip if unsigned>",
  "ip": "203.0.113.7",
  "heuristic": "H2",
  "reason": "repeat-signature: count_primes x47 in 5m — mining shape",
  "severity": "low|med|high",
  "sample": { "func": "count_primes", "endpoint": "/tasks" }
}
```

## How the hub pushes flags

The hub's detector fires flags best-effort, non-blocking — it must never delay task dispatch:

```
POST {CE_WATCH_URL}/ingest          # CE_WATCH_URL default http://127.0.0.1:8971
x-ce-watch-token: {CE_WATCH_INGEST_TOKEN}
body: <one FlagEvent>
```

Errors are ignored (fire-and-forget). ce-watch is a sink, not a dependency.

## Run

```bash
CE_WATCH_INGEST_TOKEN=… CE_WATCH_ADMIN_TOKEN=… PORT=8971 \
  cargo run --release
```

## Test

```bash
cargo test
```

Covers: `/ingest` rejects a bad token (401) and accepts + stores a good one; `/admin/flags`
requires the admin token; `mark seen` clears the unseen count; the log survives restart; filters
apply.

## Deploy (on the relay, behind nginx, admin-only)

ce-watch listens on `127.0.0.1:8971`. Put it behind the relay's nginx so only the operator reaches
it. Example location block (restrict by IP / basic-auth in addition to the in-app admin token):

```nginx
location /watch/ {
    # allow <your-ip>; deny all;          # optional network-level lockdown
    proxy_pass         http://127.0.0.1:8971/;
    proxy_set_header   Host $host;
    proxy_set_header   X-Forwarded-For $remote_addr;
}
```

Run it under systemd alongside `ce-relay` and `ce-hub`:

```ini
[Unit]
Description=ce-watch security console
After=network.target

[Service]
Environment=CE_WATCH_INGEST_TOKEN=…
Environment=CE_WATCH_ADMIN_TOKEN=…
Environment=PORT=8971
Environment=CE_WATCH_DATA_DIR=/var/lib/ce-watch
ExecStart=/usr/local/bin/ce-watch
Restart=always

[Install]
WantedBy=multi-user.target
```

The console is **admin-only** by design — there is no public surface. Keep both tokens secret and
prefer additional network-level restriction at nginx.
