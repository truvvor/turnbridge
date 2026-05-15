# captcha-service

Server-side companion to the iOS TurnBridge NetworkExtension. Hosts
the VK captcha + identity-registration pipeline outside the
50-100 MB iOS sandbox so the heavy work (slider rendering, PoW
solving, the 8-RT VK auth flow) runs on a real machine with proper
memory and proper DNS.

The server does **not** open TURN allocations on behalf of the
client — TURN allocations are bound by RFC 5766 to the 5-tuple that
issued them and can't be handed off. What the server does is the
captcha + auth flow, then returns the `{user, pass, addr}` triple
from VK's `vchat.joinConversationByLink` response. The iOS client
uses those credentials to issue its own `Allocate` from the
phone's source IP, within VK's ~50 s rotation window.

## Why this exists

Per-IP captcha rate-limit (`ERROR_LIMIT`) caps the iOS client at
roughly 8 unique identities per `connect`. The other ceiling — the
49-candidate slider ranker allocating ~70 MB transiently — was
already softened in F5 but still constrains how many solves can run
in parallel. Moving captcha solving to a server with its own IP
budget and gigabytes of RAM lifts both ceilings.

Each server instance gives the fleet **one** fresh per-IP budget
(`directSaturated` cools down 60 s after `ERROR_LIMIT`). Run several
behind a round-robin load balancer or rotating residential proxies
for multiplicative throughput.

## Running locally

```sh
go run . # requires API_KEY env
```

```sh
API_KEY=$(openssl rand -hex 16) go run .
```

The service listens on `:8080` by default. Healthcheck at
`GET /healthz`, stats snapshot at `GET /stats` (unauthenticated).

## API

`POST /cred` — solve one captcha + register one VK identity, return
ready-to-use TURN creds.

```http
POST /cred HTTP/1.1
Authorization: Bearer <API_KEY>
Content-Type: application/json

{"link": "<vk-call-join-link>"}
```

Successful response (typical 2-10 s):

```json
{
  "user": "1715792025:guest",
  "pass": "abc123…",
  "addr": "95.163.34.151:3478",
  "expires_at": "2026-05-15T07:45:00Z"
}
```

Error responses:
- `400` — missing/invalid `link`.
- `401` — missing or wrong bearer token.
- `429` — egress is in the 60 s `ERROR_LIMIT` cooldown. Client
  should back off until `Retry-After` (header) seconds elapse.
- `502` — captcha pipeline failed (downstream VK returned
  something we can't parse, or captcha solving exhausted retries).
- `503` — solve queue full (more than `maxConcurrentCaptchaSolves`
  in flight; client backoff and retry).

## Environment

| Var | Default | Purpose |
| --- | --- | --- |
| `LISTEN_ADDR` | `:8080` | bind address |
| `API_KEY` | *(required)* | bearer token clients must send |
| `CAPTCHA_TRAP_DIR` | `./trap` | where to write debug artefacts for failed solves (slider images, etc.) |

## Deployment (Docker)

```sh
docker build -t turnbridge/captcha-service .
docker run -d \
  -p 8080:8080 \
  -e API_KEY=$(openssl rand -hex 16) \
  -v $(pwd)/trap:/var/trap \
  --name captcha-service \
  turnbridge/captcha-service
```

The container uses a non-root `app` user and exposes a `wget`-based
healthcheck on `/healthz`.

## Concurrency

`maxConcurrentCaptchaSolves = 5` matches the iOS client's pacing.
VK trips `ERROR_LIMIT` more aggressively when more than ~5-6 solves
land on the same source IP in the same 60 s window. Scale capacity
by adding more peers on different IPs (see Cluster mode below),
not by raising this limit on one instance.

## Cluster mode (V2)

Every binary is symmetric. The peer the client hits acts as
**master** for that request: it round-robins through the configured
peer list (including itself), forwards to `/internal/cred` when
round-robin lands on a different peer, and falls through to the
next peer on `429`. Single-node mode (no `PEERS`) is the default
and matches V1 behaviour.

### Deployment

Run one captcha-service per IP. Each binary needs to know all
peers in the fleet. Example for 3 nodes on different VPS:

```sh
# Node A (77.90.8.199)
docker run -d -p 8080:8080 \
  -e API_KEY=$SHARED_KEY \
  -e SELF_URL=http://77.90.8.199:8080 \
  -e PEERS='http://77.90.8.199:8080|'$SHARED_KEY',http://77.90.8.200:8080|'$SHARED_KEY',http://77.90.8.201:8080|'$SHARED_KEY \
  --name cs turnbridge/captcha-service

# Node B (77.90.8.200) — same PEERS list, different SELF_URL
docker run -d -p 8080:8080 \
  -e API_KEY=$SHARED_KEY \
  -e SELF_URL=http://77.90.8.200:8080 \
  -e PEERS='http://77.90.8.199:8080|'$SHARED_KEY',http://77.90.8.200:8080|'$SHARED_KEY',http://77.90.8.201:8080|'$SHARED_KEY \
  --name cs turnbridge/captcha-service

# Node C (77.90.8.201) — analogous
```

`PEERS` format: comma-separated `URL|API_KEY` entries. `SELF_URL`
must exactly match one of the `PEERS` URLs so the binary recognises
itself and bypasses HTTP when round-robin picks it. Different
peers can use different API keys (each entry carries its own); the
common pattern is one shared key across the whole fleet.

### Saturation propagation

Each peer tracks its own VK rate-limit cooldown locally
(`directSaturated()` flips on `ERROR_LIMIT` and auto-clears after
60 s). When a master forwards to a peer and the peer returns `429`
or sets `X-Captcha-Self-Saturated: 1` on its response, the master
records "peer X cool down until now + 60 s" and skips X in
subsequent rounds. No gossip / heartbeats — saturation is learned
passively from response headers.

`GET /stats` includes the master's view of each peer's availability.

### Client config

The client always talks to ONE master URL. To survive a single-node
outage, either:

- Front the cluster with a load balancer / DNS round-robin (single
  client URL → many backend nodes).
- Or accept that "master" is whichever node the client points at
  and live-edit the URL when needed.

### HTTP path summary

- `POST /cred` — public, client-facing. Master logic; forwards.
- `POST /internal/cred` — peer-only. Same auth as `/cred` but
  never forwards. Sets `X-Captcha-Self-Saturated: 1` when this
  peer is in its 60 s cooldown.
- `GET /stats` — counters + peer-view snapshot.
- `GET /healthz` — for Docker HEALTHCHECK.

