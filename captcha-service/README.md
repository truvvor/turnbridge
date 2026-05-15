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
land on the same source IP in the same 60 s window. If you front
this with a pool of egress IPs, scale the concurrency proportionally
(future work; the current build assumes one IP per binary).
