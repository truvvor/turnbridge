# Manual captcha path — hardening for bootstrap sessions

Under hard network blocking there is **no tunnel and no reachable
captcha-service until the first session is up**, so the first few VK
identities must be earned by hand in the on-device WebView. That path
was being flagged as a bot. This change addresses the likely causes,
in priority order.

## 1. Bootstrap-manual-first (skip the poisoning auto attempt)

`solveVkCaptcha` previously ran the tls-client auto solver first in
`fallback` mode; only on its failure did the manual sheet appear. But
the auto attempt reliably draws `status:BOT`, and that verdict poisons
the captcha session / source IP that the user is about to solve in a
real WebKit engine moments later.

New `manualCaptchaBootstrapActive()` (captcha_manual.go): while
`captchaSessionsReady == 0`, a manual handler is registered, the user
opted into prompts (`mode != off`), and quota remains, `solveVkCaptcha`
goes **straight to the manual sheet** and skips the auto chain. After
the first session is up it returns false and normal mode behaviour
resumes. `errDeferToRemote` (quota spent / a session came up while we
queued) falls through to the auto chain instead of failing the solve.

Net effect: the real-browser solve is the first and only thing VK sees
on a clean session during bootstrap.

## 2. Cookie / state warm-up (CaptchaWebView.swift)

A captcha session with zero prior vk.com cookies + localStorage reads
as a freshly-spun-up automation environment. Before navigating to the
captcha the WebView now briefly loads `https://m.vk.com/` so the
persistent data store picks up organic state. The real captcha load is
kicked from the warm-up's `didFinish` or a 3 s hard cap, whichever
fires first, so a blocked/slow warm-up never strands the user.

## 3. In-session replay logging (CaptchaWebView.swift)

The in-WebView replay (`window.__capRetry`) POSTs `getAnonymousToken`
inside the solved session so VK sees one coherent actor. That fetch is
**cross-origin** (captcha origin → api.vk.com) and can be silently
blocked by the page's CSP `connect-src` or missing CORS — which demotes
us to the bot-prone Go redemption path without any signal.

The JS now emits explicit status lines — `replay OK: final_response`,
`replay FALLBACK: fetch threw (… likely CORS/CSP)`, `replay FALLBACK:
empty response body` — and the native side mirrors WebView status into
`SharedLogger.debug`, so a device sysdiagnose shows exactly which branch
ran. If logs show the fallback firing, that — not the solve gesture —
is why redemption looks like a session switch.

Also added: `navigator.maxTouchPoints => 5` parity (real iPhone Safari).

## 4. Real-Safari path (EXPERIMENTAL, opt-in, not wired)

`SafariCaptchaView.swift` adds an `ASWebAuthenticationSession` solver
that runs the page in the real Safari service process — real Safari
fingerprint + shared Safari cookies. **Hard limitation:** no JS
injection and no per-navigation callbacks, so it can only capture
`success_token` if the flow ends by redirecting to a URL whose scheme
matches `callbackURLScheme`. To use it:

1. Register a `redirect_uri` you control as the captcha redirect target
   (https / Universal Link), have it 302 to
   `turnbridge://captcha?success_token=...`, set `callbackScheme`
   accordingly; **or** point the scheme at whatever target VK reflects
   `success_token` into.
2. Add the file to the TurnBridge target and gate it behind a setting.

Until that redirect plumbing exists, `CaptchaWebView` (WKWebView)
remains the shipping path; this file compiles and presents but will not
complete a solve on its own.

## Build / validation note

These edits could not be compiled here (no macOS/Xcode/Go toolchain in
the authoring environment). Go syntax was checked with `gofmt`. Swift
needs a device build + a real blocked-network run to confirm: watch the
log for `bootstrap (sessions_ready=0) — manual-first`, the warm-up
load, and the `replay OK` vs `replay FALLBACK` line.
