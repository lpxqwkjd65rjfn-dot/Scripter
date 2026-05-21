# Plan: harden rkn_probe to minimize hosting-provider ban risk

Goal: minimize (cannot guarantee 0%) probability of provider account
suspension caused by IP-churn / API abuse, and broaden checker stages
so a candidate IP is verified hard before it is declared "whitelisted".

Note on the 0% promise: not technically achievable — hoster heuristics
are opaque. We minimize risk via conservative rate limits, daily caps,
exponential backoff on errors, circuit breakers, Retry-After respect,
polite headers, jitter, and post-error cooldowns.

### [x] Step: Plan

### [ ] Step: Harden rate limiter
- Add per-provider rolling daily cap (in addition to hourly)
- Track recent errors; apply exponential backoff cooldown
- Honor server-imposed cooldown (Retry-After)
- Larger jitter; minimum spacing after release

### [ ] Step: Extend config
- New global knobs: backoff base/cap, daily cap defaults, post-error cooldown
- New global checker knobs: extra probe ports, jitter, retries
- Conservative defaults (slow & polite)

### [ ] Step: Persist daily ops budget in state
- Per-provider daily counter with date key; resets on UTC date change

### [ ] Step: Harden orchestrator
- Per-provider circuit breaker on 429 / 5xx / network errors
- Enforce daily ops budget before allocating
- Post-error exponential cooldown with jitter
- Guaranteed cleanup on cancellation, with timeout per release
- Refuse to start more than one allocation in flight per provider

### [ ] Step: Expand checker (more stages)
- Multi-port TCP sweep (configurable list, all checked)
- TLS handshake on 443 with cert presence stage
- HTTP marker on plaintext
- HTTPS marker (verify=False, port 443) as separate stage
- Latency sanity stage (RTT within bounds)
- Stability: 3 sequential TCP probes, require >= 2 successes
- Jitter between stages; retry once on transient TCP/HTTP errors

### [ ] Step: Safer provider HTTP helper
- Shared `_request` with Retry-After honoring, retry on 429/5xx with backoff
- Polite User-Agent, conservative timeout
- Wire into yandex + selectel (rest unchanged for now)

### [ ] Step: Update config.example.yaml
- Document new knobs with safe defaults
