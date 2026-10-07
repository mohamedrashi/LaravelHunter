# LaravelHunter v0.9.0 — Edge-Aware Release

## Added
- WAF/CDN provider fingerprinting with Cloudflare, Sucuri, Akamai, Imperva and generic edge indicators.
- Edge provider confidence and protected-response classification.
- Conservative 750 ms minimum request pacing when an edge/WAF provider is detected.
- Automatic suppression of safe-active probes on challenge, explicit rate-limit, or provider-backed protected responses.
- Mid-scan stop behavior if protection is triggered during version, runtime, or route-discovery probes.
- Edge-aware policy metadata in JSON/Markdown reports and CLI output.

## Safety boundary
LaravelHunter does not generate WAF bypass payloads, spoof edge headers, rotate identities, solve challenges, or attempt Cloudflare evasion. The feature is designed to measure how edge controls affect assessment visibility while respecting those controls.

## Validation
- 48 automated tests passed.
- Normal safe-active smoke scan passed.
- Simulated Cloudflare challenge smoke scan correctly selected `stop-active` and suppressed active probes.
