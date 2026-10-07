# LaravelHunter v0.9.1

## Added
- `waf-lab` private-laboratory differential testing command.
- Hard scope guard: loopback, link-local, or RFC1918/private addresses only.
- Benign GET-only request variants for comparing edge/application normalization behavior.
- JSON and Markdown WAF lab reports.
- Explicit reporting of edge-control vs application-only divergences.

## Safety boundary
`waf-lab` does not implement public-target WAF bypass, challenge solving, origin discovery, exploit payloads, or state-changing requests.
