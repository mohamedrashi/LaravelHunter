# LaravelHunter v0.7.0

LaravelHunter is a conservative Laravel security assessment engine for authorized testing. It fingerprints Laravel and common components, correlates exact versions with bundled advisories when possible, performs read-only runtime prerequisite checks, and can conduct a bounded same-origin GET-only discovery pass.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Passive scan

```bash
laravelhunter scan https://example.test
```

## Safe-active scan

```bash
laravelhunter scan https://example.test --safe-active
```

Safe-active mode is deliberately constrained: read-only dependency/version probes, one harmless non-existent-path debug response check, and bounded same-origin GET discovery of links already exposed by the application. It does not submit forms, invent parameters, call Livewire update endpoints, or send POST/PUT/PATCH/DELETE requests.

## Authorized session import

For a test account/session you are explicitly authorized to use, create a local file such as `auth.txt`:

```text
Cookie: XSRF-TOKEN=<value>; app-session=<value>
# Optional additional request headers:
Authorization: Bearer <token>
X-Requested-With: XMLHttpRequest
```

Then run:

```bash
chmod 600 auth.txt
laravelhunter scan https://example.test --safe-active --auth-file auth.txt --max-discovery-pages 15
```

LaravelHunter parses `Cookie:` into its cookie jar and applies imported headers only to the requested origin. When an auth context is loaded, cross-origin redirects are not followed with those credentials. Secret values are never intentionally written to reports; reports contain only imported cookie/header names and a coarse authentication-state inference.

Do not paste long-lived production credentials into shell history. Prefer `--auth-file` and delete the file when finished.

## What v0.7.0 adds

- Passive **Authenticated Filament Page Inventory** from pages already fetched by safe discovery.
- Extracts visible Filament/Livewire component names, resource/page hints, form markers, field/model names, and action markers.
- **Does not execute** discovered actions or submit discovered forms.
- Review-priority triage (`high`, `medium`, `normal`) for administrative surfaces. Priority is not a vulnerability severity.
- Current-session access map (`reachable`, `denied`, `redirect`, `not-found`, `other`).
- Coverage counters for inventoried Filament pages and high/medium-interest pages.
- Canonical route deduplication: query-string variants of the same page are merged for discovery/inventory purposes.
- Review priority now uses the page path and resource/page identity rather than shared nested Filament plumbing.
- Common Filament/Livewire framework actions and internal state fields are filtered from application-facing action/field counts.
- Existing exact-version and advisory safeguards remain unchanged.

## Example inventory output

```text
Authenticated Filament Page Inventory
HIGH    /admin/users                      reachable (200)
HIGH    /admin/admin-sessions             reachable (200)
HIGH    /admin/manage-synapse-admin-token reachable (200)
MEDIUM  /admin/audit-logs                 reachable (200)
```

The detailed report can also include already-visible markers such as:

```text
Resource/page hints: UserResource, ListUsers
Visible actions: create, save
Visible fields: tableSearch, email, displayname
```

These are inventory observations only. LaravelHunter does not claim broken authorization merely because the supplied session can access a page.

## Reports

By default:

```text
reports/latest/report.md
reports/latest/report.json
```

A missing exact Laravel version intentionally keeps version-specific advisories at `not-evaluated`. Runtime prerequisite evidence is tracked separately and never proves exploitability by itself.


## v0.7 Resource & Action Correlation

v0.7 keeps authenticated analysis read-only and correlates already-rendered Filament markup into:

- Resource classes (for example `UserResource`)
- Page classes and inferred page types (`list`, `create`, `edit`, `view`, `manage`, `custom`)
- Page actions, table record actions, bulk actions, and form submit actions
- Form/application fields versus table-state/filter fields
- Authorization-review surfaces such as record actions and numeric record identifiers

Authorization-review surfaces are triage hints only. They are not vulnerability findings, and LaravelHunter does not execute the observed actions or submit forms.

## v0.8 Authorization Matrix

Compare two authorized sessions without executing actions or submitting forms:

```bash
laravelhunter auth-matrix https://target.example \
  --auth-a admin-auth.txt --label-a admin \
  --auth-b reviewer-auth.txt --label-b reviewer \
  --max-discovery-pages 20
```

The matrix compares page reachability, visible application actions, and authorization-review surfaces. It does **not** infer which role should be more privileged and does not label a difference as a vulnerability automatically.


## Local project mode (owned labs/source trees)

For a Laravel project you own locally, provide the source directory to resolve exact Composer package versions without exposing those files over HTTP:

```bash
laravelhunter scan http://127.0.0.1:8000/admin --safe-active --project-path ~/Desktop/laravel-lab
```

This reads local `composer.lock` only and records package names/versions, not dependency file contents. The exact `laravel/framework` version is then used for advisory range correlation. Filament and Livewire package versions also override weak HTTP asset hints.

## v0.9.0 — Edge-Aware WAF / CDN Analysis

LaravelHunter now treats WAF/CDN behavior as part of assessment coverage rather than something to evade.

- Identifies Cloudflare and common edge/WAF indicators from response headers/body markers.
- Records provider confidence, challenge state, rate limiting, and protected-response state.
- Applies conservative request pacing when a WAF/CDN is detected.
- Suppresses safe-active probes when a challenge, explicit rate limit, or provider-backed block is observed.
- Stops bounded route discovery if protection is triggered mid-scan.
- Writes the selected edge policy and pacing decision into JSON/Markdown reports.

This feature intentionally does **not** generate WAF bypass payloads, spoof edge headers, rotate identities, solve challenges, or attempt Cloudflare evasion. It is designed for authorized, read-only assessment and controlled lab validation.

## Private WAF laboratory differential mode (v0.9.1)

For an owned loopback/RFC1918 lab only:

```bash
laravelhunter waf-lab http://127.0.0.1:8080/
```

This sends a small benign GET-only corpus and compares HTTP/edge behavior. The command hard-refuses public Internet targets. It is intended for WAF normalization and policy testing, not protective-control bypass.
