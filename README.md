# Blackveil DNS Security Scanner — GitHub Action

Scan your domain's DNS and email security configuration in CI/CD. Powered by the [Blackveil DNS MCP server](https://github.com/MadaBurns/bv-mcp).

Runs a full DNS security audit (SPF, DMARC, DKIM, DNSSEC, SSL, MTA-STS, MX, CAA, BIMI, TLS-RPT, NS, HTTP security, DANE, subdomain takeover and more) and enforces a minimum grade threshold. Fails the workflow if the domain's security posture is below the required grade — or if the domain could not be graded at all.

## Quick Start

```yaml
name: DNS Security Check
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: "0 6 * * 1" # Weekly Monday 6am

jobs:
  dns-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Scan DNS security
        uses: MadaBurns/blackveil-dns-action@v1
        id: scan
        with:
          domain: example.com
          minimum-grade: C

      - name: Print results
        if: always()
        run: |
          echo "Score: ${{ steps.scan.outputs.score }}"
          echo "Grade: ${{ steps.scan.outputs.grade }}"
          echo "Maturity: ${{ steps.scan.outputs.maturity }}"
          echo "Profile: ${{ steps.scan.outputs.scoring-profile }}"
          echo "Passed: ${{ steps.scan.outputs.passed }}"
          echo "Report: ${{ steps.scan.outputs.report-url }}"
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `domain` | Yes | — | Domain to scan (e.g. `example.com`). Bare hostname, no scheme or path. |
| `minimum-grade` | No | `C` | Minimum passing grade. One of: `A+`, `A`, `B`, `C`, `D`, `F`. Legacy `B+`/`C+`/`D+` are accepted and mapped to `B`/`C`/`D` with a warning. |
| `profile` | No | `auto` | Scoring profile: `auto`, `mail_enabled`, `enterprise_mail`, `non_mail`, `web_only`, `minimal`, `authoritative_dns_infra` |
| `fail-on-inconclusive` | No | `true` | Fail the job when the domain cannot be graded (does not resolve, too few checks completed). Set to `false` to only emit a warning. |
| `force-refresh` | No | `false` | Bypass the server-side scan cache and run a fresh scan. |
| `api-key` | No | — | Blackveil DNS API key for authenticated access (higher rate limits) |
| `endpoint` | No | `https://dns-mcp.blackveilsecurity.com/mcp` | MCP endpoint URL (`https://` only) |

## Outputs

| Output | Description | Example |
|--------|-------------|---------|
| `score` | Numeric score (0-100). Empty when not measured. | `82` |
| `grade` | Letter grade. Empty when not measured. | `B` |
| `measured` | `true` when the scan produced a grade, `false` when the domain could not be graded | `true` |
| `passed` | Whether the grade meets the threshold. Always `false` when not measured. | `true` |
| `maturity` | Email security maturity stage | `Enforcing` |
| `scoring-profile` | Scoring profile used (detected or explicit) | `mail_enabled` |
| `finding-counts` | JSON severity breakdown | `{"critical":0,"high":1,"medium":2,"low":3}` |
| `interaction-effects` | JSON scoring interaction penalties (empty when none) | `[{"ruleId":"...","penalty":5,"narrative":"..."}]` |
| `percentile-rank` | Percentile rank within scoring profile (0-100, empty when insufficient data) | `72` |
| `spoofability-score` | Email spoofability score (0-100, higher = worse, empty when not computed) | `35` |
| `report-url` | Public per-domain security report | `https://www.blackveilsecurity.com/security-report/example.com` |
| `cached` | `true` when the server returned a cached scan | `false` |

## Grade Scale

The server reports the NIST-aligned 6-band display scale:

| Grade | Score Range |
|-------|-------------|
| A+ | 95-100 |
| A | 90-94 |
| B | 80-89 |
| C | 70-79 |
| D | 60-69 |
| F | 0-59 |

### Ungraded domains

A domain that does not resolve, or where too few checks completed to score it, is reported as **not measured** rather than as an `F`. The `grade` and `score` outputs are empty, `measured` is `false`, and `passed` is `false`. By default the job fails (`fail-on-inconclusive: true`), because "could not check" must never look like "checked and clean" in a security gate. Set `fail-on-inconclusive: false` to downgrade that to a warning — for example on domains that are still being provisioned.

## Examples

### Enforce Strict Grade on Production Domains

```yaml
- name: Scan production domain
  uses: MadaBurns/blackveil-dns-action@v1
  with:
    domain: mycompany.com
    minimum-grade: B
```

### Scan Multiple Domains

```yaml
jobs:
  dns-scan:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        domain: [mycompany.com, mail.mycompany.com, api.mycompany.com]
      fail-fast: false
    steps:
      - name: Scan ${{ matrix.domain }}
        uses: MadaBurns/blackveil-dns-action@v1
        with:
          domain: ${{ matrix.domain }}
          minimum-grade: C
```

### Use Outputs in Downstream Steps

```yaml
- name: Scan DNS
  id: dns
  uses: MadaBurns/blackveil-dns-action@v1
  with:
    domain: example.com
    minimum-grade: F  # Don't fail on grade — we check manually below
    fail-on-inconclusive: false

- name: Warn when the domain could not be scanned
  if: steps.dns.outputs.measured == 'false'
  run: echo "::warning::DNS scan for example.com was inconclusive"

- name: Warn on low grade
  if: steps.dns.outputs.measured == 'true' && steps.dns.outputs.passed == 'false'
  run: echo "::warning::DNS grade ${{ steps.dns.outputs.grade }} is below target"

- name: Block deploy on critical issues
  if: steps.dns.outputs.grade == 'F'
  run: |
    echo "::error::DNS security grade F — blocking deployment"
    exit 1
```

### Scheduled Monitoring with Slack Notification

```yaml
name: Weekly DNS Audit
on:
  schedule:
    - cron: "0 9 * * 1"

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - name: Scan DNS
        id: scan
        uses: MadaBurns/blackveil-dns-action@v1
        continue-on-error: true
        with:
          domain: mycompany.com
          minimum-grade: B
          force-refresh: true   # weekly audits should not reuse a cached scan

      - name: Notify on failure
        if: steps.scan.outputs.passed == 'false'
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "DNS Security Alert: ${{ steps.scan.outputs.grade || 'not measured' }} (${{ steps.scan.outputs.score || '-' }}/100) for mycompany.com — ${{ steps.scan.outputs.report-url }}"
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
```

### Authenticated Access (Higher Rate Limits)

For CI/CD pipelines that scan frequently or use matrix strategies across many domains, use an API key:

```yaml
- name: Scan DNS (authenticated)
  uses: MadaBurns/blackveil-dns-action@v1
  with:
    domain: mycompany.com
    minimum-grade: B
    api-key: ${{ secrets.BV_API_KEY }}
```

Store your API key as a [GitHub Actions secret](https://docs.github.com/en/actions/security-guides/encrypted-secrets). It is sent as a bearer token, which is why the `endpoint` input must be `https://`.

### Context-Aware Scoring Profiles

By default, the scanner auto-detects whether a domain is mail-enabled and adjusts scoring accordingly. You can override this with an explicit profile:

```yaml
# Non-mail domain — don't penalize for missing SPF/DMARC/DKIM
- name: Scan API domain
  uses: MadaBurns/blackveil-dns-action@v1
  with:
    domain: api.mycompany.com
    profile: non_mail
    minimum-grade: B

# Enterprise mail — stricter scoring for mail infrastructure
- name: Scan mail domain
  uses: MadaBurns/blackveil-dns-action@v1
  with:
    domain: mail.mycompany.com
    profile: enterprise_mail
    minimum-grade: A
```

| Profile | Use case |
|---------|----------|
| `auto` | Auto-detect from MX records (default) |
| `mail_enabled` | Standard mail domain |
| `enterprise_mail` | Enterprise mail with stricter requirements |
| `non_mail` | Domain that doesn't send/receive email |
| `web_only` | Web-only domain (no mail infrastructure) |
| `minimal` | Minimal checks only |
| `authoritative_dns_infra` | Authoritative DNS infrastructure (nameserver hosts) |

Categories that do not apply to the chosen profile are shown as **N/A** in the job summary rather than scored; categories whose check timed out or errored are shown as **Inconclusive**.

### Branch Protection (Require DNS Grade)

To enforce DNS security as a required status check:

1. Add the scan job to your PR workflow:

```yaml
name: PR Checks
on: pull_request

jobs:
  dns-security:
    runs-on: ubuntu-latest
    steps:
      - name: DNS security gate
        uses: MadaBurns/blackveil-dns-action@v1
        with:
          domain: mycompany.com
          minimum-grade: C
```

2. In your repository settings, go to **Settings > Branches > Branch protection rules**.
3. Enable **Require status checks to pass before merging**.
4. Add `dns-security` as a required check.

## Job Summary

The action writes a detailed summary to the GitHub Actions job summary, including:

- Overall score, grade, maturity stage and a link to the full public report
- Category-by-category score breakdown (with N/A and Inconclusive states)
- Top findings with severity and category
- Scoring interaction penalties, when any applied

The summary is visible in the Actions run UI under the **Summary** tab.

## How It Works

1. **Session Initialization:** Initializes an MCP (Model Context Protocol) session with the Blackveil DNS server (protocol `2025-06-18`).
2. **Domain Scanning:** Calls the `scan_domain` tool via JSON-RPC 2.0 with the specified scoring profile.
3. **Resilience & Retries:**
   - Up to 3 attempts on network failures, timeouts (120s per request), `408`, `429` and `5xx` responses, with linear backoff.
   - `429 Too Many Requests` honours the `Retry-After` header (seconds or HTTP date, capped at 60s).
   - Other `4xx` responses and JSON-RPC errors fail immediately — they will not succeed on retry.
4. **Data Extraction:** Reads the MCP-standard `structuredContent` result. Falls back to the legacy `STRUCTURED_RESULT` block, then to parsing the human-readable report, for older or custom servers.
5. **Reporting:** Generates a Markdown **Job Summary** and sets GitHub Action outputs for downstream steps.
6. **Enforcement:** Exits non-zero if the grade does not meet `minimum-grade`, or if the domain could not be graded and `fail-on-inconclusive` is `true`.

No API key is required — the public endpoint is free to use with rate limiting (50 req/min, 300 req/hr per IP, 75 scans/day per IP). For higher limits, use the `api-key` input with a Blackveil DNS API key.

## Rate Limits

| Tier | Per-Minute | Daily Scans |
|------|-----------|-------------|
| Free (no API key) | 50 | 75 |
| Agent | 50 | 200 |
| Developer (Pro) | 50 | 500 |
| Enterprise | 50 | 10,000 |
| Partner | 50 | 100,000 |

**Tip:** If you scan multiple domains in a matrix strategy, use an API key to avoid hitting the daily scan limit. CI/CD runners often share public IPs, which can exhaust the free tier quickly.

## Development

No dependencies. Requires Node.js 20 or later (the action itself runs on Node 24).

```bash
npm test          # unit tests against captured server responses (no network)
npm run check     # syntax check every module
INPUT_DOMAIN=example.com INPUT_MINIMUM_GRADE=C node scan.mjs   # live run
```

The pure logic lives in `lib/` (`grades`, `parse`, `summary`, `mcp-client`, `github`); `scan.mjs` is the entry point. Fixtures under `test/fixtures/` are real `scan_domain` responses.

## License

[BSL 1.1](LICENSE) — Non-commercial use permitted. Converts to MIT on 2030-03-17.
