# cspresso

<div align="center">
  <img src="https://git.mig5.net/mig5/cspresso/raw/branch/main/cspresso.svg" alt="CSPresso logo" width="240" />
</div>

Observe a site using Chromium through Playwright and generate a **draft** Content
Security Policy. Review every suggested permission before deployment. A crawl
observes code; it cannot establish that the code is trustworthy or cover every
user flow.

## Installation

Requires Python 3.10+ and Playwright's Chromium binaries. Source development
and release commands use Poetry >=2.2,<3 (CI pins Poetry 2.5.1).

```bash
pip install cspresso
# Or from this repository, using Poetry >=2.2,<3:
poetry sync --with dev
```

Release AppImages can be made executable with `chmod +x CSPresso.AppImage`.
Verify release signatures with the key at <https://mig5.net/static/mig5.asc>:
`54A91143AE0AB4F7743B01FE888ED1B423A3BC99`.

If the browser executable is missing, CSPresso installs it automatically. Use
`--no-install` to prohibit installation. `--with-deps` requests OS dependencies
when installation is needed; alternatively install them explicitly:

```bash
poetry run playwright install-deps chromium
```

An existing browser that fails to launch is **not** repeatedly reinstalled.
Read the error for missing libraries, sandbox support or account restrictions.

## Discovery

```bash
cspresso https://example.com/ --max-pages 10 --json
cspresso https://example.com/ --bypass-csp --header-only
cspresso https://example.com/docs/ --exclude '/logout*' --exclude '/delete/*'
```

Links use the browser's resolved URL, including the current document and
`<base href>`. Only same-origin HTML documents are collected; non-HTML links
are skipped. GET redirects within the origin are followed explicitly at their
real URL because Playwright's routing does not intercept automatic redirect
hops. This can change redirect timing/history. Top-level redirects outside the
origin are rejected: start with the canonical HTTPS/www URL instead. Non-GET
redirects are not replayed; delayed redirects after initial load are reported
as incomplete and should be scanned using an explicit final URL.

`--exclude` applies to top-level navigation URLs/paths, not every subresource.
It is a crawl-scope control, not a network firewall. Third-party assets and
frames still load. Resources inside foreign frames do not become permissions
for the parent document. Same-origin and inherited-policy `about:blank`/`srcdoc`
frames are included.

Default text output contains comments and a `Content-Security-Policy:` line.
`--header-only` prints just the policy value, with diagnostics on stderr.
Installer messages also go to stderr, keeping `--json` output parseable.

## Chromium sandbox versus CSP bypass

**The Chromium process sandbox is enabled by default.** It contains browser
processes; it does not filter ordinary script/style origins or prevent the
resource observations needed to build a CSP. Run as a non-root user with OS
sandbox support.

`--bypass-csp` removes existing CSP and report-only **response headers** from
same-origin HTML. This is the option for discovering resources otherwise
blocked by the site's existing policy. It does not disable the process sandbox
and does not remove meta-delivered CSP. Remaining meta CSP is reported; in
evaluation mode it makes the result incomplete.

If a site is compromised, bypassing its CSP may enable malicious code that was
previously blocked. A browser sandbox is useful containment, not an assurance
that malicious sites are safe. See [SECURITY.md](SECURITY.md).

`--no-sandbox` is an explicit escape hatch for trusted scans inside suitable
external isolation. It is never selected automatically after a launch failure.
It is not needed to improve CSP discovery.

## Evaluate a proposed policy

```bash
cspresso https://example.com/ --bypass-csp \
  --evaluate "default-src 'self'; object-src 'none'" --json

cspresso https://example.com/ --bypass-csp --evaluate-file candidate-csp.txt --json
```

The candidate is injected as `Content-Security-Policy-Report-Only`; Chromium
reports violations without blocking those resources. An existing enforcing
header that remains in place makes evaluation incomplete, because it can hide
behavior from the candidate. Existing report-only headers are replaced during
evaluation, while foreign documents are not rewritten.

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | The selected scan completed without observed candidate violations. This is not a guarantee of complete application coverage. |
| 1 | The selected scan completed and candidate violations were observed. |
| 2 | Invalid input, runtime failure or incomplete scan. Check `errors`, including when violations also exist. |

Zero/negative budgets and empty candidate policies are rejected. Failed
interception never silently retries an uninstrumented navigation. Injection is
confirmed for collected documents, and violations are attributed to the
candidate and relevant frames. Browser diagnostics about rejected policy syntax
also make evaluation incomplete. This is not a complete CSP standards linter.

No report-only crawl can fully test enforcement behavior. Exercise real flows
in staging before deploying the policy, particularly forms, embedding and
authenticated interactions. A hostile page can manipulate its own behavior or
instrumentation: CSPresso is not an adversarial policy verifier.

## JSON schema v2 and permission evidence

The JSON includes:

- `csp` and `directives`: the same complete generated policy, including defaults,
  hashes and nonce templates. Earlier versions exposed only raw external
  origins through `directives`.
- `visited`: successfully scanned final HTML URLs.
- `pages`: requested/final URLs, redirects, HTTP status, completion status and
  whether candidate injection was confirmed.
- `observations`: document/frame URL, directive, resource URL/origin or inline
  hash, and observation kind. Requests are observations, not proof that a
  permission is necessary or that a response succeeded.
- `violations`, `evaluated_policy`, `notes`, `errors` and `complete`.
- `header_bytes`: UTF-8 size including the header name and separator, excluding
  HTTP framing. `--header-budget` is an advisory threshold, not a deployment
  guarantee.
- `sourcemaps`: optional developer metadata collected with `--include-sourcemaps`.

**Source-map behavior changed:** map origins are no longer automatically added
to `connect-src`. A debugging pointer is not proof the application needs that
permission. Source-map URLs are validated as HTTP(S) origins. Body scans are
skipped for unknown, compressed or large response sizes; headers can still be
inspected. Invalid metadata cannot inject CSP directives.

Output may include sensitive URL query strings and internal hostnames. Store
reports as restricted artifacts; automatic URL-secret redaction is not provided.
Human-readable diagnostics escape control characters.

## Nonces, hashes and optional permissions

Detected nonce requirements are tracked separately for scripts and styles,
including external script/stylesheet elements. `{NONCE}` is a template: your
server must replace it with a fresh unpredictable nonce on **every response**
and put matching values in the relevant HTML elements. Observed nonce values
are not emitted.

Hashes depend on stable inline content. Data-only script blocks such as JSON-LD
are not treated as executable JavaScript. Inline attributes require
`'unsafe-hashes'`; moving code into external files or nonce-bearing elements is
preferable. A settled DOM snapshot can miss code removed earlier in the load.

Optional flags: `--unsafe-eval`, `--allow-blob`, and
`--upgrade-insecure-requests`. They deliberately affect policy recommendations;
review their implications before using the output. Baseline `form-action`,
`frame-ancestors` and other defaults are recommendations, not inferred business
requirements.

## Bounds and coverage

Defaults:

| Option | Default |
| --- | --- |
| `--max-pages` | 10 attempted pages |
| `--timeout-ms` | 20000 per navigation |
| `--settle-ms` | 1500 after load/network settling |
| `--scan-timeout` | 120 seconds, excluding browser installation |
| `--max-requests` | 2000 intercepted HTTP requests |
| `--max-observations` | 10000 observation/violation records |
| `--header-budget` | 8192 bytes, advisory |

A page-budget boundary is expected finite coverage and is recorded in notes;
request/observation truncation or a wall-clock deadline makes the scan
incomplete. Inline collections have count/text limits and disclose truncation.
These limits are not a hard browser memory, network-byte or disk quota. Use
OS/container limits for hostile content; interception may buffer responses.

Service workers are blocked to make interception deterministic. Apps requiring
them need separate testing. Dedicated worker sources can be observed, but
worker-internal requests without document provenance are not merged into the
page policy. WebSockets are captured explicitly when frame attribution is
unambiguous; mixed-origin frame ambiguity produces an incomplete result.
CSS-embedded data URLs, removed early scripts, shadow DOM, user interactions,
other browsers and authenticated flows are not exhaustively covered.

## Browser cache

Default: a `cspresso/pw-browsers` directory in the user's cache location, e.g.
`~/.cache/cspresso/pw-browsers` on Linux. Override with `--browsers-path` or
`PLAYWRIGHT_BROWSERS_PATH`. The latter's special value `0` retains Playwright's
package-local convention. Explicit directories also work with `--no-install`.

Caches must be owned by the current account and not writable by other users.
Symlink paths and unsafe ancestor directories are rejected. There is no shared
`/tmp` fallback. Installation uses an OS-released lock, so a crashed process
does not leave a permanent stale lock.

## Tests

```bash
poetry run pytest                         # deterministic unit/control-flow tests
./tests.sh                                # install Chromium and run local browser fixtures too
poetry run pytest --run-browser            # local fixtures, browser already installed
poetry run pytest --run-network            # optional live-site smoke test
```

`tests.sh` uses the same browser cache for installation and scans. Browser tests
use loopback HTTP servers, not snapshots of a changing public website. CI's
Docker test step explicitly sets `CSPRESSO_TEST_NO_SANDBOX=1` for these trusted
fixtures because the existing runner runs as root. This test-only environment
variable is read by the tests, **not the production CLI**. Prefer a non-root,
sandbox-capable runner and remove that override when available.

See `cspresso --help` for all options and [CHANGELOG.md](CHANGELOG.md) for changes.
