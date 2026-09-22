## 0.1.5

### Packaging

 * Require Poetry >=2.2,<3 for development; migrate metadata, dependencies and CLI entry points to standard `[project]` tables, use the supported dev dependency group and Poetry Core >=2.2,<3 backend, and regenerate the lockfile with Poetry 2.5.1 without changing locked package versions.
 * Pin Forgejo CI to Poetry 2.5.1; validate the lockfile and synchronise dependencies with `poetry sync --with dev`.

### Security

 * Enable Chromium process sandboxing by default. Add an explicit `--no-sandbox` override for isolated, trusted environments; never automatically retry without sandboxing. Clarify that this is independent of `--bypass-csp`.
 * Validate and canonicalise HTTP(S)/WebSocket origins and validate generated CSP tokens to prevent source-map metadata injecting directives.
 * Report source-map locations as metadata instead of automatically authorising them in `connect-src`.
 * Replace the predictable cache write probe, reject unsafe/symlink cache paths, remove the shared temporary-directory fallback, and use an OS installation lock released after process death.
 * Abort failed document interception instead of silently replaying an uninstrumented request. Enforce top-level crawl scope, follow same-origin GET redirect hops explicitly at their real URLs, and reject unsafe/non-GET redirect replay.
 * Disable accepted downloads and block service workers for deterministic interception. Add scan/request/observation budgets and disclose incomplete coverage.

### Fixed

 * Invoke the report-only violation listener correctly, attribute records to the candidate policy/document, preserve distinct findings and stop trusting page-authored console strings as violations.
 * Return exit 2 for incomplete/error scans, invalid arguments, unconfirmed injection and remaining enforcing policies; retain exit 1 for completed scans with violations.
 * Resolve links through browser `a.href`, respecting nested paths, query/fragment links and `<base>`. Canonicalise equivalent origins/root URLs and record final navigation URLs.
 * Separate third-party iframe subresources from parent policy permissions; include same-origin/inherited-policy frames and explicitly observe WebSockets where attribution is unambiguous.
 * Detect external script/stylesheet nonce attributes and emit script/style nonce requirements separately. Skip data-only script blocks and disclose inline collection truncation.
 * Honour explicit browser paths with `--no-install`, preserve `PLAYWRIGHT_BROWSERS_PATH=0`, use a consistent CI cache, and avoid reinstalling an existing browser after a sandbox/library launch failure.
 * Keep installer output off JSON stdout, skip non-HTML hashing and report page errors/status explicitly.

### Added and changed

 * JSON schema v2 with complete serialised directives, permission observations, per-page status/injection confirmation, errors/completeness, source-map metadata and header byte size.
 * Add `--evaluate-file`, `--header-only`, repeatable `--exclude`, `--scan-timeout`, `--max-requests`, `--max-observations` and `--header-budget`.
 * Add deterministic unit/control-flow regressions and loopback Chromium integration fixtures; make public-site smoke tests opt-in and remove the brittle live-site policy snapshot.
 * Update README with output/exit-code migration notes, sandbox/CSP distinction and remaining coverage limits; add a realistic `SECURITY.md` threat model.

## 0.1.4

 * Don't wait for networkidle, if it doesn't get that far but 'load' does

## 0.1.3

 * Fix bug in `--evaluate` mode, which would inject the CSP into third party domains, which they would then throw violations for and trip the result

## 0.1.2

 * Add `--bypass-csp` option to ignore an existing enforcing CSP to avoid it skewing results
 * Add `--evaluate` option to test a proposed CSP without needing to install it (best to use in conjunction with --bypass-csp`)

## 0.1.1

 * Fix prog name
 * Add --ignore-non-html option to skip pages that weren't HTML (which might trigger Chromium's 'sha256-4Su6mBWzEIFnH4pAGMOuaeBrstwJN4Z3pq/s1Kn4/KQ=' hash)
 * Fix detection of Python for AppImage if it needs to install browsers via playwright

## 0.1.0

 * Initial release
