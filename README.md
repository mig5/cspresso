# cspresso

<div align="center">
  <img src="https://git.mig5.net/mig5/cspresso/raw/branch/main/cspresso.svg" alt="CSPresso logo" width="240" />
</div>

Crawl up to *N* pages of a site using a headless Chromium (via Playwright), observe what assets are loaded, and emit a **draft** Content Security Policy (CSP).

This is meant as a **starting point**. Review and tighten the resulting policy before enforcing it.

## Why "draft"?

- A crawl rarely covers all user flows (auth-only pages, A/B tests, conditional loads, etc.).
- Inline script/style handling is tricky:
  - If your pages use nonces, you must generate a **new nonce per HTML response** and insert it both in the CSP header and in the HTML tags.
  - Hashes work only if the inline content is stable *byte-for-byte*.

## Requirements

- Python 3.10+
- Playwright's Chromium browser binaries (auto-installed by this tool if missing)

## Install

If using my artifacts from the Releases page, you may wish to verify the GPG signatures with the key.

It can be found at https://mig5.net/static/mig5.asc . The fingerprint is `00AE817C24A10C2540461A9C1D7CDE0234DB458D`.

### Poetry

```bash
poetry install
```

### pip/pipx

```bash
pip install cspresso
```

### AppImage

Download the CSPresso.AppImage from the releases page, make it executable with `chmod +x`, and run it.

## Run

```bash
cspresso https://example.com --max-pages 10
```

The tool will:
1) attempt to launch Chromium headless
2) if Chromium isn't installed, it will run: `python -m playwright install chromium`
3) crawl same-origin links up to the page limit
4) print the visited URLs and a CSP header

## Where Playwright installs browsers

By default, this project installs Playwright browsers into a local folder: `./.pw-browsers`.
This makes installs deterministic and easy to cache in CI.

You can override with `--browsers-path` or by setting `PLAYWRIGHT_BROWSERS_PATH` yourself.

## Linux notes

If Chromium fails to start due to missing system libraries, try:

```bash
poetry run cspresso https://example.com --with-deps
```

That runs `python -m playwright install --with-deps chromium` (may require sudo depending on your environment).

## Output

Default output is a single CSP header line.

For JSON:

```bash
poetry run cspresso https://example.com --json
```

## Full usage info

```
usage: cspresso [-h] [--max-pages MAX_PAGES] [--timeout-ms TIMEOUT_MS] [--settle-ms SETTLE_MS] [--headed] [--no-install] [--with-deps] [--browsers-path BROWSERS_PATH] [--allow-blob] [--unsafe-eval]
                [--upgrade-insecure-requests] [--include-sourcemaps] [--ignore-non-html] [--json]
                url

Crawl up to N pages (same-origin) with Playwright and generate a draft CSP.

positional arguments:
  url                   Start URL (e.g. https://example.com)

options:
  -h, --help            show this help message and exit
  --max-pages MAX_PAGES
                        Maximum number of pages to visit (default: 10)
  --timeout-ms TIMEOUT_MS
                        Navigation timeout in ms (default: 20000)
  --settle-ms SETTLE_MS
                        Extra time after networkidle to allow hydration/delayed requests (default: 1500)
  --headed              Run with a visible browser window (not headless)
  --no-install          Do not auto-install Chromium if missing
  --with-deps           When installing, include Playwright OS deps (Linux). May require elevated privileges.
  --browsers-path BROWSERS_PATH
                        Directory to install/playwright browsers (default: ./.pw-browsers).
  --allow-blob          Include blob: in common directives (drafty)
  --unsafe-eval         Include 'unsafe-eval' in script-src (not recommended)
  --upgrade-insecure-requests
                        Add upgrade-insecure-requests directive
  --include-sourcemaps  Analyze JS/CSS for sourceMappingURL and add map origins to connect-src
  --ignore-non-html     Ignore non-HTML pages that get crawled (which might trigger Chromium's word-wrap hash: https://stackoverflow.com/a/69838710)
  --json                Output JSON instead of a header line
```
