from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import re
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urldefrag, urlparse

from playwright.async_api import async_playwright

from .ensure_playwright import ensure_chromium_installed

RESOURCE_TO_DIRECTIVE = {
    "script": "script-src",
    "stylesheet": "style-src",
    "image": "img-src",
    "font": "font-src",
    "media": "media-src",
    "xhr": "connect-src",
    "fetch": "connect-src",
    "websocket": "connect-src",
    "eventsource": "connect-src",
}

BASELINE_DIRECTIVES = {
    "default-src": {"'self'"},
    "base-uri": {"'self'"},
    "object-src": {"'none'"},
    "frame-ancestors": {"'self'"},
    "form-action": {"'self'"},
}


def origin_of(url: str) -> str:
    p = urlparse(url)
    if not p.scheme or not p.netloc:
        return ""
    return f"{p.scheme}://{p.netloc}"


def sha256_base64(s: str) -> str:
    h = hashlib.sha256(s.encode("utf-8")).digest()
    return base64.b64encode(h).decode("ascii")


def normalize_csp_string(csp: str) -> str:
    s = (csp or "").strip()
    if not s:
        return s
    return s if s.endswith(";") else s + ";"


async def collect_inline(page, *, max_attr_hashes: int = 2000):
    """
    Collect inline <script> (no src), <style> blocks, plus:
      - style="..." attributes (CSP3 style-src-attr / unsafe-hashes)
      - inline event handler attributes (onclick="...", onload="...", etc) (CSP3 script-src-attr / unsafe-hashes)

    IMPORTANT: Hashes must be computed over the EXACT string bytes. Do NOT strip.
    """
    data = await page.evaluate(
        """(maxAttr) => {
          const inlineScripts = [...document.querySelectorAll('script:not([src])')]
            .map(s => ({
              nonce: s.nonce || s.getAttribute('nonce') || null,
              text: s.textContent ?? ''
            }));

          const inlineStyles = [...document.querySelectorAll('style')]
            .map(st => ({
              nonce: st.nonce || st.getAttribute('nonce') || null,
              text: st.textContent ?? ''
            }));

          const styleAttrs = [];
          const handlerAttrs = [];

          // style="..."
          for (const el of document.querySelectorAll('[style]')) {
            if (styleAttrs.length >= maxAttr) break;
            const v = el.getAttribute('style');
            if (v !== null) styleAttrs.push(v);
          }

          // inline event handlers: on*
          // Iterate elements and look for attributes starting with "on"
          const all = document.querySelectorAll('*');
          for (let i = 0; i < all.length; i++) {
            if (handlerAttrs.length >= maxAttr) break;
            const el = all[i];
            const names = el.getAttributeNames ? el.getAttributeNames() : [];
            for (const name of names) {
              if (handlerAttrs.length >= maxAttr) break;
              if (name && name.toLowerCase().startsWith('on')) {
                const v = el.getAttribute(name);
                if (v !== null) handlerAttrs.push(v);
              }
            }
          }

          const dataImgs = [...document.querySelectorAll('img[src^="data:"]')].length > 0;
          const dataFonts = [...document.querySelectorAll('link[rel="preload"][as="font"][href^="data:"]')].length > 0;

          return { inlineScripts, inlineStyles, styleAttrs, handlerAttrs, dataImgs, dataFonts };
        }""",
        max_attr_hashes,
    )

    script_nonces = {x["nonce"] for x in data["inlineScripts"] if x.get("nonce")}
    style_nonces = {x["nonce"] for x in data["inlineStyles"] if x.get("nonce")}

    script_hashes = set()
    for x in data["inlineScripts"]:
        raw = x.get("text") or ""
        if raw.strip():  # skip pure-whitespace blocks, but DO NOT strip for hashing
            script_hashes.add(f"'sha256-{sha256_base64(raw)}'")

    style_hashes = set()
    for x in data["inlineStyles"]:
        raw = x.get("text") or ""
        if raw.strip():
            style_hashes.add(f"'sha256-{sha256_base64(raw)}'")

    # style="..." attribute hashes
    style_attr_hashes = set()
    for v in data.get("styleAttrs") or []:
        if isinstance(v, str) and v.strip():
            style_attr_hashes.add(f"'sha256-{sha256_base64(v)}'")

    # on*="..." handler hashes
    handler_attr_hashes = set()
    for v in data.get("handlerAttrs") or []:
        if isinstance(v, str) and v.strip():
            handler_attr_hashes.add(f"'sha256-{sha256_base64(v)}'")

    return (
        script_nonces,
        style_nonces,
        script_hashes,
        style_hashes,
        style_attr_hashes,
        handler_attr_hashes,
        bool(data.get("dataImgs")),
        bool(data.get("dataFonts")),
    )


async def extract_links(page, base_origin: str) -> list[str]:
    hrefs = await page.evaluate(
        """() => [...document.querySelectorAll('a[href]')].map(a => a.getAttribute('href'))"""
    )
    out: list[str] = []
    for href in hrefs or []:
        if not href:
            continue
        abs_url = urljoin(base_origin + "/", href)
        abs_url, _frag = urldefrag(abs_url)
        p = urlparse(abs_url)
        if p.scheme in ("http", "https") and origin_of(abs_url) == base_origin:
            out.append(abs_url)
    return out


def build_csp(
    directives: dict[str, set[str]],
    *,
    base_origin: str,
    nonce_detected: bool,
    script_hashes: set[str],
    style_hashes: set[str],
    style_attr_hashes: set[str],
    handler_attr_hashes: set[str],
    allow_data_img: bool,
    allow_data_font: bool,
    allow_blob: bool,
    allow_unsafe_eval: bool,
    upgrade_insecure_requests: bool,
) -> str:
    csp: dict[str, set[str]] = {k: set(v) for k, v in BASELINE_DIRECTIVES.items()}

    # Merge observed origins into directives.
    for d, vals in directives.items():
        if vals:
            csp.setdefault(d, set()).update(vals)

    # Always keep 'self' on these directives if present.
    for d in (
        "script-src",
        "style-src",
        "img-src",
        "connect-src",
        "font-src",
        "media-src",
        "frame-src",
    ):
        if d in csp:
            csp[d].add("'self'")

    # Inline handling:
    # - If we detected nonce attributes, emit nonce *template*. You must replace {NONCE} per response.
    if nonce_detected:
        csp.setdefault("script-src", {"'self'"}).add("'nonce-{NONCE}'")
        csp.setdefault("style-src", {"'self'"}).add("'nonce-{NONCE}'")

    # Hashes for inline <script>/<style> blocks
    if script_hashes:
        csp.setdefault("script-src", {"'self'"}).update(script_hashes)
    if style_hashes:
        csp.setdefault("style-src", {"'self'"}).update(style_hashes)

    # unsafe-hashes: needed for style="" and on*="" attribute hashes (CSP3 behavior)
    # We include hashes BOTH in the base directives and the CSP3 *-attr directives for best compatibility.
    if handler_attr_hashes:
        csp.setdefault("script-src", {"'self'"}).add("'unsafe-hashes'")
        csp["script-src"].update(handler_attr_hashes)
        csp.setdefault("script-src-attr", set()).update({"'unsafe-hashes'"})
        csp["script-src-attr"].update(handler_attr_hashes)

    if style_attr_hashes:
        csp.setdefault("style-src", {"'self'"}).add("'unsafe-hashes'")
        csp["style-src"].update(style_attr_hashes)
        csp.setdefault("style-src-attr", set()).update({"'unsafe-hashes'"})
        csp["style-src-attr"].update(style_attr_hashes)

    if allow_unsafe_eval:
        csp.setdefault("script-src", {"'self'"}).add("'unsafe-eval'")

    if allow_data_img:
        csp.setdefault("img-src", {"'self'"}).add("data:")
    if allow_data_font:
        csp.setdefault("font-src", {"'self'"}).add("data:")

    if allow_blob:
        for d in ("img-src", "media-src", "worker-src", "connect-src"):
            csp.setdefault(d, {"'self'"}).add("blob:")

    if upgrade_insecure_requests:
        csp["upgrade-insecure-requests"] = set()

    # Serialize
    parts: list[str] = []
    for k in sorted(csp.keys()):
        vals = csp[k]
        if vals:
            parts.append(f"{k} {' '.join(sorted(vals))}")
        else:
            parts.append(f"{k}")
    return "; ".join(parts) + ";"


_SOURCEMAP_RE = re.compile(r"sourceMappingURL\s*=\s*([^\s*]+)", re.IGNORECASE)


def _looks_like_js_or_css(url: str) -> bool:
    p = urlparse(url)
    path = (p.path or "").lower()
    return path.endswith(".js") or path.endswith(".css")


def _extract_sourcemap_origin(
    asset_url: str, body_bytes: bytes, headers: dict
) -> set[str]:
    out: set[str] = set()

    # Header-based pointers
    sm = headers.get("sourcemap") or headers.get("x-sourcemap")
    if sm:
        map_url = urljoin(asset_url, sm)
        out.add(origin_of(map_url))

    # Body-based pointer: map comment is usually near end, so just scan the tail
    tail = body_bytes[
        -200_000:
    ]  # big enough to survive minification/compression quirks
    text = tail.decode("utf-8", errors="ignore")

    m = _SOURCEMAP_RE.search(text)
    if not m:
        return {o for o in out if o}

    ref = m.group(1).strip().strip('"').strip("'")
    if ref and not ref.startswith("data:"):
        map_url = urljoin(asset_url, ref)
        out.add(origin_of(map_url))

    return {o for o in out if o}


@dataclass
class CrawlResult:
    visited: list[str]
    csp: str
    nonce_detected: bool
    directives: dict[str, list[str]]
    notes: list[str]
    violations: list[dict]


async def crawl_and_generate_csp(
    start_url: str,
    *,
    max_pages: int = 10,
    timeout_ms: int = 20000,
    settle_ms: int = 1500,
    headless: bool = True,
    browsers_path: Path | None = None,
    auto_install: bool = True,
    with_deps: bool = False,
    allow_blob: bool = False,
    allow_unsafe_eval: bool = False,
    upgrade_insecure_requests: bool = False,
    include_sourcemaps: bool = False,
    ignore_non_html: bool = False,
    bypass_csp: bool = False,
    evaluate: str | None = None,  # CSP string to inject as Report-Only and evaluate
) -> CrawlResult:
    start_url, _ = urldefrag(start_url)
    base_origin = origin_of(start_url)
    if not base_origin:
        raise ValueError(f"Invalid start URL: {start_url}")

    if auto_install:
        await ensure_chromium_installed(
            browsers_path=browsers_path, with_deps=with_deps
        )

    visited: set[str] = set()
    q: deque[str] = deque([start_url])

    # Collect CSP ingredients
    directives: dict[str, set[str]] = {
        d: set() for d in set(RESOURCE_TO_DIRECTIVE.values()) | {"frame-src"}
    }
    script_hashes: set[str] = set()
    style_hashes: set[str] = set()
    style_attr_hashes: set[str] = set()
    handler_attr_hashes: set[str] = set()
    nonce_detected = False
    allow_data_img = False
    allow_data_font = False
    notes: list[str] = []

    evaluate_policy = normalize_csp_string(evaluate) if evaluate else None
    # Captured CSP violations (Report-Only) when --evaluate is used.
    violations: list[dict] = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=headless)
        context = await browser.new_context()

        # Optionally strip any existing CSP headers, and/or inject a Report-Only CSP for evaluation.
        # NOTE: This operates on *document response headers* only.
        if bypass_csp or evaluate_policy:

            async def _route_handler(route, request):
                try:
                    if request.resource_type != "document":
                        return await route.continue_()

                    # IMPORTANT: Don't rewrite CSP on third-party iframe/object documents.
                    # Otherwise --evaluate / --bypass-csp will mutate embedded origins
                    # (e.g. asciinema.org) and produce bogus frame-ancestors violations.
                    req_origin = origin_of(request.url)
                    if not req_origin or req_origin != base_origin:
                        return await route.continue_()

                    resp = await route.fetch()
                    hdrs = {k.lower(): v for k, v in (resp.headers or {}).items()}

                    # Only treat actual HTML documents as candidates for CSP header rewriting.
                    # (Playwright classifies iframe navigations as "document" even when non-HTML.)
                    ct = (hdrs.get("content-type") or "").lower()
                    is_html = ("text/html" in ct) or ("application/xhtml+xml" in ct)
                    if not is_html:
                        return await route.fulfill(response=resp)

                    if bypass_csp:
                        hdrs.pop("content-security-policy", None)
                        hdrs.pop("content-security-policy-report-only", None)

                    if evaluate_policy:
                        hdrs["content-security-policy-report-only"] = evaluate_policy

                    try:
                        return await route.fulfill(response=resp, headers=hdrs)
                    except TypeError:
                        body = await resp.body()
                        return await route.fulfill(
                            status=resp.status, headers=hdrs, body=body
                        )
                except Exception:
                    try:
                        return await route.continue_()
                    except Exception:
                        return

            await context.route("**/*", _route_handler)

        def on_request(req):
            """
            Playwright sometimes classifies "connect-like" activity as resource_type == "other".
            Heuristic: treat resource_type=="other" with sec-fetch-dest=="empty" as connect-src.
            """
            try:
                url = req.url
                parsed = urlparse(url)
                if parsed.scheme not in ("http", "https", "ws", "wss"):
                    return

                rtype = req.resource_type
                directive = RESOURCE_TO_DIRECTIVE.get(rtype)

                if directive is None and rtype == "other":
                    hdrs = {k.lower(): v for k, v in (req.headers or {}).items()}
                    # For fetch/xhr/beacon/pings, browsers typically send: sec-fetch-dest: empty
                    if (hdrs.get("sec-fetch-dest") or "").lower() == "empty":
                        directive = "connect-src"

                if directive is None:
                    return

                req_origin = origin_of(url)
                if req_origin and req_origin != base_origin:
                    directives.setdefault(directive, set()).add(req_origin)
            except Exception:
                return

        context.on("request", on_request)

        max_queue = max_pages * 20

        while q and len(visited) < max_pages:
            url = q.popleft()
            if url in visited:
                continue
            visited.add(url)

            page = await context.new_page()

            # If evaluating a candidate CSP, capture Report-Only violations.
            if evaluate_policy:

                def _record_violation(_source, payload):
                    try:
                        if (
                            isinstance(payload, dict)
                            and payload.get("disposition") == "report"
                        ):
                            violations.append(payload)
                    except Exception:
                        return

                try:
                    await page.expose_binding("__cspresso_violation", _record_violation)
                    await page.add_init_script(
                        "() => { try { window.addEventListener('securitypolicyviolation', (e) => { "
                        "const payload = {documentURI:e.documentURI, referrer:e.referrer, blockedURI:e.blockedURI, "
                        "violatedDirective:e.violatedDirective, effectiveDirective:e.effectiveDirective, originalPolicy:e.originalPolicy, "
                        "disposition:e.disposition, sourceFile:e.sourceFile, lineNumber:e.lineNumber, columnNumber:e.columnNumber, "
                        "statusCode:e.statusCode, sample:e.sample}; "
                        "if (typeof window.__cspresso_violation === 'function') { window.__cspresso_violation(payload); }"
                        "}, true); } catch(_){} }"
                    )
                except Exception:
                    pass  # nosec

                def _on_console(msg):
                    try:
                        t = msg.text or ""
                        tl = t.lower()
                        if (
                            "content security policy" in tl
                            or "content-security-policy" in tl
                        ) and (
                            "would violate" in tl
                            or "report-only" in tl
                            or "report only" in tl
                        ):
                            violations.append(
                                {
                                    "console": True,
                                    "type": msg.type,
                                    "text": t,
                                    "documentURI": page.url,
                                    "disposition": "report",
                                }
                            )
                    except Exception:
                        return

                page.on("console", _on_console)

            pending: set[asyncio.Task] = set()

            if include_sourcemaps:

                async def handle_response(resp):
                    try:
                        url = resp.url
                        if not _looks_like_js_or_css(url):
                            return

                        headers = {
                            k.lower(): v for k, v in (resp.headers or {}).items()
                        }

                        # Read the *actual* bytes the browser received
                        body = await resp.body()
                        origins = _extract_sourcemap_origin(url, body, headers)

                        for o in origins:
                            if o and o != base_origin:
                                directives.setdefault("connect-src", set()).add(o)

                    except Exception:
                        return

                def on_response(resp):
                    t = asyncio.create_task(handle_response(resp))
                    pending.add(t)
                    t.add_done_callback(lambda _t: pending.discard(_t))

                page.on("response", on_response)

            try:
                resp = await page.goto(
                    url, wait_until="networkidle", timeout=timeout_ms
                )

                ct = ""
                if resp is not None:
                    ct = (await resp.header_value("content-type") or "").lower()

                is_html = ("text/html" in ct) or ("application/xhtml+xml" in ct)
                if not is_html and ignore_non_html:
                    # Still count as visited, but don't hash inline attrs / don't extract links.
                    continue

                # Give the page a moment to run hydration / delayed fetches.
                if settle_ms > 0:
                    await page.wait_for_timeout(settle_ms)

                (
                    s_nonces,
                    st_nonces,
                    s_hashes,
                    st_hashes,
                    st_attr_hashes,
                    h_attr_hashes,
                    has_data_img,
                    has_data_font,
                ) = await collect_inline(page)

                if include_sourcemaps and pending:
                    # Give the handler a moment to finish reading bodies
                    await asyncio.wait(pending, timeout=5.0)

                if s_nonces or st_nonces:
                    nonce_detected = True
                script_hashes.update(s_hashes)
                style_hashes.update(st_hashes)
                style_attr_hashes.update(st_attr_hashes)
                handler_attr_hashes.update(h_attr_hashes)

                allow_data_img = allow_data_img or has_data_img
                allow_data_font = allow_data_font or has_data_font

                # Frame destinations
                for fr in page.frames:
                    if fr.url and fr.url != "about:blank":
                        fr_origin = origin_of(fr.url)
                        if fr_origin and fr_origin != base_origin:
                            directives["frame-src"].add(fr_origin)

                # Enqueue same-origin links
                links = await extract_links(page, base_origin)
                for link in links:
                    if link not in visited and link not in q and len(q) < max_queue:
                        q.append(link)

            finally:
                await page.close()

        await browser.close()

    csp = build_csp(
        directives=directives,
        base_origin=base_origin,
        nonce_detected=nonce_detected,
        script_hashes=script_hashes,
        style_hashes=style_hashes,
        style_attr_hashes=style_attr_hashes,
        handler_attr_hashes=handler_attr_hashes,
        allow_data_img=allow_data_img,
        allow_data_font=allow_data_font,
        allow_blob=allow_blob,
        allow_unsafe_eval=allow_unsafe_eval,
        upgrade_insecure_requests=upgrade_insecure_requests,
    )

    if style_attr_hashes or handler_attr_hashes:
        notes.append(
            'Detected inline attribute code (style="..." and/or on*="..."). '
            "Hashes for these require 'unsafe-hashes' (and modern browsers may use style-src-attr/script-src-attr)."
        )
    if nonce_detected:
        notes.append(
            "Nonce detected: replace {NONCE} per HTML response (server must generate and inject nonce)."
        )

    directives_out = {k: sorted(v) for k, v in directives.items() if v}

    # De-duplicate violations (same doc+directive+blocked URI) to keep output stable.
    if violations:
        seen = set()
        uniq: list[dict] = []
        for v in violations:
            if not isinstance(v, dict):
                continue
            key = (
                v.get("documentURI"),
                v.get("effectiveDirective") or v.get("violatedDirective"),
                v.get("blockedURI"),
                v.get("sourceFile"),
                v.get("lineNumber"),
                v.get("columnNumber"),
            )
            if key in seen:
                continue
            seen.add(key)
            uniq.append(v)
        violations = uniq

    return CrawlResult(
        visited=sorted(visited),
        csp=csp,
        nonce_detected=nonce_detected,
        directives=directives_out,
        notes=notes,
        violations=violations,
    )


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="cspresso",
        description="Crawl up to N pages (same-origin) with Playwright and generate a draft CSP.",
    )
    ap.add_argument("url", help="Start URL (e.g. https://example.com)")
    ap.add_argument(
        "--max-pages",
        type=int,
        default=10,
        help="Maximum number of pages to visit (default: 10)",
    )
    ap.add_argument(
        "--timeout-ms",
        type=int,
        default=20000,
        help="Navigation timeout in ms (default: 20000)",
    )
    ap.add_argument(
        "--settle-ms",
        type=int,
        default=1500,
        help="Extra time after networkidle to allow hydration/delayed requests (default: 1500)",
    )

    ap.add_argument(
        "--headed",
        action="store_true",
        help="Run with a visible browser window (not headless)",
    )

    ap.add_argument(
        "--no-install",
        action="store_true",
        help="Do not auto-install Chromium if missing",
    )
    ap.add_argument(
        "--with-deps",
        action="store_true",
        help="When installing, include Playwright OS deps (Linux). May require elevated privileges.",
    )
    ap.add_argument(
        "--browsers-path",
        default=None,
        help="Directory to install/playwright browsers (default: ./.pw-browsers).",
    )

    ap.add_argument(
        "--allow-blob",
        action="store_true",
        help="Include blob: in common directives (drafty)",
    )
    ap.add_argument(
        "--unsafe-eval",
        action="store_true",
        help="Include 'unsafe-eval' in script-src (not recommended)",
    )
    ap.add_argument(
        "--upgrade-insecure-requests",
        action="store_true",
        help="Add upgrade-insecure-requests directive",
    )
    ap.add_argument(
        "--include-sourcemaps",
        action="store_true",
        default=False,
        help="Analyze JS/CSS for sourceMappingURL and add map origins to connect-src",
    )

    ap.add_argument(
        "--bypass-csp",
        action="store_true",
        help="Strip any existing CSP/CSP-Report-Only response headers from HTML documents (useful for discovery or evaluation).",
    )
    ap.add_argument(
        "--evaluate",
        metavar="CSP",
        default=None,
        help="Inject the provided CSP string as Content-Security-Policy-Report-Only on HTML documents and exit 1 if any Report-Only violations are detected. Quote the value.",
    )
    ap.add_argument(
        "--ignore-non-html",
        action="store_true",
        default=False,
        help="Ignore non-HTML pages that get crawled (which might trigger Chromium's word-wrap hash: https://stackoverflow.com/a/69838710)",
    )
    ap.add_argument(
        "--json", action="store_true", help="Output JSON instead of a header line"
    )
    return ap.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    browsers_path = Path(args.browsers_path).resolve() if args.browsers_path else None

    result = asyncio.run(
        crawl_and_generate_csp(
            args.url,
            max_pages=args.max_pages,
            timeout_ms=args.timeout_ms,
            settle_ms=args.settle_ms,
            headless=not args.headed,
            browsers_path=browsers_path,
            auto_install=not args.no_install,
            with_deps=args.with_deps,
            allow_blob=args.allow_blob,
            allow_unsafe_eval=args.unsafe_eval,
            upgrade_insecure_requests=args.upgrade_insecure_requests,
            include_sourcemaps=args.include_sourcemaps,
            bypass_csp=args.bypass_csp,
            evaluate=args.evaluate,
            ignore_non_html=args.ignore_non_html,
        )
    )

    if args.json:
        print(
            json.dumps(
                {
                    "visited": result.visited,
                    "nonce_detected": result.nonce_detected,
                    "csp": result.csp,
                    "directives": result.directives,
                    "notes": result.notes,
                    "violations": result.violations,
                    "evaluated_policy": args.evaluate,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1 if (args.evaluate and result.violations) else 0

    # Default: print header + visited pages as comments.
    for u in result.visited:
        print(f"# visited: {u}")
    for n in result.notes:
        print(f"# NOTE: {n}")
    print("Content-Security-Policy:", result.csp)

    if args.evaluate:
        if result.violations:
            print("# CSP Report-Only violations detected:")
            for v in result.violations:
                try:
                    blocked = v.get("blockedURI")
                    eff = v.get("effectiveDirective") or v.get("violatedDirective")
                    doc = v.get("documentURI")
                    print(f"# - {eff} blocked={blocked} on {doc}")
                except Exception:
                    print(f"# - {v}")
            return 1
        return 0

    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
