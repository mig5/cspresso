from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import re
import sys
import fnmatch
from collections import deque
from dataclasses import dataclass, field, asdict
from pathlib import Path
from urllib.parse import urljoin, urlparse

from playwright.async_api import (
    async_playwright,
    TimeoutError as PlaywrightTimeoutError,
)

from .ensure_playwright import ensure_chromium_installed, configure_browsers_path
from .urls import origin_of, canonical_url

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


def sha256_base64(s: str) -> str:
    h = hashlib.sha256(s.encode("utf-8")).digest()
    return base64.b64encode(h).decode("ascii")


def normalize_csp_string(csp: str) -> str:
    s = (csp or "").strip()
    if not s:
        return s
    return s if s.endswith(";") else s + ";"


async def collect_inline(page, *, max_attr_hashes: int = 2000, notes=None):
    """
    Collect inline <script> (no src), <style> blocks, plus:
      - style="..." attributes (CSP3 style-src-attr / unsafe-hashes)
      - inline event handler attributes (onclick="...", onload="...", etc) (CSP3 script-src-attr / unsafe-hashes)

    IMPORTANT: Hashes must be computed over the EXACT string bytes. Do NOT strip.
    """
    data = await page.evaluate(
        r"""(maxAttr) => {
          let truncated = false;
          const bounded = list => { if (list.length > maxAttr) truncated = true; return [...list].slice(0, maxAttr); };
          const text = value => { if (value.length > 65536) { truncated = true; return ""; } return value; };
          const inlineScripts = bounded(document.querySelectorAll('script'))
            .map(s => ({
              nonce: s.nonce || s.getAttribute('nonce') || null,
              text: !s.src && (!s.type || /^(module|text\/javascript|application\/javascript)$/i.test(s.type)) ? text(s.textContent ?? '') : ''
            }));

          const inlineStyles = bounded(document.querySelectorAll('style, link[rel="stylesheet"][nonce]'))
            .map(st => ({
              nonce: st.nonce || st.getAttribute('nonce') || null,
              text: text(st.textContent ?? '')
            }));

          const styleAttrs = [];
          const handlerAttrs = [];

          // style="..."
          for (const el of document.querySelectorAll('[style]')) {
            if (styleAttrs.length >= maxAttr) break;
            const v = el.getAttribute('style');
            if (v !== null) styleAttrs.push(text(v));
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
                if (v !== null) handlerAttrs.push(text(v));
              }
            }
          }

          const dataImgs = [...document.querySelectorAll('img[src^="data:"]')].length > 0;
          const dataFonts = [...document.querySelectorAll('link[rel="preload"][as="font"][href^="data:"]')].length > 0;

          return { inlineScripts, inlineStyles, styleAttrs, handlerAttrs, dataImgs, dataFonts,
            truncated: truncated || styleAttrs.length >= maxAttr || handlerAttrs.length >= maxAttr };
        }""",
        max_attr_hashes,
    )

    if data.get("truncated") and notes is not None:
        notes.append(
            "Inline collection reached its count/text limit; coverage is incomplete."
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
        """() => [...document.querySelectorAll('a[href]')].map(a => a.href)"""
    )
    out: list[str] = []
    for href in hrefs or []:
        if not href:
            continue
        try:
            abs_url = canonical_url(href)
        except ValueError:
            continue
        if origin_of(abs_url) == base_origin:
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
    script_nonce: bool | None = None,
    style_nonce: bool | None = None,
) -> str:
    csp: dict[str, set[str]] = {k: set(v) for k, v in BASELINE_DIRECTIVES.items()}

    # Merge observed origins into directives.
    for d, vals in directives.items():
        if d not in set(RESOURCE_TO_DIRECTIVE.values()) | {"frame-src", "worker-src"}:
            raise ValueError("Invalid observed directive")
        if any(v != origin_of(v) for v in vals):
            raise ValueError("Invalid observed CSP origin")
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
    if script_nonce if script_nonce is not None else nonce_detected:
        csp.setdefault("script-src", {"'self'"}).add("'nonce-{NONCE}'")
    if style_nonce if style_nonce is not None else nonce_detected:
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

    # Hashes and generated tokens also cross the serialization boundary.
    for hashes in (script_hashes, style_hashes, style_attr_hashes, handler_attr_hashes):
        if any(not re.fullmatch(r"'sha256-[A-Za-z0-9+/]{43}='", h) for h in hashes):
            raise ValueError("Invalid CSP hash")

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
        try:
            map_url = urljoin(asset_url, sm)
            out.add(origin_of(map_url))
        except ValueError:
            pass

    # Body-based pointer: map comment is usually near end, so just scan the tail
    tail = body_bytes[
        -200_000:
    ]  # big enough to survive minification/compression quirks
    text = tail.decode("utf-8", errors="ignore")

    m = _SOURCEMAP_RE.search(text)
    if not m:
        return {o for o in out if o.startswith(("http://", "https://"))}

    ref = m.group(1).strip().strip('"').strip("'")
    if ref and not ref.startswith("data:"):
        try:
            map_url = urljoin(asset_url, ref)
            out.add(origin_of(map_url))
        except ValueError:
            pass

    return {o for o in out if o.startswith(("http://", "https://"))}


@dataclass
class CrawlResult:
    visited: list[str]
    csp: str
    nonce_detected: bool
    directives: dict[str, list[str]]
    notes: list[str]
    violations: list[dict]
    pages: list[dict] = field(default_factory=list)
    observations: list[dict] = field(default_factory=list)
    sourcemaps: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    complete: bool = True
    header_bytes: int = 0
    schema_version: int = 2

    @property
    def exit_code(self):
        return 2 if not self.complete else (1 if self.violations else 0)


VIOLATION_SCRIPT = """(() => {
  const report = window.__cspresso_violation;
  window.addEventListener('securitypolicyviolation', e => {
    if (!e.isTrusted || e.disposition !== 'report') return;
    report({documentURI:e.documentURI, blockedURI:e.blockedURI,
      effectiveDirective:e.effectiveDirective, originalPolicy:e.originalPolicy,
      disposition:e.disposition, sourceFile:e.sourceFile,
      lineNumber:e.lineNumber, columnNumber:e.columnNumber,
      statusCode:e.statusCode}).catch(() => {});
  }, true);
})();"""


def _policy_key(policy):
    return tuple(
        " ".join(part.split()) for part in policy.strip().split(";") if part.strip()
    )


def _owned_frame(frame, base_origin):
    """Include normal same-origin and inherited-policy documents, not widgets."""
    while frame is not None:
        if origin_of(frame.url) == base_origin:
            return True
        if frame.url not in {"", "about:blank", "about:srcdoc"}:
            return False
        frame = frame.parent_frame
    return False


def _deduplicate(records):
    seen, result = set(), []
    for item in records:
        key = json.dumps(item, sort_keys=True)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _validate(
    start_url,
    max_pages,
    timeout_ms,
    settle_ms,
    evaluate,
    scan_timeout,
    max_requests,
    max_observations,
    header_budget,
):
    start_url = canonical_url(start_url)
    if (
        min(
            max_pages,
            timeout_ms,
            scan_timeout,
            max_requests,
            max_observations,
            header_budget,
        )
        <= 0
    ):
        raise ValueError(
            "Page, timeout, request, observation and header budgets must be positive"
        )
    if settle_ms < 0:
        raise ValueError("settle-ms must be nonnegative")
    if evaluate is not None:
        if not evaluate.strip() or any(ord(c) < 32 or ord(c) == 127 for c in evaluate):
            raise ValueError(
                "Candidate CSP must be nonempty and contain no control characters"
            )
        if not _policy_key(evaluate):
            raise ValueError("Candidate CSP must contain a directive")
        known = (
            set(RESOURCE_TO_DIRECTIVE.values())
            | set(BASELINE_DIRECTIVES)
            | {
                "script-src-elem",
                "script-src-attr",
                "style-src-elem",
                "style-src-attr",
                "frame-src",
                "child-src",
                "worker-src",
                "manifest-src",
                "sandbox",
                "report-uri",
                "report-to",
                "upgrade-insecure-requests",
                "block-all-mixed-content",
                "require-trusted-types-for",
                "trusted-types",
            }
        )
        seen = set()
        for directive in _policy_key(evaluate):
            name = directive.split()[0].lower()
            if name not in known or name in seen:
                raise ValueError(
                    "Unknown or duplicate candidate CSP directive: " + name
                )
            seen.add(name)

    return start_url


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
    evaluate: str | None = None,
    no_sandbox: bool = False,
    scan_timeout: int = 120,
    max_requests: int = 2000,
    max_observations: int = 10000,
    header_budget: int = 8192,
    exclude: list[str] | None = None,
) -> CrawlResult:
    start_url = _validate(
        start_url,
        max_pages,
        timeout_ms,
        settle_ms,
        evaluate,
        scan_timeout,
        max_requests,
        max_observations,
        header_budget,
    )
    base_origin = origin_of(start_url)
    configure_browsers_path(browsers_path)
    if auto_install:
        await ensure_chromium_installed(
            browsers_path=browsers_path, with_deps=with_deps
        )
    evaluate_policy = normalize_csp_string(evaluate) if evaluate is not None else None
    directives = {
        d: set()
        for d in set(RESOURCE_TO_DIRECTIVE.values()) | {"frame-src", "worker-src"}
    }
    script_hashes, style_hashes, style_attrs, handlers = set(), set(), set(), set()
    script_nonce = style_nonce = data_img = data_font = False
    visited, attempted = set(), set()
    q = deque([start_url])
    notes, errors, violations, pages, observations, sourcemaps = [], [], [], [], [], []
    injected = {}  # frame -> last successfully injected document URL
    redirect_targets = {}
    requests_seen = 0
    pending = set()
    if no_sandbox:
        notes.append(
            "Chromium sandbox explicitly disabled; use only inside trusted external isolation."
        )
    notes.append(
        "Service workers are blocked for deterministic interception; worker-dependent flows need separate testing."
    )

    def error(message):
        if message not in errors and len(errors) < 100:
            errors.append(message)

    def excluded(url):
        return any(
            fnmatch.fnmatchcase(url, pattern)
            or fnmatch.fnmatchcase(urlparse(url).path, pattern)
            for pattern in (exclude or [])
        )

    def observe(directive, url, frame_url, kind):
        if len(observations) >= max_observations:
            error("Observation budget reached; coverage is incomplete")
            return
        origin = origin_of(url)
        if not origin:
            return
        if origin != base_origin:
            directives[directive].add(origin)
        item = {
            "directive": directive,
            "origin": origin,
            "document": frame_url,
            "url": url,
            "kind": kind,
        }
        if item not in observations:
            observations.append(item)

    async def run():
        nonlocal script_nonce, style_nonce, data_img, data_font
        async with async_playwright() as p:
            try:
                browser = await p.chromium.launch(
                    headless=headless, chromium_sandbox=not no_sandbox
                )
            except Exception as exc:
                raise RuntimeError(
                    "Chromium could not launch. Keep sandboxing enabled: run as a non-root user "
                    "with OS sandbox support and required libraries. --no-sandbox is only for "
                    "explicitly isolated environments. Original error: " + str(exc)
                ) from exc
            try:
                context = await browser.new_context(
                    service_workers="block", accept_downloads=False
                )
            except Exception:
                await browser.close()
                raise
            try:

                async def route_handler(route, request):
                    nonlocal requests_seen
                    requests_seen += 1
                    if requests_seen > max_requests:
                        error("Request budget reached; coverage is incomplete")
                        return await route.abort()
                    if request.resource_type != "document":
                        return await route.continue_()
                    frame = request.frame
                    target_origin = origin_of(request.url)
                    if frame.parent_frame is None and (
                        target_origin != base_origin or excluded(request.url)
                    ):
                        error("Top-level navigation left crawl scope: " + request.url)
                        return await route.abort()
                    if target_origin != base_origin:
                        return await route.continue_()
                    response = None
                    try:
                        # Playwright does not re-route automatic redirect hops. Fetch
                        # one hop, then navigate GET redirects explicitly at their real URL.
                        response = await route.fetch(
                            max_redirects=0, timeout=timeout_ms
                        )
                        headers = dict(response.headers)
                        if 300 <= response.status < 400 and headers.get("location"):
                            destination = canonical_url(
                                urljoin(request.url, headers["location"])
                            )
                            if origin_of(destination) != base_origin or excluded(
                                destination
                            ):
                                raise RuntimeError(
                                    "Redirect left crawl scope: " + destination
                                )
                            if getattr(request, "method", "GET") != "GET":
                                raise RuntimeError(
                                    "Non-GET redirect cannot be replayed safely; scan its final URL explicitly"
                                )
                            redirect_targets[frame] = destination
                            # Finish this navigation without starting Chromium's error
                            # page, which can otherwise interrupt the next goto().
                            # No redirect body or headers are exposed to the page.
                            return await route.fulfill(
                                status=200,
                                headers={
                                    "content-type": "text/html",
                                    "content-security-policy": "default-src 'none'; sandbox",
                                },
                                body="",
                            )
                        if 300 <= response.status < 400:
                            raise RuntimeError("Redirect response has no Location")
                        if origin_of(response.url) != base_origin:
                            raise RuntimeError("Unexpected cross-origin response")
                        ct = headers.get("content-type", "").lower()
                        if "text/html" not in ct and "application/xhtml+xml" not in ct:
                            return await route.fulfill(response=response)
                        if bypass_csp:
                            headers.pop("content-security-policy", None)
                            headers.pop("content-security-policy-report-only", None)
                        elif evaluate_policy and headers.get("content-security-policy"):
                            error(
                                "Existing enforcing CSP limits evaluation: "
                                + request.url
                                + "; use --bypass-csp"
                            )
                        if evaluate_policy:
                            headers["content-security-policy-report-only"] = (
                                evaluate_policy
                            )
                        await route.fulfill(response=response, headers=headers)
                        if evaluate_policy:
                            injected[frame] = canonical_url(request.url)
                    except Exception as exc:
                        error(
                            "Document interception failed for "
                            + request.url
                            + ": "
                            + str(exc)
                        )
                        # Do not replay a request that might already have caused a side effect.
                        await route.abort()
                    finally:
                        if response is not None:
                            await response.dispose()

                await context.route("**/*", route_handler)

                def on_request(req):
                    try:
                        frame = req.frame
                    except Exception:
                        if "Worker request provenance unavailable" not in notes:
                            notes.append(
                                "Worker request provenance unavailable; worker-internal loads are not added to the page policy."
                            )
                        return
                    dest = req.headers.get("sec-fetch-dest", "")
                    if req.resource_type == "document":
                        if frame.parent_frame and _owned_frame(
                            frame.parent_frame, base_origin
                        ):
                            observe(
                                "frame-src", req.url, frame.parent_frame.url, "frame"
                            )
                        return
                    if not _owned_frame(frame, base_origin):
                        return
                    directive = (
                        "worker-src"
                        if dest in {"worker", "sharedworker"}
                        else RESOURCE_TO_DIRECTIVE.get(req.resource_type)
                    )
                    if (
                        directive is None
                        and req.resource_type == "other"
                        and dest == "empty"
                    ):
                        directive = "connect-src"
                    if directive:
                        observe(directive, req.url, frame.url, req.resource_type)

                context.on("request", on_request)

                while (
                    q and len(attempted) < max_pages and requests_seen <= max_requests
                ):
                    url = q.popleft()
                    if url in attempted or url in visited or excluded(url):
                        continue
                    attempted.add(url)
                    item = {
                        "requested_url": url,
                        "status": "failed",
                        "evaluated": False,
                    }
                    pages.append(item)
                    page = await context.new_page()
                    sockets = []
                    # Playwright's websocket event has no frame property. Attribute only when
                    # this page contains no foreign documents; otherwise report the limitation.
                    page.on("websocket", lambda socket: sockets.append(socket.url))
                    if evaluate_policy:

                        def record(source, payload):
                            if not _owned_frame(
                                source["frame"], base_origin
                            ) or not isinstance(payload, dict):
                                return
                            if payload.get("disposition") != "report" or not isinstance(
                                payload.get("originalPolicy"), str
                            ):
                                return
                            if _policy_key(payload["originalPolicy"]) != _policy_key(
                                evaluate_policy
                            ):
                                return
                            if not isinstance(payload.get("effectiveDirective"), str):
                                return
                            if len(violations) >= max_observations:
                                error("Violation budget reached")
                                return
                            allowed = {
                                "documentURI",
                                "blockedURI",
                                "effectiveDirective",
                                "originalPolicy",
                                "disposition",
                                "sourceFile",
                                "lineNumber",
                                "columnNumber",
                                "statusCode",
                            }
                            violations.append(
                                {
                                    k: v
                                    for k, v in payload.items()
                                    if k in allowed and isinstance(v, (str, int))
                                }
                            )

                        await page.expose_binding("__cspresso_violation", record)
                        await page.add_init_script(VIOLATION_SCRIPT)
                        # Browser security diagnostics, not page-authored console.log messages.
                        session = await context.new_cdp_session(page)

                        def security_log(event):
                            entry = event.get("entry", {})
                            text = entry.get("text", "")
                            if (
                                entry.get("url")
                                and origin_of(entry["url"]) != base_origin
                            ):
                                return
                            if entry.get("source") == "security" and re.search(
                                r"(unrecognized.*directive|invalid.*(source|directive)|ignoring.*(source|directive)|duplicate.*directive)",
                                text,
                                re.I,
                            ):
                                error("Browser rejected policy syntax: " + text)

                        session.on("Log.entryAdded", security_log)
                        await session.send("Log.enable")

                    async def handle_response(resp):
                        try:
                            if not _owned_frame(
                                resp.request.frame, base_origin
                            ) or not _looks_like_js_or_css(resp.url):
                                return
                            hdrs = resp.headers
                            # Skip unbounded body materialization. Headers can still be inspected.
                            length = int(hdrs.get("content-length", "0"))
                            body = b""
                            if (
                                0 < length <= 2_000_000
                                and hdrs.get("content-encoding", "identity")
                                == "identity"
                            ):
                                body = await resp.body()
                            else:
                                notes.append(
                                    "Source-map body scan skipped (unknown/large/compressed size): "
                                    + resp.url
                                )
                            for origin in _extract_sourcemap_origin(
                                resp.url, body, hdrs
                            ):
                                if len(sourcemaps) < max_observations:
                                    sourcemaps.append(
                                        {"asset": resp.url, "origin": origin}
                                    )
                            # Developer map locations are metadata, not application permissions.
                        except Exception as exc:
                            notes.append("Source-map inspection failed: " + str(exc))

                    def on_response(resp):
                        task = asyncio.create_task(handle_response(resp))
                        pending.add(task)
                        task.add_done_callback(pending.discard)

                    if include_sourcemaps:
                        page.on("response", on_response)
                    try:

                        async def navigate(frame, target):
                            chain = []
                            while True:
                                try:
                                    response = await frame.goto(
                                        target, wait_until="load", timeout=timeout_ms
                                    )
                                except Exception:
                                    # A pending redirect is not permission to suppress
                                    # navigation errors or replay an uncertain request.
                                    redirect_targets.pop(frame, None)
                                    raise
                                destination = redirect_targets.pop(frame, None)
                                if destination is None:
                                    return response, chain
                                chain.append(target)
                                if destination in chain or len(chain) >= 10:
                                    raise RuntimeError(
                                        "Redirect loop or redirect limit exceeded"
                                    )
                                target = destination

                        resp, chain = await navigate(page.main_frame, url)
                        if chain:
                            item["redirects"] = chain
                        # Initial child-frame redirects loaded inert placeholders.
                        # Resume at the real target URL, so CSP and relative URLs use
                        # that document's origin. Never replay a POST navigation.
                        for _ in range(10):
                            if not redirect_targets:
                                break
                            frame, target = redirect_targets.popitem()
                            await navigate(frame, target)
                        if redirect_targets:
                            raise RuntimeError("Too many deferred frame redirects")
                        item["final_url"] = page.url
                        if origin_of(page.url) != base_origin:
                            raise RuntimeError("Navigation ended outside crawl origin")
                        if resp is None or resp.status >= 400:
                            raise RuntimeError(
                                "Missing response or HTTP error "
                                + str(resp.status if resp else "")
                            )
                        item["http_status"] = resp.status
                        content_type = (
                            await resp.header_value("content-type") or ""
                        ).lower()
                        is_html = any(
                            t in content_type
                            for t in ("text/html", "application/xhtml+xml")
                        )
                        if not is_html:
                            item["status"] = "skipped_non_html"
                            if not ignore_non_html:
                                notes.append("Skipped non-HTML document: " + url)
                            continue
                        try:
                            await page.wait_for_load_state(
                                "networkidle", timeout=min(5000, timeout_ms)
                            )
                        except PlaywrightTimeoutError:
                            notes.append("Network did not settle: " + url)
                        if settle_ms:
                            await page.wait_for_timeout(settle_ms)
                        if redirect_targets:
                            error(
                                "A delayed navigation redirected after initial load; scan its final URL explicitly"
                            )
                            redirect_targets.clear()
                        if evaluate_policy:
                            if injected.get(page.main_frame) != canonical_url(page.url):
                                raise RuntimeError(
                                    "Candidate policy injection was not confirmed for final document"
                                )
                            item["evaluated"] = True
                        for frame in page.frames:
                            if not _owned_frame(frame, base_origin):
                                continue
                            if (
                                evaluate_policy
                                and origin_of(frame.url) == base_origin
                                and injected.get(frame) != canonical_url(frame.url)
                            ):
                                error(
                                    "Candidate injection not confirmed for frame: "
                                    + frame.url
                                )
                            metas = await frame.locator(
                                'meta[http-equiv="Content-Security-Policy" i]'
                            ).count()
                            if metas:
                                message = (
                                    "Meta CSP still enforces on "
                                    + frame.url
                                    + "; header bypass cannot remove it"
                                )
                                (error if evaluate_policy else notes.append)(message)
                            truncation = []
                            sn, stn, sh, sth, sa, ha, di, df = await collect_inline(
                                frame, notes=truncation
                            )
                            for message in truncation:
                                error(message)
                            script_nonce |= bool(sn)
                            style_nonce |= bool(stn)
                            script_hashes.update(sh)
                            style_hashes.update(sth)
                            style_attrs.update(sa)
                            handlers.update(ha)
                            data_img |= di
                            data_font |= df
                            for directive, hashes in (
                                ("script-src", sh),
                                ("style-src", sth),
                                ("style-src-attr", sa),
                                ("script-src-attr", ha),
                            ):
                                for value in hashes:
                                    if len(observations) < max_observations:
                                        observations.append(
                                            {
                                                "directive": directive,
                                                "hash": value,
                                                "document": frame.url,
                                                "kind": "inline",
                                            }
                                        )
                                    else:
                                        error(
                                            "Observation budget reached; coverage is incomplete"
                                        )
                        if sockets and any(
                            not _owned_frame(f, base_origin) for f in page.frames
                        ):
                            error(
                                "WebSocket frame attribution is ambiguous on "
                                + page.url
                            )
                        else:
                            for socket in sockets:
                                observe("connect-src", socket, page.url, "websocket")
                        visited.add(canonical_url(page.url))
                        item["status"] = "completed"
                        for link in await extract_links(page, base_origin):
                            if (
                                link not in attempted
                                and link not in q
                                and not excluded(link)
                            ):
                                if len(q) >= max_pages * 20:
                                    notes.append("Link queue limit reached")
                                    break
                                q.append(link)
                    except Exception as exc:
                        item["error"] = str(exc)
                        error("Failed page " + url + ": " + str(exc))
                    finally:
                        if pending:
                            _, unfinished = await asyncio.wait(pending, timeout=2)
                            for task in unfinished:
                                task.cancel()
                            await asyncio.gather(*unfinished, return_exceptions=True)
                        await page.close()
                if q:
                    notes.append(
                        "Page limit reached; additional discovered URLs were not visited."
                    )
            finally:
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                try:
                    await context.close()
                finally:
                    await browser.close()

    try:
        await asyncio.wait_for(run(), timeout=scan_timeout)
    except asyncio.TimeoutError:
        error("Scan wall-clock deadline reached")
    except Exception as exc:
        error(str(exc))
    if not visited:
        error("No HTML pages successfully scanned")
    csp = build_csp(
        directives,
        base_origin=base_origin,
        nonce_detected=script_nonce or style_nonce,
        script_nonce=script_nonce,
        style_nonce=style_nonce,
        script_hashes=script_hashes,
        style_hashes=style_hashes,
        style_attr_hashes=style_attrs,
        handler_attr_hashes=handlers,
        allow_data_img=data_img,
        allow_data_font=data_font,
        allow_blob=allow_blob,
        allow_unsafe_eval=allow_unsafe_eval,
        upgrade_insecure_requests=upgrade_insecure_requests,
    )
    final_directives = {}
    for part in csp.rstrip(";").split(";"):
        name, *values = part.split()
        final_directives[name] = values
    if style_attrs or handlers:
        notes.append(
            "Attribute hashes require unsafe-hashes; prefer external code or nonce-bearing elements."
        )
    if script_nonce or style_nonce:
        notes.append(
            "Replace {NONCE} with a fresh unpredictable nonce per HTML response, in headers and matching elements."
        )
    header_bytes = len(("Content-Security-Policy: " + csp).encode("utf-8"))
    if header_bytes > header_budget:
        notes.append(
            f"CSP header is {header_bytes} bytes, exceeding the {header_budget}-byte advisory budget."
        )
    return CrawlResult(
        sorted(visited),
        csp,
        script_nonce or style_nonce,
        final_directives,
        list(dict.fromkeys(notes)),
        _deduplicate(violations),
        pages,
        _deduplicate(observations),
        _deduplicate(sourcemaps),
        errors,
        not errors,
        header_bytes,
    )


def _positive(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def _nonnegative(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be nonnegative")
    return number


def _parse_args(argv=None):
    ap = argparse.ArgumentParser(
        prog="cspresso", description="Observe same-origin pages and draft a CSP."
    )
    ap.add_argument("url")
    for name, default, help_text in (
        ("max-pages", 10, "Maximum attempted pages"),
        ("timeout-ms", 20000, "Per-navigation timeout"),
        (
            "scan-timeout",
            120,
            "Overall scan deadline in seconds (excluding installation)",
        ),
        ("max-requests", 2000, "Maximum intercepted HTTP requests"),
        ("max-observations", 10000, "Maximum observations/violations"),
        ("header-budget", 8192, "Advisory header size in bytes"),
    ):
        ap.add_argument("--" + name, type=_positive, default=default, help=help_text)
    ap.add_argument("--settle-ms", type=_nonnegative, default=1500)
    ap.add_argument(
        "--browsers-path",
        help="Browser cache directory (default: user cache, or PLAYWRIGHT_BROWSERS_PATH)",
    )
    ap.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Exclude top-level URL/path glob (repeatable)",
    )
    for name, help_text in (
        ("headed", "Show the browser"),
        ("no-install", "Never install browsers"),
        ("with-deps", "Install OS dependencies if a browser installation is needed"),
        (
            "no-sandbox",
            "Explicitly disable Chromium sandbox: isolated trusted environments only",
        ),
        ("allow-blob", "Include blob: in common directives"),
        ("unsafe-eval", "Include unsafe-eval in script-src"),
        ("upgrade-insecure-requests", "Add upgrade-insecure-requests"),
        (
            "include-sourcemaps",
            "Inspect map metadata without granting connect-src permissions",
        ),
        ("bypass-csp", "Remove existing CSP response headers (not meta CSP)"),
        ("ignore-non-html", "Suppress notes about skipped non-HTML documents"),
        ("json", "Emit structured JSON schema v2"),
        ("header-only", "Emit just the CSP value; diagnostics go to stderr"),
    ):
        ap.add_argument("--" + name, action="store_true", help=help_text)
    candidate = ap.add_mutually_exclusive_group()
    candidate.add_argument("--evaluate", metavar="CSP")
    candidate.add_argument(
        "--evaluate-file", type=Path, help="Read a candidate policy from a UTF-8 file"
    )
    args = ap.parse_args(argv)
    if args.json and args.header_only:
        ap.error("--json and --header-only are mutually exclusive")
    if args.evaluate_file:
        try:
            args.evaluate = " ".join(
                args.evaluate_file.read_text(encoding="utf-8").splitlines()
            )
        except OSError as exc:
            ap.error(str(exc))
    try:
        _validate(
            args.url,
            args.max_pages,
            args.timeout_ms,
            args.settle_ms,
            args.evaluate,
            args.scan_timeout,
            args.max_requests,
            args.max_observations,
            args.header_budget,
        )
    except ValueError as exc:
        ap.error(str(exc))
    return args


def _safe_text(value):
    return "".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in str(value))


def main(argv=None):
    args = _parse_args(argv)
    kwargs = vars(args).copy()
    for key in (
        "url",
        "json",
        "header_only",
        "evaluate_file",
        "headed",
        "no_install",
        "unsafe_eval",
    ):
        kwargs.pop(key)
    kwargs.update(
        headless=not args.headed,
        auto_install=not args.no_install,
        allow_unsafe_eval=args.unsafe_eval,
        browsers_path=Path(args.browsers_path) if args.browsers_path else None,
    )
    try:
        result = asyncio.run(crawl_and_generate_csp(args.url, **kwargs))
    except (OSError, RuntimeError, ValueError) as exc:
        if args.json:
            print(
                json.dumps(
                    {"schema_version": 2, "complete": False, "errors": [str(exc)]}
                )
            )
        else:
            print(_safe_text(exc), file=sys.stderr)
        return 2
    if args.json:
        payload = asdict(result)
        payload["evaluated_policy"] = args.evaluate
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        stream = sys.stderr if args.header_only else sys.stdout
        for label, values in (
            ("visited", result.visited),
            ("NOTE", result.notes),
            ("ERROR", result.errors),
        ):
            for value in values:
                print(f"# {label}: {_safe_text(value)}", file=stream)
        for violation in result.violations:
            print("# violation: " + _safe_text(json.dumps(violation)), file=stream)
        print(
            result.csp if args.header_only else "Content-Security-Policy: " + result.csp
        )
    return result.exit_code


if __name__ == "__main__":
    sys.exit(main())
