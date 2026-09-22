"""Deterministic, loopback-only integration tests; no public websites required."""

import asyncio
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cspresso.crawl import crawl_and_generate_csp

pytestmark = pytest.mark.browser


@pytest.fixture
def sites():
    routes = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            status, headers, body = routes.get(
                (self.server.server_port, self.path), (404, {}, b"not found")
            )
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    servers = [ThreadingHTTPServer(("127.0.0.1", 0), Handler) for _ in range(2)]
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in servers]
    for thread in threads:
        thread.start()
    origins = [f"http://127.0.0.1:{s.server_port}" for s in servers]

    def put(index, path, body="", status=200, **headers):
        routes[(servers[index].server_port, path)] = (
            status,
            {"Content-Type": "text/html", **headers},
            body.encode(),
        )

    yield origins, put
    for server in servers:
        server.shutdown()
        server.server_close()
    for thread in threads:
        thread.join()


def scan(url, **kwargs):
    return asyncio.run(
        crawl_and_generate_csp(
            url,
            auto_install=False,
            settle_ms=100,
            timeout_ms=3000,
            scan_timeout=20,
            no_sandbox=os.environ.get("CSPRESSO_TEST_NO_SANDBOX") == "1",
            **kwargs,
        )
    )


def test_nested_links_and_base(sites):
    origins, put = sites
    put(0, "/docs/start", '<base href="/base/"><a href="next">next</a>')
    put(0, "/base/next", "<h1>next</h1>")
    result = scan(origins[0] + "/docs/start", max_pages=2)
    assert result.complete, result.errors
    assert origins[0] + "/base/next" in result.visited


def test_report_only_collects_multiple_structured_violations(sites):
    origins, put = sites
    put(0, "/", "<script>window.test=1</script><style>body{color:red}</style>")
    result = scan(origins[0], max_pages=1, evaluate="default-src 'none'")
    assert result.complete, result.errors
    assert result.exit_code == 1
    kinds = {v["effectiveDirective"] for v in result.violations}
    assert "script-src-elem" in kinds and "style-src-elem" in kinds


def test_clean_evaluation(sites):
    origins, put = sites
    put(0, "/", "<h1>hello</h1>")
    result = scan(origins[0], max_pages=1, evaluate="default-src 'self'")
    assert result.exit_code == 0, result.errors
    assert result.pages[0]["evaluated"]


def test_same_origin_redirect_preserves_final_url_and_injection(sites):
    origins, put = sites
    put(0, "/start", status=302, Location="/docs/end")
    put(0, "/docs/end", "<script>window.test=1</script>")
    result = scan(origins[0] + "/start", max_pages=1, evaluate="default-src 'none'")
    assert result.complete, result.errors
    assert result.pages[0]["final_url"] == origins[0] + "/docs/end"
    assert result.violations


def test_cross_origin_redirect_fails_scope(sites):
    origins, put = sites
    put(0, "/", status=302, Location=origins[1] + "/external")
    put(1, "/external", "<script>window.external=true</script>")
    result = scan(origins[0], max_pages=1, bypass_csp=True)
    assert result.exit_code == 2
    assert not result.visited


def test_foreign_frame_policy_not_merged(sites):
    origins, put = sites
    put(0, "/", f'<iframe src="{origins[1]}/widget"></iframe>')
    put(1, "/widget", '<script src="/foreign.js"></script>')
    put(
        1,
        "/foreign.js",
        "window.loaded=true",
        **{"Content-Type": "application/javascript"},
    )
    result = scan(origins[0], max_pages=1)
    assert result.complete, result.errors
    assert origins[1] in result.directives["frame-src"]
    assert origins[1] not in result.directives.get("script-src", [])


def test_header_bypass_keeps_candidate_active(sites):
    origins, put = sites
    put(
        0,
        "/",
        "<script>window.test=1</script>",
        **{"Content-Security-Policy": "default-src 'none'"},
    )
    result = scan(
        origins[0], max_pages=1, bypass_csp=True, evaluate="default-src 'none'"
    )
    assert result.complete, result.errors
    assert result.violations


def test_meta_policy_disclosed(sites):
    origins, put = sites
    put(
        0,
        "/",
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'">',
    )
    result = scan(
        origins[0], max_pages=1, bypass_csp=True, evaluate="default-src 'self'"
    )
    assert result.exit_code == 2
    assert any("Meta CSP" in e for e in result.errors)


def test_invalid_source_expression_is_not_a_pass(sites):
    origins, put = sites
    put(0, "/", "<h1>test</h1>")
    result = scan(origins[0], max_pages=1, evaluate="script-src 'made-up-keyword'")
    assert result.exit_code == 2, result


def test_inherited_srcdoc_is_collected(sites):
    origins, put = sites
    put(0, "/", '<iframe srcdoc="&lt;script&gt;window.test=1&lt;/script&gt;"></iframe>')
    result = scan(origins[0], max_pages=1)
    assert result.complete, result.errors
    assert any(
        o.get("kind") == "inline" and o["document"] == "about:srcdoc"
        for o in result.observations
    )


def test_external_script_nonce(sites):
    origins, put = sites
    put(0, "/", '<script src="/app.js" nonce="abcdef0123456789"></script>')
    put(0, "/app.js", "window.test=1", **{"Content-Type": "application/javascript"})
    result = scan(origins[0], max_pages=1)
    assert result.complete, result.errors
    assert result.nonce_detected
    assert "'nonce-{NONCE}'" in result.directives["script-src"]
    assert "style-src" not in result.directives


def test_http_error_is_incomplete(sites):
    origins, _ = sites
    result = scan(origins[0] + "/missing", max_pages=1)
    assert result.exit_code == 2
    assert result.pages[0]["status"] == "failed"


@pytest.mark.parametrize("hops", [1, 3])
def test_redirect_chain_uses_final_base_and_candidate(sites, hops):
    origins, put = sites
    for i in range(hops):
        put(
            0,
            f"/hop/{i}",
            status=302,
            Location=f"/hop/{i + 1}" if i + 1 < hops else "/docs/end",
        )
    put(0, "/docs/end", '<script>window.test=1</script><a href="child">child</a>')
    put(0, "/docs/child", "child")
    result = scan(origins[0] + "/hop/0", max_pages=2, evaluate="default-src 'none'")
    assert result.complete, result.errors
    assert set(result.visited) == {origins[0] + "/docs/end", origins[0] + "/docs/child"}
    assert result.pages[0]["evaluated"]
    assert len(result.pages[0]["redirects"]) == hops
    assert any(
        v.get("effectiveDirective") == "script-src-elem" for v in result.violations
    )


def test_redirect_loop_is_incomplete(sites):
    origins, put = sites
    put(0, "/a", status=302, Location="/b")
    put(0, "/b", status=302, Location="/a")
    result = scan(origins[0] + "/a", max_pages=1, evaluate="default-src 'none'")
    assert result.exit_code == 2
    assert any("Redirect loop" in e for e in result.errors)
