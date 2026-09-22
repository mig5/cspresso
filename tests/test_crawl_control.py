"""Exercise real crawl control flow against a controlled Playwright interface."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from cspresso import crawl


class FakePage:
    def __init__(self, context):
        self.context = context
        self.url = "about:blank"
        self.main_frame = self
        self.parent_frame = None
        self.frames = [self]
        self.events = {}
        self.close = AsyncMock()
        self.expose_binding = AsyncMock()
        self.add_init_script = AsyncMock()
        self.wait_for_load_state = AsyncMock()
        self.wait_for_timeout = AsyncMock()

    def on(self, event, callback):
        self.events[event] = callback

    def locator(self, selector):
        return SimpleNamespace(count=AsyncMock(return_value=self.context.meta_count))

    async def evaluate(self, script, *args):
        if "a.href" in script:
            return []
        return dict(
            inlineScripts=[],
            inlineStyles=[],
            styleAttrs=[],
            handlerAttrs=[],
            dataImgs=False,
            dataFonts=False,
        )

    async def goto(self, url, **kwargs):
        self.url = url
        response = SimpleNamespace(
            headers={"content-type": "text/html"},
            url=url,
            status=200,
            dispose=AsyncMock(),
            header_value=AsyncMock(return_value="text/html"),
        )
        route = SimpleNamespace(
            fetch=AsyncMock(return_value=response),
            fulfill=AsyncMock(),
            abort=AsyncMock(),
            continue_=AsyncMock(),
        )
        if self.context.failure:
            route.fetch.side_effect = RuntimeError("simulated fetch failure")
        req = SimpleNamespace(url=url, resource_type="document", frame=self)
        self.context.last_route = route
        await self.context.handler(route, req)
        return response


class FakeContext:
    def __init__(self, failure=False, meta_count=0):
        self.failure = failure
        self.meta_count = meta_count
        self.close = AsyncMock()
        self.pages = []
        self.events = {}

    async def route(self, pattern, handler):
        self.handler = handler

    def on(self, event, handler):
        self.events[event] = handler

    async def new_cdp_session(self, page):
        return SimpleNamespace(on=Mock(), send=AsyncMock())

    async def new_page(self):
        page = FakePage(self)
        self.pages.append(page)
        return page


@pytest.fixture
def fake(monkeypatch, tmp_path):
    context = FakeContext()
    browser = SimpleNamespace(
        new_context=AsyncMock(return_value=context), close=AsyncMock()
    )
    launcher = AsyncMock(return_value=browser)

    class Manager:
        async def __aenter__(self):
            return SimpleNamespace(chromium=SimpleNamespace(launch=launcher))

        async def __aexit__(self, *args):
            pass

    monkeypatch.setattr(crawl, "async_playwright", Manager)
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(tmp_path / "browsers"))
    return context, browser, launcher


def scan(**kwargs):
    return asyncio.run(
        crawl.crawl_and_generate_csp(
            "https://example.com",
            auto_install=False,
            settle_ms=0,
            evaluate="default-src 'self'",
            **kwargs,
        )
    )


def test_injection_failure_never_passes_or_replays(fake):
    context, browser, _ = fake
    context.failure = True
    result = scan()
    assert result.exit_code == 2
    context.last_route.continue_.assert_not_awaited()
    context.last_route.abort.assert_awaited_once()
    browser.close.assert_awaited_once()


def test_success_confirms_injection_and_preserves_redirects(fake):
    context, _, launcher = fake
    result = scan()
    assert result.complete
    assert result.pages[0]["evaluated"] is True
    assert result.pages[0]["status"] == "completed"
    assert result.directives["default-src"] == ["'self'"]
    assert launcher.call_args.kwargs["chromium_sandbox"] is True
    assert context.last_route.fetch.call_args.kwargs["max_redirects"] == 0
    assert context.pages[0].add_init_script.call_args.args[0].endswith("})();")


def test_explicit_no_sandbox_only(fake):
    result = scan(no_sandbox=True)
    assert result.complete
    assert fake[2].call_args.kwargs["chromium_sandbox"] is False
    assert any("explicitly disabled" in n for n in result.notes)


def test_remaining_meta_csp_is_incomplete(fake):
    fake[0].meta_count = 1
    result = scan(bypass_csp=True)
    assert result.exit_code == 2
    assert any("Meta CSP" in e for e in result.errors)


def test_foreign_frame_requests_do_not_broaden_policy(fake):
    context = fake[0]
    original = context.new_page

    async def new_page():
        page = await original()
        original_goto = page.goto

        async def goto(*args, **kwargs):
            resp = await original_goto(*args, **kwargs)
            foreign = SimpleNamespace(url="https://widget.example", parent_frame=page)
            context.events["request"](
                SimpleNamespace(
                    frame=foreign,
                    url="https://evil.example/x.js",
                    resource_type="script",
                    headers={"sec-fetch-dest": "script"},
                )
            )
            context.events["request"](
                SimpleNamespace(
                    frame=page,
                    url="https://cdn.example/x.js",
                    resource_type="script",
                    headers={"sec-fetch-dest": "script"},
                )
            )
            return resp

        page.goto = goto
        return page

    context.new_page = new_page
    result = scan()
    assert "https://cdn.example" in result.directives["script-src"]
    assert "https://evil.example" not in result.csp


def test_foreign_or_wrong_policy_reports_ignored(fake):
    result = scan()
    page = fake[0].pages[0]
    callback = page.expose_binding.call_args.args[1]
    good = {
        "disposition": "report",
        "originalPolicy": "default-src 'self'",
        "effectiveDirective": "script-src-elem",
    }
    callback(
        {"frame": SimpleNamespace(url="https://foreign.example", parent_frame=page)},
        good,
    )
    callback({"frame": page}, {**good, "originalPolicy": "default-src 'none'"})
    assert result.violations == []


def test_out_of_scope_navigation_aborts_before_fetch(fake):
    scan()
    context = fake[0]
    route = SimpleNamespace(fetch=AsyncMock(), abort=AsyncMock())
    req = SimpleNamespace(
        resource_type="document", frame=context.pages[0], url="https://foreign.example"
    )
    asyncio.run(context.handler(route, req))
    route.abort.assert_awaited_once()
    route.fetch.assert_not_awaited()


def test_foreign_redirect_response_is_never_fulfilled(fake):
    scan()
    context = fake[0]
    response = SimpleNamespace(
        status=302, headers={"location": "https://foreign.example"}, dispose=AsyncMock()
    )
    route = SimpleNamespace(
        fetch=AsyncMock(return_value=response), fulfill=AsyncMock(), abort=AsyncMock()
    )
    req = SimpleNamespace(
        resource_type="document",
        frame=context.pages[0],
        url="https://example.com/redirect",
    )
    asyncio.run(context.handler(route, req))
    route.fulfill.assert_not_awaited()
    route.abort.assert_awaited_once()
    response.dispose.assert_awaited_once()


@pytest.mark.parametrize("redirect_loop", [False, True])
def test_same_origin_redirect_is_navigated_at_real_url(fake, redirect_loop):
    context = fake[0]
    original = context.new_page

    async def new_page():
        page = await original()
        original_goto = page.goto

        async def goto(url, **kwargs):
            if url == "https://example.com/" or redirect_loop:
                page.url = url
                response = SimpleNamespace(
                    status=302,
                    headers={"location": "/" if url.endswith("/final") else "/final"},
                    dispose=AsyncMock(),
                )
                route = SimpleNamespace(
                    fetch=AsyncMock(return_value=response),
                    fulfill=AsyncMock(),
                    abort=AsyncMock(),
                )
                await context.handler(
                    route,
                    SimpleNamespace(
                        url=url, resource_type="document", frame=page, method="GET"
                    ),
                )
                route.abort.assert_not_awaited()
                route.fulfill.assert_awaited_once_with(
                    status=200,
                    headers={
                        "content-type": "text/html",
                        "content-security-policy": "default-src 'none'; sandbox",
                    },
                    body="",
                )
                response.dispose.assert_awaited_once()
                return SimpleNamespace(status=200)
            return await original_goto(url, **kwargs)

        page.goto = goto
        return page

    context.new_page = new_page
    result = scan()
    if redirect_loop:
        assert result.exit_code == 2
        assert any("Redirect loop" in e for e in result.errors)
        assert not result.visited
        return
    assert result.complete, result.errors
    assert result.visited == ["https://example.com/final"]
    assert result.pages[0]["redirects"] == ["https://example.com/"]
    assert result.pages[0]["evaluated"]


def test_deadline_is_incomplete_and_closes_browser(fake):
    context, browser, _ = fake

    async def stalled_page():
        await asyncio.sleep(1)

    context.new_page = stalled_page
    result = scan(scan_timeout=0.01)
    assert result.exit_code == 2
    assert "Scan wall-clock deadline reached" in result.errors
    browser.close.assert_awaited_once()


def test_request_budget_aborts(fake):
    scan(max_requests=1)
    context = fake[0]
    route = SimpleNamespace(abort=AsyncMock(), continue_=AsyncMock())
    asyncio.run(context.handler(route, SimpleNamespace(resource_type="image")))
    route.abort.assert_awaited_once()
    route.continue_.assert_not_awaited()
