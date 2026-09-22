"""Optional public-site smoke tests. Core regressions use local fixtures."""

import asyncio
import os

import pytest

from cspresso.crawl import crawl_and_generate_csp


@pytest.mark.network
@pytest.mark.slow
def test_public_site_smoke():
    result = asyncio.run(
        crawl_and_generate_csp(
            "https://enroll.sh/",
            auto_install=False,
            max_pages=1,
            timeout_ms=60000,
            no_sandbox=os.environ.get("CSPRESSO_TEST_NO_SANDBOX") == "1",
        )
    )
    assert result.complete, result.errors
    assert result.visited
    assert result.directives["object-src"] == ["'none'"]
    assert result.csp.endswith(";")
