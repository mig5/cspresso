import asyncio
import json
from typing import Dict, List

import pytest

from cspresso.crawl import crawl_and_generate_csp, main


EXPECTED_DEFAULT = {
    "csp": "base-uri 'self'; connect-src 'self' https://asciinema.org; default-src 'self'; font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com; form-action 'self'; frame-ancestors 'self'; frame-src 'self' https://asciinema.org; object-src 'none'; script-src 'self' 'sha256-RgHx7FbVPh+gGLwA0wcJoRi+CfxNF3XcFY/jrcB0gHE=' 'sha256-rnSilqx70ysJSINaYijSOVvGOzG2uzSgg0sneaLAnns=' https://asciinema.org https://cdn.jsdelivr.net; style-src 'self' 'sha256-4hlN/4xO4xlov7xyb72ScvzOD/JFatd+xEAodkxYce8=' 'sha256-Gl5UiI26mHesRnN1ntr0nSHHoAOSYh6XOZx19azQ0Fk=' 'sha256-QuPEWNp+rjVYSLUmS8MFUfVHy/Fh3081C+aZBHEczfA=' 'sha256-SGlitudZ76fvsMgZ/sIf2NcPXwhTuwOaTeB2nvZ0OjA=' 'sha256-emAdQwdjLp3d7bWxgW041mgnWTwEzDtokllulE67Ugc=' 'sha256-eyENtx/C0Tm21pZwh9zjr5u4q+H/WMxZL0zxGk1/M4w=' 'sha256-q/F11RqjQHAMnbYF6csaGyctuo2K9/fRKvGpUsGdeVQ=' 'unsafe-hashes' https://asciinema.org https://cdn.jsdelivr.net https://fonts.googleapis.com; style-src-attr 'sha256-4hlN/4xO4xlov7xyb72ScvzOD/JFatd+xEAodkxYce8=' 'sha256-Gl5UiI26mHesRnN1ntr0nSHHoAOSYh6XOZx19azQ0Fk=' 'sha256-QuPEWNp+rjVYSLUmS8MFUfVHy/Fh3081C+aZBHEczfA=' 'sha256-SGlitudZ76fvsMgZ/sIf2NcPXwhTuwOaTeB2nvZ0OjA=' 'sha256-emAdQwdjLp3d7bWxgW041mgnWTwEzDtokllulE67Ugc=' 'sha256-eyENtx/C0Tm21pZwh9zjr5u4q+H/WMxZL0zxGk1/M4w=' 'sha256-q/F11RqjQHAMnbYF6csaGyctuo2K9/fRKvGpUsGdeVQ=' 'unsafe-hashes';",
}


def parse_csp(csp: str) -> Dict[str, List[str]]:
    """
    Parse: "directive value value; directive value; upgrade-insecure-requests; ..."
    into: {"directive": ["value", ...], "upgrade-insecure-requests": []}
    """
    out: Dict[str, List[str]] = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        toks = part.split()
        out[toks[0]] = toks[1:]
    return out


@pytest.mark.network
@pytest.mark.slow
def test_cspresso_default_snapshot_csp_only():
    """
    Hits https://enroll.sh with default args and asserts the exact CSP string.
    NOTE: This is an integration snapshot; it will fail if the site changes.
    """
    res = asyncio.run(
        crawl_and_generate_csp(
            "https://enroll.sh",
            timeout_ms=60000,
            # defaults:
            # max_pages=10, include_sourcemaps=False, upgrade_insecure_requests=False
        )
    )
    got = {"csp": res.csp}
    assert got == EXPECTED_DEFAULT


@pytest.mark.network
@pytest.mark.slow
def test_include_sourcemaps_adds_jsdelivr_to_connect_src():
    """
    With --include-sourcemaps, ensure https://cdn.jsdelivr.net appears in connect-src.
    """
    res = asyncio.run(
        crawl_and_generate_csp(
            "https://enroll.sh",
            max_pages=1,  # faster; bootstrap assets are on the homepage
            timeout_ms=60000,
            include_sourcemaps=True,
        )
    )
    d = parse_csp(res.csp)
    assert "connect-src" in d
    assert "https://cdn.jsdelivr.net" in d["connect-src"]


@pytest.mark.network
@pytest.mark.slow
def test_upgrade_inseure_requests_present():
    """
    With --upgrade-insecure-requests, ensure the directive is emitted.
    """
    res = asyncio.run(
        crawl_and_generate_csp(
            "https://enroll.sh",
            max_pages=1,
            timeout_ms=60000,
            upgrade_insecure_requests=True,
        )
    )
    assert "upgrade-insecure-requests;" in res.csp
    assert "upgrade-insecure-requests" in parse_csp(res.csp)


@pytest.mark.network
@pytest.mark.slow
def test_cli_json_output_valid(capsys):
    """
    Smoke test: running the CLI with --json prints valid JSON (even if other lines slip in).
    """
    main(["https://enroll.sh", "--json", "--max-pages", "1", "--timeout-ms", "60000"])
    out = capsys.readouterr().out.strip()

    # Robust JSON extraction in case of stray log lines.
    start = out.find("{")
    end = out.rfind("}") + 1
    assert start != -1 and end > start, f"stdout did not contain JSON: {out!r}"

    payload = json.loads(out[start:end])
    assert "csp" in payload
    assert isinstance(payload["csp"], str)
    assert payload["csp"].endswith(";")
    assert payload.get("visited")  # should be non-empty


def test_parse_csp_smoke():
    d = parse_csp("default-src 'self'; object-src 'none'; upgrade-insecure-requests;")
    assert d["default-src"] == ["'self'"]
    assert d["object-src"] == ["'none'"]
    assert d["upgrade-insecure-requests"] == []
