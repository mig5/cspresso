import asyncio
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from cspresso import crawl, ensure_playwright as installer
from cspresso.urls import origin_of, canonical_url


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://Example.COM:443/a", "https://example.com"),
        ("http://localhost:8000/a", "http://localhost:8000"),
        ("https://[::1]:8443/a", "https://[::1]:8443"),
        ("https://bücher.example/a", "https://xn--bcher-kva.example"),
        ("https://example.com; script-src *", ""),
        ("https://u:p@example.com/a", ""),
        ("https://example.com:bad/a", ""),
        ("https://example.com:99999/a", ""),
        ("https://example.com\n/a", ""),
        ("https://example.com\\evil/a", ""),
        ("file://example.com/a", ""),
        ("https://[invalid]/", ""),
    ],
)
def test_origin_validation(url, expected):
    assert origin_of(url) == expected


def test_normalized_url():
    assert canonical_url("https://EXAMPLE.com:443#x") == "https://example.com/"


def test_metadata_cannot_inject_directives():
    malicious = "https://maps.example; script-src-attr 'unsafe-inline'; img-src *; x"
    assert (
        crawl._extract_sourcemap_origin(
            "https://cdn.example/x.js", b"", {"sourcemap": malicious}
        )
        == set()
    )
    assert (
        crawl._extract_sourcemap_origin(
            "https://cdn.example/x.js", b"", {"sourcemap": "https://[bad"}
        )
        == set()
    )
    assert crawl._extract_sourcemap_origin(
        "https://cdn.example/x.js", b"//# sourceMappingURL=../x.map", {}
    ) == {"https://cdn.example"}


def policy(**kwargs):
    args = dict(
        directives={},
        base_origin="https://example.com",
        nonce_detected=False,
        script_hashes=set(),
        style_hashes=set(),
        style_attr_hashes=set(),
        handler_attr_hashes=set(),
        allow_data_img=False,
        allow_data_font=False,
        allow_blob=False,
        allow_unsafe_eval=False,
        upgrade_insecure_requests=False,
    )
    args.update(kwargs)
    return crawl.build_csp(**args)


def test_serializer_defense():
    with pytest.raises(ValueError):
        policy(directives={"connect-src": {"https://example.com; script-src *"}})
    with pytest.raises(ValueError):
        policy(script_hashes={"'sha256-x'; script-src *"})
    with pytest.raises(ValueError):
        policy(directives={"script-src; img-src": set()})


def test_nonce_directives_separate():
    output = policy(script_nonce=True, style_nonce=False)
    assert (
        "script-src 'self' 'nonce-{NONCE}'" not in output
    )  # serialization sorts tokens
    assert "script-src 'nonce-{NONCE}' 'self'" in output
    assert "style-src" not in output


def test_browser_resolved_links():
    page = SimpleNamespace(
        evaluate=AsyncMock(
            return_value=[
                "https://example.com/docs/next.html",
                "https://example.com/docs/?q=1#x",
                "https://other.example/a",
                "javascript:alert(1)",
            ]
        )
    )
    assert asyncio.run(crawl.extract_links(page, "https://example.com")) == [
        "https://example.com/docs/next.html",
        "https://example.com/docs/?q=1",
    ]
    assert "a.href" in page.evaluate.call_args.args[0]


@pytest.mark.parametrize(
    "args",
    [
        ["--max-pages", "0"],
        ["--timeout-ms", "-1"],
        ["--settle-ms", "-1"],
        ["--scan-timeout", "0"],
        ["--evaluate", "   "],
        ["--evaluate", ";"],
        ["--evaluate", "default-scr self"],
        ["--evaluate", "default-src 'self'; default-src *"],
        ["--evaluate", "default-src 'self'\nX-Header: evil"],
    ],
)
def test_invalid_cli_arguments(args):
    with pytest.raises(SystemExit) as exc:
        crawl._parse_args(["https://example.com", *args])
    assert exc.value.code == 2


def test_evaluate_file(tmp_path):
    file = tmp_path / "policy.txt"
    file.write_text("default-src 'self';\nobject-src 'none';")
    args = crawl._parse_args(["https://example.com", "--evaluate-file", str(file)])
    assert args.evaluate == "default-src 'self'; object-src 'none';"


def test_probe_does_not_follow_or_delete_existing_file(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("keep me")
    cache = tmp_path / "cache"
    cache.mkdir(mode=0o700)
    (cache / ".write_probe").symlink_to(victim)
    assert installer._is_writable_dir(cache)
    assert victim.read_text() == "keep me"
    assert (cache / ".write_probe").is_symlink()


def test_shared_cache_rejected(tmp_path):
    if os.name == "nt":
        pytest.skip("POSIX permission check")
    cache = tmp_path / "shared"
    cache.mkdir(mode=0o777)
    cache.chmod(0o777)
    with pytest.raises(OSError):
        installer._private_directory(cache)


def test_lock_is_reusable_and_not_unlinked(tmp_path):
    path = tmp_path / ".install.lock"
    with installer._install_lock(path, 1):
        inode = path.stat().st_ino
    with installer._install_lock(path, 1):
        assert path.stat().st_ino == inode


def test_lock_symlink_rejected(tmp_path):
    if not hasattr(os, "O_NOFOLLOW"):
        pytest.skip("POSIX nofollow check")
    victim = tmp_path / "victim"
    victim.write_text("keep me")
    path = tmp_path / ".install.lock"
    path.symlink_to(victim)
    with pytest.raises(OSError):
        with installer._install_lock(path, 1):
            pass
    assert victim.read_text() == "keep me"


def test_browser_path_zero_preserved(monkeypatch):
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", "0")
    assert installer.configure_browsers_path() == "0"


def test_explicit_path_applies_without_install(monkeypatch, tmp_path):
    class Manager:
        async def __aenter__(self):
            self.chromium = SimpleNamespace(
                launch=AsyncMock(side_effect=RuntimeError("controlled launch failure"))
            )
            return self

        async def __aexit__(self, *args):
            pass

    manager = Manager()
    monkeypatch.setattr(crawl, "async_playwright", lambda: manager)
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(tmp_path / "old"))
    result = asyncio.run(
        crawl.crawl_and_generate_csp(
            "https://example.com", auto_install=False, browsers_path=tmp_path / "chosen"
        )
    )
    assert os.environ["PLAYWRIGHT_BROWSERS_PATH"] == str(tmp_path / "chosen")
    assert manager.chromium.launch.call_args.kwargs["chromium_sandbox"] is True
    assert result.exit_code == 2
    assert "controlled launch failure" in result.errors[0]


def test_frame_provenance():
    root = SimpleNamespace(url="https://example.com/", parent_frame=None)
    child = SimpleNamespace(url="about:srcdoc", parent_frame=root)
    foreign = SimpleNamespace(url="https://widget.example/", parent_frame=root)
    assert crawl._owned_frame(child, "https://example.com")
    assert not crawl._owned_frame(foreign, "https://example.com")


def test_distinct_console_records_not_collapsed():
    a = {"documentURI": "https://example.com", "text": "script violation"}
    b = {"documentURI": "https://example.com", "text": "image violation"}
    assert crawl._deduplicate([a, b, a]) == [a, b]


def test_exit_codes():
    result = crawl.CrawlResult([], "", False, {}, [], [])
    assert result.exit_code == 0
    result.violations = [{"effectiveDirective": "script-src"}]
    assert result.exit_code == 1
    result.complete = False
    assert result.exit_code == 2


def test_installer_stdout_goes_to_stderr(monkeypatch):
    runner = Mock()
    monkeypatch.setattr(installer.subprocess, "run", runner)
    installer._install_chromium("0")
    assert runner.call_args.kwargs["stdout"] is installer.sys.stderr
    assert runner.call_args.kwargs["env"]["PLAYWRIGHT_BROWSERS_PATH"] == "0"


def test_cli_json_contract(monkeypatch, capsys):
    import json

    result = crawl.CrawlResult(
        ["https://example.com/"],
        "default-src 'self';",
        False,
        {"default-src": ["'self'"]},
        [],
        [],
        complete=False,
        errors=["injection failed"],
    )
    monkeypatch.setattr(crawl, "crawl_and_generate_csp", AsyncMock(return_value=result))
    assert crawl.main(["https://example.com", "--json", "--no-install"]) == 2
    output = json.loads(capsys.readouterr().out)
    assert output["schema_version"] == 2
    assert output["complete"] is False
    assert output["errors"] == ["injection failed"]


def test_header_only_clean_stdout(monkeypatch, capsys):
    result = crawl.CrawlResult(
        ["https://example.com/"], "default-src 'self';", False, {}, ["notice"], []
    )
    monkeypatch.setattr(crawl, "crawl_and_generate_csp", AsyncMock(return_value=result))
    assert crawl.main(["https://example.com", "--header-only"]) == 0
    captured = capsys.readouterr()
    assert captured.out == "default-src 'self';\n"
    assert "notice" in captured.err


def test_installed_browser_does_not_trigger_launch_or_reinstall(monkeypatch, tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir(mode=0o700)
    executable = cache / "chromium-1" / "chrome"
    executable.parent.mkdir()
    executable.write_text("fixture")

    class Manager:
        async def __aenter__(self):
            return SimpleNamespace(
                chromium=SimpleNamespace(executable_path=str(executable))
            )

        async def __aexit__(self, *args):
            pass

    install = Mock()
    monkeypatch.setattr(installer, "async_playwright", Manager)
    monkeypatch.setattr(installer, "_install_chromium", install)
    result = asyncio.run(installer.ensure_chromium_installed(cache))
    assert not result.installed
    install.assert_not_called()
