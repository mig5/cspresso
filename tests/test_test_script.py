"""Exercise the actual shell wrapper without downloading another Chromium."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.parametrize("test_exit", [0, 1])
def test_private_browser_cache_and_cleanup(tmp_path, test_exit):
    _run_script(tmp_path, test_exit=test_exit)


def test_explicit_safe_cache_is_preserved(tmp_path):
    cache = tmp_path / "explicit-cache"
    cache.mkdir(mode=0o700)
    _run_script(tmp_path, explicit=cache)
    assert cache.is_dir()


def test_explicit_unsafe_cache_fails_before_install(tmp_path):
    if os.name == "nt":
        pytest.skip("POSIX permissions")
    cache = tmp_path / "unsafe-cache"
    cache.mkdir(mode=0o777)
    cache.chmod(0o777)
    calls, result = _run_script(tmp_path, explicit=cache, unsafe=True)
    assert result.returncode != 0
    assert len(calls) == 1 and calls[0]["args"][1] == "python"
    assert cache.is_dir()
    assert "writable by others" in result.stderr


def _run_script(tmp_path, test_exit=0, explicit=None, unsafe=False):
    repo = Path(__file__).resolve().parents[1]
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    log = tmp_path / "calls.jsonl"
    # Validate the real cache function; stand in only for installation/pytest.
    stub = stub_dir / "poetry"
    stub.write_text(
        "#!"
        + sys.executable
        + "\n"
        + """
import json, os, subprocess, sys
args = sys.argv[1:]
with open(os.environ['CALL_LOG'], 'a') as stream:
    stream.write(json.dumps({'args': args, 'cache': os.environ.get('PLAYWRIGHT_BROWSERS_PATH')}) + '\\n')
if args[:2] == ['run', 'python']:
    sys.exit(subprocess.call([sys.executable, *args[2:]]))
if args[:2] == ['run', 'pytest']:
    sys.exit(int(os.environ['TEST_EXIT']))
if args[:2] != ['run', 'playwright']:
    sys.exit(99)
"""
    )
    stub.chmod(0o700)
    permissive = tmp_path / "runner-cache"
    permissive.mkdir(mode=0o777)
    permissive.chmod(0o777)
    env = os.environ.copy()
    env.pop("PLAYWRIGHT_BROWSERS_PATH", None)
    env.update(
        PATH=str(stub_dir) + os.pathsep + env.get("PATH", ""),
        PYTHONPATH=str(repo / "src"),
        TMPDIR=str(tmp_path),
        XDG_CACHE_HOME=str(permissive),
        CALL_LOG=str(log),
        TEST_EXIT=str(test_exit),
    )
    if explicit:
        env["PLAYWRIGHT_BROWSERS_PATH"] = str(explicit)
    result = subprocess.run(
        ["bash", str(repo / "tests.sh")], env=env, capture_output=True, text=True
    )
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    if unsafe:
        return calls, result
    assert result.returncode == test_exit, result.stderr
    assert [c["args"][1] for c in calls] == ["python", "playwright", "pytest"]
    assert len({c["cache"] for c in calls}) == 1
    selected = Path(calls[0]["cache"])
    if explicit is None:
        assert selected.parent == tmp_path
        assert selected.name.startswith("cspresso-tests.")
        assert not selected.exists()
    else:
        assert selected == explicit and selected.is_dir()
    assert permissive.stat().st_mode & 0o777 == 0o777
    return calls, result
