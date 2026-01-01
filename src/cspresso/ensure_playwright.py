from __future__ import annotations

import os
import sys
import time
import subprocess  # nosec
from dataclasses import dataclass
from pathlib import Path

from playwright.async_api import async_playwright, Error as PlaywrightError


@dataclass(frozen=True)
class EnsureResult:
    browsers_path: Path
    installed: bool


def _default_browsers_path() -> Path:
    # Project-local by default. Override with PLAYWRIGHT_BROWSERS_PATH or CLI flag.
    return Path(__file__).resolve().parents[2] / ".pw-browsers"


def _env_with_browsers_path(browsers_path: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["PLAYWRIGHT_BROWSERS_PATH"] = str(browsers_path)
    return env


def _acquire_install_lock(
    lock_path: Path, timeout_s: float = 120.0, poll_s: float = 0.2
) -> None:
    """Very small cross-platform lock using atomic file creation.
    Avoids concurrent Playwright installs when multiple processes start at once.

    Not perfect, but good enough for most CLI usage.
    """
    start = time.time()
    while True:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            return
        except FileExistsError:
            if time.time() - start > timeout_s:
                raise TimeoutError(f"Timed out waiting for install lock: {lock_path}")
            time.sleep(poll_s)


def _release_install_lock(lock_path: Path) -> None:
    try:
        lock_path.unlink(missing_ok=True)  # Python 3.8+
    except Exception:
        pass  # nosec


def _install_chromium(browsers_path: Path, with_deps: bool = False) -> None:
    env = _env_with_browsers_path(browsers_path)
    cmd = [sys.executable, "-m", "playwright", "install"]
    if with_deps:
        cmd.append("--with-deps")
    cmd.append("chromium")

    subprocess.run(cmd, check=True, env=env)  # nosec


async def _can_launch_chromium(browsers_path: Path) -> bool:
    # Ensure this process uses the same path too.
    os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(browsers_path)
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            await browser.close()
        return True
    except PlaywrightError:
        return False


async def ensure_chromium_installed(
    browsers_path: Path | None = None,
    *,
    with_deps: bool = False,
    lock_timeout_s: float = 120.0,
) -> EnsureResult:
    """Ensure Playwright's Chromium is installed and launchable.

    Strategy:
    - Attempt a tiny headless launch.
    - If it fails, acquire a lock and run `python -m playwright install chromium` (optionally --with-deps).
    - Retry launch once.
    """
    bp = browsers_path or _default_browsers_path()
    bp.mkdir(parents=True, exist_ok=True)

    if await _can_launch_chromium(bp):
        return EnsureResult(browsers_path=bp, installed=False)

    lock_path = bp / ".install.lock"
    _acquire_install_lock(lock_path, timeout_s=lock_timeout_s)
    try:
        # Another process might have installed while we waited; check again.
        if await _can_launch_chromium(bp):
            return EnsureResult(browsers_path=bp, installed=False)

        _install_chromium(bp, with_deps=with_deps)

        if not await _can_launch_chromium(bp):
            raise RuntimeError(
                "Playwright Chromium install completed, but Chromium still failed to launch. "
                "On Linux, you may need additional system dependencies."
            )

        return EnsureResult(browsers_path=bp, installed=True)
    finally:
        _release_install_lock(lock_path)
