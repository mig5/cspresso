from __future__ import annotations

import os
import shutil
import subprocess  # nosec
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from playwright.async_api import async_playwright, Error as PlaywrightError

__all__ = ["EnsureResult", "ensure_chromium_installed"]


@dataclass(frozen=True)
class EnsureResult:
    browsers_path: Path
    installed: bool


def _user_cache_dir() -> Path:
    """
    Cross-platform cache dir without extra deps.
    Linux: $XDG_CACHE_HOME or ~/.cache
    macOS: ~/Library/Caches
    Windows: %LOCALAPPDATA%
    """
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base)

    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches"

    return Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache")))


def _default_browsers_path() -> Path:
    """
    If PLAYWRIGHT_BROWSERS_PATH is set, honor it (Playwright-standard).
    Otherwise use a user-writable cache path (safe for AppImage/pip installs).
    """
    env = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if env and env.strip() and env.strip() != "0":
        return Path(env).expanduser()

    return _user_cache_dir() / "cspresso" / "pw-browsers"


def _looks_like_python(path: str) -> bool:
    p = Path(path)
    name = p.name.lower()
    return (
        p.exists()
        and os.access(str(p), os.X_OK)
        and (
            name == "python" or name.startswith("python3") or name.startswith("python")
        )
    )


def _find_python_executable() -> str:
    """
    In AppImage bundles, sys.executable may be the AppImage itself.
    We need the embedded python binary so we can run: python -m playwright install chromium
    """
    # 1) Normal venv/system case
    if _looks_like_python(sys.executable):
        return sys.executable

    # 2) Sometimes present
    base = getattr(sys, "_base_executable", None)
    if base and _looks_like_python(base):
        return base

    # 3) Embedded python typically lives under sys.prefix/bin
    bindir = "Scripts" if os.name == "nt" else "bin"
    candidates = [
        Path(sys.prefix)
        / bindir
        / f"python{sys.version_info.major}.{sys.version_info.minor}",
        Path(sys.prefix) / bindir / f"python{sys.version_info.major}",
        Path(sys.prefix) / bindir / "python3",
        Path(sys.prefix) / bindir / "python",
        Path(sys.base_prefix)
        / bindir
        / f"python{sys.version_info.major}.{sys.version_info.minor}",
        Path(sys.base_prefix) / bindir / f"python{sys.version_info.major}",
        Path(sys.base_prefix) / bindir / "python3",
        Path(sys.base_prefix) / bindir / "python",
    ]
    for c in candidates:
        if _looks_like_python(str(c)):
            return str(c)

    # 4) Last resort: host python on PATH
    for name in (
        f"python{sys.version_info.major}.{sys.version_info.minor}",
        "python3",
        "python",
    ):
        p = shutil.which(name)
        if p and _looks_like_python(p):
            return p

    # Fallback (won't fix AppImage, but avoids crashing)
    return sys.executable


def _env_with_browsers_path(browsers_path: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["PLAYWRIGHT_BROWSERS_PATH"] = str(browsers_path)
    return env


def _is_writable_dir(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".write_probe"
        probe.write_text("x", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True
    except OSError:
        return False


def _acquire_install_lock(
    lock_path: Path, timeout_s: float = 120.0, poll_s: float = 0.2
) -> None:
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
        lock_path.unlink(missing_ok=True)
    except Exception:
        pass  # nosec


def _install_chromium(browsers_path: Path, with_deps: bool = False) -> None:
    env = _env_with_browsers_path(browsers_path)
    py = _find_python_executable()

    cmd = [py, "-m", "playwright", "install"]
    if with_deps:
        cmd.append("--with-deps")
    cmd.append("chromium")

    subprocess.run(cmd, check=True, env=env)  # nosec


async def _can_launch_chromium(browsers_path: Path) -> bool:
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
    """
    Ensure Playwright Chromium is installed and launchable.

    - Honors PLAYWRIGHT_BROWSERS_PATH if set.
    - Defaults to a user cache dir (safe for AppImage readonly mounts).
    - Uses embedded python to run playwright installer when sys.executable is the AppImage.
    """
    explicit = browsers_path is not None
    bp = browsers_path or _default_browsers_path()

    # If it already works, do nothing.
    if await _can_launch_chromium(bp):
        return EnsureResult(browsers_path=bp, installed=False)

    # If we need to install and the chosen dir isn't writable, fall back (unless explicit).
    if not explicit and not _is_writable_dir(bp):
        bp = _user_cache_dir() / "cspresso" / "pw-browsers"
        if not _is_writable_dir(bp):
            bp = Path(tempfile.gettempdir()) / "cspresso" / "pw-browsers"
            bp.mkdir(parents=True, exist_ok=True)

    if explicit and not _is_writable_dir(bp):
        raise OSError(
            f"Browsers path is not writable: {bp}\n"
            "Choose a writable directory via --browsers-path or set PLAYWRIGHT_BROWSERS_PATH."
        )

    lock_path = bp / ".install.lock"
    _acquire_install_lock(lock_path, timeout_s=lock_timeout_s)
    try:
        if await _can_launch_chromium(bp):
            return EnsureResult(browsers_path=bp, installed=False)

        _install_chromium(bp, with_deps=with_deps)

        if not await _can_launch_chromium(bp):
            raise RuntimeError(
                "Chromium install completed, but Chromium still failed to launch. "
                "On Linux, you may need additional system dependencies."
            )

        return EnsureResult(browsers_path=bp, installed=True)
    finally:
        _release_install_lock(lock_path)
