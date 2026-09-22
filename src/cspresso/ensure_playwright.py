from __future__ import annotations

import os
import shutil
import subprocess  # nosec
import sys
import tempfile
import time
import stat
import asyncio
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from playwright.async_api import async_playwright

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


def configure_browsers_path(browsers_path: Path | None = None) -> str:
    """Configure the driver before starting it, even when installation is disabled."""
    if browsers_path is not None:
        value = str(browsers_path.expanduser().absolute())
    elif os.environ.get("PLAYWRIGHT_BROWSERS_PATH") == "0":
        value = "0"  # Playwright's package-local installation convention.
    else:
        value = str(_default_browsers_path().absolute())
    if value != "0":
        _private_directory(Path(value))
    os.environ["PLAYWRIGHT_BROWSERS_PATH"] = value
    return value


def _private_directory(path: Path) -> None:
    """Refuse executable caches controlled by another local user."""
    path = path.absolute()
    # Create/check one component at a time. Checking all missing ancestors and
    # then mkdir(parents=True) would leave a pre-creation race in shared /tmp.
    for part in reversed((path, *path.parents)):
        try:
            part.mkdir(mode=0o700)
        except FileExistsError:
            pass
        st = part.lstat()
        if not stat.S_ISDIR(st.st_mode) or part.is_symlink():
            raise OSError(f"Browser cache path is not a real directory: {part}")
        if os.name != "nt":
            if st.st_uid not in {0, os.getuid()}:
                raise OSError(f"Browser cache ancestor has another owner: {part}")
            if st.st_mode & 0o022 and not (st.st_mode & stat.S_ISVTX):
                raise OSError(f"Browser cache ancestor is writable by others: {part}")
            if part == path and (st.st_uid != os.getuid() or st.st_mode & 0o022):
                raise OSError(
                    f"Browser cache must be owned by you and not writable by others: {path}"
                )


def _is_writable_dir(path: Path) -> bool:
    try:
        _private_directory(path)
        with tempfile.TemporaryFile(dir=path):
            pass
        return True
    except OSError:
        return False


@contextmanager
def _install_lock(path: Path, timeout_s: float):
    # Keep the inode: unlinking a lock file allows two independent locks.
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    if path.is_symlink():
        raise OSError("Installation lock must not be a symlink")
    fd = os.open(path, flags, 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise OSError("Unsafe browser installation lock")
        if os.name != "nt" and (st.st_uid != os.getuid() or st.st_mode & 0o022):
            raise OSError("Unsafe browser installation lock permissions")
        if st.st_size == 0:
            os.write(fd, b"0")
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                if os.name == "nt":
                    import msvcrt

                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except (BlockingIOError, PermissionError):
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        "Timed out waiting for browser installation lock"
                    )
                time.sleep(0.1)
        yield
    finally:
        os.close(fd)  # OS releases the lock, including after process death.


def _install_chromium(browsers_path: str, with_deps: bool = False) -> None:
    cmd = [_find_python_executable(), "-m", "playwright", "install"]
    if with_deps:
        cmd.append("--with-deps")
    cmd.append("chromium")
    try:
        subprocess.run(
            cmd,
            check=True,
            env=_env_with_browsers_path(browsers_path),
            stdout=sys.stderr,
            stderr=sys.stderr,
        )  # nosec B603
    except subprocess.SubprocessError as exc:
        raise RuntimeError(
            "Chromium installation failed; see installer diagnostics on stderr"
        ) from exc


async def ensure_chromium_installed(
    browsers_path: Path | None = None,
    *,
    with_deps: bool = False,
    lock_timeout_s: float = 120.0,
) -> EnsureResult:
    value = configure_browsers_path(browsers_path)
    async with async_playwright() as p:
        executable = Path(p.chromium.executable_path)
    if value == "0":
        bp = next(
            parent.parent
            for parent in executable.parents
            if parent.name.startswith("chromium-")
        )
    else:
        bp = Path(value)
    _private_directory(bp)
    # Check installation, not launchability. Sandbox/library errors must not
    # trigger reinstall attempts or silently weaken browser launch settings.
    if executable.is_file():
        return EnsureResult(bp, False)

    def install():
        with _install_lock(bp / ".install.lock", lock_timeout_s):
            if executable.is_file():
                return False
            _install_chromium(value, with_deps)
            if not executable.is_file():
                raise RuntimeError(
                    "Chromium installer did not provide the expected executable"
                )
            return True

    installed = await asyncio.to_thread(install)
    return EnsureResult(bp, installed)
