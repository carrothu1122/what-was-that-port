"""Cross-platform privilege handling for advanced scans.

The GUI must stay unprivileged. This module owns the platform-specific work of
launching a short-lived privileged worker and exchanging JSON request/result
files with it.
"""

from __future__ import annotations

import ctypes
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any


ADVANCED_METHODS = {"TCP SYN", "TCP FIN", "UDP"}


def get_advanced_methods(methods: list[str]) -> list[str]:
    """Return scan methods that need raw socket privileges."""
    return [method for method in methods if method in ADVANCED_METHODS]


def needs_privileged_scan(methods: list[str]) -> bool:
    """Return whether the selected methods include privileged scans."""
    return bool(get_advanced_methods(methods))


def current_platform() -> str:
    """Return a normalized platform name."""
    system = platform.system().lower()
    if system.startswith("windows"):
        return "windows"
    if system.startswith("linux"):
        return "linux"
    if system.startswith("darwin"):
        return "macos"
    return system or "unknown"


def is_windows_admin() -> bool:
    """Return whether the current process is elevated on Windows."""
    if current_platform() != "windows":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def is_running_as_root() -> bool:
    """Return whether the current process has root privileges on POSIX."""
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid is not None and geteuid() == 0)


def is_running_as_admin() -> bool:
    """Return whether the current process can run privileged scans directly."""
    if current_platform() == "windows":
        return is_windows_admin()
    return is_running_as_root()


def is_pkexec_available() -> bool:
    """Return whether Linux polkit's pkexec is available."""
    return shutil.which("pkexec") is not None


def can_launch_privileged_worker() -> bool:
    """Return whether this platform has a supported elevation launcher."""
    system = current_platform()
    if is_running_as_admin():
        return True
    if system == "linux":
        return is_pkexec_available() and _command_base_looks_available(worker_command_base())
    if system == "windows":
        return _command_base_looks_available(worker_command_base())
    return False


def is_npcap_available() -> bool:
    """Return whether Npcap appears to be installed on Windows."""
    if current_platform() != "windows":
        return True

    windir = os.environ.get("WINDIR", r"C:\Windows")
    candidates = [
        Path(windir) / "System32" / "Npcap" / "Packet.dll",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Npcap" / "Packet.dll",
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Npcap" / "Packet.dll",
    ]
    return any(path.exists() for path in candidates)


def advanced_scan_environment_warning(methods: list[str]) -> str:
    """Return a platform-specific warning for advanced scan dependencies."""
    if current_platform() == "windows" and needs_privileged_scan(methods) and not is_npcap_available():
        return "未检测到 Npcap。Windows 上 TCP SYN / TCP FIN / UDP 通常需要 Npcap 才能正常发包和抓包。"
    return ""


def worker_script_path() -> Path:
    """Return the source-tree privileged worker path."""
    return Path(__file__).resolve().with_name("privileged_worker.py")


def _packaged_worker_path() -> Path | None:
    """Return a worker executable next to the running executable, if present."""
    if current_platform() != "windows":
        return None

    executable = Path(sys.executable)
    candidates = [
        executable.with_name("what-was-that-port-worker.exe"),
        executable.with_name("privileged_worker.exe"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def worker_command_base() -> list[str]:
    """Return the command prefix used to run the privileged worker.

    Packagers can set WHAT_WAS_THAT_PORT_WORKER to point at a packaged worker
    executable. Otherwise we prefer an installed console script, then fall back
    to the source-tree Python worker.
    """
    override = os.environ.get("WHAT_WAS_THAT_PORT_WORKER")
    if override:
        return [override]

    packaged_worker = _packaged_worker_path()
    if packaged_worker is not None:
        return [str(packaged_worker)]

    installed_worker = shutil.which("what-was-that-port-worker")
    if installed_worker:
        return [installed_worker]

    return [sys.executable, str(worker_script_path())]


def _command_base_looks_available(command_base: list[str]) -> bool:
    if not command_base:
        return False

    executable = command_base[0]
    if len(command_base) > 1:
        return Path(command_base[1]).exists()

    executable_path = Path(executable)
    if executable_path.is_absolute() or executable_path.parent != Path("."):
        return executable_path.exists()

    return shutil.which(executable) is not None


def _write_json_file(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def _read_json_file(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _make_temp_paths() -> tuple[Path, Path]:
    token = uuid.uuid4().hex
    temp_dir = Path(tempfile.gettempdir())
    return (
        temp_dir / f"what-was-that-port-request-{token}.json",
        temp_dir / f"what-was-that-port-result-{token}.json",
    )


def _launch_linux_worker(command_base: list[str], request_path: Path, result_path: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["pkexec", *command_base, str(request_path), str(result_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )


def _launch_windows_worker(command_base: list[str], request_path: Path, result_path: Path) -> None:
    executable = command_base[0]
    worker_args = [*command_base[1:], str(request_path), str(result_path)]
    params = subprocess.list2cmdline(worker_args)
    result = ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, params, None, 0)
    if result <= 32:
        raise RuntimeError(f"UAC 启动失败，ShellExecuteW 返回 {result}")


def _wait_for_result_file(result_path: Path, timeout: int) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if result_path.exists():
            return _read_json_file(result_path)
        time.sleep(0.2)
    raise TimeoutError("高级扫描授权进程超时")


def run_privileged_worker(request: dict[str, Any], timeout: int) -> tuple[dict[str, Any] | None, str]:
    """Launch a privileged worker and return (payload, error_message)."""
    command_base = worker_command_base()
    if not _command_base_looks_available(command_base):
        return None, "缺少 privileged_worker.py"

    request_path, result_path = _make_temp_paths()
    _write_json_file(request_path, request)

    try:
        system = current_platform()
        if system == "linux":
            if not is_pkexec_available():
                return None, "未找到 pkexec，无法授权运行高级扫描"
            completed = _launch_linux_worker(command_base, request_path, result_path, timeout)
            if completed.returncode != 0:
                return None, completed.stderr.strip() or "用户取消授权或 pkexec 执行失败"
            return _wait_for_result_file(result_path, timeout), ""

        if system == "windows":
            _launch_windows_worker(command_base, request_path, result_path)
            return _wait_for_result_file(result_path, timeout), ""

        return None, f"当前平台不支持授权扫描：{system}"
    except subprocess.TimeoutExpired:
        return None, "高级扫描授权进程超时"
    except TimeoutError as exc:
        return None, str(exc)
    except json.JSONDecodeError as exc:
        return None, f"高级扫描返回非 JSON 数据：{exc}"
    except Exception as exc:
        return None, f"启动授权扫描失败：{exc}"
    finally:
        for path in (request_path, result_path):
            try:
                path.unlink(missing_ok=True)
            except Exception:
                pass
