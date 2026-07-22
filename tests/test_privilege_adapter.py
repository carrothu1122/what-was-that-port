from types import SimpleNamespace

import privilege_adapter


def test_privilege_adapter_detects_advanced_methods():
    methods = ["ICMP", "TCP Connect", "TCP SYN", "TCP FIN", "UDP"]

    assert privilege_adapter.get_advanced_methods(methods) == ["TCP SYN", "TCP FIN", "UDP"]
    assert privilege_adapter.needs_privileged_scan(methods) is True
    assert privilege_adapter.needs_privileged_scan(["ICMP", "TCP Connect"]) is False


def test_linux_worker_uses_request_and_result_files(monkeypatch, tmp_path):
    worker_path = tmp_path / "privileged_worker.py"
    worker_path.write_text("# worker placeholder\n", encoding="utf-8")
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        seen["kwargs"] = kwargs
        result_path = cmd[4]
        with open(result_path, "w", encoding="utf-8") as handle:
            handle.write('{"ok": true, "rows": [{"method": "UDP"}]}')
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(privilege_adapter, "current_platform", lambda: "linux")
    monkeypatch.setattr(privilege_adapter, "is_pkexec_available", lambda: True)
    monkeypatch.setattr(privilege_adapter, "worker_command_base", lambda: ["python", str(worker_path)])
    monkeypatch.setattr(privilege_adapter.subprocess, "run", fake_run)

    payload, error = privilege_adapter.run_privileged_worker(
        {"ip": "192.0.2.1", "ports": [53], "methods": ["UDP"], "host_status": "在线"},
        timeout=30,
    )

    assert error == ""
    assert payload == {"ok": True, "rows": [{"method": "UDP"}]}
    assert seen["cmd"][0] == "pkexec"
    assert seen["cmd"][2] == str(worker_path)
    assert seen["kwargs"]["timeout"] == 30


def test_unsupported_platform_returns_clear_error(monkeypatch, tmp_path):
    worker_path = tmp_path / "privileged_worker.py"
    worker_path.write_text("# worker placeholder\n", encoding="utf-8")

    monkeypatch.setattr(privilege_adapter, "current_platform", lambda: "plan9")
    monkeypatch.setattr(privilege_adapter, "worker_command_base", lambda: ["python", str(worker_path)])

    payload, error = privilege_adapter.run_privileged_worker({}, timeout=30)

    assert payload is None
    assert "当前平台不支持授权扫描" in error


def test_windows_packaged_worker_next_to_executable_is_preferred(monkeypatch, tmp_path):
    gui_exe = tmp_path / "what-was-that-port.exe"
    worker_exe = tmp_path / "what-was-that-port-worker.exe"
    worker_exe.write_text("placeholder", encoding="utf-8")

    monkeypatch.delenv("WHAT_WAS_THAT_PORT_WORKER", raising=False)
    monkeypatch.setattr(privilege_adapter, "current_platform", lambda: "windows")
    monkeypatch.setattr(privilege_adapter.sys, "executable", str(gui_exe))

    assert privilege_adapter.worker_command_base() == [str(worker_exe)]


def test_windows_requires_available_worker_for_elevation(monkeypatch, tmp_path):
    missing_worker = tmp_path / "missing-worker.exe"

    monkeypatch.setattr(privilege_adapter, "current_platform", lambda: "windows")
    monkeypatch.setattr(privilege_adapter, "is_running_as_admin", lambda: False)
    monkeypatch.setattr(privilege_adapter, "worker_command_base", lambda: [str(missing_worker)])

    assert privilege_adapter.can_launch_privileged_worker() is False


def test_windows_npcap_warning_is_reported_when_missing(monkeypatch):
    monkeypatch.setattr(privilege_adapter, "current_platform", lambda: "windows")
    monkeypatch.setattr(privilege_adapter, "is_npcap_available", lambda: False)

    warning = privilege_adapter.advanced_scan_environment_warning(["TCP SYN"])

    assert "Npcap" in warning


def test_windows_uac_launch_uses_executable_and_arguments(monkeypatch, tmp_path):
    calls = {}

    class FakeShell32:
        def ShellExecuteW(self, hwnd, verb, executable, params, directory, show):
            calls["verb"] = verb
            calls["executable"] = executable
            calls["params"] = params
            return 33

    monkeypatch.setattr(privilege_adapter.ctypes, "windll", SimpleNamespace(shell32=FakeShell32()), raising=False)

    privilege_adapter._launch_windows_worker(
        ["worker.exe"],
        tmp_path / "request file.json",
        tmp_path / "result file.json",
    )

    assert calls["verb"] == "runas"
    assert calls["executable"] == "worker.exe"
    assert "request file.json" in calls["params"]
    assert "result file.json" in calls["params"]
