from __future__ import annotations

from conftest import mkproc, svc
from memwatch.grouping import group_processes, suite_from_path


def test_chrome_children_one_suite(cfg):
    procs = [mkproc(1, 999, "explorer.exe", r"C:\Windows\explorer.exe"),
             mkproc(10, 1, "chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
             mkproc(11, 10, "chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe")]
    g = group_processes(procs, {}, cfg)
    assert g["suite:google chrome"].pids == [(10, 1.0), (11, 1.0)]
    assert g["protected:windows"].kind == "protected"


def test_each_claude_session_separate(cfg):
    exe = r"C:\Users\u\.local\bin\claude.exe"
    procs = [mkproc(20, 5, "claude.exe", exe), mkproc(21, 5, "claude.exe", exe), mkproc(22, 20, "node.exe", None)]
    keys = {k for k in group_processes(procs, {}, cfg) if k.startswith("claude-cli:")}
    assert keys == {"claude-cli:20:1", "claude-cli:21:1"}
    assert (22, 1.0) in group_processes(procs, {}, cfg)["claude-cli:20:1"].pids


def test_claude_label_with_cwd(cfg):
    exe = r"C:\Users\u\.local\bin\claude.exe"
    g = group_processes([mkproc(20, 5, "claude.exe", exe, cwd=r"C:\proj")], {}, cfg)
    label = g["claude-cli:20:1"].label
    assert label.startswith("Claude Code session (started ") and label.endswith(") \u2014 C:\\proj")


def test_python_and_emulator_labels(cfg):
    procs = [mkproc(30, 5, "python.exe", r"C:\Py\python.exe", ["python", "train_lgbm.py"]),
             mkproc(31, 5, "qemu-system-x86_64.exe", r"C:\x\qemu-system-x86_64.exe", ["q", "-avd", "Medium_Phone_API_36.1"]),
             mkproc(32, 5, "python.exe", r"C:\Py\python.exe", ["python", "-m", "http.server"]),
             mkproc(33, 5, "pythonw.exe", r"C:\Py\pythonw.exe", ["pythonw"])]
    g = group_processes(procs, {}, cfg)
    assert g["python:30:1"].label == "Python: train_lgbm.py"
    assert g["emulator:31:1"].label == "Android emulator (Medium_Phone_API_36.1)"
    assert g["python:32:1"].label == "Python: -m http.server"
    assert g["python:33:1"].label == "Python: interpreter"


def test_vendor_service_joins_vendor_suite(cfg):
    procs = [mkproc(40, 3, "ss_conn_service.exe", r"C:\Program Files (x86)\Samsung\USB Drivers\ss_conn_service.exe"),
             mkproc(41, 1, "SamsungApp.exe", r"C:\Program Files\Samsung\App\SamsungApp.exe")]
    g = group_processes(procs, {40: [svc("ss_conn_service")]}, cfg)["suite:samsung"]
    assert {p for p, _ in g.pids} == {40, 41} and g.services == ["ss_conn_service"]


def test_svchost_core_protected_optional_not(cfg):
    procs = [mkproc(50, 3, "svchost.exe", r"C:\Windows\System32\svchost.exe"),
             mkproc(51, 3, "svchost.exe", r"C:\Windows\System32\svchost.exe")]
    g = group_processes(procs, {50: [svc("RpcSs")], 51: [svc("WSearch")]}, cfg)
    assert (50, 1.0) in g["protected:windows"].pids
    assert g["service:wsearch"].microsoft and g["service:wsearch"].kind == "windows"


def test_svchost_multiple_services_sorted_key(cfg):
    procs = [mkproc(50, 3, "svchost.exe", r"C:\Windows\System32\svchost.exe")]
    g = group_processes(procs, {50: [svc("WSearch", display_name="Windows Search"),
                                     svc("Fax", display_name="Fax")]}, cfg)
    assert g["service:fax+wsearch"].services == ["Fax", "WSearch"]


def test_shell_children_do_not_inherit(cfg):
    procs = [mkproc(60, 1, "WindowsTerminal.exe", r"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.2_x64__8w\WindowsTerminal.exe"),
             mkproc(61, 60, "steam.exe", r"C:\Program Files (x86)\Steam\steam.exe")]
    assert "suite:steam" in group_processes(procs, {}, cfg)


def test_suite_from_path_rules(cfg):
    assert suite_from_path(r"C:\Users\u\AppData\Local\Programs\Foo\foo.exe", "foo.exe", cfg)[:2] == ("suite:foo", "Foo")
    assert suite_from_path(r"C:\Users\u\AppData\Local\Bar\bar.exe", "bar.exe", cfg)[:2] == ("suite:bar", "Bar")
    assert suite_from_path(r"C:\Users\u\AppData\Roaming\Baz\baz.exe", "baz.exe", cfg)[:2] == ("suite:baz", "Baz")
    assert suite_from_path(r"C:\Program Files\Microsoft OneDrive\OneDrive.exe", "OneDrive.exe", cfg) == (
        "suite:microsoft onedrive", "Microsoft OneDrive", True)
    assert suite_from_path(r"C:\Users\u\AppData\Local\Microsoft\OneDrive\OneDrive.exe", "OneDrive.exe", cfg) == (
        "suite:microsoft onedrive", "Microsoft OneDrive", True)
    assert suite_from_path(r"C:\Windows\System32\foo.exe", "Foo.exe", cfg) == ("windows:foo.exe", "Foo.exe", True)
    assert suite_from_path(None, "Mystery.exe", cfg) == ("suite:mystery", "Mystery", False)
    assert suite_from_path(r"C:\Program Files\WindowsApps\Microsoft.YourPhone_1.0_x64__8w\a.exe", "a.exe", cfg) == (
        "suite:microsoft.yourphone", "Microsoft.YourPhone", True)


def test_totals_and_limited(cfg):
    procs = [mkproc(10, 1, "chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe", private_bytes=100, working_set=50),
             mkproc(11, 10, "chrome.exe", None, private_bytes=200, working_set=70, limited=True)]
    g = group_processes(procs, {}, cfg)["suite:google chrome"]
    assert (g.private_bytes, g.working_set, g.limited) == (300, 120, True)
