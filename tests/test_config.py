import os
from pathlib import Path

from memwatch.config import load_config


def test_defaults():
    c = load_config(Path("nonexistent.toml"))
    assert c.sample_interval_s == 60 and c.retention_days == 30 and c.logger_cap_mb == 50
    assert "csrss.exe" in c.protected_names and "msmpeng.exe" in c.protected_names
    assert "spoolsv.exe" not in c.protected_names
    assert c.data_dir == Path(os.environ["LOCALAPPDATA"]) / "memwatch"


def test_toml_overrides_scalars_and_extends_sets(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text('idle_days = 5\nprotected_names = ["myagent.exe"]\n[notes]\n"suite:foo" = "Foo note"\n')
    c = load_config(p)
    assert c.idle_days == 5
    assert "myagent.exe" in c.protected_names and "csrss.exe" in c.protected_names
    assert c.notes["suite:foo"] == "Foo note" and "service:wsearch" in c.notes
