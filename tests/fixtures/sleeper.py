"""Test fixture: a windowless process that sleeps. `--child PATH` also spawns one child
sleeper and writes its pid to PATH. Exits on its own after 120 s so a failed test
leaks nothing. Other arguments are ignored."""
import subprocess
import sys
import time

if "--child" in sys.argv:
    path = sys.argv[sys.argv.index("--child") + 1]
    child = subprocess.Popen([sys.executable, __file__])
    with open(path, "w") as f:
        f.write(str(child.pid))
time.sleep(120)
