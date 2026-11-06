"""Test fixture: a windowless process that sleeps. `--child` also spawns one child
sleeper and prints its pid. Exits on its own after 120 s so a failed test leaks nothing."""
import subprocess
import sys
import time

if "--child" in sys.argv:
    child = subprocess.Popen([sys.executable, __file__])
    print(child.pid, flush=True)
time.sleep(120)
