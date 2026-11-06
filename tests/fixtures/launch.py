"""Test fixture: start `sys.executable argv[1:]`, print its pid and exit at once, so the
started process is not a descendant of the test process (memwatch guards its own
descendants)."""
import subprocess
import sys

p = subprocess.Popen([sys.executable, *sys.argv[1:]], stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(p.pid, flush=True)
