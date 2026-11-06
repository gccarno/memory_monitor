"""Test fixture: a small tkinter window that exits on WM_CLOSE. With `--stubborn` it
ignores WM_CLOSE. Exits on its own after 120 s so a failed test leaks nothing."""
import sys
import tkinter as tk

root = tk.Tk()
root.title("memwatch test window")
root.geometry("260x60+40+40")
tk.Label(root, text="memwatch test fixture").pack(padx=10, pady=10)
if "--stubborn" in sys.argv:
    root.protocol("WM_DELETE_WINDOW", lambda: None)
root.after(120_000, root.destroy)
root.mainloop()
