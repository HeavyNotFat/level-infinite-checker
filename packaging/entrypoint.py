"""Entry point for the single-file VirusChecker build.

Without --cli the Tkinter GUI starts and the console window is hidden.
With --cli the same executable behaves exactly like vcheck.py, which lets the
GUI run scans as a separate process (so Stop can terminate the whole tree).
"""
from __future__ import annotations

import ctypes
import os
import sys


def _hide_console() -> None:
    if os.name != "nt":
        return
    try:
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)
    except Exception:
        pass


def main() -> int:
    if "--cli" in sys.argv:
        argv = [arg for arg in sys.argv[1:] if arg != "--cli"]
        from vcheck import main as cli_main
        return int(cli_main(argv))
    _hide_console()
    from vcheck_gui import main as gui_main
    return int(gui_main())


if __name__ == "__main__":
    raise SystemExit(main())
