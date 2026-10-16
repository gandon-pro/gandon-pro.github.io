"""Gandon-PRO Python plugin: restore the legacy code font."""

import sys


def query_font() -> str:
    return "ANSI_FIXED_FONT"


if __name__ == "__main__":
    if "--query-font" in sys.argv:
        print(f"font={query_font()}")
    elif "--gandon-load" in sys.argv:
        print(f"font={query_font()}")
        print("Legacy ANSI_FIXED_FONT plugin loaded")
