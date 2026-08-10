"""PyInstaller-compatible launcher for the AegisScan macOS app."""

import sys

from src.gui import main


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        from src.full_scan import run_full_scan  # noqa: F401
        from src.models import ReviewIssue, ReviewReport  # noqa: F401

        raise SystemExit(0)
    main()
