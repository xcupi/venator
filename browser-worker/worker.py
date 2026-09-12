"""Standalone browser validation worker entry point."""
import os
import sys

sys.path.insert(0, "/app/backend")

from browser_validator import poll_forever  # noqa: E402

if __name__ == "__main__":
    interval = float(os.environ.get("BROWSER_POLL_INTERVAL", "3"))
    poll_forever(interval)
