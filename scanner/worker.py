"""Standalone scanner worker entry point. Runs polling loop against the DB."""
import os
import sys

# Ensure the backend package is on the path when running inside docker
sys.path.insert(0, "/app/backend")

from scanner_engine import poll_and_run_forever  # noqa: E402

if __name__ == "__main__":
    interval = float(os.environ.get("SCANNER_POLL_INTERVAL", "2"))
    poll_and_run_forever(interval)
