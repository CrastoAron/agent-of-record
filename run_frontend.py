#!/usr/bin/env python3
"""Run the Vite frontend from the project root in a single command."""

from __future__ import annotations

import os
import signal
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
FRONTEND = os.path.join(ROOT, "frontend")


def main() -> int:
    env = os.environ.copy()
    env.setdefault("PATH", os.environ.get("PATH", "") + ":/usr/local/bin:/usr/bin")
    process = subprocess.Popen(["npm", "run", "dev", "--", "--host", "0.0.0.0"], cwd=FRONTEND, env=env)

    def _stop(_signum=None, _frame=None):
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
        raise SystemExit(0)

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    print("Starting AoR frontend...")
    print("Open: http://127.0.0.1:5173")
    try:
        process.wait()
    except KeyboardInterrupt:
        _stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
