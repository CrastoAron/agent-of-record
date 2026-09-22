#!/usr/bin/env python3
"""Run all backend services for the AoR demo in one command."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _uvicorn_cmd(app_module: str, port: int) -> list[str]:
    return [
        sys.executable,
        "-m",
        "uvicorn",
        app_module,
        "--host",
        "0.0.0.0",
        "--port",
        str(port),
    ]


def main() -> int:
    env = os.environ.copy()
    env.setdefault("PYTHONPATH", str(ROOT))

    processes = [
        subprocess.Popen(_uvicorn_cmd("verifier_service.main:app", 8000), cwd=str(ROOT), env=env),
    ]

    def _stop_all(signum: int | None = None, frame=None) -> None:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
        raise SystemExit(0)

    signal.signal(signal.SIGINT, _stop_all)
    signal.signal(signal.SIGTERM, _stop_all)

    print("Starting unified AoR backend...")
    print("- verifier, artifact executor, and verification portal: http://127.0.0.1:8000")
    print("Press Ctrl+C to stop")

    try:
        processes[0].wait()
        if processes[0].returncode:
            print(f"Backend exited unexpectedly with code {processes[0].returncode}")
    except KeyboardInterrupt:
        _stop_all()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
