#!/usr/bin/env python3
"""Hunt3r Celery Worker — entry point for distributed scan workers (v1.1-OVERLORD).

Each container / process running this file becomes a worker that:
  1. Connects to Redis (REDIS_URL env)
  2. Pulls targets from the hunt3r.scan queue
  3. Executes the full Hunt3r pipeline (subfinder → dnsx → httpx → katana →
     js_hunter → nuclei → FP filter → AI → notify → report)
  4. Stores the result dict in Redis for the watchdog to collect

Scaling:
  docker compose up --scale worker=4      # 4 parallel workers
  python worker.py --concurrency=1        # single process (recommended per container)
  python worker.py --hostname=w1@%h       # named worker

Prerequisites:
  - Redis reachable at REDIS_URL (default: redis://localhost:6379/0)
  - Go binaries (subfinder, dnsx, httpx, nuclei, …) on PATH
  - Python dependencies: pip install celery[redis]
  - Shared volume at ./recon (read/write, same path on all workers)
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

# ── Project root must be importable before any Hunt3r import ──────────────────
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# ── Go binary paths (before importing recon modules that call find_tool) ──────
_HOME = os.path.expanduser("~")
os.environ["PATH"] = (
    os.environ.get("PATH", "")
    + os.pathsep + os.path.join(_HOME, "go", "bin")
    + os.pathsep + "/usr/local/bin"
    + os.pathsep + "/usr/local/go/bin"
)

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)-8s %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Import after PATH is patched so tool_discovery finds Go binaries correctly.
from core.celery_app import app, TASK_QUEUE  # noqa: E402


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Hunt3r distributed scan worker",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=1,
        help="Parallel task slots. Keep at 1 — each scan is CPU/IO heavy.",
    )
    parser.add_argument(
        "--loglevel",
        default="info",
        choices=["debug", "info", "warning", "error"],
        help="Celery log level.",
    )
    parser.add_argument(
        "--hostname",
        default=None,
        help="Worker hostname (e.g. worker1@%%h). Auto-generated if omitted.",
    )
    parser.add_argument(
        "--queue",
        default=TASK_QUEUE,
        help="Queue to consume from.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    argv = [
        "worker",
        f"--queues={args.queue}",
        f"--concurrency={args.concurrency}",
        f"--loglevel={args.loglevel}",
        # One task at a time — no over-fetching (scans can run for hours).
        "--prefetch-multiplier=1",
    ]
    if args.hostname:
        argv.append(f"--hostname={args.hostname}")

    logging.info(
        "Hunt3r worker starting | queue=%s concurrency=%d broker=%s",
        args.queue,
        args.concurrency,
        os.getenv("REDIS_URL", "redis://localhost:6379/0"),
    )
    app.worker_main(argv=argv)


if __name__ == "__main__":
    main()
