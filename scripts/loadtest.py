#!/usr/bin/env python3
"""Bounded load driver for an already provisioned, isolated SOCKS test client.

Never provisions panel records, starts nodes, or changes running services.
"""
import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlsplit


def percentile(values, fraction):
    return sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)] if values else None


def validate(args):
    host, port = args.socks.rsplit(":", 1)
    if not ipaddress.ip_address(host).is_loopback or not 1 <= int(port) <= 65535:
        raise ValueError("SOCKS endpoint must be loopback")
    url = urlsplit(args.url)
    if url.scheme != "https" or url.username or url.password or not url.hostname:
        raise ValueError("use HTTPS without embedded credentials")
    address = ipaddress.ip_address(args.target_ip)
    if not address.is_private or address.is_unspecified or address.is_multicast:
        raise ValueError("target IP must belong to the isolated private test environment")
    if not 1 <= args.concurrency <= 8 or not 1 <= args.duration <= 300:
        raise ValueError("concurrency must be 1..8 and duration 1..300 seconds")
    if not 0 <= args.warmup <= 10 or not 1 <= args.timeout <= 30:
        raise ValueError("warmup must be 0..10 requests; timeout 1..30 seconds")
    if not 1 <= args.rate_kib <= 2048 or not 1 <= args.size <= 16 * 1024 * 1024:
        raise ValueError("rate must be 1..2048 KiB/s; size at most 16 MiB")
    if len(args.sha256) != 64 or any(c not in "0123456789abcdef" for c in args.sha256):
        raise ValueError("expected lowercase SHA-256 required")
    if args.node_pid is not None and args.node_pid <= 0:
        raise ValueError("node PID must be positive")
    if not Path(args.ca).is_file():
        raise ValueError("test CA certificate missing")


def process_sample(pid):
    # Linux /proc stat comm can contain spaces or parentheses.
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return {"cpu_seconds": (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK"),
            "rss_bytes": int(fields[21]) * os.sysconf("SC_PAGE_SIZE"),
            "start_ticks": int(fields[19])}


def run(args):
    stop = threading.Event()
    previous = {}
    for sig in (signal.SIGINT, signal.SIGTERM):
        previous[sig] = signal.signal(sig, lambda *_: stop.set())
    rows, samples = [], []
    started = time.monotonic()
    def request(directory, worker):
        payload = Path(directory) / f"payload-{worker}"
        url = urlsplit(args.url)
        address = f"[{args.target_ip}]" if ":" in args.target_ip else args.target_ip
        command = ["curl", "--disable", "--silent", "--show-error", "--fail",
                   "--noproxy", "", "--max-time", str(args.timeout),
                   "--max-filesize", str(args.size), "--limit-rate", f"{args.rate_kib}k",
                   "--socks5", args.socks, "--resolve", f"{url.hostname}:{url.port or 443}:{address}",
                   "--cacert", args.ca, args.url, "-o", str(payload),
                   "-w", "%{time_total} %{time_starttransfer}"]
        try:
            with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as child:
                while True:
                    try:
                        output, _ = child.communicate(timeout=0.1)
                        break
                    except subprocess.TimeoutExpired:
                        if stop.is_set():
                            child.kill()
                            child.communicate()
                            return {"ok": False, "cancelled": True}
                if child.returncode:
                    return {"ok": False, "curl_exit": child.returncode}
            total, first = map(float, output.split())
            data = payload.read_bytes()
            return {"ok": len(data) == args.size and hashlib.sha256(data).hexdigest() == args.sha256,
                    "seconds": total, "ttfb_seconds": first}
        finally:
            payload.unlink(missing_ok=True)

    error = None
    try:
        with tempfile.TemporaryDirectory(prefix="vless-load-") as directory:
            for _ in range(args.warmup):
                if stop.is_set() or not request(directory, "warmup")["ok"]:
                    raise RuntimeError("warmup failed or interrupted")
            started = time.monotonic()
            deadline = started + args.duration
            def worker(index):
                result = []
                while not stop.is_set() and time.monotonic() < deadline:
                    row = request(directory, index)
                    result.append(row)
                    if not row["ok"]:
                        stop.set()  # fail fast, do not continue loading an unhealthy target
                return result
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
                if args.node_pid:
                    samples.append(process_sample(args.node_pid))
                jobs = [pool.submit(worker, i) for i in range(args.concurrency)]
                while not all(job.done() for job in jobs):
                    time.sleep(0.2)
                    if args.node_pid:
                        try:
                            sample = process_sample(args.node_pid)
                            if sample["start_ticks"] != samples[0]["start_ticks"]:
                                raise RuntimeError("node process restarted")
                            samples.append(sample)
                        except (OSError, RuntimeError) as exc:
                            error = str(exc)
                            stop.set()
                for job in jobs:
                    rows.extend(job.result())
    except Exception as exc:
        error = type(exc).__name__  # avoid exposing URLs/credentials in exception text
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    elapsed = time.monotonic() - started
    good = [row for row in rows if row["ok"]]
    result = {"schema": 1, "label": args.label, "concurrency": args.concurrency,
              "configured_duration_seconds": args.duration, "elapsed_seconds": elapsed,
              "requests": len(rows), "successes": len(good), "error": error,
              "interrupted_or_failed": stop.is_set(), "samples": rows,
              "payload_mib_s": len(good) * args.size / max(elapsed, .001) / 1048576,
              "request_p50_seconds": percentile([r["seconds"] for r in good], .5),
              "request_p95_seconds": percentile([r["seconds"] for r in good], .95),
              "node_peak_rss_bytes": max((r["rss_bytes"] for r in samples), default=None),
              "node_cpu_percent_one_core": ((samples[-1]["cpu_seconds"] - samples[0]["cpu_seconds"]) / elapsed * 100) if len(samples) > 1 else None}
    Path(args.output).write_text(json.dumps(result, indent=2) + "\n")
    return 0 if rows and len(good) == len(rows) and not error and not stop.is_set() else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socks", default="127.0.0.1:25443")
    for flag in ("url", "target-ip", "ca", "sha256", "output", "label"):
        parser.add_argument("--" + flag, required=True)
    for flag, default in (("duration", 30), ("concurrency", 1), ("warmup", 2),
                          ("timeout", 15), ("rate-kib", 1024)):
        parser.add_argument("--" + flag, type=int, default=default)
    parser.add_argument("--size", type=int, required=True)
    parser.add_argument("--node-pid", type=int)
    args = parser.parse_args()
    try:
        validate(args)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
