#!/usr/bin/env python3
"""
run_workshop.py — Launches both the SDG and APM trace generator together.

Runs sdg-prime.py and apm_trace_generator.py as child processes with a
shared stop signal (Ctrl+C). Both processes write to the same Elasticsearch
cluster. Status is printed every 10 seconds.

Usage:
    python run_workshop.py \\
        --host https://localhost:9200 \\
        --user elastic --password changeme \\
        --no-verify-ssl \\
        [--sdg-config mortgage-workshop.yml] \\
        [--apm-rate 2] \\
        [--purge-apm]     # wipe stale SDG traces before starting
"""

import argparse
import os
import subprocess
import sys
import tempfile
import time
import signal
import yaml


def tail_log(path, n=5):
    """Return the last n non-empty lines of a log file."""
    try:
        with open(path) as f:
            lines = [l.rstrip() for l in f.readlines() if l.strip()]
        return lines[-n:] if lines else []
    except Exception:
        return []


def _patch_sdg_config(sdg_config, host, user, password, verify_ssl, script_dir):
    """
    Write a temporary copy of the SDG YAML with connection settings overridden
    by the values passed on the command line.  Returns the path to the temp file.
    The caller is responsible for deleting it.
    """
    config_path = os.path.join(script_dir, sdg_config)         if not os.path.isabs(sdg_config) else sdg_config

    with open(config_path) as fh:
        cfg = yaml.safe_load(fh)

    # Parse scheme, host, port out of the --host URL
    # Accepts:  https://hostname:port  or  http://hostname  or  hostname
    import re
    m = re.match(r"(?:(https?)://)?([^:/]+)(?::(\d+))?", host)
    scheme = m.group(1) or "https"
    hostname = m.group(2)
    port = int(m.group(3)) if m.group(3) else (9200)

    cfg["elasticsearchScheme"]   = scheme
    cfg["elasticsearchHost"]     = hostname
    cfg["elasticsearchPort"]     = port
    cfg["elasticsearchUser"]     = user
    cfg["elasticsearchPassword"] = password
    cfg["verifyCerts"]           = verify_ssl

    # Write to a named temp file in the same directory so relative paths inside
    # the YAML (e.g. field value files) still resolve correctly
    fd, tmp_path = tempfile.mkstemp(
        suffix=".yml", prefix=".sdg_patched_", dir=script_dir
    )
    with os.fdopen(fd, "w") as fh:
        yaml.dump(cfg, fh, default_flow_style=False, allow_unicode=True)

    return tmp_path


def run(host, user, password, verify_ssl, sdg_config, apm_rate, purge_apm=False):
    script_dir = os.path.dirname(os.path.abspath(__file__))

    sdg_script   = os.path.join(script_dir, "sdg-prime.py")
    apm_script   = os.path.join(script_dir, "apm_trace_generator.py")
    sdg_log_path = os.path.join(script_dir, "sdg.log")
    apm_log_path = os.path.join(script_dir, "apm.log")

    for script in (sdg_script, apm_script):
        if not os.path.exists(script):
            print(f"ERROR: {script} not found in {script_dir}")
            sys.exit(1)

    python = sys.executable

    # ── Patch SDG YAML with CLI connection settings ───────────────────────────
    # The SDG reads connection settings from its YAML config, not from argv.
    # We write a temporary patched copy so the user only has to specify
    # credentials once (on the run_workshop.py command line).
    tmp_config = _patch_sdg_config(
        sdg_config, host, user, password, verify_ssl, script_dir
    )

    # ── Build argument lists ──────────────────────────────────────────────────
    sdg_cmd = [python, sdg_script, tmp_config]

    apm_cmd = [
        python, apm_script,
        "--host",     host,
        "--user",     user,
        "--password", password,
        "--rate",     str(apm_rate),
    ]
    if not verify_ssl:
        apm_cmd.append("--no-verify-ssl")
    if purge_apm:
        apm_cmd.append("--purge")

    # ── Launch ────────────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  LendPath ML Workshop — Data Generators")
    print("=" * 60)
    print(f"\n  SDG config:  {sdg_config}  (patched with CLI credentials)")
    print(f"  APM rate:    {apm_rate} trace(s)/sec")
    print(f"  Purge APM:   {'yes — stale traces will be deleted first' if purge_apm else 'no'}")
    print(f"  Target:      {host}")
    print(f"\n  SDG log:     {sdg_log_path}")
    print(f"  APM log:     {apm_log_path}")
    print("\n  Press Ctrl+C to stop both generators.\n")

    sdg_log  = open(sdg_log_path,  "w")
    apm_log  = open(apm_log_path,  "w")

    sdg_proc = subprocess.Popen(
        sdg_cmd,
        stdout=sdg_log, stderr=subprocess.STDOUT,
        cwd=script_dir,
    )
    apm_proc = subprocess.Popen(
        apm_cmd,
        stdout=apm_log, stderr=subprocess.STDOUT,
        cwd=script_dir,
    )

    print(f"  ✓ SDG started         (PID {sdg_proc.pid})")
    print(f"  ✓ APM trace generator (PID {apm_proc.pid})")
    print()

    def shutdown(signum=None, frame=None):
        print("\n\nShutting down…")
        for proc in (sdg_proc, apm_proc):
            try:
                proc.terminate()
            except Exception:
                pass
        for proc in (sdg_proc, apm_proc):
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
        sdg_log.close()
        apm_log.close()
        # Remove the temporary patched YAML config
        try:
            os.unlink(tmp_config)
        except Exception:
            pass
        print("Both generators stopped.")
        print(f"\nFull logs saved to:\n  {sdg_log_path}\n  {apm_log_path}\n")
        sys.exit(0)

    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # ── Status loop ───────────────────────────────────────────────────────────
    tick = 0
    while True:
        time.sleep(10)
        tick += 1

        # Check processes are still alive
        sdg_alive = sdg_proc.poll() is None
        apm_alive = apm_proc.poll() is None

        print(f"[{tick * 10:>4}s]  SDG: {'running' if sdg_alive else 'STOPPED'}  |  "
              f"APM: {'running' if apm_alive else 'STOPPED'}")

        # Print last APM line so you can see trace counts
        apm_lines = tail_log(apm_log_path, 2)
        for line in apm_lines:
            if "traces" in line.lower() or "error" in line.lower():
                print(f"        APM: {line}")

        # Restart a crashed process
        if not sdg_alive:
            print("  ⚠ SDG exited — restarting…")
            sdg_log.close()
            sdg_log = open(sdg_log_path, "a")
            sdg_proc = subprocess.Popen(
                sdg_cmd, stdout=sdg_log, stderr=subprocess.STDOUT, cwd=script_dir
            )
            print(f"  ✓ SDG restarted (PID {sdg_proc.pid})")

        if not apm_alive:
            print("  ⚠ APM trace generator exited — restarting…")
            apm_log.close()
            apm_log = open(apm_log_path, "a")
            apm_proc = subprocess.Popen(
                apm_cmd, stdout=apm_log, stderr=subprocess.STDOUT, cwd=script_dir
            )
            print(f"  ✓ APM trace generator restarted (PID {apm_proc.pid})")


def main():
    p = argparse.ArgumentParser(
        description="Run SDG and APM trace generator together for the LendPath workshop"
    )
    p.add_argument("--host",       default="https://localhost:9200")
    p.add_argument("--user",       default="elastic")
    p.add_argument("--password",   default="changeme")
    p.add_argument("--no-verify-ssl", action="store_true")
    p.add_argument("--sdg-config", default="mortgage-workshop.yml",
                   help="SDG YAML config file (default: mortgage-workshop.yml)")
    p.add_argument("--apm-rate",   type=float, default=2.0,
                   help="APM traces per second (default: 2)")
    p.add_argument("--purge-apm",  action="store_true",
                   help="Delete traces-apm-mortgage before starting to clear "
                        "stale SDG-generated unlinked traces. Use this on first "
                        "run if the service map shows disconnected services.")
    args = p.parse_args()

    run(
        host       = args.host,
        user       = args.user,
        password   = args.password,
        verify_ssl = not args.no_verify_ssl,
        sdg_config = args.sdg_config,
        apm_rate   = args.apm_rate,
        purge_apm  = args.purge_apm,
    )


if __name__ == "__main__":
    main()
