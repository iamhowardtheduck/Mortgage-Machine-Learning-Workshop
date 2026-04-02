#!/usr/bin/env python3
"""
backfill_all.py — Run SDG and APM backfill in parallel, then optionally
                  hand off to real-time generators.

Overall daily target: 100,000–150,000 events (default midpoint 125,000)
  70% SDG  →  87,500 docs/day on weekdays
  30% APM  →  6,250 traces/day (~37,500 docs) on weekdays
  Weekend/US Federal Holiday: ≤30% of weekday volume for both

Diurnal pattern: 9 AM → 1 PM peak → 5 PM taper, zero overnight.
Business calendar: automatically detects and reduces volume on US Federal
holidays in the backfill window.

Usage:
    python backfill_all.py --host https://localhost:9200 \\
        --user elastic --password changeme --no-verify-ssl

    # Backfill then go straight to live:
    python backfill_all.py ... --then-run

    # 24-core recommended settings:
    python backfill_all.py ... \\
        --sdg-workers 10 --sdg-pb-threads 4 --sdg-bulk 2000 \\
        --apm-workers 8  --apm-pb-threads 4 --apm-bulk 500
"""

import argparse
import os
import subprocess
import sys
import time
import threading
import signal
from datetime import date, timedelta

_HERE  = os.path.dirname(os.path.abspath(__file__))
PYTHON = sys.executable

# Import calendar for the schedule preview
sys.path.insert(0, _HERE)
try:
    from business_calendar import (
        day_volume_factor, is_us_federal_holiday, is_business_day
    )
    _CAL = True
except ImportError:
    _CAL = False


def stream_output(proc, prefix, logfile):
    with open(logfile, "w") as lf:
        for line in proc.stdout:
            txt = line.rstrip()
            if txt:
                print(f"  [{prefix}] {txt}", flush=True)
                lf.write(txt + "\n")


def schedule_preview(days, sdg_weekday, apm_weekday):
    """Print a compact schedule showing volume per day in the backfill window."""
    today     = date.today()
    start_day = today - timedelta(days=days - 1)
    print(f"\n  {'Date':<12} {'Day':<4} {'Type':<9} {'SDG docs':>10} {'APM traces':>11} {'Total':>10}")
    print(f"  {'-'*60}")
    grand = 0
    for d in range(days):
        day    = start_day + timedelta(days=d)
        factor = day_volume_factor(day)
        sdg    = round(sdg_weekday * factor)
        apm    = round(apm_weekday * factor)
        apm_d  = apm * 6
        total  = sdg + apm_d
        grand += total
        dtype  = ("HOLIDAY" if is_us_federal_holiday(day)
                  else "weekend" if day.weekday() >= 5
                  else "workday")
        print(f"  {str(day):<12} {day.strftime('%a'):<4} {dtype:<9} {sdg:>10,} {apm:>11,} {total:>10,}")
    print(f"  {'-'*60}")
    print(f"  {'TOTAL':<27} {sum(round(sdg_weekday*day_volume_factor(start_day+timedelta(days=d))) for d in range(days)):>10,} "
          f"{sum(round(apm_weekday*day_volume_factor(start_day+timedelta(days=d))) for d in range(days)):>11,} {grand:>10,}")


def run_backfill(host, user, password, verify_ssl,
                 days, sdg_target, apm_traces,
                 sdg_workers, apm_workers,
                 sdg_bulk, apm_bulk,
                 sdg_pb_threads, apm_pb_threads,
                 sdg_config, then_run,
                 bootstrap_script=None,
                 kibana_host=None,
                 job_files=None):

    sdg_script = os.path.join(_HERE, "backfill_sdg.py")
    apm_script = os.path.join(_HERE, "backfill_apm.py")
    run_script = os.path.join(_HERE, "run_workshop.py")

    for s in (sdg_script, apm_script):
        if not os.path.exists(s):
            print(f"ERROR: {s} not found"); sys.exit(1)

    common = ["--host", host, "--user", user, "--password", password] \
             + (["--no-verify-ssl"] if not verify_ssl else [])

    sdg_cmd = [PYTHON, sdg_script] + common + [
        "--days",         str(days),
        "--tpd",          str(sdg_target),
        "--workers",      str(sdg_workers),
        "--bulk-size",    str(sdg_bulk),
        "--pb-threads",   str(sdg_pb_threads),
        "--config",       sdg_config,
    ]
    apm_cmd = [PYTHON, apm_script] + common + [
        "--days",         str(days),
        "--tpd",          str(apm_traces),
        "--workers",      str(apm_workers),
        "--bulk-size",    str(apm_bulk),
        "--pb-threads",   str(apm_pb_threads),
    ]

    print(f"\n{'='*64}")
    print(f"  LendPath ML Workshop — Historical Backfill")
    print(f"{'='*64}")
    print(f"  Overall daily target:  100,000–150,000 events")
    print(f"  SDG (70% of budget):   {sdg_target:>10,} docs/day on weekdays")
    print(f"  APM (30% of budget):   {apm_traces:>10,} traces/day (~{apm_traces*6:,} docs)")
    print(f"  Weekend/holiday:       ≤30% of weekday volume")
    print(f"  Diurnal peak:          1 PM  (9 AM–5 PM window)")
    print(f"  Target:                {host}")

    if _CAL:
        schedule_preview(days, sdg_target, apm_traces)

    print(f"\n  Launching SDG and APM backfill in parallel…\n")

    procs = []; threads = []; start = time.time()

    for script, cmd, prefix, logname in [
        (sdg_script, sdg_cmd, "SDG", "backfill_sdg.log"),
        (apm_script, apm_cmd, "APM", "backfill_apm.log"),
    ]:
        logpath = os.path.join(_HERE, logname)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, cwd=_HERE)
        procs.append(proc)
        t = threading.Thread(target=stream_output,
                             args=(proc, prefix, logpath), daemon=True)
        t.start(); threads.append(t)
        print(f"  ✓ {prefix} started  (PID {proc.pid})  →  {logname}")

    print()

    def shutdown(signum=None, frame=None):
        print("\n\nInterrupted — stopping…")
        for proc in procs:
            try: proc.terminate()
            except: pass
        sys.exit(0)

    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    for proc in procs: proc.wait()
    for t in threads:  t.join(timeout=5)

    elapsed = time.time() - start
    h, rem  = divmod(int(elapsed), 3600)
    m, s    = divmod(rem, 60)

    print(f"\n{'='*64}")
    print(f"  Both backfills complete.  Elapsed: {h:02d}h{m:02d}m{s:02d}s")
    print(f"  SDG exit: {procs[0].returncode}   APM exit: {procs[1].returncode}")

    if procs[0].returncode != 0 or procs[1].returncode != 0:
        print("  ⚠ One or more processes had errors.")
        print("    Review backfill_sdg.log and backfill_apm.log.")
    else:
        print(f"  ✓ {days} days of historical data indexed successfully.")
    print(f"{'='*64}\n")

    # ── Post-backfill sequence ────────────────────────────────────────────────
    # Resolve bootstrap script
    bs = bootstrap_script
    if bs is None:
        for _bname in ["bootstrap-MLv2-WORKSHOP.py", "bootstrap.py"]:
            _bp = os.path.join(_HERE, _bname)
            if os.path.exists(_bp):
                bs = _bp
                break

    bs_common = ["--host", host, "--user", user, "--password", password] \
                + (["--no-verify-ssl"] if not verify_ssl else []) \
                + (["--kibana-host", kibana_host] if kibana_host else []) \
                + (["--skip-kibana"] if not kibana_host else [])

    if job_files:
        for jf in job_files:
            bs_common += ["--job-files"] if bs_common[-1] != "--job-files" else []
        bs_common += ["--job-files"] + job_files

    # ── Step A: Start AD datafeeds ───────────────────────────────────────────
    if bs and os.path.exists(bs):
        print(f"\n{'='*68}")
        print(f"  Post-Backfill Automation")
        print(f"{'='*68}")
        print(f"  Bootstrap: {os.path.basename(bs)}")
        print()

        print("▸ Step 1/3 — Starting AD datafeeds…")
        try:
            result = subprocess.run(
                [PYTHON, bs] + bs_common + ["--start-datafeeds", "--skip-kibana"],
                cwd=_HERE
            )
            if result.returncode == 0:
                print("  ✓ AD datafeeds started")
            else:
                print(f"  ⚠ AD datafeed start returned exit code {result.returncode}")
        except Exception as e:
            print(f"  ⚠ Could not start AD datafeeds: {e}")

        # ── Step B: Create and start DFA jobs ─────────────────────────────────
        print()
        print("▸ Step 2/3 — Creating and starting DFA jobs…")
        try:
            result = subprocess.run(
                [PYTHON, bs] + bs_common + ["--create-dfa", "--run-dfa", "--skip-kibana"],
                cwd=_HERE
            )
            if result.returncode == 0:
                print("  ✓ DFA jobs created and started")
            else:
                print(f"  ⚠ DFA job creation returned exit code {result.returncode}")
        except Exception as e:
            print(f"  ⚠ Could not create DFA jobs: {e}")

        print(f"\n{'='*68}\n")
    else:
        print(f"\n  ⚠ bootstrap script not found — skipping AD/DFA automation.")
        print(f"    Run manually:")
        print(f"      python bootstrap.py --start-datafeeds ...")
        print(f"      python bootstrap.py --create-dfa --run-dfa ...")
        print()

    # ── Step C: Start live generators ────────────────────────────────────────
    if then_run:
        if not os.path.exists(run_script):
            print(f"WARNING: run_workshop.py not found.")
            return
        run_common = ["--host", host, "--user", user, "--password", password] \
                     + (["--no-verify-ssl"] if not verify_ssl else [])
        pass  # sdg_script_path not used in original backfill_all
        print("▸ Step 3/3 — Starting live generators (continuing from present)…")
        try:
            subprocess.run([PYTHON, run_script] + run_common, cwd=_HERE)
        except KeyboardInterrupt:
            print("\nStopped.")
    else:
        run_common = f"--host {host} --user {user} --password {password}" \
                     + (" --no-verify-ssl" if not verify_ssl else "")
        print(f"  Next:  python run_workshop.py {run_common}\n")



def _load_workshop_config():
    """Load connection config saved by bootstrap.py."""
    for search in [
        os.path.dirname(os.path.realpath(os.path.abspath(__file__))),
        os.getcwd(),
    ]:
        p = os.path.join(search, "workshop-config.json")
        if os.path.exists(p):
            try:
                import json as _json
                cfg = _json.load(open(p))
                print(f"  ✓ Loaded config: {p}")
                return cfg
            except Exception:
                pass
    return {}


def main():
    p = argparse.ArgumentParser(
        description="LendPath historical backfill — 100-150k events/day with US business calendar",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Volume split:
  70% SDG  →  87,500 docs/day weekdays,  ≤26,250 weekends/holidays
  30% APM  →   6,250 traces/day weekdays, ≤1,875  weekends/holidays
  ~Total   →  125,000 events/day weekdays, ~37,500 weekends/holidays

24-core recommended:
  python backfill_all.py --host https://localhost:9200 \\
      --user elastic --password changeme --no-verify-ssl \\
      --sdg-workers 10 --sdg-pb-threads 4 --sdg-bulk 2000 \\
      --apm-workers 8  --apm-pb-threads 4 --apm-bulk 500 \\
      --then-run

Quick test (1 day):
  python backfill_all.py ... --days 1 --sdg-target 5000 --apm-traces 850
        """
    )
    p.add_argument("--host",     default="https://localhost:9200")
    p.add_argument("--user",     default="elastic")
    p.add_argument("--password", default="changeme")
    p.add_argument("--no-verify-ssl", action="store_true")
    p.add_argument("--days",          type=int, default=30)
    p.add_argument("--sdg-target",    type=int, default=3_500_000,
                   help="Weekday SDG docs/day — 70%% of budget (default: 3,500,000)")
    p.add_argument("--apm-traces",    type=int, default=250_000,
                   help="Weekday APM traces/day — 30%% of budget (default: 250,000 → ~1,500,000 docs)")
    p.add_argument("--sdg-workers",   type=int, default=10)
    p.add_argument("--apm-workers",   type=int, default=8)
    p.add_argument("--sdg-bulk",      type=int, default=2000)
    p.add_argument("--apm-bulk",      type=int, default=500)
    p.add_argument("--sdg-pb-threads",type=int, default=4)
    p.add_argument("--apm-pb-threads",type=int, default=4)
    p.add_argument("--sdg-config",    default="mortgage-workshop.yml")
    p.add_argument("--bootstrap-script", default=None, metavar="PATH",
                   help="Path to bootstrap.py to run after backfill. "
                        "Auto-detected if not set.")
    p.add_argument("--kibana-host",    default=None, metavar="URL",
                   help="Kibana URL for bootstrap post-backfill steps.")
    p.add_argument("--job-files",      nargs="+", default=None, metavar="FILE",
                   help="ML job definition files passed to bootstrap.")
    p.add_argument("--then-run",       action="store_true",
                   help="After backfill completes, start run_workshop.py automatically")
    # Load previously saved bootstrap config and use as defaults for
    # any arg the user didn't explicitly pass on the command line.
    _cfg = _load_workshop_config()
    if _cfg:
        # argparse doesn't support post-parse defaults elegantly, so we
        # patch the namespace directly for args left at their default values.
        _defaults = {
            "host":           "https://localhost:9200",
            "user":           "elastic",
            "password":       "changeme",
            "kibana_host":    None,
            "no_verify_ssl":  False,
            "timezone":       None,
            "job_files":      None,
        }
        # Parse first so explicit CLI args take priority
        args = p.parse_args()
        # Then back-fill from config only where the user left the default
        if args.host          == _defaults["host"]         and _cfg.get("host"):
            args.host          = _cfg["host"]
        if args.user          == _defaults["user"]         and _cfg.get("user"):
            args.user          = _cfg["user"]
        if args.password      == _defaults["password"]     and _cfg.get("password"):
            args.password      = _cfg["password"]
        if not args.no_verify_ssl and _cfg.get("no_verify_ssl"):
            args.no_verify_ssl = _cfg["no_verify_ssl"]
        if not getattr(args, "kibana_host", None) and _cfg.get("kibana_host"):
            args.kibana_host   = _cfg["kibana_host"]
        if not getattr(args, "timezone", None) and _cfg.get("timezone"):
            args.timezone      = _cfg["timezone"]
        if not getattr(args, "job_files", None) and _cfg.get("job_files"):
            args.job_files     = _cfg["job_files"]
    else:
        args = p.parse_args()
        if not _cfg:
            print("  ℹ  No workshop-config.json found — using CLI args only.")
            print("     Run bootstrap.py first to save connection settings.")
            print()


    run_backfill(
        host=args.host, user=args.user, password=args.password,
        verify_ssl=not args.no_verify_ssl,
        days=args.days, sdg_target=args.sdg_target, apm_traces=args.apm_traces,
        sdg_workers=args.sdg_workers, apm_workers=args.apm_workers,
        sdg_bulk=args.sdg_bulk, apm_bulk=args.apm_bulk,
        sdg_pb_threads=args.sdg_pb_threads, apm_pb_threads=args.apm_pb_threads,
        sdg_config=args.sdg_config, then_run=args.then_run,
        bootstrap_script=args.bootstrap_script,
        kibana_host=args.kibana_host,
        job_files=args.job_files,
    )

if __name__ == "__main__": main()
