#!/usr/bin/env python3
"""
sdg-prime-outlier.py
━━━━━━━━━━━━━━━━━━━━
Focused synthetic data generator for the Elastic ML Outlier Detection Workshop.
Generates ONLY the data stream needed for:

  • mortgage-spans-outlier-detection
      → traces-apm-default

Data is produced by the same apm_trace_generator module used in the full
workshop, so the APM Service Map, Trace Waterfall, and all APM UI views
work correctly alongside the ML jobs.

Key controls
────────────
  --days             Historical window in days            (default: 30)
  --traces-per-day   Max APM traces per day (weekdays)    (default: 500)
  --anomaly-chance   Fraction of traces with anomalous geo (default: 0.03)
  --timezone         Local timezone for diurnal pattern   (auto-detected)
  --backfill         Stop after backfill, do not start live generation
  --live-only        Skip backfill entirely, start live generation immediately

What counts as an "outlier" in this data
─────────────────────────────────────────
The outlier detection DFA job scores transactions on these features:

  labels.loan_amount          — uniform 75k–2.5M  (normal range)
  labels.session_duration_sec — uniform 30–7200s
  labels.pages_visited        — uniform 1–80
  labels.docs_downloaded      — uniform 0–25
  labels.failed_auth_attempts — uniform 0–3
  transaction.duration.us     — varies by service + span topology
  http.response.status_code   — weighted toward 200/201

When --anomaly-chance is raised (e.g. 0.30), a fraction of traces are
generated from anomalous geo locations (Lagos, Moscow, Beijing, etc.)
which produces clusters the outlier model can separate from normal
home-city traffic.  The label features remain the same range — the
geographic signal is the primary outlier driver in this stream.

Live generation
───────────────
After the historical backfill completes, the generator transitions to
live mode, generating traces at a natural per-second rate that respects
the diurnal pattern and today's remaining quota.

Example: --traces-per-day 1000, today backfill wrote 257 traces →
live mode generates 743 more traces spread across the remaining hours.

Usage
─────
  python sdg-prime-outlier.py \\
      --host https://localhost:9200 \\
      --user elastic --password changeme \\
      --no-verify-ssl

  # Custom parameters:
  python sdg-prime-outlier.py ... \\
      --days 60 --traces-per-day 1000 --anomaly-chance 0.15

  # Backfill only:
  python sdg-prime-outlier.py ... --backfill

  # List timezones:
  python sdg-prime-outlier.py --list-timezones
"""

import argparse
import json
import os
import random
import sys
import time
import threading
from datetime import datetime, timedelta, timezone, date
from queue import Queue, Empty

_HERE = os.path.dirname(os.path.realpath(os.path.abspath(__file__)))
sys.path.insert(0, _HERE)

# ── Optional business calendar ─────────────────────────────────────────────────
try:
    from business_calendar import is_us_federal_holiday, is_business_day
    _HAS_CAL = True
except ImportError:
    _HAS_CAL = False

# ── APM trace generator — imported for generate_trace / generate_metrics ──────
# We import the module's internals rather than calling run() so we can inject
# historical timestamps during backfill.  The module calls sys.exit() if
# elasticsearch-py is missing, so that check is shared.
try:
    import apm_trace_generator as _apm
    from elasticsearch import Elasticsearch
    from elasticsearch.helpers import parallel_bulk
except ImportError as _e:
    if "apm_trace_generator" in str(_e):
        print(f"ERROR: apm_trace_generator.py not found in {_HERE}")
        print("  Ensure sdg-prime-outlier.py is in the same directory.")
    else:
        print(f"ERROR: elasticsearch-py not installed.  Run: pip install elasticsearch")
    sys.exit(1)

import multiprocessing as _mp

# ── Constants ──────────────────────────────────────────────────────────────────

DEFAULT_DAYS        = 30
DEFAULT_TPD         = 500       # traces per weekday
DEFAULT_ANOMALY     = 0.03      # fraction of traces with anomalous geo

_CPU_CORES         = _mp.cpu_count() or 4
DEFAULT_WORKERS    = min(_CPU_CORES * 2, 32)
DEFAULT_PB_THREADS = min(4, max(2, _CPU_CORES // 4))
DEFAULT_BULK_SIZE  = 200        # traces produce multiple docs each; keep batches modest
DEFAULT_PB_QUEUE   = 4

# Diurnal weights — business-hours peak (10:00–14:00), same as classification SDG
_WORKDAY_W = [
    0.00, 0.00, 0.00, 0.00, 0.00, 0.01,
    0.03, 0.15, 0.55, 0.80, 0.95, 1.00,
    0.98, 0.95, 0.85, 0.75, 0.60, 0.40,
    0.20, 0.08, 0.03, 0.01, 0.00, 0.00,
]
_WEEKEND_W = [
    0.00, 0.00, 0.00, 0.00, 0.00, 0.00,
    0.01, 0.02, 0.03, 0.04, 0.04, 0.04,
    0.04, 0.04, 0.03, 0.03, 0.02, 0.02,
    0.01, 0.01, 0.00, 0.00, 0.00, 0.00,
]

# Service names from the topology — used to pick the initiating service each trace
_SERVICE_NAMES   = list(_apm.SERVICES.keys())
_SERVICE_WEIGHTS = [40, 20, 15, 15, 10]   # weight lendpath-los as primary entry point
_METRICS_EVERY   = 30                     # emit JVM metrics every N traces


# ── Timezone helpers ───────────────────────────────────────────────────────────

def _local_tz():
    try:
        import tzlocal
        return tzlocal.get_localzone()
    except Exception:
        import time as _t
        offset = -_t.timezone if not _t.daylight else -_t.altzone
        return timezone(timedelta(seconds=offset))

def resolve_tz(name):
    if not name:
        return _local_tz()
    try:
        import zoneinfo
        return zoneinfo.ZoneInfo(name)
    except Exception:
        pass
    try:
        import pytz
        return pytz.timezone(name)
    except Exception:
        pass
    print(f"  ⚠ Unknown timezone {name!r} — using local")
    return _local_tz()

def tz_str(tz):
    return getattr(tz, 'key', getattr(tz, 'zone', str(tz)))

def list_timezones():
    try:
        import zoneinfo
        zones = sorted(zoneinfo.available_timezones())
    except ImportError:
        try:
            import pytz
            zones = sorted(pytz.all_timezones)
        except ImportError:
            print("Install zoneinfo or pytz to list timezones.")
            return
    cols, w = 3, 35
    print(f"\n{len(zones)} timezones:\n")
    for i in range(0, len(zones), cols):
        print("  " + "".join(f"{z:<{w}}" for z in zones[i:i+cols]))
    print()


# ── Calendar helpers ───────────────────────────────────────────────────────────

def _is_reduced_day(d):
    if _HAS_CAL:
        return not is_business_day(d) or is_us_federal_holiday(d)
    return d.weekday() >= 5

def _day_factor(d):
    return 0.15 if _is_reduced_day(d) else 1.0

def _hour_weights(d):
    return _WEEKEND_W if _is_reduced_day(d) else _WORKDAY_W

def _hour_counts(target, weights):
    total_w = sum(weights)
    counts, allocated = [], 0
    for w in weights:
        n = round(target * w / total_w) if total_w > 0 else 0
        counts.append(n)
        allocated += n
    counts[11] += target - allocated   # remainder goes to peak hour
    return counts


# ── Timestamp helpers ──────────────────────────────────────────────────────────

def timestamps_for_day(day_dt, count, tz):
    """Yield ISO timestamp strings distributed by diurnal pattern for a past day."""
    weights   = _hour_weights(day_dt)
    counts    = _hour_counts(count, weights)
    day_start = datetime(day_dt.year, day_dt.month, day_dt.day, tzinfo=tz)
    for hour, n in enumerate(counts):
        if n <= 0:
            continue
        h_utc = (day_start + timedelta(hours=hour)).astimezone(timezone.utc)
        for _ in range(n):
            ts = h_utc + timedelta(seconds=random.uniform(0, 3599))
            yield ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond//1000:03d}Z"


def timestamps_from_now(count, tz):
    """Yield (ts_string, sleep_seconds) for live generation of today's remaining events."""
    now_utc      = datetime.now(timezone.utc)
    today_local  = now_utc.astimezone(tz).date()
    weights      = _hour_weights(today_local)
    current_hour = now_utc.astimezone(tz).hour

    remaining_weights = list(weights)
    for h in range(current_hour):
        remaining_weights[h] = 0

    if sum(remaining_weights) == 0 or count <= 0:
        return

    counts    = _hour_counts(count, remaining_weights)
    day_start = datetime(today_local.year, today_local.month, today_local.day, tzinfo=tz)

    events = []
    for hour, n in enumerate(counts):
        if n <= 0:
            continue
        h_utc = (day_start + timedelta(hours=hour)).astimezone(timezone.utc)
        for _ in range(n):
            ts = h_utc + timedelta(seconds=random.uniform(0, 3599))
            if ts < now_utc:
                ts = now_utc + timedelta(seconds=random.uniform(1, 30))
            events.append(ts)
    events.sort()

    prev = now_utc
    for ts in events:
        sleep_s = max(0.0, (ts - prev).total_seconds())
        yield ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond//1000:03d}Z", sleep_s
        prev = ts


# ── Timestamp injection ────────────────────────────────────────────────────────

def _inject_timestamp(actions, ts_iso):
    """
    Patch every @timestamp and timestamp.us field in a list of bulk actions.

    generate_trace() calls _now_iso() internally so all docs get the current
    time.  For backfill we overwrite @timestamp with the historical ts after
    generation — this is simpler than re-implementing generate_trace with a
    ts parameter and keeps the APM document structure identical.

    timestamp.us is the microsecond epoch used internally by the APM UI;
    we derive it from the injected ISO string.
    """
    # Parse ts_iso back to a UTC datetime for microsecond conversion
    try:
        dt = datetime.strptime(ts_iso, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        ts_us = int(dt.timestamp() * 1_000_000)
    except ValueError:
        ts_us = int(datetime.now(timezone.utc).timestamp() * 1_000_000)

    for action in actions:
        src = action.get("_source", {})
        if "@timestamp" in src:
            src["@timestamp"] = ts_iso
        if "timestamp" in src and isinstance(src["timestamp"], dict):
            src["timestamp"]["us"] = ts_us
    return actions


# ── Backfill worker ────────────────────────────────────────────────────────────

def _day_worker(es, day_dt, trace_count, anomaly_chance,
                bulk_size, pb_threads, pb_queue, progress_q, tz,
                metrics_counter):
    """
    Generate and index all traces (+ periodic JVM metrics) for one day.
    Runs in a worker thread during backfill.
    """
    def _action_gen():
        local_trace_count = 0
        for ts in timestamps_for_day(day_dt, trace_count, tz):
            svc_name = random.choices(_SERVICE_NAMES, weights=_SERVICE_WEIGHTS, k=1)[0]
            actions  = _apm.generate_trace(svc_name, anomaly_chance=anomaly_chance)
            actions  = _inject_timestamp(actions, ts)
            yield from actions
            local_trace_count += 1

            # Emit JVM metrics every _METRICS_EVERY traces using the same timestamp
            if local_trace_count % _METRICS_EVERY == 0:
                for svc in _SERVICE_NAMES:
                    yield from _apm.generate_metrics(svc, ts_iso=ts)

    try:
        for ok, info in parallel_bulk(
            es,
            _action_gen(),
            thread_count=pb_threads,
            chunk_size=bulk_size,
            queue_size=pb_queue,
            raise_on_error=False,
            raise_on_exception=False,
            request_timeout=120,
        ):
            progress_q.put("OK" if ok else f"ERR:{info}")
    except Exception as e:
        progress_q.put(f"ERR:{day_dt}:{e}")


# ── Live generation ────────────────────────────────────────────────────────────

def live_generate(es, tpd, anomaly_chance, backfill_days, backfill_today_count,
                  bulk_size, pb_threads, pb_queue, tz):
    """
    Continuous live trace generation after backfill completes.
    Mirrors the structure of sdg-prime-classification.py live_generate().
    """
    tz_name = tz_str(tz)
    print(f"\n{'='*70}")
    print(f"  Backfill complete — {backfill_days} days indexed.")
    print(f"  Generating live traces at ~{tpd:,} traces/day.")
    print(f"  Timezone: {tz_name} | Press Ctrl+C to stop.\n")

    indexed_live  = 0
    error_count   = 0
    start_time    = time.time()
    _last_status  = time.time()
    current_day   = datetime.now(tz).date()
    trace_counter = [0]   # mutable counter for metrics cadence

    today_target = max(0, round(tpd * _day_factor(current_day)) - backfill_today_count)
    end_of_today = (
        datetime(current_day.year, current_day.month, current_day.day, tzinfo=tz)
        + timedelta(days=1)
    ).astimezone(timezone.utc)

    print(f"  Today ({current_day}):")
    print(f"    Backfill wrote:  {backfill_today_count:>8,} traces")
    print(f"    Remaining today: {today_target:>8,} traces")
    print(f"    Day rolls at:    {end_of_today.strftime('%H:%M:%S UTC')}\n")

    def _index_trace(ts_str):
        """Generate and index one trace (+ metrics if due) at the given timestamp."""
        svc_name = random.choices(_SERVICE_NAMES, weights=_SERVICE_WEIGHTS, k=1)[0]
        actions  = _apm.generate_trace(svc_name, anomaly_chance=anomaly_chance)
        actions  = _inject_timestamp(actions, ts_str)

        trace_counter[0] += 1
        if trace_counter[0] % _METRICS_EVERY == 0:
            for svc in _SERVICE_NAMES:
                actions.extend(_apm.generate_metrics(svc, ts_iso=ts_str))

        ok_count = 0
        try:
            for ok, info in parallel_bulk(
                es, actions,
                thread_count=1, chunk_size=len(actions),
                queue_size=1, raise_on_error=False,
                raise_on_exception=False, request_timeout=30,
            ):
                if ok:
                    ok_count += 1
        except Exception:
            return 0
        return ok_count

    # ── Today's remaining traces ───────────────────────────────────────────────
    if today_target > 0:
        for ts_str, sleep_s in timestamps_from_now(today_target, tz):
            if sleep_s > 0:
                time.sleep(min(sleep_s, 5.0))
            n = _index_trace(ts_str)
            indexed_live += n
            if n == 0:
                error_count += 1
            if time.time() - _last_status >= 30:
                print(f"  [{indexed_live:,} live docs indexed"
                      + (f", {error_count} errors" if error_count else "") + "]")
                _last_status = time.time()

    # ── Full days after midnight ───────────────────────────────────────────────
    print(f"\n  Today's remaining traces complete — entering continuous mode.")
    print(f"  Generating full days as they roll. Press Ctrl+C to stop.\n")

    while True:
        now_local  = datetime.now(tz)
        today      = now_local.date()
        day_target = max(1, round(tpd * _day_factor(today)))
        midnight   = datetime(today.year, today.month, today.day, tzinfo=tz) + timedelta(days=1)
        secs_left  = max(1, (midnight.astimezone(timezone.utc)
                              - datetime.now(timezone.utc)).total_seconds())
        # sleep_per_trace: distribute day_target traces across remaining seconds
        sleep_per_trace = secs_left / day_target

        try:
            while datetime.now(tz).date() == today:
                ts_str = (datetime.now(timezone.utc)
                          .strftime("%Y-%m-%dT%H:%M:%S.")
                          + f"{datetime.now(timezone.utc).microsecond//1000:03d}Z")
                n = _index_trace(ts_str)
                indexed_live += n
                if n == 0:
                    error_count += 1
                time.sleep(max(0.001, sleep_per_trace))
                if time.time() - _last_status >= 30:
                    print(f"  Backfill: {backfill_days} days | Live docs: {indexed_live:,}"
                          + (f" | {error_count} errors" if error_count else ""))
                    _last_status = time.time()
        except KeyboardInterrupt:
            break

    elapsed = time.time() - start_time
    h, m, s = int(elapsed//3600), int((elapsed%3600)//60), int(elapsed%60)
    print(f"\n{'='*70}")
    print(f"  Live generation stopped.")
    print(f"  Backfill: {backfill_days} days | Live docs indexed: {indexed_live:,}"
          + (f" | {error_count} errors" if error_count else ""))
    print(f"  Live elapsed: {h:02d}h {m:02d}m {s:02d}s")
    print(f"{'='*70}\n")


# ── Main backfill ──────────────────────────────────────────────────────────────

def backfill(host, user, password, verify_ssl,
             days, tpd, anomaly_chance, tz,
             workers, bulk_size, pb_threads, pb_queue):

    ssl_opts = {"verify_certs": verify_ssl, "ssl_show_warn": False}
    if not verify_ssl:
        ssl_opts["ssl_assert_fingerprint"] = None
    es = Elasticsearch(host, basic_auth=(user, password), **ssl_opts)

    today     = datetime.now(tz).date()
    yesterday = today - timedelta(days=1)
    start_day = today - timedelta(days=days)
    tz_name   = tz_str(tz)

    schedule = []
    for d in range(days):
        day    = start_day + timedelta(days=d)
        factor = _day_factor(day)
        count  = max(1, round(tpd * factor))
        schedule.append((day, count))

    # Each trace produces multiple docs (transaction + spans + child transactions
    # + periodic JVM metrics).  Average ~8–12 docs per trace depending on service.
    # Use 10 as a conservative estimate for the total doc count display.
    est_docs_per_trace = 10
    total_traces = sum(c for _, c in schedule)
    total_docs   = total_traces * est_docs_per_trace

    print(f"\n{'='*70}")
    print(f"  SDG-Prime Outlier — APM Trace Generator")
    print(f"{'='*70}")
    print(f"  Stream:         traces-apm-default")
    print(f"  Days:           {days}")
    print(f"  Weekday target: {tpd:,} traces/day")
    print(f"  Weekend/holiday:{round(tpd * 0.15):,} traces/day")
    print(f"  Anomaly chance: {anomaly_chance:.0%}  (geo-anomalous traces)")
    print(f"  Timezone:       {tz_name}")
    print(f"  Window:         {start_day}  →  {yesterday}  (today excluded)")
    print(f"  ~Total traces:  {total_traces:,}  (~{total_docs:,} docs incl. spans/metrics)")
    print(f"  CPU cores:      {_CPU_CORES}  →  workers={workers}, pb_threads={pb_threads}")
    print()

    if "utc" in tz_name.lower() or tz_name in ("UTC","Etc/UTC","GMT"):
        print("  ⚠ Timezone is UTC — diurnal peak may appear shifted in Kibana.")
        print("    Use --timezone 'America/New_York' to align with local time.\n")

    print(f"  {'Date':<12} {'Day':<4} {'Type':<10} {'Traces':>8}  {'~Docs':>8}")
    print(f"  {'-'*48}")
    for day, count in schedule:
        if _HAS_CAL and is_us_federal_holiday(day):
            dtype = "holiday"
        elif _is_reduced_day(day):
            dtype = "weekend"
        else:
            dtype = "workday"
        print(f"  {str(day):<12} {day.strftime('%a'):<4} {dtype:<10} "
              f"{count:>8,}  {count*est_docs_per_trace:>8,}")
    print(f"  {'-'*48}")
    print(f"  {'TOTAL':<28} {total_traces:>8,}  {total_docs:>8,}")
    print()
    print(f"  Outlier signal embedded:")
    print(f"    Geo-anomalous traces: ~{anomaly_chance:.0%} (foreign IPs, unusual locations)")
    print(f"    DFA features:  loan_amount, session_duration_sec, pages_visited,")
    print(f"                   docs_downloaded, failed_auth_attempts,")
    print(f"                   transaction.duration.us, http.response.status_code")
    print(f"\n  Press Ctrl+C to stop.\n")

    progress_q    = Queue()
    start_time    = time.time()
    indexed_total = 0
    error_count   = 0

    def printer():
        nonlocal indexed_total, error_count
        last = time.time()
        while True:
            try:
                item = progress_q.get(timeout=1)
                if item is None:
                    break
                if isinstance(item, str) and item.startswith("ERR:"):
                    error_count += 1
                    if error_count <= 50:
                        print(f"\n  ✗ {item[4:]}")
                    elif error_count == 51:
                        print("\n  (further errors suppressed)")
                else:
                    indexed_total += 1
                now = time.time()
                if now - last >= 10:
                    elapsed = now - start_time
                    rate    = indexed_total / elapsed if elapsed > 0 else 0
                    pct     = min(indexed_total / total_docs * 100, 100) if total_docs else 0
                    eta     = (total_docs - indexed_total) / rate if rate > 0 else 0
                    print(f"  [{pct:5.1f}%] {indexed_total:>10,}/~{total_docs:,}"
                          f"  |  {rate:>8,.0f} docs/sec"
                          f"  |  ETA {int(eta//3600):02d}h{int((eta%3600)//60):02d}m"
                          + (f"  | {error_count} errs" if error_count else ""))
                    last = now
            except Empty:
                continue

    t_print = threading.Thread(target=printer, daemon=True)
    t_print.start()

    # Pre-flight: verify traces-apm-default data stream exists
    print("  Checking data stream…")
    try:
        es.indices.get_data_stream(name="traces-apm-default")
        print("    ✓ traces-apm-default")
    except Exception:
        print("    ✗ traces-apm-default — NOT FOUND.")
        print("      Run bootstrap.py (or bootstrap-MLv2-WORKSHOP.py) first.")

    # Work queue: one item per day
    work_q = Queue()
    for day, count in schedule:
        work_q.put((day, count))

    metrics_counter = [0]

    def worker():
        while True:
            try:
                day_dt, count = work_q.get_nowait()
            except Empty:
                return
            try:
                _day_worker(es, day_dt, count, anomaly_chance,
                            bulk_size, pb_threads, pb_queue, progress_q, tz,
                            metrics_counter)
            except KeyboardInterrupt:
                return
            except Exception as e:
                progress_q.put(f"ERR:{day_dt}:{e}")
            finally:
                work_q.task_done()

    threads = [threading.Thread(target=worker, daemon=True)
               for _ in range(min(workers, days))]
    for t in threads:
        t.start()
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\n\nStopped early.")

    progress_q.put(None)
    t_print.join(timeout=10)

    elapsed = time.time() - start_time
    rate    = indexed_total / elapsed if elapsed > 0 else 0
    h, m, s = int(elapsed//3600), int((elapsed%3600)//60), int(elapsed%60)
    elapsed_str = f"{h:02d}h {m:02d}m {s:02d}s" if h else f"{m:02d}m {s:02d}s"

    print(f"\n{'='*70}")
    print(f"  Backfill complete — {days} days indexed in {elapsed_str}")
    print(f"  {'─'*66}")
    print(f"  Indexed:  {indexed_total:,} documents  (traces + spans + JVM metrics)"
          + (f"   [{error_count} errors]" if error_count else ""))
    print(f"  Rate:     {rate:,.0f} docs/sec")
    print()
    print(f"  Outlier signal embedded:")
    print(f"    Geo-anomalous traces: ~{anomaly_chance:.0%} of {total_traces:,} traces")
    print(f"    (~{round(total_traces * anomaly_chance):,} anomalous transactions in traces-apm-default)")
    print(f"{'='*70}")

    # today excluded from backfill — return 0 so live generates full day quota
    return days, tpd, 0


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="SDG-Prime Outlier: focused APM trace generator for ML outlier detection workshop",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Standard run — 30 days backfill then live generation:
  python sdg-prime-outlier.py \\
      --host https://localhost:9200 \\
      --user elastic --password changeme --no-verify-ssl

  # Higher volume with custom anomaly rate:
  python sdg-prime-outlier.py ... \\
      --days 30 --traces-per-day 2000 --anomaly-chance 0.15 \\
      --timezone "America/New_York"

  # Backfill only — no live generation:
  python sdg-prime-outlier.py ... --backfill

  # Live only — skip backfill, generate new traces going forward:
  python sdg-prime-outlier.py ... --live-only

  # List timezones:
  python sdg-prime-outlier.py --list-timezones
        """
    )
    p.add_argument("--host",             default="https://localhost:9200")
    p.add_argument("--user",             default="elastic")
    p.add_argument("--password",         default="changeme")
    p.add_argument("--no-verify-ssl",    action="store_true")
    p.add_argument("--days",             type=int,   default=DEFAULT_DAYS,
                   help=f"Historical window in days (default: {DEFAULT_DAYS})")
    p.add_argument("--traces-per-day",   "--tpd", type=int, default=DEFAULT_TPD,
                   help=f"Max APM traces per weekday (default: {DEFAULT_TPD:,}). "
                        f"Each trace produces ~10 docs (transaction + spans + metrics).")
    p.add_argument("--anomaly-chance",   type=float, default=DEFAULT_ANOMALY,
                   metavar="RATE",
                   help=(f"Fraction of traces with anomalous geo locations 0.0-1.0 "
                         f"(default: {DEFAULT_ANOMALY} = "
                         f"{int(DEFAULT_ANOMALY*100)} pct). "
                         f"Raise to 0.15-0.30 for stronger outlier signals in demos."))
    p.add_argument("--workers",  "-w",   type=int,   default=DEFAULT_WORKERS,
                   help=f"Worker threads for backfill (default: {DEFAULT_WORKERS})")
    p.add_argument("--bulk-size", "-b",  type=int,   default=DEFAULT_BULK_SIZE,
                   help=f"Documents per bulk request (default: {DEFAULT_BULK_SIZE})")
    p.add_argument("--pb-threads",       type=int,   default=DEFAULT_PB_THREADS,
                   help=f"parallel_bulk threads per worker (default: {DEFAULT_PB_THREADS})")
    p.add_argument("--pb-queue",         type=int,   default=DEFAULT_PB_QUEUE,
                   help=f"parallel_bulk queue depth (default: {DEFAULT_PB_QUEUE})")
    p.add_argument("--timezone",         default=None, metavar="TZ",
                   help="Timezone for diurnal timestamps (default: system local).")
    p.add_argument("--list-timezones",   action="store_true")
    p.add_argument("--backfill",         action="store_true",
                   help="Run the backfill then stop. Omit to also start live generation after backfill completes.")
    p.add_argument("--live-only",        action="store_true",
                   help="Skip backfill entirely and start live generation immediately.")

    # Load workshop-config.json if present (same pattern as classification SDG)
    _cfg = {}
    _cfg_file = os.path.join(_HERE, "workshop-config.json")
    if os.path.exists(_cfg_file):
        try:
            _cfg = json.load(open(_cfg_file))
            print(f"  ✓ Loaded config: {_cfg_file}")
        except Exception:
            pass

    args = p.parse_args()

    if args.list_timezones:
        list_timezones()
        sys.exit(0)

    # Back-fill from saved config where CLI left defaults
    _def = {"host": "https://localhost:9200", "user": "elastic", "password": "changeme"}
    if args.host     == _def["host"]     and _cfg.get("host"):     args.host     = _cfg["host"]
    if args.user     == _def["user"]     and _cfg.get("user"):     args.user     = _cfg["user"]
    if args.password == _def["password"] and _cfg.get("password"): args.password = _cfg["password"]
    if not args.no_verify_ssl            and _cfg.get("no_verify_ssl"):
        args.no_verify_ssl = _cfg["no_verify_ssl"]
    if not args.timezone                 and _cfg.get("timezone"):
        args.timezone = _cfg["timezone"]

    if not (0.0 <= args.anomaly_chance <= 1.0):
        print(f"ERROR: --anomaly-chance must be between 0.0 and 1.0 "
              f"(got {args.anomaly_chance}).")
        sys.exit(1)

    tz = resolve_tz(args.timezone)

    ssl_opts = {"verify_certs": not args.no_verify_ssl, "ssl_show_warn": False}
    if args.no_verify_ssl:
        ssl_opts["ssl_assert_fingerprint"] = None
    es = Elasticsearch(args.host, basic_auth=(args.user, args.password), **ssl_opts)

    if args.live_only:
        print("\n  --live-only: skipping backfill, starting live generation immediately.")
        live_generate(
            es                   = es,
            tpd                  = args.traces_per_day,
            anomaly_chance       = args.anomaly_chance,
            backfill_days        = 0,
            backfill_today_count = 0,
            bulk_size            = args.bulk_size,
            pb_threads           = args.pb_threads,
            pb_queue             = args.pb_queue,
            tz                   = tz,
        )
    else:
        backfill_days, backfill_tpd, backfill_today_count = backfill(
            host          = args.host,
            user          = args.user,
            password      = args.password,
            verify_ssl    = not args.no_verify_ssl,
            days          = args.days,
            tpd           = args.traces_per_day,
            anomaly_chance= args.anomaly_chance,
            tz            = tz,
            workers       = args.workers,
            bulk_size     = args.bulk_size,
            pb_threads    = args.pb_threads,
            pb_queue      = args.pb_queue,
        )

        if not args.backfill:
            live_generate(
                es                   = es,
                tpd                  = args.traces_per_day,
                anomaly_chance       = args.anomaly_chance,
                backfill_days        = backfill_days,
                backfill_today_count = backfill_today_count,
                bulk_size            = args.bulk_size,
                pb_threads           = args.pb_threads,
                pb_queue             = args.pb_queue,
                tz                   = tz,
            )


if __name__ == "__main__":
    main()
