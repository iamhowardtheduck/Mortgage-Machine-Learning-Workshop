#!/usr/bin/env python3
"""
bootstrap-prime-multilayer.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Focused bootstrap for the Elastic ML Multilayer Security Workshop.

Creates ONLY the index templates and Kibana data views required for:

  Stream 1 — APM transaction spans:
    traces-apm-default           (ML outlier + classification source)

  Stream 2 — Edge security logs:
    logs-akamai.siem-mortgage    (WAF / bot signals)
    logs-aws.waf-mortgage        (AWS WAF actions)

Workshop flow
─────────────
  Step 1  python bootstrap-prime-multilayer.py ...
             → Creates 3 index templates + common component template
             → Creates Kibana data views for DFA result indices
             → Saves workshop-config.json for reuse by the SDG

  Step 2  python sdg-prime-multilayer.py ... --backfill [--livedata]
             → Generates historical data for all three streams
             → Transitions to live generation after backfill

  Step 3  In Kibana ML UI:
             → Create outlier detection DFA job on traces-apm-default
             → Clone and modify as classification job
             → Apply model as inference pipeline

  Step 4  python sdg-prime-multilayer.py ... --livedata-only
             → Continuous live generation (omit if already running from Step 2)

Usage
─────
  # Full bootstrap (templates + data views):
  python bootstrap-prime-multilayer.py \\
      --host https://localhost:9200 \\
      --kibana-host https://localhost:5601 \\
      --user elastic --password changeme \\
      --no-verify-ssl

  # Templates only, skip Kibana:
  python bootstrap-prime-multilayer.py ... --skip-kibana

  # Register DFA data views only (after running the DFA job in Kibana):
  python bootstrap-prime-multilayer.py ... --create-dfa-views

  # Purge all workshop resources:
  python bootstrap-prime-multilayer.py ... --purge [--force]
"""

import argparse
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.request


# ══════════════════════════════════════════════════════════════════════════════
# HTTP helpers
# ══════════════════════════════════════════════════════════════════════════════

def _make_ctx(verify_ssl):
    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _request(url, method, body, auth, verify_ssl, extra_headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req  = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type",  "application/json")
    req.add_header("Authorization", auth)
    if extra_headers:
        for k, v in extra_headers.items():
            req.add_header(k, v)
    ctx = _make_ctx(verify_ssl)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {"error": str(e)}
    except Exception as e:
        return 0, {"error": str(e)}


def _put(host, path, body, auth, verify_ssl, label=None):
    status, resp = _request(f"{host}{path}", "PUT", body, auth, verify_ssl)
    ok = status in (200, 201)
    lbl = label or path
    print(f"  {'✓' if ok else '✗'} [{status}] PUT {lbl}")
    if not ok:
        print(f"      {resp}")
    return ok


def _delete(host, path, auth, verify_ssl, label):
    status, resp = _request(f"{host}{path}", "DELETE", None, auth, verify_ssl)
    if status in (200, 201):
        print(f"  ✓ [{status}] Deleted {label}")
        return True
    if status == 404:
        print(f"  ~ [404]  Not found (skipped): {label}")
        return True
    print(f"  ✗ [{status}] Failed to delete {label}: {resp}")
    return False


def _kibana_request(url, method, body, auth, verify_ssl):
    return _request(url, method, body, auth, verify_ssl,
                    extra_headers={"kbn-xsrf": "true"})


def _kibana_reachable(kibana_host, auth, verify_ssl):
    status, resp = _kibana_request(f"{kibana_host}/api/status",
                                    "GET", None, auth, verify_ssl)
    if status == 0:
        return False, resp.get("error", "connection refused")
    if status in (200, 201):
        version = (resp.get("version") or {}).get("number", "unknown")
        return True, version
    return False, f"HTTP {status}"


# ══════════════════════════════════════════════════════════════════════════════
# Shared mapping blocks (copied from bootstrap.py helpers)
# ══════════════════════════════════════════════════════════════════════════════

def _geo(extra=None):
    props = {
        "location":         {"type": "geo_point"},
        "country_iso_code": {"type": "keyword"},
        "city_name":        {"type": "keyword"},
        "region_name":      {"type": "keyword"},
    }
    if extra:
        props.update(extra)
    return {"properties": props}


def _source_with_geo():
    return {"properties": {
        "ip":      {"type": "ip"},
        "address": {"type": "keyword"},
        "port":    {"type": "integer"},
        "bytes":   {"type": "long"},
        "packets": {"type": "integer"},
        "geo":     _geo(),
    }}


def _client_with_geo():
    return {"properties": {
        "ip":      {"type": "ip"},
        "address": {"type": "keyword"},
        "geo":     _geo(),
        "user":    {"properties": {"id": {"type": "keyword"}, "name": {"type": "keyword"}}},
    }}


def _user_block():
    return {"properties": {
        "id":        {"type": "keyword"},
        "name":      {"type": "keyword"},
        "email":     {"type": "keyword"},
        "roles":     {"type": "keyword"},
        "full_name": {"type": "keyword"},
        "domain":    {"type": "keyword"},
    }}


def _http_block():
    return {"properties": {
        "version": {"type": "keyword"},
        "request":  {"properties": {"method": {"type": "keyword"}}},
        "response": {"properties": {
            "status_code": {"type": "integer"},
            "body": {"properties": {"bytes": {"type": "long"}}},
        }},
    }}


def _service_block():
    return {"properties": {
        "name":        {"type": "keyword"},
        "type":        {"type": "keyword"},
        "address":     {"type": "keyword"},
        "version":     {"type": "keyword"},
        "environment": {"type": "keyword"},
    }}


# ══════════════════════════════════════════════════════════════════════════════
# Common component template
# ══════════════════════════════════════════════════════════════════════════════

def _create_common_component(host, auth, verify_ssl):
    """Create the mortgage-common@mappings component template (subset for our 3 streams)."""
    _put(host, "/_component_template/mortgage-common@mappings", {
        "template": {
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "ecs":        {"properties": {"version": {"type": "keyword"}}},
                    "data_stream": {"properties": {
                        "type":      {"type": "constant_keyword"},
                        "dataset":   {"type": "constant_keyword"},
                        "namespace": {"type": "constant_keyword"},
                    }},
                    "host": {"properties": {
                        "hostname":     {"type": "keyword"},
                        "name":         {"type": "keyword"},
                        "type":         {"type": "keyword"},
                        "architecture": {"type": "keyword"},
                        "os": {"properties": {
                            "type":    {"type": "keyword"},
                            "name":    {"type": "keyword"},
                            "version": {"type": "keyword"},
                            "family":  {"type": "keyword"},
                        }},
                    }},
                    "agent": {"properties": {
                        "type":    {"type": "keyword"},
                        "version": {"type": "keyword"},
                        "name":    {"type": "keyword"},
                        "id":      {"type": "keyword"},
                    }},
                    "event": {"properties": {
                        "kind":     {"type": "keyword"},
                        "category": {"type": "keyword"},
                        "type":     {"type": "keyword"},
                        "dataset":  {"type": "keyword"},
                        "module":   {"type": "keyword"},
                        "outcome":  {"type": "keyword"},
                        "action":   {"type": "keyword"},
                        "duration": {"type": "long"},
                        "sequence": {"type": "long"},
                        "id":       {"type": "keyword"},
                        "start":    {"type": "date"},
                        "end":      {"type": "date"},
                    }},
                    "tags":    {"type": "keyword"},
                    "message": {"type": "text"},
                    "log": {"properties": {
                        "level":  {"type": "keyword"},
                        "offset": {"type": "long"},
                        "file":   {"properties": {"path": {"type": "keyword"}}},
                        "flags":  {"type": "keyword"},
                    }},
                    "observer": {"properties": {
                        "type":   {"type": "keyword"},
                        "vendor": {"type": "keyword"},
                    }},
                    "network": {"properties": {
                        "protocol":     {"type": "keyword"},
                        "transport":    {"type": "keyword"},
                        "type":         {"type": "keyword"},
                        "bytes":        {"type": "long"},
                        "community_id": {"type": "keyword"},
                    }},
                    "cloud": {"properties": {
                        "provider":          {"type": "keyword"},
                        "region":            {"type": "keyword"},
                        "availability_zone": {"type": "keyword"},
                        "account":           {"properties": {"id": {"type": "keyword"}}},
                    }},
                    "tls": {"properties": {
                        "version":          {"type": "keyword"},
                        "version_protocol": {"type": "keyword"},
                    }},
                    "rule": {"properties": {
                        "id":      {"type": "keyword"},
                        "ruleset": {"type": "keyword"},
                        "name":    {"type": "keyword"},
                    }},
                    "related": {"properties": {
                        "ip":    {"type": "ip"},
                        "hosts": {"type": "keyword"},
                        "user":  {"type": "keyword"},
                    }},
                    "destination": {"properties": {
                        "ip":      {"type": "ip"},
                        "address": {"type": "keyword"},
                        "port":    {"type": "integer"},
                        "bytes":   {"type": "long"},
                    }},
                }
            }
        }
    }, auth, verify_ssl, "mortgage-common@mappings component template")


# ══════════════════════════════════════════════════════════════════════════════
# The three focused index templates
# ══════════════════════════════════════════════════════════════════════════════

def _create_traces_apm_template(host, auth, verify_ssl):
    """
    traces-apm-default  — APM transaction spans.

    Includes all fields required by the Kibana APM UI (processor.event,
    service.target, span.destination.service.resource, observer, etc.)
    and the DFA outlier feature fields stored under labels.*
    """
    _put(host, "/_index_template/traces-apm-default", {
        "index_patterns": ["traces-apm-default*"],
        "data_stream": {}, "priority": 300,
        "composed_of": ["mortgage-common@mappings"],
        "template": {
            "settings": {"index": {"lifecycle": {"name": "traces"}}},
            "mappings": {
                "properties": {
                    # ── Service ──────────────────────────────────────────────
                    "service": {"properties": {
                        "name":        {"type": "keyword"},
                        "version":     {"type": "keyword"},
                        "environment": {"type": "keyword"},
                        "node":        {"properties": {"name": {"type": "keyword"}}},
                        "language": {"properties": {
                            "name":    {"type": "keyword"},
                            "version": {"type": "keyword"},
                        }},
                        "runtime": {"properties": {
                            "name":    {"type": "keyword"},
                            "version": {"type": "keyword"},
                        }},
                        "framework": {"properties": {
                            "name":    {"type": "keyword"},
                            "version": {"type": "keyword"},
                        }},
                        # Required by Kibana 8.x+ APM Service Map
                        "target": {"properties": {
                            "name": {"type": "keyword"},
                            "type": {"type": "keyword"},
                        }},
                    }},
                    # ── Processor — single most important APM UI requirement ──
                    "processor": {"properties": {
                        "event": {"type": "keyword"},
                        "name":  {"type": "keyword"},
                    }},
                    # ── Trace / parent / child linkage ───────────────────────
                    "trace":   {"properties": {"id": {"type": "keyword"}}},
                    "parent":  {"properties": {"id": {"type": "keyword"}}},
                    "child":   {"properties": {"id": {"type": "keyword"}}},
                    "timestamp": {"properties": {"us": {"type": "long"}}},
                    # ── Transaction ──────────────────────────────────────────
                    "transaction": {"properties": {
                        "id":       {"type": "keyword"},
                        "name":     {"type": "keyword"},
                        "type":     {"type": "keyword"},
                        "result":   {"type": "keyword"},
                        "sampled":  {"type": "boolean"},
                        "duration": {"properties": {"us": {"type": "long"}}},
                    }},
                    # ── Span ─────────────────────────────────────────────────
                    "span": {"properties": {
                        "id":       {"type": "keyword"},
                        "name":     {"type": "keyword"},
                        "type":     {"type": "keyword"},
                        "subtype":  {"type": "keyword"},
                        "action":   {"type": "keyword"},
                        "duration": {"properties": {"us": {"type": "long"}}},
                        # APM service map edge field — must be nested inside span{}
                        "destination": {"properties": {
                            "service": {"properties": {
                                "name":     {"type": "keyword"},
                                "resource": {"type": "keyword"},
                                "type":     {"type": "keyword"},
                            }}
                        }},
                    }},
                    # ── Top-level destination (backwards compatibility) ───────
                    "destination": {"properties": {
                        "service": {"properties": {
                            "name":     {"type": "keyword"},
                            "resource": {"type": "keyword"},
                            "type":     {"type": "keyword"},
                        }}
                    }},
                    # ── Observer — required for Kibana APM UI ────────────────
                    "observer": {"properties": {
                        "type":          {"type": "keyword"},
                        "version":       {"type": "keyword"},
                        "version_major": {"type": "integer"},
                    }},
                    # ── Network context ──────────────────────────────────────
                    "client": _client_with_geo(),
                    "source": {"properties": {"ip": {"type": "ip"}}},
                    "user":   _user_block(),
                    "http":   _http_block(),
                    "url": {"properties": {
                        "full":   {"type": "keyword"},
                        "path":   {"type": "keyword"},
                        "domain": {"type": "keyword"},
                    }},
                    # ── DFA outlier / classification feature fields ───────────
                    # These are the numeric features the outlier detection job
                    # scores transactions on. They are also used as features
                    # when the job is converted to a classification model.
                    "labels": {"properties": {
                        "loan_amount":          {"type": "float"},
                        "session_duration_sec": {"type": "integer"},
                        "pages_visited":        {"type": "integer"},
                        "docs_downloaded":      {"type": "integer"},
                        "failed_auth_attempts": {"type": "integer"},
                        # Written by the inference pipeline after classification.
                        # Storing them as keyword preserves the label string values.
                        "is_suspicious":        {"type": "keyword"},
                        "risk_tier":            {"type": "keyword"},
                    }},
                    # ── Geo anomaly fields (set by SDG on anomalous traces) ───
                    # Used as influencers in the associated AD job and as a
                    # signal feature in the classification model.
                    "geo_anomaly": {"properties": {
                        "is_anomalous": {"type": "boolean"},
                        "city":         {"type": "keyword"},
                        "country":      {"type": "keyword"},
                    }},
                }
            },
        },
    }, auth, verify_ssl, "traces-apm-default index template")


def _create_akamai_template(host, auth, verify_ssl):
    """
    logs-akamai.siem-mortgage  — Akamai SIEM WAF/bot events.

    Runtime mappings expose the AWS WAF action field so the two streams
    can be used together in a single multi-index DFA source query.
    """
    _put(host, "/_index_template/logs-akamai.siem-mortgage", {
        "index_patterns": ["logs-akamai.siem-mortgage*"],
        "data_stream": {}, "priority": 300,
        "composed_of": ["mortgage-common@mappings"],
        "template": {
            "settings": {"index": {"lifecycle": {"name": "logs"}}},
            "mappings": {
                # Runtime mappings make AWS WAF action field visible to _field_caps
                # when this index is queried alongside logs-aws.waf-mortgage in
                # the multilayer-security DFA job.
                "runtime": {
                    "aws.waf.action":            {"type": "keyword"},
                    "http.response.status_code": {"type": "long"},
                },
                "properties": {
                    "source": _source_with_geo(),
                    "client": _client_with_geo(),
                    "http":   _http_block(),
                    "url": {"properties": {
                        "domain":  {"type": "keyword"},
                        "path":    {"type": "keyword"},
                        "full":    {"type": "keyword"},
                        "query":   {"type": "keyword"},
                        "port":    {"type": "integer"},
                    }},
                    "akamai": {"properties": {
                        "siem": {"properties": {
                            "config_id":    {"type": "keyword"},
                            "policy_id":    {"type": "keyword"},
                            "rule_actions": {"type": "keyword"},
                            "rule_tags":    {"type": "keyword"},
                            "bot": {"properties": {
                                "score":            {"type": "integer"},
                                "response_segment": {"type": "integer"},
                            }},
                            "user_risk": {"properties": {
                                "score":  {"type": "integer"},
                                "status": {"type": "integer"},
                                "allow":  {"type": "integer"},
                                "uuid":   {"type": "keyword"},
                                "trust":  {"properties": {"ugp": {"type": "keyword"}}},
                                "general": {"properties": {
                                    "duc_1d": {"type": "keyword"},
                                    "duc_1h": {"type": "keyword"},
                                }},
                            }},
                            "client_data": {"properties": {
                                "app_bundle_id":  {"type": "keyword"},
                                "app_version":    {"type": "keyword"},
                                "sdk_version":    {"type": "keyword"},
                                "telemetry_type": {"type": "integer"},
                            }},
                        }}
                    }},
                },
            },
        },
    }, auth, verify_ssl, "logs-akamai.siem-mortgage index template")


def _create_waf_template(host, auth, verify_ssl):
    """
    logs-aws.waf-mortgage  — AWS WAF request logs.

    Runtime mappings expose Akamai bot/risk score fields so DFA can merge
    them across both indices in a single multi-index source query without
    _field_caps rejecting the job at creation time.
    WAF documents return null for these fields; DFA imputes missing values.
    """
    _put(host, "/_index_template/logs-aws.waf-mortgage", {
        "index_patterns": ["logs-aws.waf-mortgage*"],
        "data_stream": {}, "priority": 300,
        "composed_of": ["mortgage-common@mappings"],
        "template": {
            "settings": {"index": {"lifecycle": {"name": "logs"}}},
            "mappings": {
                # Runtime mappings make Akamai fields visible to _field_caps
                # so DFA can merge them across both indices in a single job.
                "runtime": {
                    "akamai.siem.bot.score":        {"type": "double"},
                    "akamai.siem.user_risk.score":  {"type": "double"},
                    "akamai.siem.user_risk.status": {"type": "long"},
                },
                "properties": {
                    "source": {"properties": {"ip": {"type": "ip"}}},
                    "url":    {"properties": {"path": {"type": "keyword"}}},
                    "http":   _http_block(),
                    "aws": {"properties": {
                        "waf": {"properties": {
                            "arn":            {"type": "keyword"},
                            "id":             {"type": "keyword"},
                            "format_version": {"type": "keyword"},
                            "action":         {"type": "keyword"},
                            "request": {"properties": {
                                "headers": {"properties": {
                                    "User-Agent": {"type": "keyword"},
                                    "Host":       {"type": "keyword"},
                                }}
                            }},
                        }},
                        "s3": {"properties": {
                            "bucket": {"properties": {
                                "arn":  {"type": "keyword"},
                                "name": {"type": "keyword"},
                            }},
                            "object": {"properties": {"key": {"type": "keyword"}}},
                        }},
                    }},
                },
            },
        },
    }, auth, verify_ssl, "logs-aws.waf-mortgage index template")


# ══════════════════════════════════════════════════════════════════════════════
# Setup entry point
# ══════════════════════════════════════════════════════════════════════════════

def setup(host, auth, verify_ssl):
    """Create the common component template and all three index templates."""
    print("▸ Component template…")
    _create_common_component(host, auth, verify_ssl)

    print("\n▸ Index templates…")
    _create_traces_apm_template(host, auth, verify_ssl)
    _create_akamai_template(host, auth, verify_ssl)
    _create_waf_template(host, auth, verify_ssl)

    print("\n✓ Index templates complete — 3 data stream templates created.")
    print("    traces-apm-default")
    print("    logs-akamai.siem-mortgage")
    print("    logs-aws.waf-mortgage")


# ══════════════════════════════════════════════════════════════════════════════
# Kibana — DFA data views
# ══════════════════════════════════════════════════════════════════════════════

# DFA result indices created by the outlier detection job (and its classification
# clone).  The index name is set in the Kibana DFA UI when the job is created.
_DFA_DATA_VIEWS = {
    # title → index_pattern
    "mortgage-multilayer-security-outliers":       "mortgage-multilayer-security-outliers",
    "mortgage-multilayer-security-classification": "mortgage-multilayer-security-classification",
}


def create_dfa_data_views(kibana_host, auth, verify_ssl):
    """
    Register Kibana data views for the DFA destination indices so that the
    'Explore Results' page can render without the 'No data view exists' error.

    Safe to run before the DFA job exists — Kibana data views are just
    index pattern registrations and do not require the backing index.
    """
    print("\n▸ Creating Kibana data views for DFA result indices…")
    reachable, info = _kibana_reachable(kibana_host, auth, verify_ssl)
    if not reachable:
        print(f"  ⚠ Cannot reach Kibana: {info}")
        return

    for title, index_pattern in _DFA_DATA_VIEWS.items():
        status, resp = _kibana_request(
            f"{kibana_host}/api/data_views/data_view",
            "POST",
            {
                "data_view": {
                    "title":         index_pattern,
                    "name":          title,
                    "timeFieldName": "@timestamp",
                }
            },
            auth, verify_ssl,
        )
        if status in (200, 201):
            print(f"  ✓ [{status}] Data view created: {title}")
        elif status == 400 and "already exists" in str(resp).lower():
            print(f"  ~ [exists] Data view: {title}")
        else:
            print(f"  ✗ [{status}] Failed to create data view: {title}")
            print(f"      {resp}")


# ══════════════════════════════════════════════════════════════════════════════
# Purge
# ══════════════════════════════════════════════════════════════════════════════

_INDEX_TEMPLATES = [
    "traces-apm-default",
    "logs-akamai.siem-mortgage",
    "logs-aws.waf-mortgage",
]

_COMPONENT_TEMPLATES = [
    "mortgage-common@mappings",
]

_DATA_STREAMS = [
    "traces-apm-default",
    "logs-akamai.siem-mortgage",
    "logs-aws.waf-mortgage",
]

_DFA_RESULT_INDICES = [
    "mortgage-multilayer-security-outliers",
    "mortgage-multilayer-security-classification",
]


def purge(host, auth, verify_ssl,
          kibana_host=None, kibana_auth=None,
          skip_data=False, skip_templates=False,
          skip_kibana=False, force=False):
    """
    Remove all multilayer-security workshop resources.
    Safe to run against a partially-configured environment — 404s are silently skipped.
    """
    print("\n=== Multilayer Security Workshop — Purge ===\n")

    if not force:
        print("  ⚠ This will permanently delete all workshop data, index templates,")
        print("    DFA result indices, and Kibana data views for this workshop.")
        print()
        answer = input("  Type YES to confirm: ").strip()
        if answer != "YES":
            print("  Aborted.")
            return
        print()

    # DFA result indices (not data streams — regular indices)
    print("▸ Deleting DFA result indices…")
    for idx in _DFA_RESULT_INDICES:
        _delete(host, f"/{idx}", auth, verify_ssl, f"DFA result index: {idx}")

    # Data streams
    if not skip_data:
        print("\n▸ Deleting data streams…")
        for ds in _DATA_STREAMS:
            _delete(host, f"/_data_stream/{ds}", auth, verify_ssl,
                    f"Data stream: {ds}")

    # Index + component templates
    if not skip_templates:
        print("\n▸ Deleting index templates…")
        for tmpl in _INDEX_TEMPLATES:
            _delete(host, f"/_index_template/{tmpl}", auth, verify_ssl,
                    f"Index template: {tmpl}")
        print("\n▸ Deleting component templates…")
        for tmpl in _COMPONENT_TEMPLATES:
            _delete(host, f"/_component_template/{tmpl}", auth, verify_ssl,
                    f"Component template: {tmpl}")

    # Kibana data views
    if not skip_kibana and kibana_host and kibana_auth:
        print("\n▸ Deleting Kibana data views…")
        reachable, info = _kibana_reachable(kibana_host, kibana_auth, verify_ssl)
        if not reachable:
            print(f"  ⚠ Cannot reach Kibana at {kibana_host}: {info}")
            print("    Skipping Kibana cleanup. Re-run with --kibana-host to retry.")
        else:
            for title in _DFA_DATA_VIEWS:
                # Find by title, then delete
                url = (f"{kibana_host}/api/saved_objects/_find"
                       f"?type=index-pattern&search_fields=title"
                       f"&search={urllib.request.quote(title)}")
                status, resp = _kibana_request(url, "GET", None, kibana_auth, verify_ssl)
                if status == 200:
                    for obj in resp.get("saved_objects", []):
                        if obj.get("attributes", {}).get("title") == title:
                            obj_id = obj["id"]
                            s2, _ = _kibana_request(
                                f"{kibana_host}/api/saved_objects/index-pattern/{obj_id}",
                                "DELETE", None, kibana_auth, verify_ssl,
                            )
                            if s2 in (200, 201):
                                print(f"  ✓ Deleted Kibana data view: {title}")
                            else:
                                print(f"  ~ Could not delete Kibana data view: {title}")
                else:
                    print(f"  ~ No Kibana data view found: {title}")

    print("\n" + "=" * 52)
    print("✓ Purge complete.")
    print()
    print("  To rebuild: python bootstrap-prime-multilayer.py ...")


# ══════════════════════════════════════════════════════════════════════════════
# Workshop config persistence
# ══════════════════════════════════════════════════════════════════════════════

def _config_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "workshop-config.json")


def save_config(args):
    cfg = {
        "host":          args.host,
        "user":          args.user,
        "password":      args.password,
        "no_verify_ssl": args.no_verify_ssl,
        "kibana_host":   args.kibana_host,
    }
    try:
        with open(_config_path(), "w") as fh:
            json.dump(cfg, fh, indent=2)
        print(f"  ✓ Config saved → {_config_path()}")
    except Exception as e:
        print(f"  ⚠ Could not save config: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

def main():
    p = argparse.ArgumentParser(
        description=(
            "Bootstrap for the Multilayer Security Workshop — "
            "creates index templates and Kibana data views for "
            "traces-apm-default, logs-akamai.siem-mortgage, and logs-aws.waf-mortgage."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Workshop flow
─────────────
  Step 1  python bootstrap-prime-multilayer.py ...  ← this script
  Step 2  python sdg-prime-multilayer.py ... --backfill [--livedata]
  Step 3  In Kibana: create outlier DFA job, clone → classification, apply inference pipeline
  Step 4  python sdg-prime-multilayer.py ... --livedata-only  (if not already running)

Examples
────────
  # Full bootstrap (templates + Kibana data views):
  python bootstrap-prime-multilayer.py \\
      --host https://localhost:9200 \\
      --kibana-host https://localhost:5601 \\
      --user elastic --password changeme --no-verify-ssl

  # Templates only, no Kibana:
  python bootstrap-prime-multilayer.py ... --skip-kibana

  # Register DFA result-index data views after creating the DFA job:
  python bootstrap-prime-multilayer.py ... --create-dfa-views

  # Purge all workshop resources:
  python bootstrap-prime-multilayer.py ... --purge [--force]

  # Purge data + DFA indices only (keep templates):
  python bootstrap-prime-multilayer.py ... --purge --purge-skip-templates
        """,
    )
    p.add_argument("--host",           default="https://localhost:9200",
                   help="Elasticsearch base URL (default: https://localhost:9200)")
    p.add_argument("--user",           default="elastic")
    p.add_argument("--password",       default="changeme")
    p.add_argument("--no-verify-ssl",  action="store_true",
                   help="Disable SSL certificate verification")
    p.add_argument("--kibana-host",    default="https://localhost:5601",
                   help="Kibana base URL (default: https://localhost:5601)")
    p.add_argument("--skip-kibana",    action="store_true",
                   help="Skip Kibana data view creation")
    p.add_argument("--create-dfa-views", action="store_true",
                   help="Register Kibana data views for DFA result indices and exit. "
                        "Safe to run before or after the DFA job exists.")

    # Purge flags
    p.add_argument("--purge",                  action="store_true")
    p.add_argument("--force",                  action="store_true",
                   help="Skip confirmation prompt when used with --purge")
    p.add_argument("--purge-skip-data",        action="store_true",
                   help="With --purge: keep data streams")
    p.add_argument("--purge-skip-templates",   action="store_true",
                   help="With --purge: keep index templates")
    p.add_argument("--purge-skip-kibana",      action="store_true",
                   help="With --purge: keep Kibana data views")

    args = p.parse_args()

    verify_ssl = not args.no_verify_ssl
    auth = "Basic " + base64.b64encode(
        f"{args.user}:{args.password}".encode()
    ).decode()

    print("\n=== Multilayer Security Workshop — Bootstrap ===")
    print(f"    Target: {args.host}\n")

    # ── Save config for SDG reuse ─────────────────────────────────────────────
    if not args.purge:
        save_config(args)

    # ── Purge mode ────────────────────────────────────────────────────────────
    if args.purge:
        kibana_host = args.kibana_host if not args.purge_skip_kibana else None
        kibana_auth = auth             if not args.purge_skip_kibana else None
        purge(
            host             = args.host,
            auth             = auth,
            verify_ssl       = verify_ssl,
            kibana_host      = kibana_host,
            kibana_auth      = kibana_auth,
            skip_data        = args.purge_skip_data,
            skip_templates   = args.purge_skip_templates,
            skip_kibana      = args.purge_skip_kibana,
            force            = args.force,
        )
        return

    # ── DFA data views only ───────────────────────────────────────────────────
    if args.create_dfa_views:
        if args.skip_kibana:
            print("  (--skip-kibana: DFA data view creation skipped)")
        else:
            create_dfa_data_views(args.kibana_host, auth, verify_ssl)
        return

    # ── Full bootstrap ────────────────────────────────────────────────────────

    # 1. Index templates
    setup(args.host, auth, verify_ssl)

    # 2. Kibana data views
    if args.skip_kibana:
        print("\n  (--skip-kibana: Kibana data view creation skipped)")
    else:
        create_dfa_data_views(args.kibana_host, auth, verify_ssl)

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "=" * 56)
    print("✓ Bootstrap complete.")
    print()
    print("  Index templates created:")
    print("    • traces-apm-default")
    print("    • logs-akamai.siem-mortgage")
    print("    • logs-aws.waf-mortgage")
    if not args.skip_kibana:
        print()
        print("  Kibana data views registered:")
        for title in _DFA_DATA_VIEWS:
            print(f"    • {title}")
    print()
    print("  Next step:")
    print("    python sdg-prime-multilayer.py \\")
    print(f"        --host {args.host} \\")
    print(f"        --user {args.user} --password {args.password} \\")
    if args.no_verify_ssl:
        print("        --no-verify-ssl \\")
    print("        --backfill --livedata")
    print()
    print("  Workshop flow:")
    print("    1. ✓ bootstrap-prime-multilayer.py   (templates + data views)")
    print("    2.   sdg-prime-multilayer.py --backfill [--livedata]")
    print("    3.   Kibana ML: create outlier DFA job → clone → classification → pipeline")
    print("    4.   sdg-prime-multilayer.py --livedata-only  (if not already running)")
    print()


if __name__ == "__main__":
    main()
