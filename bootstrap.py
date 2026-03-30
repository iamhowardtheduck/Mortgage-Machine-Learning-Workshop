#!/usr/bin/env python3
"""
bootstrap.py — Full bootstrap for the LendPath Mortgage ML Workshop.

Creates index templates, ML anomaly detection jobs + datafeeds, and
Data Frame Analytics jobs so the environment is completely ready before
the SDG starts generating data.

Covers all 21 data streams:
  Core LendPath (8):  nginx access/error/stubstatus, LOS applications,
                      services, APM spans, audit, host metrics
  Integrations (13):  Akamai SIEM, AWS VPC Flow, AWS WAF, CoreDNS,
                      HAProxy log/stat/info, Kafka broker/partition,
                      Oracle database_audit/sysmetric/tablespace, PingOne audit

ML jobs loaded from:
  ml-job-definitions.json              Core jobs  (Modules 1–14)
  ml-job-definitions-integrations.json Integration jobs (Modules 15–21)

Usage:
    # Full bootstrap (templates + ML jobs):
    python bootstrap.py --host https://localhost:9200 \
                        --user elastic --password changeme \
                        --no-verify-ssl

    # Templates only (skip all ML job creation):
    python bootstrap.py ... --skip-ml

    # Templates + AD jobs only (default — safe before SDG has run):
    python bootstrap.py ...

    # Create DFA jobs (run AFTER SDG has populated source indices):
    python bootstrap.py ... --create-dfa

    # Create DFA jobs AND immediately start them:
    python bootstrap.py ... --create-dfa --run-dfa

    # Templates + AD jobs + start all datafeeds immediately:
    python bootstrap.py ... --start-datafeeds

    # Use alternate job definition files:
    python bootstrap.py ... --job-files jobs1.json jobs2.json
"""

import argparse
import json
import os
import sys
import urllib.request
import urllib.error
import ssl
import base64


def make_request(url, method, body, auth_header, verify_ssl=True):
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", auth_header)
    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, context=ctx) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def put(host, path, body, auth, verify_ssl):
    status, resp = make_request(f"{host}{path}", "PUT", body, auth, verify_ssl)
    ok = status in (200, 201)
    print(f"  {'✓' if ok else '✗'} [{status}] PUT {path}")
    if not ok:
        print(f"      {resp}")
    return ok


# ─── Shared geo block — reused across multiple templates ──────────────────────
def _geo(extra=None):
    props = {
        "location":          {"type": "geo_point"},
        "country_iso_code":  {"type": "keyword"},
        "city_name":         {"type": "keyword"},
        "region_name":       {"type": "keyword"},
    }
    if extra:
        props.update(extra)
    return {"properties": props}


def _source_with_geo():
    return {
        "properties": {
            "ip":      {"type": "ip"},
            "address": {"type": "keyword"},
            "port":    {"type": "integer"},
            "bytes":   {"type": "long"},
            "packets": {"type": "integer"},
            "geo":     _geo(),
        }
    }


def _client_with_geo():
    return {
        "properties": {
            "ip":      {"type": "ip"},
            "address": {"type": "keyword"},
            "geo":     _geo(),
            "user":    {"properties": {"id": {"type": "keyword"}, "name": {"type": "keyword"}}},
        }
    }


def _user_block():
    return {
        "properties": {
            "id":        {"type": "keyword"},
            "name":      {"type": "keyword"},
            "email":     {"type": "keyword"},
            "roles":     {"type": "keyword"},
            "full_name": {"type": "keyword"},
            "domain":    {"type": "keyword"},
        }
    }


def _http_block():
    return {
        "properties": {
            "version": {"type": "keyword"},
            "request":  {"properties": {"method": {"type": "keyword"}}},
            "response": {
                "properties": {
                    "status_code": {"type": "integer"},
                    "body": {"properties": {"bytes": {"type": "long"}}},
                }
            },
        }
    }


def _service_block():
    return {
        "properties": {
            "name":        {"type": "keyword"},
            "type":        {"type": "keyword"},
            "address":     {"type": "keyword"},
            "version":     {"type": "keyword"},
            "environment": {"type": "keyword"},
        }
    }


def _metricset_block():
    return {
        "properties": {
            "name":   {"type": "keyword"},
            "period": {"type": "long"},
        }
    }


def setup(host, user, password, verify_ssl):
    creds = base64.b64encode(f"{user}:{password}".encode()).decode()
    auth  = f"Basic {creds}"


    # =========================================================================
    # COMPONENT TEMPLATES
    # =========================================================================
    print("▸ Component templates…")

    put(host, "/_component_template/mortgage-common@mappings", {
        "template": {
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "ecs":        {"properties": {"version": {"type": "keyword"}}},
                    "data_stream": {
                        "properties": {
                            "type":      {"type": "constant_keyword"},
                            "dataset":   {"type": "constant_keyword"},
                            "namespace": {"type": "constant_keyword"},
                        }
                    },
                    "host": {
                        "properties": {
                            "hostname":     {"type": "keyword"},
                            "name":         {"type": "keyword"},
                            "type":         {"type": "keyword"},
                            "architecture": {"type": "keyword"},
                            "os": {
                                "properties": {
                                    "type":    {"type": "keyword"},
                                    "name":    {"type": "keyword"},
                                    "version": {"type": "keyword"},
                                    "family":  {"type": "keyword"},
                                }
                            },
                        }
                    },
                    "agent": {
                        "properties": {
                            "type":    {"type": "keyword"},
                            "version": {"type": "keyword"},
                            "name":    {"type": "keyword"},
                            "id":      {"type": "keyword"},
                        }
                    },
                    "event": {
                        "properties": {
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
                        }
                    },
                    "tags":    {"type": "keyword"},
                    "message": {"type": "text"},
                    "input":   {"properties": {"type": {"type": "keyword"}}},
                    "log": {
                        "properties": {
                            "level":  {"type": "keyword"},
                            "offset": {"type": "long"},
                            "file":   {"properties": {"path": {"type": "keyword"}}},
                            "flags":  {"type": "keyword"},
                        }
                    },
                    "observer": {
                        "properties": {
                            "type":   {"type": "keyword"},
                            "vendor": {"type": "keyword"},
                        }
                    },
                    "network": {
                        "properties": {
                            "protocol":     {"type": "keyword"},
                            "transport":    {"type": "keyword"},
                            "type":         {"type": "keyword"},
                            "iana_number":  {"type": "keyword"},
                            "bytes":        {"type": "long"},
                            "packets":      {"type": "long"},
                            "community_id": {"type": "keyword"},
                        }
                    },
                    "cloud": {
                        "properties": {
                            "provider":           {"type": "keyword"},
                            "region":             {"type": "keyword"},
                            "availability_zone":  {"type": "keyword"},
                            "account":            {"properties": {"id": {"type": "keyword"}}},
                        }
                    },
                    "tls": {
                        "properties": {
                            "version":          {"type": "keyword"},
                            "version_protocol": {"type": "keyword"},
                        }
                    },
                    "rule": {
                        "properties": {
                            "id":      {"type": "keyword"},
                            "ruleset": {"type": "keyword"},
                            "name":    {"type": "keyword"},
                        }
                    },
                    "process": {
                        "properties": {
                            "name":   {"type": "keyword"},
                            "pid":    {"type": "integer"},
                            "thread": {
                                "properties": {
                                    "id":   {"type": "integer"},
                                    "name": {"type": "keyword"},
                                }
                            },
                        }
                    },
                    "related": {
                        "properties": {
                            "ip":    {"type": "ip"},
                            "hosts": {"type": "keyword"},
                            "user":  {"type": "keyword"},
                        }
                    },
                    "server": {
                        "properties": {
                            "address": {"type": "keyword"},
                            "domain":  {"type": "keyword"},
                        }
                    },
                    "destination": {
                        "properties": {
                            "ip":      {"type": "ip"},
                            "address": {"type": "keyword"},
                            "port":    {"type": "integer"},
                            "bytes":   {"type": "long"},
                        }
                    },
                }
            }
        }
    }, auth, verify_ssl)

    # =========================================================================
    # INDEX TEMPLATES — CORE LENDPATH STREAMS
    # =========================================================================
    print("\n▸ Core LendPath index templates…")

    # ── nginx access ──────────────────────────────────────────────────────────
    put(host, "/_index_template/logs-nginx.access-mortgage", {
        "index_patterns": ["logs-nginx.access-mortgage*"],
        "data_stream": {}, "priority": 300,
        "composed_of": ["mortgage-common@mappings"],
        "template": {
            "settings": {"index": {"lifecycle": {"name": "logs"}}},
            "mappings": {
                "properties": {
                    "http":       _http_block(),
                    "url":        {"properties": {"path": {"type": "keyword"}, "original": {"type": "keyword"}}},
                    "source":     {"properties": {"ip": {"type": "ip"}, "address": {"type": "keyword"}}},
                    "client":     {"properties": {"ip": {"type": "ip"}}},
                    "user_agent": {"properties": {"original": {"type": "keyword"}, "name": {"type": "keyword"}}},
                    "service":    _service_block(),
                    "nginx": {
                        "properties": {
                            "access": {
                                "properties": {
                                    "response_time":  {"type": "long"},
                                    "remote_ip_list": {"type": "ip"},
                                }
                            }
                        }
                    },
                }
            },
        },
    }, auth, verify_ssl)

    # ── nginx error ───────────────────────────────────────────────────────────
    put(host, "/_index_template/logs-nginx.error-mortgage", {
        "index_patterns": ["logs-nginx.error-mortgage*"],
        "data_stream": {}, "priority": 300,
        "composed_of": ["mortgage-common@mappings"],
        "template": {
            "settings": {"index": {"lifecycle": {"name": "logs"}}},
            "mappings": {
                "properties": {
                    "nginx": {
                        "properties": {
                            "error": {"properties": {"connection_id": {"type": "long"}}}
                        }
                    },
                }
            },
        },
    }, auth, verify_ssl)

    # ── nginx stubstatus ──────────────────────────────────────────────────────
    put(host, "/_index_template/metrics-nginx.stubstatus-mortgage", {
        "index_patterns": ["metrics-nginx.stubstatus-mortgage*"],
        "data_stream": {}, "priority": 300,
        "composed_of": ["mortgage-common@mappings"],
        "template": {
            "settings": {"index": {"lifecycle": {"name": "metrics"}}},
            "mappings": {
                "properties": {
                    "service":    _service_block(),
                    "metricset":  _metricset_block(),
                    "nginx": {
                        "properties": {
                            "stubstatus": {
                                "properties": {
                                    "hostname": {"type": "keyword"},
                                    "active":   {"type": "long"},
                                    "current":  {"type": "long"},
                                    "accepts":  {"type": "long"},
                                    "handled":  {"type": "long"},
                                    "requests": {"type": "long"},
                                    "reading":  {"type": "long"},
                                    "writing":  {"type": "long"},
                                    "waiting":  {"type": "long"},
                                    "dropped":  {"type": "long"},
                                }
                            }
                        }
                    },
                }
            },
        },
    }, auth, verify_ssl)

    # ── LOS application logs ──────────────────────────────────────────────────
    put(host, "/_index_template/logs-mortgage.applications", {
        "index_patterns": ["logs-mortgage.applications-*"],
        "data_stream": {}, "priority": 300,
        "composed_of": ["mortgage-common@mappings"],
        "template": {
            "settings": {"index": {"lifecycle": {"name": "logs"}}},
            "mappings": {
                "properties": {
                    "service": _service_block(),
                    "trace":       {"properties": {"id": {"type": "keyword"}}},
                    "transaction": {"properties": {"id": {"type": "keyword"}}},
                    "span":        {"properties": {"id": {"type": "keyword"}}},
                    "mortgage": {
                        "properties": {
                            "application": {
                                "properties": {
                                    "id":              {"type": "keyword"},
                                    "stage":           {"type": "keyword"},
                                    "loan_type":       {"type": "keyword"},
                                    "loan_purpose":    {"type": "keyword"},
                                    "loan_amount":     {"type": "float"},
                                    "property_value":  {"type": "float"},
                                    "ltv_ratio":       {"type": "float"},
                                    "dti_ratio":       {"type": "float"},
                                    "credit_score":    {"type": "integer"},
                                    "interest_rate":   {"type": "float"},
                                    "term_months":     {"type": "integer"},
                                    "days_in_stage":   {"type": "integer"},
                                    "loan_officer_id": {"type": "keyword"},
                                    "branch":          {"type": "keyword"},
                                }
                            }
                        }
                    },
                }
            },
        },
    }, auth, verify_ssl)

    # ── service metrics ───────────────────────────────────────────────────────
    put(host, "/_index_template/metrics-mortgage.services", {
        "index_patterns": ["metrics-mortgage.services-*"],
        "data_stream": {}, "priority": 300,
        "composed_of": ["mortgage-common@mappings"],
        "template": {
            "settings": {"index": {"lifecycle": {"name": "metrics"}}},
            "mappings": {
                "properties": {
                    "service": _service_block(),
                    "jvm": {
                        "properties": {
                            "memory": {
                                "properties": {
                                    "heap": {
                                        "properties": {
                                            "used":    {"properties": {"bytes": {"type": "long"}}},
                                            "max":     {"properties": {"bytes": {"type": "long"}}},
                                            "percent": {"type": "float"},
                                        }
                                    }
                                }
                            },
                            "gc": {
                                "properties": {
                                    "collection": {
                                        "properties": {
                                            "time_ms": {"type": "long"},
                                            "count":   {"type": "long"},
                                        }
                                    }
                                }
                            },
                            "threads": {"properties": {"count": {"type": "integer"}}},
                        }
                    },
                    "http": {
                        "properties": {
                            "server": {
                                "properties": {
                                    "requests": {
                                        "properties": {
                                            "count":       {"type": "long"},
                                            "error_count": {"type": "long"},
                                            "latency": {
                                                "properties": {
                                                    "p50_ms": {"type": "float"},
                                                    "p95_ms": {"type": "float"},
                                                    "p99_ms": {"type": "float"},
                                                }
                                            },
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "db": {
                        "properties": {
                            "pool": {
                                "properties": {
                                    "active_connections": {"type": "integer"},
                                    "idle_connections":   {"type": "integer"},
                                    "max_connections":    {"type": "integer"},
                                    "wait_count":         {"type": "integer"},
                                    "timeout_count":      {"type": "integer"},
                                }
                            }
                        }
                    },
                    "mortgage": {
                        "properties": {
                            "metrics": {
                                "properties": {
                                    "applications_per_min":    {"type": "float"},
                                    "decisions_per_min":       {"type": "float"},
                                    "queue_depth":             {"type": "integer"},
                                    "avg_processing_time_sec": {"type": "float"},
                                }
                            }
                        }
                    },
                }
            },
        },
    }, auth, verify_ssl)

    # ── APM spans / traces ────────────────────────────────────────────────────
    # ── APM transactions + spans  (traces-apm-mortgage) ─────────────────────────
    # Matches the traces-apm* index pattern that Kibana APM UI queries.
    # Includes all fields required by the APM UI:
    #   processor.event/name  — classifies document type (transaction vs span)
    #   service.language.*    — used for agent icon and language filter
    #   service.node.name     — instance identity in the service map
    #   transaction.result    — HTTP 2xx / 4xx / 5xx in the transactions table
    #   transaction.sampled   — required for trace waterfall rendering
    #   destination.service.* — drives edges in the APM service map
    #   parent.id             — links spans to their parent transaction/span
    put(host, "/_index_template/traces-apm-mortgage", {
        "index_patterns": ["traces-apm-mortgage*"],
        "data_stream": {}, "priority": 300,
        "composed_of": ["mortgage-common@mappings"],
        "template": {
            "settings": {"index": {"lifecycle": {"name": "traces"}}},
            "mappings": {
                "properties": {
                    "service": {
                        "properties": {
                            "name":        {"type": "keyword"},
                            "version":     {"type": "keyword"},
                            "environment": {"type": "keyword"},
                            "node":        {"properties": {"name": {"type": "keyword"}}},
                            "language": {
                                "properties": {
                                    "name":    {"type": "keyword"},
                                    "version": {"type": "keyword"},
                                }
                            },
                            "runtime": {
                                "properties": {
                                    "name":    {"type": "keyword"},
                                    "version": {"type": "keyword"},
                                }
                            },
                            "framework": {
                                "properties": {
                                    "name":    {"type": "keyword"},
                                    "version": {"type": "keyword"},
                                }
                            },
                        }
                    },
                    # processor fields — the single most important APM UI requirement
                    "processor": {
                        "properties": {
                            "event": {"type": "keyword"},
                            "name":  {"type": "keyword"},
                        }
                    },
                    "trace":       {"properties": {"id": {"type": "keyword"}}},
                    "parent":      {"properties": {"id": {"type": "keyword"}}},
                    "transaction": {
                        "properties": {
                            "id":       {"type": "keyword"},
                            "name":     {"type": "keyword"},
                            "type":     {"type": "keyword"},
                            "result":   {"type": "keyword"},
                            "sampled":  {"type": "boolean"},
                            "duration": {"properties": {"us": {"type": "long"}}},
                        }
                    },
                    "span": {
                        "properties": {
                            "id":       {"type": "keyword"},
                            "name":     {"type": "keyword"},
                            "type":     {"type": "keyword"},
                            "subtype":  {"type": "keyword"},
                            "action":   {"type": "keyword"},
                            "duration": {"properties": {"us": {"type": "long"}}},
                        }
                    },
                    # destination.service — drives APM service map topology edges
                    "destination": {
                        "properties": {
                            "service": {
                                "properties": {
                                    "name":     {"type": "keyword"},
                                    "resource": {"type": "keyword"},
                                    "type":     {"type": "keyword"},
                                }
                            }
                        }
                    },
                    "client":  _client_with_geo(),
                    "user":    _user_block(),
                    "http":    _http_block(),
                    "url": {
                        "properties": {
                            "full":   {"type": "keyword"},
                            "path":   {"type": "keyword"},
                            "domain": {"type": "keyword"},
                        }
                    },
                    "labels": {
                        "properties": {
                            "loan_amount":          {"type": "float"},
                            "session_duration_sec": {"type": "integer"},
                            "pages_visited":        {"type": "integer"},
                            "docs_downloaded":      {"type": "integer"},
                            "failed_auth_attempts": {"type": "integer"},
                        }
                    },
                }
            },
        },
    }, auth, verify_ssl)

    # ── internal audit ────────────────────────────────────────────────────────
    put(host, "/_index_template/logs-mortgage.audit", {
        "index_patterns": ["logs-mortgage.audit-*"],
        "data_stream": {}, "priority": 300,
        "composed_of": ["mortgage-common@mappings"],
        "template": {
            "settings": {"index": {"lifecycle": {"name": "logs"}}},
            "mappings": {
                "properties": {
                    "user":     _user_block(),
                    "source":   _source_with_geo(),
                    "file":     {"properties": {"name": {"type": "keyword"}}},
                    "database": {"properties": {"instance": {"type": "keyword"}}},
                    "audit": {
                        "properties": {
                            "risk_score":  {"type": "float"},
                            "is_suspicious": {"type": "keyword"},
                            "session_id":  {"type": "keyword"},
                            "mfa_used":    {"type": "boolean"},
                            "off_hours":   {"type": "boolean"},
                            "new_device":  {"type": "boolean"},
                            "vpn_detected": {"type": "boolean"},
                        }
                    },
                }
            },
        },
    }, auth, verify_ssl)

    # ── host system metrics ───────────────────────────────────────────────────
    put(host, "/_index_template/metrics-mortgage.hosts", {
        "index_patterns": ["metrics-mortgage.hosts-*"],
        "data_stream": {}, "priority": 300,
        "composed_of": ["mortgage-common@mappings"],
        "template": {
            "settings": {"index": {"lifecycle": {"name": "metrics"}}},
            "mappings": {
                "properties": {
                    "system": {
                        "properties": {
                            "cpu": {
                                "properties": {
                                    "total":  {"properties": {"pct": {"type": "float"}}},
                                    "user":   {"properties": {"pct": {"type": "float"}}},
                                    "system": {"properties": {"pct": {"type": "float"}}},
                                    "iowait": {"properties": {"pct": {"type": "float"}}},
                                    "cores":  {"type": "integer"},
                                }
                            },
                            "memory": {
                                "properties": {
                                    "total": {"type": "long"},
                                    "used":  {"properties": {"bytes": {"type": "long"}, "pct": {"type": "float"}}},
                                    "free":  {"type": "long"},
                                }
                            },
                            "filesystem": {"properties": {"used": {"properties": {"pct": {"type": "float"}}}}},
                            "diskio": {
                                "properties": {
                                    "read":  {"properties": {"bytes": {"type": "long"}}},
                                    "write": {"properties": {"bytes": {"type": "long"}}},
                                }
                            },
                            "network": {
                                "properties": {
                                    "in":  {"properties": {"bytes": {"type": "long"}, "errors": {"type": "integer"}}},
                                    "out": {"properties": {"bytes": {"type": "long"}, "errors": {"type": "integer"}}},
                                }
                            },
                            "load": {
                                "properties": {
                                    "1": {"type": "float"}, "5": {"type": "float"},
                                    "15": {"type": "float"}, "cores": {"type": "integer"},
                                }
                            },
                        }
                    },
                    "mortgage": {
                        "properties": {
                            "host": {
                                "properties": {
                                    "memory_pressure_score": {"type": "float"},
                                    "incident_count":        {"type": "integer"},
                                    "role":                  {"type": "keyword"},
                                }
                            }
                        }
                    },
                }
            },
        },
    }, auth, verify_ssl)

    # =========================================================================
    # INDEX TEMPLATES — INTEGRATION STREAMS
    # =========================================================================
    print("\n▸ Integration index templates…")

    # ── Akamai SIEM ───────────────────────────────────────────────────────────
    put(host, "/_index_template/logs-akamai.siem-mortgage", {
        "index_patterns": ["logs-akamai.siem-mortgage*"],
        "data_stream": {}, "priority": 300,
        "composed_of": ["mortgage-common@mappings"],
        "template": {
            "settings": {"index": {"lifecycle": {"name": "logs"}}},
            "mappings": {
                "properties": {
                    "source":  _source_with_geo(),
                    "client":  _client_with_geo(),
                    "http":    _http_block(),
                    "url": {
                        "properties": {
                            "domain":   {"type": "keyword"},
                            "path":     {"type": "keyword"},
                            "full":     {"type": "keyword"},
                            "query":    {"type": "keyword"},
                            "port":     {"type": "integer"},
                        }
                    },
                    "akamai": {
                        "properties": {
                            "siem": {
                                "properties": {
                                    "config_id":  {"type": "keyword"},
                                    "policy_id":  {"type": "keyword"},
                                    "rule_actions": {"type": "keyword"},
                                    "rule_tags":    {"type": "keyword"},
                                    "bot": {
                                        "properties": {
                                            "score":            {"type": "integer"},
                                            "response_segment": {"type": "integer"},
                                        }
                                    },
                                    "user_risk": {
                                        "properties": {
                                            "score":  {"type": "integer"},
                                            "status": {"type": "integer"},
                                            "allow":  {"type": "integer"},
                                            "uuid":   {"type": "keyword"},
                                            "trust":  {"properties": {"ugp": {"type": "keyword"}}},
                                            "general": {
                                                "properties": {
                                                    "duc_1d": {"type": "keyword"},
                                                    "duc_1h": {"type": "keyword"},
                                                }
                                            },
                                        }
                                    },
                                    "client_data": {
                                        "properties": {
                                            "app_bundle_id": {"type": "keyword"},
                                            "app_version":   {"type": "keyword"},
                                            "sdk_version":   {"type": "keyword"},
                                            "telemetry_type": {"type": "integer"},
                                        }
                                    },
                                }
                            }
                        }
                    },
                }
            },
        },
    }, auth, verify_ssl)

    # ── AWS VPC Flow ──────────────────────────────────────────────────────────
    put(host, "/_index_template/logs-aws.vpcflow-mortgage", {
        "index_patterns": ["logs-aws.vpcflow-mortgage*"],
        "data_stream": {}, "priority": 300,
        "composed_of": ["mortgage-common@mappings"],
        "template": {
            "settings": {"index": {"lifecycle": {"name": "logs"}}},
            "mappings": {
                "properties": {
                    "source":      _source_with_geo(),
                    "destination": {
                        "properties": {
                            "ip":      {"type": "ip"},
                            "address": {"type": "keyword"},
                            "port":    {"type": "integer"},
                            "bytes":   {"type": "long"},
                        }
                    },
                }
            },
        },
    }, auth, verify_ssl)

    # ── AWS WAF ───────────────────────────────────────────────────────────────
    put(host, "/_index_template/logs-aws.waf-mortgage", {
        "index_patterns": ["logs-aws.waf-mortgage*"],
        "data_stream": {}, "priority": 300,
        "composed_of": ["mortgage-common@mappings"],
        "template": {
            "settings": {"index": {"lifecycle": {"name": "logs"}}},
            "mappings": {
                "properties": {
                    "source": {"properties": {"ip": {"type": "ip"}}},
                    "url":    {"properties": {"path": {"type": "keyword"}}},
                    "http":   _http_block(),
                    "aws": {
                        "properties": {
                            "waf": {
                                "properties": {
                                    "arn":            {"type": "keyword"},
                                    "id":             {"type": "keyword"},
                                    "format_version": {"type": "keyword"},
                                    "request": {
                                        "properties": {
                                            "headers": {
                                                "properties": {
                                                    "User-Agent": {"type": "keyword"},
                                                    "Host":       {"type": "keyword"},
                                                }
                                            }
                                        }
                                    },
                                }
                            },
                            "s3": {
                                "properties": {
                                    "bucket": {"properties": {"arn": {"type": "keyword"}, "name": {"type": "keyword"}}},
                                    "object": {"properties": {"key": {"type": "keyword"}}},
                                }
                            },
                        }
                    },
                }
            },
        },
    }, auth, verify_ssl)

    # ── CoreDNS ───────────────────────────────────────────────────────────────
    put(host, "/_index_template/logs-coredns.log-mortgage", {
        "index_patterns": ["logs-coredns.log-mortgage*"],
        "data_stream": {}, "priority": 300,
        "composed_of": ["mortgage-common@mappings"],
        "template": {
            "settings": {"index": {"lifecycle": {"name": "logs"}}},
            "mappings": {
                "properties": {
                    "source": {"properties": {"ip": {"type": "ip"}, "port": {"type": "integer"}}},
                    "dns": {
                        "properties": {
                            "id":            {"type": "keyword"},
                            "response_code": {"type": "keyword"},
                            "header_flags":  {"type": "keyword"},
                            "question": {
                                "properties": {
                                    "type":              {"type": "keyword"},
                                    "class":             {"type": "keyword"},
                                    "name":              {"type": "keyword"},
                                    "registered_domain": {"type": "keyword"},
                                    "top_level_domain":  {"type": "keyword"},
                                }
                            },
                        }
                    },
                    "destination": {"properties": {"bytes": {"type": "integer"}}},
                    "coredns": {
                        "properties": {
                            "log": {
                                "properties": {
                                    "buffer_size": {"type": "integer"},
                                    "dnssec_ok":   {"type": "boolean"},
                                }
                            }
                        }
                    },
                }
            },
        },
    }, auth, verify_ssl)

    # ── HAProxy access logs ───────────────────────────────────────────────────
    put(host, "/_index_template/logs-haproxy.log-mortgage", {
        "index_patterns": ["logs-haproxy.log-mortgage*"],
        "data_stream": {}, "priority": 300,
        "composed_of": ["mortgage-common@mappings"],
        "template": {
            "settings": {"index": {"lifecycle": {"name": "logs"}}},
            "mappings": {
                "properties": {
                    "source": {"properties": {"ip": {"type": "ip"}, "address": {"type": "keyword"}, "port": {"type": "integer"}}},
                    "http":   _http_block(),
                    "haproxy": {
                        "properties": {
                            "frontend_name":          {"type": "keyword"},
                            "backend_name":           {"type": "keyword"},
                            "backend_queue":          {"type": "integer"},
                            "bytes_read":             {"type": "long"},
                            "connection_wait_time_ms": {"type": "integer"},
                            "server_name":            {"type": "keyword"},
                            "server_queue":           {"type": "integer"},
                            "total_waiting_time_ms":  {"type": "integer"},
                            "connections": {
                                "properties": {
                                    "active":   {"type": "integer"},
                                    "backend":  {"type": "integer"},
                                    "frontend": {"type": "integer"},
                                    "retries":  {"type": "integer"},
                                    "server":   {"type": "integer"},
                                }
                            },
                            "http": {
                                "properties": {
                                    "request": {
                                        "properties": {
                                            "raw_request_line":           {"type": "keyword"},
                                            "time_wait_ms":               {"type": "integer"},
                                            "time_wait_without_data_ms":  {"type": "integer"},
                                            "captured_cookie":            {"type": "keyword"},
                                        }
                                    },
                                    "response": {
                                        "properties": {
                                            "captured_cookie": {"type": "keyword"},
                                        }
                                    },
                                }
                            },
                        }
                    },
                }
            },
        },
    }, auth, verify_ssl)

    # ── HAProxy stat metrics ──────────────────────────────────────────────────
    put(host, "/_index_template/metrics-haproxy.stat-mortgage", {
        "index_patterns": ["metrics-haproxy.stat-mortgage*"],
        "data_stream": {}, "priority": 300,
        "composed_of": ["mortgage-common@mappings"],
        "template": {
            "settings": {"index": {"lifecycle": {"name": "metrics"}}},
            "mappings": {
                "properties": {
                    "haproxy": {
                        "properties": {
                            "stat": {
                                "properties": {
                                    "proxy":          {"properties": {"id": {"type": "integer"}, "name": {"type": "keyword"}}},
                                    "service_name":   {"type": "keyword"},
                                    "component_type": {"type": "integer"},
                                    "in":             {"properties": {"bytes": {"type": "long"}}},
                                    "out":            {"properties": {"bytes": {"type": "long"}}},
                                    "connection":     {"properties": {"total": {"type": "long"}}},
                                    "request": {
                                        "properties": {
                                            "total":  {"type": "long"},
                                            "errors": {"type": "integer"},
                                            "denied": {"type": "integer"},
                                            "rate":   {"properties": {"value": {"type": "integer"}, "max": {"type": "integer"}}},
                                        }
                                    },
                                    "response": {
                                        "properties": {
                                            "denied": {"type": "integer"},
                                            "http": {
                                                "properties": {
                                                    "1xx":   {"type": "integer"},
                                                    "2xx":   {"type": "long"},
                                                    "3xx":   {"type": "integer"},
                                                    "4xx":   {"type": "integer"},
                                                    "5xx":   {"type": "integer"},
                                                    "other": {"type": "integer"},
                                                }
                                            },
                                        }
                                    },
                                    "session": {
                                        "properties": {
                                            "current": {"type": "integer"},
                                            "max":     {"type": "integer"},
                                            "limit":   {"type": "integer"},
                                        }
                                    },
                                    "server": {"properties": {"id": {"type": "integer"}}},
                                    "compressor": {
                                        "properties": {
                                            "bypassed":  {"properties": {"bytes": {"type": "long"}}},
                                            "in":        {"properties": {"bytes": {"type": "long"}}},
                                            "out":       {"properties": {"bytes": {"type": "long"}}},
                                            "response":  {"properties": {"bytes": {"type": "long"}}},
                                        }
                                    },
                                    "check": {
                                        "properties": {
                                            "status":       {"type": "keyword"},
                                            "health.last":  {"type": "keyword"},
                                            "agent.last":   {"type": "keyword"},
                                        }
                                    },
                                    "queue": {"type": "object"},
                                }
                            }
                        }
                    },
                }
            },
        },
    }, auth, verify_ssl)

    # ── HAProxy info metrics ──────────────────────────────────────────────────
    put(host, "/_index_template/metrics-haproxy.info-mortgage", {
        "index_patterns": ["metrics-haproxy.info-mortgage*"],
        "data_stream": {}, "priority": 300,
        "composed_of": ["mortgage-common@mappings"],
        "template": {
            "settings": {"index": {"lifecycle": {"name": "metrics"}}},
            "mappings": {
                "properties": {
                    "haproxy": {
                        "properties": {
                            "info": {
                                "properties": {
                                    "process_num": {"type": "integer"},
                                    "processes":   {"type": "integer"},
                                    "run_queue":   {"type": "integer"},
                                    "idle":        {"properties": {"pct": {"type": "float"}}},
                                    "memory":      {"properties": {"max": {"properties": {"bytes": {"type": "long"}}}}},
                                    "requests":    {"properties": {"total": {"type": "long"}}},
                                    "pipes": {
                                        "properties": {
                                            "free": {"type": "integer"},
                                            "used": {"type": "integer"},
                                            "max":  {"type": "integer"},
                                        }
                                    },
                                    "connection": {
                                        "properties": {
                                            "current":  {"type": "integer"},
                                            "max":      {"type": "integer"},
                                            "hard_max": {"type": "integer"},
                                            "total":    {"type": "long"},
                                            "rate": {
                                                "properties": {
                                                    "limit": {"type": "integer"},
                                                    "max":   {"type": "integer"},
                                                    "value": {"type": "integer"},
                                                }
                                            },
                                            "ssl": {
                                                "properties": {
                                                    "current": {"type": "integer"},
                                                    "max":     {"type": "integer"},
                                                    "total":   {"type": "long"},
                                                }
                                            },
                                        }
                                    },
                                    "compress": {
                                        "properties": {
                                            "bps": {
                                                "properties": {
                                                    "in":         {"type": "long"},
                                                    "out":        {"type": "long"},
                                                    "rate_limit": {"type": "long"},
                                                }
                                            }
                                        }
                                    },
                                }
                            }
                        }
                    },
                }
            },
        },
    }, auth, verify_ssl)

    # ── Kafka broker metrics ──────────────────────────────────────────────────
    put(host, "/_index_template/metrics-kafka.broker-mortgage", {
        "index_patterns": ["metrics-kafka.broker-mortgage*"],
        "data_stream": {}, "priority": 300,
        "composed_of": ["mortgage-common@mappings"],
        "template": {
            "settings": {"index": {"lifecycle": {"name": "metrics"}}},
            "mappings": {
                "properties": {
                    "kafka": {
                        "properties": {
                            "broker": {
                                "properties": {
                                    "mbean":   {"type": "keyword"},
                                    "address": {"type": "keyword"},
                                    "id":      {"type": "integer"},
                                    "topic": {
                                        "properties": {
                                            "net": {
                                                "properties": {
                                                    "out": {"properties": {"bytes_per_sec": {"type": "float"}}},
                                                    "in":  {"properties": {"bytes_per_sec": {"type": "float"}}},
                                                }
                                            }
                                        }
                                    },
                                }
                            },
                            "topic": {"properties": {"name": {"type": "keyword"}}},
                        }
                    },
                }
            },
        },
    }, auth, verify_ssl)

    # ── Kafka partition metrics ───────────────────────────────────────────────
    put(host, "/_index_template/metrics-kafka.partition-mortgage", {
        "index_patterns": ["metrics-kafka.partition-mortgage*"],
        "data_stream": {}, "priority": 300,
        "composed_of": ["mortgage-common@mappings"],
        "template": {
            "settings": {"index": {"lifecycle": {"name": "metrics"}}},
            "mappings": {
                "properties": {
                    "kafka": {
                        "properties": {
                            "broker": {
                                "properties": {
                                    "address": {"type": "keyword"},
                                    "id":      {"type": "integer"},
                                }
                            },
                            "topic": {"properties": {"name": {"type": "keyword"}}},
                            "partition": {
                                "properties": {
                                    "id":             {"type": "integer"},
                                    "topic_broker_id": {"type": "keyword"},
                                    "topic_id":        {"type": "keyword"},
                                    "offset": {
                                        "properties": {
                                            "newest": {"type": "long"},
                                            "oldest": {"type": "long"},
                                        }
                                    },
                                    "partition": {
                                        "properties": {
                                            "insync_replica": {"type": "boolean"},
                                            "is_leader":      {"type": "boolean"},
                                            "leader":         {"type": "integer"},
                                            "replica":        {"type": "integer"},
                                        }
                                    },
                                }
                            },
                        }
                    },
                }
            },
        },
    }, auth, verify_ssl)

    # ── Oracle database audit ─────────────────────────────────────────────────
    put(host, "/_index_template/logs-oracle.database_audit-mortgage", {
        "index_patterns": ["logs-oracle.database_audit-mortgage*"],
        "data_stream": {}, "priority": 300,
        "composed_of": ["mortgage-common@mappings"],
        "template": {
            "settings": {"index": {"lifecycle": {"name": "logs"}}},
            "mappings": {
                "properties": {
                    "user":   _user_block(),
                    "client": {"properties": {"user": {"properties": {"name": {"type": "keyword"}}}}},
                    "oracle": {
                        "properties": {
                            "database_audit": {
                                "properties": {
                                    "action":         {"type": "keyword"},
                                    "action_number":  {"type": "integer"},
                                    "entry":          {"properties": {"id": {"type": "long"}}},
                                    "length":         {"type": "integer"},
                                    "privilege":      {"type": "keyword"},
                                    "result_code":    {"type": "integer"},
                                    "session_id":     {"type": "long"},
                                    "status":         {"type": "keyword"},
                                    "terminal":       {"type": "keyword"},
                                    "database":       {"properties": {"user": {"type": "keyword"}}},
                                    "obj": {
                                        "properties": {
                                            "name":   {"type": "keyword"},
                                            "schema": {"type": "keyword"},
                                        }
                                    },
                                }
                            }
                        }
                    },
                }
            },
        },
    }, auth, verify_ssl)

    # ── Oracle sysmetric ──────────────────────────────────────────────────────
    put(host, "/_index_template/metrics-oracle.sysmetric-mortgage", {
        "index_patterns": ["metrics-oracle.sysmetric-mortgage*"],
        "data_stream": {}, "priority": 300,
        "composed_of": ["mortgage-common@mappings"],
        "template": {
            "settings": {"index": {"lifecycle": {"name": "metrics"}}},
            "mappings": {
                "properties": {
                    "service":    _service_block(),
                    "metricset":  _metricset_block(),
                    "oracle": {
                        "properties": {
                            "sysmetric": {
                                "properties": {
                                    # Key float metrics — all others auto-mapped as float is fine
                                    "average_active_sessions":      {"type": "float"},
                                    "buffer_cache_hit_ratio":       {"type": "float"},
                                    "cpu_usage_per_sec":            {"type": "float"},
                                    "current_logons_count":         {"type": "integer"},
                                    "current_open_cursors_count":   {"type": "integer"},
                                    "database_cpu_time_ratio":      {"type": "float"},
                                    "database_time_per_sec":        {"type": "float"},
                                    "database_wait_time_ratio":     {"type": "float"},
                                    "executions_per_sec":           {"type": "float"},
                                    "hard_parse_count_per_sec":     {"type": "float"},
                                    "host_cpu_utilization_pct":     {"type": "float"},
                                    "io_megabytes_per_second":      {"type": "float"},
                                    "library_cache_hit_ratio":      {"type": "float"},
                                    "library_cache_miss_ratio":     {"type": "float"},
                                    "logical_reads_per_sec":        {"type": "float"},
                                    "physical_reads_per_sec":       {"type": "float"},
                                    "redo_generated_per_sec":       {"type": "float"},
                                    "response_time_per_txn":        {"type": "float"},
                                    "session_count":                {"type": "integer"},
                                    "session_limit_pct":            {"type": "float"},
                                    "shared_pool_free_pct":         {"type": "float"},
                                    "sql_service_response_time":    {"type": "float"},
                                    "user_transaction_per_sec":     {"type": "float"},
                                    "active_serial_sessions":       {"type": "integer"},
                                    "active_parallel_sessions":     {"type": "integer"},
                                }
                            }
                        }
                    },
                }
            },
        },
    }, auth, verify_ssl)

    # ── Oracle tablespace ─────────────────────────────────────────────────────
    put(host, "/_index_template/metrics-oracle.tablespace-mortgage", {
        "index_patterns": ["metrics-oracle.tablespace-mortgage*"],
        "data_stream": {}, "priority": 300,
        "composed_of": ["mortgage-common@mappings"],
        "template": {
            "settings": {"index": {"lifecycle": {"name": "metrics"}}},
            "mappings": {
                "properties": {
                    "service":   _service_block(),
                    "metricset": _metricset_block(),
                    "oracle": {
                        "properties": {
                            "tablespace": {
                                "properties": {
                                    "name":     {"type": "keyword"},
                                    "query_id": {"type": "keyword"},
                                    "extended_space": {
                                        "properties": {
                                            "free":  {"properties": {"bytes": {"type": "long"}}},
                                            "total": {"properties": {"bytes": {"type": "long"}}},
                                        }
                                    },
                                }
                            }
                        }
                    },
                }
            },
        },
    }, auth, verify_ssl)

    # ── PingOne audit ─────────────────────────────────────────────────────────
    put(host, "/_index_template/logs-ping_one.audit-mortgage", {
        "index_patterns": ["logs-ping_one.audit-mortgage*"],
        "data_stream": {}, "priority": 300,
        "composed_of": ["mortgage-common@mappings"],
        "template": {
            "settings": {"index": {"lifecycle": {"name": "logs"}}},
            "mappings": {
                "properties": {
                    "user":   _user_block(),
                    "client": _client_with_geo(),
                    "source": _source_with_geo(),
                    "ping_one": {
                        "properties": {
                            "audit": {
                                "properties": {
                                    "action": {"properties": {"type": {"type": "keyword"}}},
                                    "result": {
                                        "properties": {
                                            "status":      {"type": "keyword"},
                                            "description": {"type": "keyword"},
                                        }
                                    },
                                    "risk": {
                                        "properties": {
                                            "score": {"type": "float"},
                                            "level": {"type": "keyword"},
                                        }
                                    },
                                    "actors": {
                                        "properties": {
                                            "client": {
                                                "properties": {
                                                    "id":   {"type": "keyword"},
                                                    "name": {"type": "keyword"},
                                                    "type": {"type": "keyword"},
                                                    "href": {"type": "keyword"},
                                                    "environment": {"properties": {"id": {"type": "keyword"}}},
                                                }
                                            },
                                            "user": {
                                                "properties": {
                                                    "id":   {"type": "keyword"},
                                                    "name": {"type": "keyword"},
                                                    "type": {"type": "keyword"},
                                                    "href": {"type": "keyword"},
                                                    "environment": {"properties": {"id": {"type": "keyword"}}},
                                                    "population": {"properties": {"id": {"type": "keyword"}}},
                                                }
                                            },
                                        }
                                    },
                                }
                            }
                        }
                    },
                }
            },
        },
    }, auth, verify_ssl)

    # =========================================================================
    print("\n✓ Index templates complete — all 21 data stream templates created.")


# =============================================================================
# ML JOB LOADING
# =============================================================================

def _load_job_files(job_files):
    """Load and merge job definitions from one or more JSON files."""
    anomaly_jobs, dfa_jobs = [], []
    for path in job_files:
        if not os.path.exists(path):
            print(f"  ⚠ Job file not found, skipping: {path}")
            continue
        with open(path) as fh:
            data = json.load(fh)
        anomaly_jobs.extend(data.get("anomaly_detection_jobs", []))
        dfa_jobs.extend(data.get("data_frame_analytics_jobs", []))
        print(f"  ✓ Loaded {path}")
    return anomaly_jobs, dfa_jobs


def _put_ml_job(host, path, body, auth, verify_ssl, label):
    """PUT an ML resource.

    Success: 200 / 201  → ✓
    Already exists:
      - AD jobs return 400 resource_already_exists_exception
      - Datafeeds return 409 status_exception with 'already exists'
      Both are treated as soft warnings → ~
    Any other error → ✗
    """
    status, resp = make_request(f"{host}{path}", "PUT", body, auth, verify_ssl)
    if status in (200, 201):
        print(f"  ✓ [{status}] {label}")
        return True
    # Both 400 (AD jobs) and 409 (datafeeds) can mean "already exists"
    if status in (400, 409):
        resp_text = json.dumps(resp).lower()
        if "already exists" in resp_text or "already used" in resp_text:
            print(f"  ~ [exists] {label}")
            return True
    print(f"  ✗ [{status}] {label}")
    print(f"      {resp}")
    return False


def _post_ml(host, path, body, auth, verify_ssl, label):
    """POST to an ML endpoint (e.g. open job, start datafeed)."""
    status, resp = make_request(f"{host}{path}", "POST", body, auth, verify_ssl)
    ok = status in (200, 201)
    print(f"  {'✓' if ok else '✗'} [{status}] {label}")
    if not ok:
        print(f"      {resp}")
    return ok


def load_anomaly_jobs(host, auth, verify_ssl, job_files, start_datafeeds=False):
    """Create anomaly detection jobs and datafeeds.

    Safe to run before any data exists — AD jobs do not validate that
    source indices are populated at creation time.
    """
    print("\n▸ Loading ML job definition files…")
    anomaly_jobs, _ = _load_job_files(job_files)

    if not anomaly_jobs:
        print("  ⚠ No anomaly detection jobs found.")
        return

    print(f"\n▸ Creating {len(anomaly_jobs)} anomaly detection jobs…")
    datafeeds_to_start = []

    for job in anomaly_jobs:
        job_body = {k: v for k, v in job.items() if not k.startswith("_")}
        datafeed_cfg = job_body.pop("datafeed_config", None)
        job_id = job_body.get("job_id", "unknown")

        _put_ml_job(
            host, f"/_ml/anomaly_detectors/{job_id}",
            job_body, auth, verify_ssl,
            f"AD job: {job_id}"
        )

        if datafeed_cfg:
            datafeed_id = datafeed_cfg.get("datafeed_id", f"datafeed-{job_id}")
            datafeed_cfg["job_id"] = job_id
            _put_ml_job(
                host, f"/_ml/datafeeds/{datafeed_id}",
                datafeed_cfg, auth, verify_ssl,
                f"Datafeed: {datafeed_id}"
            )
            datafeeds_to_start.append((job_id, datafeed_id))

    if start_datafeeds and datafeeds_to_start:
        print(f"\n▸ Opening jobs and starting {len(datafeeds_to_start)} datafeeds…")
        for job_id, datafeed_id in datafeeds_to_start:
            _post_ml(host, f"/_ml/anomaly_detectors/{job_id}/_open",
                     {}, auth, verify_ssl, f"Open job: {job_id}")
            _post_ml(host, f"/_ml/datafeeds/{datafeed_id}/_start",
                     {}, auth, verify_ssl, f"Start datafeed: {datafeed_id}")


def load_dfa_jobs(host, auth, verify_ssl, job_files, run_dfa=False):
    """Create Data Frame Analytics jobs.

    IMPORTANT: DFA jobs validate that source indices exist and contain data
    at creation time. Only run this after the SDG has been running long
    enough to populate all source indices (typically 30–60 minutes).

    Required minimum documents per source index:
      Outlier Detection:  1,000+
      Regression:         1,000+
      Classification:     5,000+  (recommended for a useful model)
    """
    _, dfa_jobs = _load_job_files(job_files)

    if not dfa_jobs:
        print("  ⚠ No DFA jobs found.")
        return

    print(f"\n▸ Creating {len(dfa_jobs)} Data Frame Analytics jobs…")
    print("  (source indices must already contain data)")

    created = []
    for job in dfa_jobs:
        job_body = {k: v for k, v in job.items() if not k.startswith("_")}
        job_id = job_body.get("id", "unknown")
        ok = _put_ml_job(
            host, f"/_ml/data_frame/analytics/{job_id}",
            job_body, auth, verify_ssl,
            f"DFA job: {job_id}"
        )
        if ok:
            created.append(job_id)

    if run_dfa and created:
        print(f"\n▸ Starting {len(created)} DFA jobs…")
        for job_id in created:
            _post_ml(host, f"/_ml/data_frame/analytics/{job_id}/_start",
                     {}, auth, verify_ssl, f"Start DFA: {job_id}")


# kept for backwards compatibility — calls both functions
def load_ml_jobs(host, auth, verify_ssl, job_files,
                 start_datafeeds=False, skip_dfa=True,
                 run_dfa=False):
    load_anomaly_jobs(host, auth, verify_ssl, job_files, start_datafeeds)
    if not skip_dfa:
        load_dfa_jobs(host, auth, verify_ssl, job_files, run_dfa)


# =============================================================================
# ENTRY POINT
# =============================================================================


def make_kibana_request(url, method, body, auth_header, verify_ssl=True):
    """Like make_request but adds the kbn-xsrf header required by Kibana APIs."""
    data = json.dumps(body).encode() if body else None
    req  = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type",  "application/json")
    req.add_header("Authorization", auth_header)
    req.add_header("kbn-xsrf",      "true")           # required by all Kibana write APIs
    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, context=ctx) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {"error": str(e)}


def load_kibana_assets(kibana_host, auth, verify_ssl, vega_files):
    """Upload Vega visualizations to Kibana via the Saved Objects API.

    Each .vega.json file is posted as a visualization saved object.
    Existing objects with the same title are updated (overwrite=true).

    Kibana Saved Objects API:
      POST /api/saved_objects/visualization
      POST /api/saved_objects/_import   (bulk, used for ndjson)

    We use the single-object endpoint to keep dependencies minimal.
    """
    print("\n▸ Uploading Kibana assets…")

    for vega_path in vega_files:
        if not os.path.exists(vega_path):
            print(f"  ⚠ Vega file not found, skipping: {vega_path}")
            continue

        with open(vega_path) as fh:
            try:
                spec = json.load(fh)
            except json.JSONDecodeError as e:
                print(f"  ✗ Invalid JSON in {vega_path}: {e}")
                continue

        # Derive a title from the description field or filename
        title = spec.get("description", os.path.splitext(os.path.basename(vega_path))[0])

        # visState is a JSON-encoded string containing the Vega spec
        vis_state = json.dumps({
            "title":  title,
            "type":   "vega",
            "aggs":   [],
            "params": {
                "spec": json.dumps(spec, separators=(",", ":"))
            },
        })

        body = {
            "attributes": {
                "title":        title,
                "visState":     vis_state,
                "uiStateJSON":  "{}",
                "description":  title,
                "version":      1,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
                },
            }
        }

        # Try to create; if 409 conflict (already exists) update instead
        url    = f"{kibana_host}/api/saved_objects/visualization"
        status, resp = make_kibana_request(url, "POST", body, auth, verify_ssl)

        if status in (200, 201):
            obj_id = resp.get("id", "?")
            print(f"  ✓ [{status}] Vega viz created: {title} (id: {obj_id})")
        elif status == 409:
            # Already exists — update it
            obj_id = resp.get("id") or (resp.get("error", {}) or {}).get("meta", {}).get("id", "")
            if not obj_id:
                # Extract from error message if possible
                err_str = json.dumps(resp)
                import re
                m = re.search(r'"id"\s*:\s*"([^"]+)"', err_str)
                obj_id = m.group(1) if m else None

            if obj_id:
                put_url = f"{kibana_host}/api/saved_objects/visualization/{obj_id}"
                put_body = {"attributes": body["attributes"]}
                s2, r2 = make_kibana_request(put_url, "PUT", put_body, auth, verify_ssl)
                if s2 in (200, 201):
                    print(f"  ~ [updated] Vega viz: {title} (id: {obj_id})")
                else:
                    print(f"  ✗ [{s2}] Could not update Vega viz: {title}")
                    print(f"      {r2}")
            else:
                print(f"  ~ [exists] Vega viz: {title} (could not retrieve id to update)")
        else:
            print(f"  ✗ [{status}] Failed to upload Vega viz: {title}")
            print(f"      {resp}")
            if status in (401, 403):
                print("      Check that --kibana-host is correct and credentials have Kibana write access.")
            elif status == 404:
                print("      Kibana may not be running, or the host/port is wrong.")
                print(f"      Tried: {url}")


def main():
    p = argparse.ArgumentParser(
        description="Bootstrap the LendPath ML Workshop — templates + ML jobs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Step 1 — Run once before starting the SDG (templates + AD jobs + Vega viz):
  python bootstrap.py --host https://localhost:9200 --kibana-host https://localhost:5601 \
      --user elastic --password changeme --no-verify-ssl

  # Step 2 — Start the data generator:
  python run_workshop.py --host https://localhost:9200 --user elastic --password changeme --no-verify-ssl

  # Step 3 — After 30-60 min of data, create DFA jobs:
  python bootstrap.py ... --create-dfa

  # Step 3 (alternative) — Create AND immediately start DFA jobs:
  python bootstrap.py ... --create-dfa --run-dfa

  # Start AD datafeeds immediately (if SDG is already running):
  python bootstrap.py ... --start-datafeeds

  # Templates only, no ML jobs at all, no Kibana:
  python bootstrap.py ... --skip-ml --skip-kibana

  # Use custom job files or Vega spec:
  python bootstrap.py ... --job-files my-jobs.json extra-jobs.json
  python bootstrap.py ... --vega-file my-topology.vega.json
        """,
    )
    p.add_argument("--host",     default="https://localhost:9200",
                   help="Elasticsearch base URL (default: https://localhost:9200)")
    p.add_argument("--user",     default="elastic")
    p.add_argument("--password", default="changeme")
    p.add_argument("--no-verify-ssl", action="store_true",
                   help="Disable SSL certificate verification")
    p.add_argument("--skip-ml", action="store_true",
                   help="Create index templates only; skip all ML job creation")
    p.add_argument("--start-datafeeds", action="store_true",
                   help="Open AD jobs and start datafeeds after creating them "
                        "(only useful if the SDG is already running)")
    p.add_argument("--create-dfa", action="store_true",
                   help="Create Data Frame Analytics jobs. Run this AFTER the "
                        "SDG has populated source indices (30-60 min of data). "
                        "DFA jobs fail at creation if source indices are empty.")
    p.add_argument("--run-dfa", action="store_true",
                   help="Immediately start DFA jobs after creating them "
                        "(only meaningful combined with --create-dfa)")
    p.add_argument("--job-files", nargs="+",
                   default=["ml-job-definitions.json",
                            "ml-job-definitions-integrations.json"],
                   metavar="FILE",
                   help="ML job definition JSON files to load "
                        "(default: ml-job-definitions.json "
                        "ml-job-definitions-integrations.json)")
    p.add_argument("--kibana-host", default="https://localhost:5601",
                   help="Kibana base URL (default: https://localhost:5601)")
    p.add_argument("--skip-kibana", action="store_true",
                   help="Skip Kibana asset upload (Vega visualizations)")
    p.add_argument("--vega-file", nargs="+",
                   default=["lendpath-topology.vega.json"],
                   metavar="FILE",
                   help="Vega spec files to upload to Kibana "
                        "(default: lendpath-topology.vega.json)")
    args = p.parse_args()

    verify_ssl = not args.no_verify_ssl
    creds = base64.b64encode(
        f"{args.user}:{args.password}".encode()
    ).decode()
    auth = f"Basic {creds}"

    print("\n=== LendPath Mortgage ML Workshop — Bootstrap ===")
    print(f"    Target: {args.host}\n")

    # 1. Index templates (always runs)
    setup(args.host, args.user, args.password, verify_ssl)

    # 2. Kibana assets (Vega visualizations)
    if args.skip_kibana:
        print("\n  (--skip-kibana: Kibana asset upload skipped)")
    else:
        load_kibana_assets(
            args.kibana_host, auth, verify_ssl,
            args.vega_file,
        )

    # 3. ML job creation
    if args.skip_ml:
        print("\n  (--skip-ml: all ML job creation skipped)")

    elif args.create_dfa:
        # DFA-only mode — create (and optionally start) DFA jobs
        print("\n▸ Loading ML job definition files…")
        _, _ = _load_job_files(args.job_files)   # prints load summary
        load_dfa_jobs(
            args.host, auth, verify_ssl,
            args.job_files,
            run_dfa=args.run_dfa,
        )

    else:
        # Default — create AD jobs + datafeeds only (safe before SDG runs)
        load_anomaly_jobs(
            args.host, auth, verify_ssl,
            args.job_files,
            start_datafeeds=args.start_datafeeds,
        )

    # 4. Summary
    print("\n" + "=" * 56)
    print("✓ Bootstrap complete.")
    print()

    if args.skip_ml:
        print("  No ML jobs created.")
        print("  Re-run without --skip-ml to create AD jobs.")
    elif args.create_dfa:
        if args.run_dfa:
            print("  DFA jobs created and started.")
            print("  Monitor progress: ML → Data Frame Analytics")
        else:
            print("  DFA jobs created but NOT yet started.")
            print("  Start them in Kibana: ML → Data Frame Analytics → ▶")
            print("  Or re-run with --create-dfa --run-dfa")
    elif args.start_datafeeds:
        print("  AD jobs and datafeeds created and started.")
        print("  Monitor: ML → Anomaly Detection → Jobs")
    else:
        print("  AD jobs + datafeeds created. Datafeeds NOT yet started.")
        print("  Start the SDG, then either:")
        print("    a) Open jobs in Kibana: ML → Anomaly Detection → Jobs → ▶")
        print("    b) Re-run with --start-datafeeds")
        print()
        print("  Once 30–60 min of data has accumulated, create DFA jobs:")
        print("    python bootstrap.py --create-dfa --no-verify-ssl")
        print("      --host ... --user ... --password ...")
    print()
    if not args.skip_kibana:
        print("  Kibana:")
        print("    Dashboards → LendPath Service Network Topology (Vega viz)")
        print()
    print("Workflow:")
    print("  1. python bootstrap.py ...             (this script — run first)")
    print("  2. python run_workshop.py ...          (starts SDG + APM generator)")
    print("  3. Wait 30–60 minutes for data")
    print("  4. Start AD datafeeds in Kibana: ML → Anomaly Detection → Jobs → ▶")
    print("  5. python bootstrap.py --create-dfa ... (after data is populated)")
    print("  6. Follow WORKSHOP_GUIDE.md")
    print()


if __name__ == "__main__":
    main()
