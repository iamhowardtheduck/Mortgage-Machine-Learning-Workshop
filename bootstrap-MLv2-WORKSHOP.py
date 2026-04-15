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
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())
    except Exception as e:
        # Timeout or connection error — return a synthetic error response
        return 0, {"error": {"reason": str(e)}}


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
    # ── APM transactions + spans  (traces-apm-default) ─────────────────────────
    # Matches the traces-apm* index pattern that Kibana APM UI queries.
    # Includes all fields required by the APM UI:
    #   processor.event/name  — classifies document type (transaction vs span)
    #   service.language.*    — used for agent icon and language filter
    #   service.node.name     — instance identity in the service map
    #   service.target.*      — downstream node identity for service map edges (8.x+)
    #   transaction.result    — HTTP 2xx / 4xx / 5xx in the transactions table
    #   transaction.sampled   — required for trace waterfall rendering
    #   destination.service.* — drives edges in the APM service map (legacy + 8.x)
    #   parent.id             — links spans to their parent transaction/span
    put(host, "/_index_template/traces-apm-default", {
        "index_patterns": ["traces-apm-default*"],
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
                            # service.target — required by Kibana 8.x+ APM Service Map
                            # Identifies the downstream service node for each span.
                            # Without this mapping, spans are written but the service
                            # map cannot build edges between services.
                            "target": {
                                "properties": {
                                    "name": {"type": "keyword"},
                                    "type": {"type": "keyword"},
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
                    "timestamp":   {"properties": {"us": {"type": "long"}}},
                    # child.id — set on spans that call downstream app services.
                    # Kibana uses this to confirm destination is a real service
                    # node (circle) not an external dependency (diamond).
                    "child":       {"properties": {"id": {"type": "keyword"}}},
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
                            # span.destination.service.resource — the field Kibana
                            # APM service map aggregates on to draw edges.
                            # Must be nested inside span{} not at top-level.
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
                        }
                    },
                    # top-level destination.service for backwards compatibility
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
                    # source.ip is referenced by the geo ML job as an influencer
                    "source": {
                        "properties": {
                            "ip": {"type": "ip"},
                        }
                    },
                    # observer — required by Kibana APM UI to render service map nodes
                    # and edges. Without observer.type = "apm-server" Kibana will not
                    # process documents as APM data regardless of other field content.
                    "observer": {
                        "properties": {
                            "type":          {"type": "keyword"},
                            "version":       {"type": "keyword"},
                            "version_major": {"type": "integer"},
                        }
                    },
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

    # ── APM JVM + system metrics  (metrics-apm.app.*-default) ──────────────────
    put(host, "/_index_template/metrics-apm.app", {
        "index_patterns": ["metrics-apm.app.*"],
        "data_stream":    {}, "priority": 300,
        "composed_of":    ["mortgage-common@mappings"],
        "template": {
            "settings": {"index": {"lifecycle": {"name": "metrics"}}},
            "mappings": {
                "properties": {
                    "timestamp":  {"properties": {"us": {"type": "long"}}},
                    "metricset":  {"properties": {
                        "name":     {"type": "keyword"},
                        "interval": {"type": "keyword"},
                    }},
                    "labels":    {"properties": {"name": {"type": "keyword"}}},
                    "system": {"properties": {
                        "cpu": {"properties": {
                            "total": {"properties": {
                                "norm": {"properties": {"pct": {"type": "float"}}}
                            }}
                        }},
                        "memory": {"properties": {
                            "actual": {"properties": {"free": {"type": "long"}}},
                            "total":  {"type": "long"},
                        }},
                    }},
                    "jvm": {"properties": {
                        "memory": {"properties": {
                            "heap": {"properties": {
                                "used":      {"type": "long"},
                                "max":       {"type": "long"},
                                "committed": {"type": "long"},
                                "pool": {"properties": {
                                    "used":      {"type": "long"},
                                    "max":       {"type": "long"},
                                    "committed": {"type": "long"},
                                }},
                            }},
                            "non_heap": {"properties": {
                                "used":      {"type": "long"},
                                "committed": {"type": "long"},
                            }},
                        }},
                        "thread": {"properties": {"count": {"type": "integer"}}},
                        "gc":     {"properties": {
                            "time":  {"type": "long"},
                            "count": {"type": "long"},
                            "alloc": {"type": "long"},
                        }},
                    }},
                    "service":   {"properties": {
                        "name":        {"type": "keyword"},
                        "environment": {"type": "keyword"},
                        "version":     {"type": "keyword"},
                        "node":        {"properties": {"name": {"type": "keyword"}}},
                    }},
                    "agent":     {"properties": {
                        "name":    {"type": "keyword"},
                        "version": {"type": "keyword"},
                    }},
                    "observer":  {"properties": {
                        "type":          {"type": "keyword"},
                        "version":       {"type": "keyword"},
                        "version_major": {"type": "integer"},
                    }},
                    "processor": {"properties": {
                        "event": {"type": "keyword"},
                        "name":  {"type": "keyword"},
                    }},
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
                # Runtime mappings make AWS WAF fields visible to _field_caps
                # when this index is queried alongside logs-aws.waf-mortgage
                # in the mortgage-multilayer-security-outlier DFA job.
                "runtime": {
                    "aws.waf.action":            {"type": "keyword"},
                    "http.response.status_code": {"type": "long"},
                },
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
    # NOTE: runtime_mappings here declare the Akamai SIEM fields as present
    # in this index with type double/long. Without this, _field_caps reports
    # them as absent from logs-aws.waf-mortgage and DFA refuses to analyze
    # them — even though runtime_mappings on the DFA job itself would shadow
    # them at query time. _field_caps runs before the query, so the fields
    # must be declared at the index level for DFA to accept them.
    # WAF documents will return null for these fields; DFA handles nulls via
    # missing value imputation, so the job runs correctly across both indices.
    put(host, "/_index_template/logs-aws.waf-mortgage", {
        "index_patterns": ["logs-aws.waf-mortgage*"],
        "data_stream": {}, "priority": 300,
        "composed_of": ["mortgage-common@mappings"],
        "template": {
            "settings": {"index": {"lifecycle": {"name": "logs"}}},
            "mappings": {
                # Runtime mappings make Akamai fields visible to _field_caps
                # so DFA can merge them across logs-aws.waf-mortgage and
                # logs-akamai.siem-mortgage in a single job.
                "runtime": {
                    "akamai.siem.bot.score":          {"type": "double"},
                    "akamai.siem.user_risk.score":    {"type": "double"},
                    "akamai.siem.user_risk.status":   {"type": "long"},
                },
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
# TIMEZONE PICKER — interactive curses GUI with numbered CLI fallback
# =============================================================================

def _get_all_timezones():
    """Return sorted list of all available timezone name strings."""
    try:
        import zoneinfo
        return sorted(zoneinfo.available_timezones())
    except ImportError:
        pass
    try:
        import pytz
        return sorted(pytz.all_timezones)
    except ImportError:
        pass
    # Minimal fallback list
    return [
        "US/Eastern","US/Central","US/Mountain","US/Pacific",
        "US/Alaska","US/Hawaii","America/New_York","America/Chicago",
        "America/Denver","America/Los_Angeles","America/Phoenix",
        "America/Anchorage","America/Honolulu","Europe/London",
        "Europe/Paris","Europe/Berlin","Asia/Tokyo","Asia/Shanghai",
        "Asia/Kolkata","Australia/Sydney","Pacific/Auckland","UTC",
    ]


def _resolve_tzinfo(name):
    """Turn a timezone name string into a tzinfo object."""
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
    return None


def _detect_local_tz():
    """Return local timezone name string."""
    try:
        import tzlocal
        tz = tzlocal.get_localzone()
        return getattr(tz, 'key', getattr(tz, 'zone', str(tz)))
    except Exception:
        pass
    try:
        import datetime as _dt
        offset = -time.timezone if not time.daylight else -time.altzone
        h, m   = divmod(abs(offset) // 60, 60)
        sign   = "+" if offset >= 0 else "-"
        return f"Etc/GMT{sign}{h}" if m == 0 else "UTC"
    except Exception:
        return "UTC"


def _tz_picker_curses(zones, local_tz):
    """
    Interactive curses timezone picker.

    Controls:
      ↑ / ↓          scroll one line
      PgUp / PgDn    scroll one page
      / + typing     filter by search string
      Backspace      delete last search character
      Esc            clear search
      Enter          confirm selection
      q              quit without selecting (uses local tz)
    """
    import curses

    def _run(stdscr):
        curses.curs_set(0)
        curses.use_default_colors()

        # Colour pairs
        curses.init_pair(1, curses.COLOR_CYAN,    -1)   # title
        curses.init_pair(2, curses.COLOR_BLACK,   curses.COLOR_CYAN)  # selected
        curses.init_pair(3, curses.COLOR_YELLOW,  -1)   # hint
        curses.init_pair(4, curses.COLOR_GREEN,   -1)   # local marker
        curses.init_pair(5, curses.COLOR_WHITE,   -1)   # normal

        filtered  = list(zones)
        query     = ""
        cursor    = 0
        scroll    = 0
        selected  = None

        # Try to start with local tz highlighted
        if local_tz in filtered:
            cursor = filtered.index(local_tz)

        while True:
            stdscr.erase()
            h, w = stdscr.getmaxyx()
            list_h = h - 6   # rows available for the list

            # ── Title bar ─────────────────────────────────────────────────
            title = " LendPath ML Workshop v2 — Select Timezone "
            stdscr.addstr(0, max(0, (w - len(title)) // 2), title,
                          curses.color_pair(1) | curses.A_BOLD)

            # ── Search bar ────────────────────────────────────────────────
            search_label = f" Search: {query}_"
            stdscr.addstr(1, 0, search_label[:w], curses.color_pair(3))
            stdscr.addstr(2, 0, f" {len(filtered)} timezone(s) matched"[:w],
                          curses.color_pair(5))
            stdscr.addstr(3, 0, "─" * w)

            # ── List ──────────────────────────────────────────────────────
            if cursor < scroll:
                scroll = cursor
            if cursor >= scroll + list_h:
                scroll = cursor - list_h + 1

            for i in range(list_h):
                idx = scroll + i
                if idx >= len(filtered):
                    break
                tz  = filtered[idx]
                row = 4 + i
                is_selected = (idx == cursor)
                is_local    = (tz == local_tz)

                line = f"  {'▶ ' if is_selected else '  '}{tz}"
                if is_local:
                    line += "  ← local"
                line = line[:w]

                attr = (curses.color_pair(2) | curses.A_BOLD if is_selected
                        else curses.color_pair(4) if is_local
                        else curses.color_pair(5))
                stdscr.addstr(row, 0, line, attr)

            # ── Footer ────────────────────────────────────────────────────
            footer = " ↑↓ move  PgUp/PgDn page  / search  Enter select  q=use local"
            stdscr.addstr(h - 1, 0, footer[:w], curses.color_pair(3))

            stdscr.refresh()

            # ── Input ─────────────────────────────────────────────────────
            try:
                key = stdscr.get_wch()
            except Exception:
                continue

            if key in (curses.KEY_UP, "k"):
                cursor = max(0, cursor - 1)
            elif key in (curses.KEY_DOWN, "j"):
                cursor = min(len(filtered) - 1, cursor + 1)
            elif key == curses.KEY_PPAGE:
                cursor = max(0, cursor - list_h)
            elif key == curses.KEY_NPAGE:
                cursor = min(len(filtered) - 1, cursor + list_h)
            elif key in (curses.KEY_HOME,):
                cursor = 0
            elif key in (curses.KEY_END,):
                cursor = len(filtered) - 1
            elif key in ("\n", "\r", curses.KEY_ENTER, 10, 13):
                selected = filtered[cursor] if filtered else local_tz
                break
            elif key in ("q", "Q"):
                selected = local_tz
                break
            elif key == 27:   # Escape — clear search
                query    = ""
                filtered = list(zones)
                cursor   = 0
            elif key in (curses.KEY_BACKSPACE, 127, "\x7f"):
                query    = query[:-1]
                filtered = [z for z in zones
                            if query.lower() in z.lower()] if query else list(zones)
                cursor   = 0
                if local_tz in filtered and not query:
                    cursor = filtered.index(local_tz)
            elif isinstance(key, str) and key.isprintable():
                query    = query + key
                filtered = [z for z in zones if query.lower() in z.lower()]
                cursor   = 0

        return selected

    return curses.wrapper(_run)


def _tz_picker_cli(zones, local_tz):
    """
    Numbered CLI timezone picker — used when curses is unavailable or the
    terminal doesn't support it.  Groups zones by region for readability.
    """
    # Group by prefix
    from collections import defaultdict
    groups = defaultdict(list)
    for z in zones:
        prefix = z.split("/")[0] if "/" in z else "Other"
        groups[prefix].append(z)

    regions = sorted(groups.keys())

    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║   LendPath ML Workshop v2 — Select Timezone              ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"  Detected local timezone: {local_tz}")
    print()
    print("  Press Enter to accept local timezone, or select a region:")
    print()

    for i, region in enumerate(regions, 1):
        count = len(groups[region])
        print(f"  {i:>3}.  {region:<20} ({count} zones)")

    print()
    print("  0.  Use local timezone and continue")
    print()

    while True:
        choice = input("  Region number (or 0 for local): ").strip()
        if choice == "" or choice == "0":
            return local_tz
        try:
            n = int(choice)
            if 1 <= n <= len(regions):
                break
        except ValueError:
            pass
        print("  Invalid choice — try again.")

    region   = regions[n - 1]
    tz_list  = sorted(groups[region])

    print()
    print(f"  ── {region} timezones ──")
    print()
    for i, tz in enumerate(tz_list, 1):
        marker = "  ← local" if tz == local_tz else ""
        print(f"  {i:>4}.  {tz}{marker}")
    print()
    print("  0.  Back / use local timezone")
    print()

    while True:
        choice = input("  Timezone number (or 0 for local): ").strip()
        if choice == "" or choice == "0":
            return local_tz
        try:
            n = int(choice)
            if 1 <= n <= len(tz_list):
                return tz_list[n - 1]
        except ValueError:
            pass
        print("  Invalid choice — try again.")


def pick_timezone(prefer_local=False):
    """
    Launch the timezone picker.  Returns a (name_str, tzinfo) tuple.
    Tries the curses GUI first; falls back to CLI numbered list if the
    terminal doesn't support it.
    """
    zones    = _get_all_timezones()
    local_tz = _detect_local_tz()

    if prefer_local:
        tz_name = local_tz
    else:
        try:
            import curses
            tz_name = _tz_picker_curses(zones, local_tz)
        except Exception:
            tz_name = _tz_picker_cli(zones, local_tz)

    tz_info = _resolve_tzinfo(tz_name)
    return tz_name, tz_info


# =============================================================================
# ML JOB LOADING
# =============================================================================

def _load_job_files(job_files):
    """Load and merge job definitions from one or more JSON files.

    Relative paths are resolved against the directory containing bootstrap.py
    so the script works correctly regardless of the current working directory.
    """
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    anomaly_jobs, dfa_jobs = [], []
    for path in job_files:
        # Resolve relative paths against the script directory
        if not os.path.isabs(path):
            resolved = os.path.join(_script_dir, path)
        else:
            resolved = path
        if not os.path.exists(resolved):
            # Also try cwd as fallback
            cwd_path = os.path.join(os.getcwd(), path)
            if os.path.exists(cwd_path):
                resolved = cwd_path
            else:
                print(f"  ✗ Job file not found: {resolved}")
                print(f"    Also tried: {cwd_path}")
                print(f"    Ensure all workshop files are in the same directory as bootstrap.py")
                continue
        with open(resolved) as fh:
            data = json.load(fh)
        anomaly_jobs.extend(data.get("anomaly_detection_jobs", []))
        dfa_jobs.extend(data.get("data_frame_analytics_jobs", []))
        print(f"  ✓ Loaded {resolved}")
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
    """POST to an ML endpoint (e.g. open job, start datafeed).

    Treats the following non-2xx responses as soft warnings (~ symbol):
      - "already finished"  — DFA job ran successfully in a previous session
      - "already started" / "already exist" — job is currently running
      - "already exists"   — datafeed already started
    These are all expected when re-running --create-dfa or --start-datafeeds
    against a cluster that still has results from a previous run.
    """
    status, resp = make_request(f"{host}{path}", "POST", body, auth, verify_ssl)
    if status in (200, 201):
        print(f"  ✓ [{status}] {label}")
        return True
    resp_text = json.dumps(resp).lower()
    soft = (
        "already finished" in resp_text or
        "already started"  in resp_text or
        "already exist"    in resp_text or
        "already been started" in resp_text
    )
    if soft:
        # Extract a short reason for the message
        reason = (
            "already finished — results available"  if "already finished" in resp_text else
            "already running"                        if "already started"  in resp_text or "already been started" in resp_text else
            "already exists"
        )
        print(f"  ~ [{status}] {label}  ({reason})")
        return True
    print(f"  ✗ [{status}] {label}")
    print(f"      {resp}")
    return False



def fix_stale_datafeeds(host, auth, verify_ssl, job_files):
    """
    Scan all datafeeds and compare their source indices against what the
    job definition files say they should be.  For any datafeed whose index
    list doesn't match, stop → delete → recreate → start it.

    Use with --fix-datafeeds when a datafeed was created from a stale job
    file and now points to an index that no longer exists.
    """
    anomaly_jobs, _ = _load_job_files(job_files)
    if not anomaly_jobs:
        print("  ⚠ No anomaly detection jobs found in job files.")
        return

    print("\n▸ Checking datafeeds for stale source indices…")

    fixed = 0
    for job in anomaly_jobs:
        df_cfg = job.get("datafeed_config")
        if not df_cfg:
            continue

        job_id    = job.get("job_id", "?")
        feed_id   = df_cfg.get("datafeed_id", f"datafeed-{job_id}")
        expected  = sorted(df_cfg.get("indices", []))

        # Get current datafeed config from cluster
        status, resp = make_request(
            f"{host}/_ml/datafeeds/{feed_id}", "GET", None, auth, verify_ssl
        )
        if status == 404:
            print(f"  ~ {feed_id}: not found on cluster (will be created by --start-datafeeds)")
            continue
        if status != 200:
            print(f"  ✗ {feed_id}: could not retrieve ({status})")
            continue

        datafeeds = resp.get("datafeeds", [resp])  # single or list
        if not datafeeds:
            continue
        current = sorted(datafeeds[0].get("indices", []))

        if current == expected:
            print(f"  ✓ {feed_id}: {current}  (correct)")
            continue

        # Stale — needs updating
        print(f"  ✗ {feed_id}: index mismatch")
        print(f"      cluster:  {current}")
        print(f"      expected: {expected}")
        print(f"    → fixing…")

        # Stop datafeed
        _post_ml(host, f"/_ml/datafeeds/{feed_id}/_stop?force=true",
                 {}, auth, verify_ssl, f"Stop datafeed: {feed_id}")

        # Close job
        _post_ml(host, f"/_ml/anomaly_detectors/{job_id}/_close?force=true",
                 {}, auth, verify_ssl, f"Close job: {job_id}")

        # Delete datafeed
        status2, _ = make_request(
            f"{host}/_ml/datafeeds/{feed_id}?force=true",
            "DELETE", None, auth, verify_ssl
        )
        if status2 not in (200, 404):
            print(f"    ✗ Could not delete datafeed ({status2}) — skipping")
            continue
        print(f"    ✓ Deleted {feed_id}")

        # Recreate with correct indices
        df_body = {k: v for k, v in df_cfg.items()
                   if k not in ("datafeed_id",)}
        df_body["job_id"] = job_id
        _put_ml_job(
            host, f"/_ml/datafeeds/{feed_id}",
            df_body, auth, verify_ssl,
            f"Recreate datafeed: {feed_id}"
        )

        # Open job and start datafeed
        _post_ml(host, f"/_ml/anomaly_detectors/{job_id}/_open?timeout=0s",
                 {}, auth, verify_ssl, f"Open job: {job_id}")
        _post_ml(host, f"/_ml/datafeeds/{feed_id}/_start",
                 {"start": "0"}, auth, verify_ssl, f"Start datafeed: {feed_id}")
        fixed += 1

    if fixed:
        print(f"\n  Fixed {fixed} stale datafeed(s).")
    else:
        print("\n  All datafeeds have correct source indices.")


def load_anomaly_jobs(host, auth, verify_ssl, job_files, start_datafeeds=False):
    """Create anomaly detection jobs and datafeeds.

    Safe to run before any data exists — AD jobs do not validate that
    source indices are populated at creation time.
    """
    print("\n▸ Loading ML job definition files…")
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    for _jf in job_files:
        _resolved = _jf if os.path.isabs(_jf) else os.path.join(_script_dir, _jf)
        _cwd      = os.path.join(os.getcwd(), _jf)
        if not os.path.exists(_resolved) and not os.path.exists(_cwd):
            print(f"  ✗ MISSING: {_jf}")
            print(f"    Copy this file to: {_script_dir}")
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
        print(f"\n▸ Opening {len(datafeeds_to_start)} jobs…")
        for job_id, datafeed_id in datafeeds_to_start:
            # timeout=0s returns immediately — job opens asynchronously
            _post_ml(host, f"/_ml/anomaly_detectors/{job_id}/_open?timeout=0s",
                     {}, auth, verify_ssl, f"Open job: {job_id}")

        print(f"\n▸ Starting {len(datafeeds_to_start)} datafeeds…")
        for job_id, datafeed_id in datafeeds_to_start:
            # start=0 tells the datafeed to begin from the earliest available data
            _post_ml(host, f"/_ml/datafeeds/{datafeed_id}/_start",
                     {"start": "0"}, auth, verify_ssl, f"Start datafeed: {datafeed_id}")

        print(f"\n  All datafeeds dispatched. Jobs will open and begin")
        print(f"  consuming data in the background.")
        print(f"  Check status in Kibana: ML → Anomaly Detection → Jobs")


def _check_indices_exist(host, auth, verify_ssl, indices):
    """Check which indices exist and have data.
    Returns (existing, missing) where:
      existing = [(index_name, doc_count), ...]
      missing  = [(index_name, reason), ...]
    """
    existing, missing = [], []
    for idx in sorted(indices):
        status, resp = make_request(
            f"{host}/{idx}/_count", "GET", None, auth, verify_ssl
        )
        if status == 200:
            count = resp.get("count", 0)
            if count > 0:
                existing.append((idx, count))
            else:
                missing.append((idx, "exists but EMPTY — run backfill first"))
        else:
            missing.append((idx, "does not exist — run backfill first"))
    return existing, missing


def load_dfa_jobs(host, auth, verify_ssl, job_files, run_dfa=False, dfa_types=None):
    """Create Data Frame Analytics jobs.

    IMPORTANT: DFA jobs validate that source indices exist and contain data
    at creation time. Only run this after the SDG has been running long
    enough to populate all source indices (typically 30–60 minutes).

    Required minimum documents per source index:
      Outlier Detection:  1,000+
      Regression:         1,000+
      Classification:     5,000+  (recommended for a useful model)

    dfa_types: set/list of {"outlier","regression","classification","all","none"}.
               Filters which job analysis types to create.  None/"all" = all three.
    """
    _, dfa_jobs = _load_job_files(job_files)

    if not dfa_jobs:
        print("  ⚠ No DFA jobs found.")
        return

    # ── Filter by requested DFA type ─────────────────────────────────────────
    types = {t.lower() for t in (dfa_types or ["all"])}
    if "none" in types:
        print("  (--dfa-types none: DFA job creation skipped)")
        return
    if "all" not in types:
        def _job_type(job):
            analysis = job.get("analysis", {})
            if "outlier_detection" in analysis: return "outlier"
            if "regression"        in analysis: return "regression"
            if "classification"    in analysis: return "classification"
            return "unknown"
        before = len(dfa_jobs)
        dfa_jobs = [j for j in dfa_jobs if _job_type(j) in types]
        skipped = before - len(dfa_jobs)
        if skipped:
            print(f"  ℹ  Filtered to types {sorted(types)}: "
                  f"{len(dfa_jobs)} job(s) selected, {skipped} skipped.")
    if not dfa_jobs:
        print("  ⚠ No DFA jobs match the requested types.")
        return

    # ── Pre-flight: verify all source indices exist and have data ─────────────
    # Build a map of job → source indices so we can report per-job status
    job_indices = {}
    all_source_indices = set()
    for job in dfa_jobs:
        indices = job.get("source", {}).get("index", [])
        job_indices[job.get("id","?")] = indices
        for idx in indices:
            all_source_indices.add(idx)

    print(f"\n▸ Pre-flight — checking {len(all_source_indices)} DFA source indices…")
    existing, missing = _check_indices_exist(host, auth, verify_ssl,
                                              all_source_indices)
    existing_set = {idx for idx, _ in existing}
    missing_set  = {idx for idx, _ in missing}

    for idx, count in existing:
        print(f"  ✓ {idx:<52} {count:>12,} docs")
    for idx, reason in missing:
        print(f"  ✗ {idx:<52} {reason}")

    # Determine which DFA jobs can proceed vs must wait
    jobs_ready   = []
    jobs_blocked = []
    for job in dfa_jobs:
        job_id  = job.get("id", "?")
        indices = job_indices.get(job_id, [])
        blocking = [i for i in indices if i in missing_set and "does not exist" in
                    next((r for n,r in missing if n == i), "")]
        if blocking:
            jobs_blocked.append((job_id, blocking))
        else:
            jobs_ready.append(job)

    if jobs_blocked:
        print(f"\n  ⚠ {len(jobs_blocked)} DFA job(s) blocked — source indices missing:")
        for job_id, blocking in jobs_blocked:
            print(f"    {job_id}")
            for idx in blocking:
                print(f"      missing: {idx}")
        print()
        print("    These jobs will be skipped. Run --create-dfa again after backfill")
        print("    has populated the missing indices.")
        if not jobs_ready:
            print("\n  No DFA jobs can proceed. Aborting.")
            return
        print(f"\n  Proceeding with {len(jobs_ready)} ready job(s).")
        dfa_jobs = jobs_ready   # only create the jobs that can proceed

    empty_indices = [idx for idx, r in missing if "EMPTY" in r]
    if empty_indices:
        print(f"\n  ⚠ {len(empty_indices)} index/indices exist but are empty — limited training data.")

    print(f"\n▸ Creating {len(dfa_jobs)} Data Frame Analytics jobs…")

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
            # timeout=0s returns immediately — DFA starts asynchronously
            _post_ml(host, f"/_ml/data_frame/analytics/{job_id}/_start?timeout=0s",
                     {}, auth, verify_ssl, f"Start DFA: {job_id}")
        print(f"\n  DFA jobs dispatched. They will run in the background.")
        print(f"  Check progress in Kibana: ML → Data Frame Analytics")


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
    """Like make_request but adds the kbn-xsrf header required by Kibana APIs.

    Returns (status, response_dict) on HTTP responses.
    Returns (0, {"error": message}) on connection-level failures so callers
    can handle them without catching exceptions.
    """
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
    except urllib.error.URLError as e:
        # Connection-level failure (refused, DNS, timeout, SSL error)
        return 0, {"error": str(e.reason)}
    except OSError as e:
        return 0, {"error": str(e)}


def _kibana_is_reachable(kibana_host, auth, verify_ssl):
    """Probe the Kibana status endpoint. Returns (True, version) or (False, reason)."""
    status, resp = make_kibana_request(
        f"{kibana_host}/api/status", "GET", None, auth, verify_ssl
    )
    if status == 0:
        return False, resp.get("error", "connection refused")
    if status in (200, 201):
        version = (resp.get("version") or {}).get("number", "unknown")
        return True, version
    return False, f"HTTP {status}"




def create_dfa_data_views(kibana_host, auth, verify_ssl, dfa_types=None):
    """
    Create Kibana data views for DFA destination indices so the
    Explore Results page can render without the
    "No data view exists for index" error.

    dfa_types: set/list of strings from {"outlier","regression","classification"}.
               None or {"all"} creates views for all three types.
               {"none"} skips entirely.
    """
    # Full catalogue: title -> (index_pattern, job_type)
    _ALL = {
        "mortgage-spans-outliers":                   ("mortgage-spans-outliers",                   "outlier"),
        "mortgage-security-outliers":                ("mortgage-security-outliers",                "outlier"),
        "mortgage-hosts-regression":                 ("mortgage-hosts-regression",                 "regression"),
        "mortgage-oracle-regression":                ("mortgage-oracle-regression",                "regression"),
        "mortgage-audit-classification":             ("mortgage-audit-classification",             "classification"),
        "mortgage-privileged-access-classification": ("mortgage-privileged-access-classification", "classification"),
    }

    types = {t.lower() for t in (dfa_types or ["all"])}
    if "none" in types:
        print("\n  (--dfa-types none: DFA data view creation skipped)")
        return
    if "all" in types:
        types = {"outlier", "regression", "classification"}

    dfa_views = {
        title: index_pattern
        for title, (index_pattern, job_type) in _ALL.items()
        if job_type in types
    }

    if not dfa_views:
        return

    print("\n▸ Creating Kibana data views for DFA result indices…")
    reachable, info = _kibana_is_reachable(kibana_host, auth, verify_ssl)
    if not reachable:
        print(f"  ⚠ Cannot reach Kibana: {info}")
        return

    for title, index_pattern in dfa_views.items():
        # Check if it already exists
        gs, gr = make_kibana_request(
            f"{kibana_host}/api/data_views/data_view",
            "GET", None, auth, verify_ssl
        )
        # Search for existing view with this title
        existing_id = None
        if gs == 200:
            for dv in gr.get("data_view", []) if isinstance(gr.get("data_view"), list)                     else [gr.get("data_view", {})]:
                if dv.get("title") == index_pattern:
                    existing_id = dv.get("id")
                    break

        if existing_id:
            print(f"  ~ [exists] Data view: {title}")
            continue

        status, resp = make_kibana_request(
            f"{kibana_host}/api/data_views/data_view",
            "POST",
            {
                "data_view": {
                    "title":     index_pattern,
                    "name":      title,
                    "timeFieldName": "@timestamp",
                }
            },
            auth, verify_ssl
        )
        if status in (200, 201):
            print(f"  ✓ [{status}] Data view created: {title}")
        elif status == 400 and "already exists" in str(resp).lower():
            print(f"  ~ [exists] Data view: {title}")
        else:
            print(f"  ✗ [{status}] Failed to create data view: {title}")
            print(f"      {resp}")


def load_graph_workspace(kibana_host, auth, verify_ssl):
    """
    Upload a Kibana Graph workspace saved object for LendPath service topology.
    Uses service.name x span.destination.service.resource co-occurrence to
    draw the service dependency graph from APM span data.

    Valid graph-workspace attributes: title, description, numLinks,
    numVertices, wsState (JSON string). No other top-level attributes.
    """
    ws_state_obj = {
        "indexPattern": {
            "id": "apm_static_data_view_id_default",
            "title": "traces-apm-default"
        },
        "selectedFields": [
            {
                "color": "#38bdf8",
                "fieldName": "service.name",
                "hopSize": 5,
                "lastValidHopSize": 5,
                "icon": {"class": "fa-cog", "code": "\uf013", "label": "cog"},
                "indexPatternId": "apm_static_data_view_id_default",
                "indexPatternTitle": "traces-apm-default",
                "label": "Service",
                "selected": True,
                "size": 25
            },
            {
                "color": "#34d399",
                "fieldName": "span.destination.service.resource",
                "hopSize": 5,
                "lastValidHopSize": 5,
                "icon": {"class": "fa-database", "code": "\uf1c0", "label": "database"},
                "indexPatternId": "apm_static_data_view_id_default",
                "indexPatternTitle": "traces-apm-default",
                "label": "Destination",
                "selected": True,
                "size": 25
            }
        ],
        "exploreControls": {
            "useSignificance": False,
            "sampleDiversityField": None,
            "sampleSize": 2000,
            "timeoutMillis": 5000,
            "maxValuesPerDoc": 1,
            "minDocCount": 3
        },
        "blocklist": [],
        "vertices": [],
        "links": [],
        "urlTemplates": []
    }

    workspace = {
        "title": "LendPath Service Topology",
        "description": (
            "Service connections via span.destination.service.resource — "
            "shows which LendPath services call which downstream dependencies. "
            "Click any node then use Expand to explore connections."
        ),
        "numLinks": 10,
        "numVertices": 5,
        "wsState": json.dumps(ws_state_obj)
    }

    print("\n▸ Uploading Kibana Graph workspace…")
    reachable, info = _kibana_is_reachable(kibana_host, auth, verify_ssl)
    if not reachable:
        print(f"  ⚠ Cannot reach Kibana at {kibana_host}: {info}")
        return

    # Check if already exists
    gs, gr = make_kibana_request(
        f"{kibana_host}/api/saved_objects/_find"
        f"?type=graph-workspace&search_fields=title&search=LendPath+Service+Topology",
        "GET", None, auth, verify_ssl
    )
    existing_id = None
    if gs == 200:
        for obj in gr.get("saved_objects", []):
            if obj.get("attributes", {}).get("title") == "LendPath Service Topology":
                existing_id = obj["id"]
                break

    if existing_id:
        url    = f"{kibana_host}/api/saved_objects/graph-workspace/{existing_id}"
        status, resp = make_kibana_request(
            url, "PUT", {"attributes": workspace}, auth, verify_ssl
        )
        if status in (200, 201):
            print(f"  ~ [updated] Graph workspace: LendPath Service Topology")
        else:
            print(f"  ✗ [{status}] Could not update graph workspace: {resp}")
    else:
        url    = f"{kibana_host}/api/saved_objects/graph-workspace"
        status, resp = make_kibana_request(
            url, "POST", {"attributes": workspace}, auth, verify_ssl
        )
        if status in (200, 201):
            print(f"  ✓ [{status}] Graph workspace created: LendPath Service Topology"
                  f" (id: {resp.get('id','?')})")
        else:
            print(f"  ✗ [{status}] Failed to create graph workspace: {resp}")

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

    # ── Connectivity check ────────────────────────────────────────────────────
    reachable, info = _kibana_is_reachable(kibana_host, auth, verify_ssl)
    if not reachable:
        print(f"  ⚠ Cannot reach Kibana at {kibana_host}")
        print(f"      Reason: {info}")
        print()
        print("  Possible fixes:")
        print(f"    • Is Kibana running? Check with: curl -u elastic:changeme {kibana_host}/api/status")
        print(f"    • Wrong port? Try --kibana-host http://localhost:5601 (HTTP, not HTTPS)")
        print(f"    • Cloud deployment? Use your full Kibana URL, e.g.")
        print(f"      --kibana-host https://my-deployment.kb.us-east-1.aws.elastic-cloud.com")
        print()
        print("  Kibana Vega upload skipped. To retry later:")
        print(f"    python bootstrap.py --skip-ml --kibana-host <correct-url> ...")
        return
    print(f"  ✓ Connected to Kibana {info}")

    _script_dir = os.path.dirname(os.path.abspath(__file__))
    for vega_path in vega_files:
        # Resolve relative paths against the script directory
        if not os.path.isabs(vega_path):
            vega_path = os.path.join(_script_dir, vega_path)
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

    # Upload Graph workspace alongside Vega visualizations
    load_graph_workspace(kibana_host, auth, verify_ssl)


def set_kibana_timezone(kibana_host, auth, verify_ssl, tz_name):
    """
    Set the Kibana Advanced Setting dateFormat:tz via the Kibana Settings API.

    API:  POST /api/kibana/settings
    Body: {"changes": {"dateFormat:tz": "<IANA_tz_name>"}}

    Common failure — 400 "not available with the current configuration":
      This means dateFormat:tz is already locked by a uiSettings.overrides
      entry in kibana.yml.  When kibana.yml owns a setting the API (and the
      Advanced Settings UI) cannot change it.

      Fix: remove or update the override in kibana.yml and restart Kibana:
          uiSettings:
            overrides:
              "dateFormat:tz": "America/New_York"   ← change or delete this

      Alternatively you can set it there deliberately — kibana.yml takes
      effect for all spaces before anyone logs in, which is actually the
      most reliable approach for a workshop environment.
    """
    if not kibana_host:
        return

    print(f"\n▸ Setting Kibana timezone → {tz_name} …")

    reachable, info = _kibana_is_reachable(kibana_host, auth, verify_ssl)
    if not reachable:
        print(f"  ⚠ Cannot reach Kibana: {info} — timezone not set.")
        return

    status, resp = make_kibana_request(
        f"{kibana_host}/api/kibana/settings",
        "POST",
        {"changes": {"dateFormat:tz": tz_name}},
        auth,
        verify_ssl,
    )

    if status in (200, 201):
        saved = (resp.get("settings", {})
                     .get("dateFormat:tz", {})
                     .get("userValue", tz_name))
        print(f"  ✓ [{status}] Kibana dateFormat:tz = {saved}")
        return

    # ── Diagnose the 400 "not available with current configuration" error ──────
    resp_text = json.dumps(resp).lower()
    if status == 400 and "not available with the current configuration" in resp_text:
        print(f"  ⚠ [{status}] Kibana rejected the timezone setting.")
        print()
        print("  Cause: dateFormat:tz is locked by a uiSettings.overrides entry")
        print("  in kibana.yml.  The API cannot change settings that kibana.yml owns.")
        print()
        print("  To fix — choose one of:")
        print()
        print("  Option A: Remove the override from kibana.yml and restart Kibana")
        print("    Find and delete/comment out any line like:")
        print('      uiSettings.overrides."dateFormat:tz": "..."')
        print("    or the YAML block form:")
        print("      uiSettings:")
        print("        overrides:")
        print('          "dateFormat:tz": "..."')
        print()
        print("  Option B: Set it directly in kibana.yml (most reliable for workshops)")
        print("    Add or update this block in kibana.yml, then restart Kibana:")
        print("      uiSettings:")
        print("        overrides:")
        print(f'          "dateFormat:tz": "{tz_name}"')
        print()
        print("  Option C: Set it manually in the Kibana UI")
        print("    Stack Management → Advanced Settings → dateFormat:tz")
        print(f"    Set value to: {tz_name}")
        return

    print(f"  ✗ [{status}] Failed to set Kibana timezone")
    print(f"      {resp}")


# =============================================================================
# PURGE — Remove all workshop resources from Elasticsearch and Kibana
# =============================================================================

# All index templates created by setup()
_INDEX_TEMPLATES = [
    "logs-nginx.access-mortgage",
    "logs-nginx.error-mortgage",
    "metrics-nginx.stubstatus-mortgage",
    "logs-mortgage.applications",
    "metrics-mortgage.services",
    "traces-apm-default",
    "metrics-apm.app",
    "logs-mortgage.audit",
    "metrics-mortgage.hosts",
    "logs-akamai.siem-mortgage",
    "logs-aws.vpcflow-mortgage",
    "logs-aws.waf-mortgage",
    "logs-coredns.log-mortgage",
    "logs-haproxy.log-mortgage",
    "metrics-haproxy.stat-mortgage",
    "metrics-haproxy.info-mortgage",
    "metrics-kafka.broker-mortgage",
    "metrics-kafka.partition-mortgage",
    "logs-oracle.database_audit-mortgage",
    "metrics-oracle.sysmetric-mortgage",
    "metrics-oracle.tablespace-mortgage",
    "logs-ping_one.audit-mortgage",
]

_COMPONENT_TEMPLATES = [
    "mortgage-common@mappings",
]

# All data streams (SDG + APM)
_DATA_STREAMS = [
    "logs-nginx.access-mortgage",
    "logs-nginx.error-mortgage",
    "metrics-nginx.stubstatus-mortgage",
    "logs-mortgage.applications-default",
    "metrics-mortgage.services-default",
    "traces-apm-default",
    "metrics-apm.app.lendpath-los-default",
    "metrics-apm.app.lendpath-underwriting-default",
    "metrics-apm.app.lendpath-credit-service-default",
    "metrics-apm.app.lendpath-document-service-default",
    "metrics-apm.app.lendpath-appraisal-service-default",
    "logs-mortgage.audit-default",
    "metrics-mortgage.hosts-default",
    "logs-akamai.siem-mortgage",
    "logs-aws.vpcflow-mortgage",
    "logs-aws.waf-mortgage",
    "logs-coredns.log-mortgage",
    "logs-haproxy.log-mortgage",
    "metrics-haproxy.stat-mortgage",
    "metrics-haproxy.info-mortgage",
    "metrics-kafka.broker-mortgage",
    "metrics-kafka.partition-mortgage",
    "logs-oracle.database_audit-mortgage",
    "metrics-oracle.sysmetric-mortgage",
    "metrics-oracle.tablespace-mortgage",
    "logs-ping_one.audit-mortgage",
]

# AD job IDs — ml-job-definitions.json
_AD_JOBS_CORE = [
    "mortgage-nginx-active-connections",
    "mortgage-nginx-multi-no-split",
    "mortgage-services-multi-split",
    "mortgage-hosts-population-no-split",
    "mortgage-hosts-population-split",
    "mortgage-los-advanced",
    "mortgage-audit-rare",
    "mortgage-geo-login-anomaly",
    "mortgage-apm-tx-anomaly",
]

# Explicit datafeed IDs — some jobs define a custom datafeed_id in their
# datafeed_config that differs from the default "datafeed-{job_id}" pattern.
_DATAFEED_IDS = {
    "mortgage-nginx-active-connections":        "datafeed-mortgage-nginx-active-connections",
    "mortgage-nginx-multi-no-split":            "datafeed-mortgage-nginx-multi-no-split",
    "mortgage-services-multi-split":            "datafeed-mortgage-services-multi-split",
    "mortgage-hosts-population-no-split":       "datafeed-mortgage-hosts-population-no-split",
    "mortgage-hosts-population-split":          "datafeed-mortgage-hosts-population-split",
    "mortgage-los-advanced":                    "datafeed-mortgage-los-advanced",
    "mortgage-audit-rare":                      "datafeed-mortgage-audit-rare",
    "mortgage-geo-login-anomaly":               "datafeed-mortgage-geo-login",           # custom
    "mortgage-akamai-bot-threat":               "datafeed-mortgage-akamai-bot-threat",
    "mortgage-edge-waf-correlated-rare":        "datafeed-mortgage-edge-waf-correlated-rare",
    "mortgage-vpcflow-network-anomaly":         "datafeed-mortgage-vpcflow-network",      # custom
    "mortgage-network-threat-combined":         "datafeed-mortgage-network-threat-combined",
    "mortgage-haproxy-backend-multi":           "datafeed-mortgage-haproxy-backend-multi",
    "mortgage-lb-tier-population":              "datafeed-mortgage-lb-tier-population",
    "mortgage-kafka-messaging-multi-split":     "datafeed-mortgage-kafka-messaging-multi-split",
    "mortgage-privileged-access-combined-rare": "datafeed-mortgage-privileged-access-rare", # custom
    "mortgage-unified-identity-geo":            "datafeed-mortgage-unified-identity-geo",
    "mortgage-oracle-db-multi-split":           "datafeed-mortgage-oracle-db-multi-split",
    "mortgage-oracle-tablespace-population":    "datafeed-mortgage-oracle-tablespace-population",
    "mortgage-oracle-db-change-point":          "datafeed-mortgage-oracle-db-change-point",
}

# AD job IDs — ml-job-definitions-integrations.json
_AD_JOBS_INTEGRATIONS = [
    "mortgage-akamai-bot-threat",
    "mortgage-edge-waf-correlated-rare",
    "mortgage-vpcflow-network-anomaly",
    "mortgage-network-threat-combined",
    "mortgage-haproxy-backend-multi",
    "mortgage-lb-tier-population",
    "mortgage-kafka-messaging-multi-split",
    "mortgage-privileged-access-combined-rare",
    "mortgage-unified-identity-geo",
    "mortgage-oracle-db-multi-split",
    "mortgage-oracle-tablespace-population",
    "mortgage-oracle-db-change-point",
]

# DFA job IDs — both files
_DFA_JOBS = [
    "mortgage-spans-outlier-detection",
    "mortgage-hosts-regression",
    "mortgage-audit-classification",
    "mortgage-akamai-outlier",
    "mortgage-oracle-response-time-regression",
    "mortgage-privileged-access-classification",
]

# DFA destination / result indices
_DFA_DEST_INDICES = [
    "mortgage-spans-outliers",
    "mortgage-hosts-regression",
    "mortgage-audit-classification",
    "mortgage-security-outliers",
    "mortgage-oracle-regression",
    "mortgage-privileged-access-classification",
]

# Vega visualization title (matched by title search in Kibana)
# All Vega visualization titles to purge — must match the "description"
# field in each .vega.json file (used as the saved object title in Kibana)
_VEGA_TITLES = [
    "LendPath Mortgage Platform — APM Service Network Topology (live traffic + errors)",
    "LendPath Network Topology",   # lendpath-network-topology.vega.json
]


def _delete(host, path, auth, verify_ssl, label):
    """DELETE a resource; treat 404 as already gone."""
    status, resp = make_request(f"{host}{path}", "DELETE", None, auth, verify_ssl)
    if status in (200, 201):
        print(f"  ✓ [{status}] Deleted {label}")
        return True
    if status == 404:
        print(f"  ~ [404]  Not found (skipped): {label}")
        return True
    print(f"  ✗ [{status}] Failed to delete {label}")
    print(f"      {resp}")
    return False


def _post(host, path, body, auth, verify_ssl, label):
    """POST helper for stop/force-delete operations."""
    status, resp = make_request(f"{host}{path}", "POST", body, auth, verify_ssl)
    ok = status in (200, 201)
    if ok:
        print(f"  ✓ [{status}] {label}")
    elif status == 404:
        print(f"  ~ [404]  {label} (not found)")
    else:
        # Suppress "already stopped/not started" noise
        reason = json.dumps(resp).lower()
        if "not started" in reason or "closed" in reason or "already" in reason:
            print(f"  ~ [{status}] {label} (already stopped/closed)")
        else:
            print(f"  ✗ [{status}] {label}: {resp}")
    return ok


def _kibana_delete(kibana_host, path, auth, verify_ssl, label):
    """DELETE a Kibana saved object; treat 404 as already gone."""
    status, resp = make_kibana_request(f"{kibana_host}{path}", "DELETE",
                                       None, auth, verify_ssl)
    if status in (200, 201):
        print(f"  ✓ [{status}] Deleted Kibana: {label}")
        return True
    if status == 404:
        print(f"  ~ [404]  Not found (skipped): {label}")
        return True
    print(f"  ✗ [{status}] Failed to delete Kibana {label}: {resp}")
    return False


def _find_kibana_viz_ids(kibana_host, auth, verify_ssl, title):
    """Search Kibana saved objects for visualizations matching a title."""
    url = (f"{kibana_host}/api/saved_objects/_find"
           f"?type=visualization&search_fields=title&search={urllib.request.quote(title)}")
    status, resp = make_kibana_request(url, "GET", None, auth, verify_ssl)
    if status != 200:
        return []
    return [obj["id"] for obj in resp.get("saved_objects", [])
            if obj.get("attributes", {}).get("title", "") == title]


def purge(host, auth, verify_ssl,
          kibana_host=None, kibana_auth=None,
          skip_data=False, skip_ml=False, skip_templates=False,
          skip_kibana=False, force=False):
    """
    Remove all LendPath workshop resources from Elasticsearch and Kibana.

    Order:
      1. Stop and delete ML datafeeds
      2. Close and delete ML AD jobs
      3. Delete DFA jobs
      4. Delete DFA result indices
      5. Delete data streams
      6. Delete index templates and component templates
      7. Delete Kibana visualizations

    All steps handle 404 (already gone) gracefully so this is safe to run
    multiple times or on a partially-configured environment.
    """
    print("\n=== LendPath Workshop — Purge ===\n")

    if not force:
        print("  ⚠ This will permanently delete ALL workshop data, ML jobs,")
        print("    index templates, and Kibana visualizations.")
        print()
        answer = input("  Type YES to confirm: ").strip()
        if answer != "YES":
            print("  Aborted.")
            return
        print()

    ad_jobs = _AD_JOBS_CORE + _AD_JOBS_INTEGRATIONS

    # ── 1. Stop datafeeds ─────────────────────────────────────────────────────
    if not skip_ml:
        print("▸ Stopping AD datafeeds…")
        for job_id in ad_jobs:
            datafeed_id = _DATAFEED_IDS.get(job_id, f"datafeed-{job_id}")
            _post(host, f"/_ml/datafeeds/{datafeed_id}/_stop?force=true",
                  {}, auth, verify_ssl, f"Stop datafeed: {datafeed_id}")

        # ── 2. Close AD jobs ──────────────────────────────────────────────────
        print("\n▸ Closing AD jobs…")
        for job_id in ad_jobs:
            _post(host, f"/_ml/anomaly_detectors/{job_id}/_close?force=true",
                  {}, auth, verify_ssl, f"Close job: {job_id}")

        # ── 3. Delete datafeeds ───────────────────────────────────────────────
        print("\n▸ Deleting AD datafeeds…")
        for job_id in ad_jobs:
            datafeed_id = _DATAFEED_IDS.get(job_id, f"datafeed-{job_id}")
            _delete(host, f"/_ml/datafeeds/{datafeed_id}",
                    auth, verify_ssl, f"Datafeed: {datafeed_id}")

        # ── 4. Delete AD jobs ─────────────────────────────────────────────────
        print("\n▸ Deleting AD jobs…")
        for job_id in ad_jobs:
            _delete(host, f"/_ml/anomaly_detectors/{job_id}",
                    auth, verify_ssl, f"AD job: {job_id}")

        # ── 5. Stop and delete DFA jobs ───────────────────────────────────────
        print("\n▸ Stopping DFA jobs…")
        for job_id in _DFA_JOBS:
            _post(host, f"/_ml/data_frame/analytics/{job_id}/_stop?force=true",
                  {}, auth, verify_ssl, f"Stop DFA: {job_id}")

        print("\n▸ Deleting DFA jobs…")
        for job_id in _DFA_JOBS:
            _delete(host, f"/_ml/data_frame/analytics/{job_id}",
                    auth, verify_ssl, f"DFA job: {job_id}")

        # ── 6. Delete DFA result/destination indices ──────────────────────────
        print("\n▸ Deleting DFA result indices…")
        for idx in _DFA_DEST_INDICES:
            _delete(host, f"/{idx}", auth, verify_ssl, f"Index: {idx}")

    # ── 7. Delete data streams ────────────────────────────────────────────────
    if not skip_data:
        print("\n▸ Deleting data streams…")
        for ds in _DATA_STREAMS:
            _delete(host, f"/_data_stream/{ds}",
                    auth, verify_ssl, f"Data stream: {ds}")

    # ── 8. Delete index templates and component templates ─────────────────────
    if not skip_templates:
        print("\n▸ Deleting index templates…")
        for tmpl in _INDEX_TEMPLATES:
            _delete(host, f"/_index_template/{tmpl}",
                    auth, verify_ssl, f"Index template: {tmpl}")

        print("\n▸ Deleting component templates…")
        for tmpl in _COMPONENT_TEMPLATES:
            _delete(host, f"/_component_template/{tmpl}",
                    auth, verify_ssl, f"Component template: {tmpl}")

    # ── 9. Delete Kibana visualizations ──────────────────────────────────────
    if not skip_kibana and kibana_host and kibana_auth:
        print("\n▸ Deleting Kibana visualizations…")
        reachable, info = _kibana_is_reachable(kibana_host, kibana_auth, verify_ssl)
        if not reachable:
            print(f"  ⚠ Cannot reach Kibana at {kibana_host}: {info}")
            print("    Skipping Kibana cleanup. Re-run with --kibana-host to retry.")
        else:
            # Find by title search and delete all matching IDs
            for title in _VEGA_TITLES:
                ids = _find_kibana_viz_ids(kibana_host, kibana_auth, verify_ssl, title)
                if ids:
                    for viz_id in ids:
                        _kibana_delete(kibana_host,
                                       f"/api/saved_objects/visualization/{viz_id}",
                                       kibana_auth, verify_ssl,
                                       f"Vega viz (id: {viz_id})")
                else:
                    print(f"  ~ No Kibana visualization found with title: {title!r}")

            # Delete Graph workspace
            gs, gr = make_kibana_request(
                f"{kibana_host}/api/saved_objects/_find"
                f"?type=graph-workspace&search_fields=title"
                f"&search=LendPath+Service+Topology",
                "GET", None, kibana_auth, verify_ssl
            )
            if gs == 200:
                for obj in gr.get("saved_objects", []):
                    if obj.get("attributes", {}).get("title") == "LendPath Service Topology":
                        _kibana_delete(kibana_host,
                                       f"/api/saved_objects/graph-workspace/{obj['id']}",
                                       kibana_auth, verify_ssl,
                                       "Graph workspace: LendPath Service Topology")

    print("\n" + "=" * 50)
    print("✓ Purge complete.")
    print()
    print("  To rebuild from scratch:")
    print("    python bootstrap.py --host ... --kibana-host ... ...")
    print()


# =============================================================================
# WORKSHOP CONFIG — persist connection args so other scripts reuse them
# =============================================================================

def _config_path():
    """Path to workshop-config.json saved alongside this script."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "workshop-config.json")


def save_workshop_config(args, selected_tz=None):
    """Persist bootstrap connection args to workshop-config.json."""
    cfg = {
        "host":          args.host,
        "user":          args.user,
        "password":      args.password,
        "no_verify_ssl": getattr(args, "no_verify_ssl", False),
        "kibana_host":   getattr(args, "kibana_host", None),
        "job_files":     getattr(args, "job_files", None),
        "timezone":      selected_tz or getattr(args, "timezone", None),
    }
    try:
        with open(_config_path(), "w") as fh:
            json.dump(cfg, fh, indent=2)
        print(f"  ✓ Config saved → {_config_path()}")
    except Exception as e:
        print(f"  ⚠ Could not save config: {e}")


# =============================================================================
# BACKFILL — inline SDG + APM historical backfill (parallel threads)
# =============================================================================

def run_backfill_mode(args, auth, verify_ssl):
    """
    Run the SDG and APM historical backfills inline — no subprocess, no external
    backfill_all script required.  Both backfills run in parallel threads so the
    combined elapsed time is dominated by whichever takes longer.

    Uses business_calendar.py, backfill_sdg.py (compile_field / make_doc),
    and apm_trace_generator.py — all resolved relative to __file__ so the
    script works correctly under any name.

    --backfill              run backfill then stop
    --backfill --livedata   run backfill then hand off to live generators
    """
    import importlib.util
    import signal
    import threading
    import random
    import time
    import yaml
    from datetime import datetime, timedelta, timezone
    from queue import Queue, Empty

    try:
        from elasticsearch import Elasticsearch
        from elasticsearch.helpers import parallel_bulk
    except ImportError:
        print("ERROR: elasticsearch-py not installed.  Run: pip install elasticsearch")
        sys.exit(1)

    _HERE = os.path.dirname(os.path.abspath(__file__))

    # ── Helper: import a .py file by path ─────────────────────────────────────
    def _file_import(name):
        for search in [_HERE, os.getcwd()]:
            candidate = os.path.join(search, f"{name}.py")
            if os.path.exists(candidate):
                spec = importlib.util.spec_from_file_location(name, candidate)
                mod  = importlib.util.module_from_spec(spec)
                sys.modules[name] = mod
                spec.loader.exec_module(mod)
                return mod
        return None

    # ── Load business_calendar ────────────────────────────────────────────────
    _cal = _file_import("business_calendar")
    if _cal is None:
        print("ERROR: business_calendar.py not found alongside bootstrap.")
        sys.exit(1)
    day_volume_factor  = _cal.day_volume_factor
    hour_weights_for_day = _cal.hour_weights_for_day

    # ── Load apm_trace_generator ──────────────────────────────────────────────
    _apm = _file_import("apm_trace_generator")
    if _apm is None:
        print("ERROR: apm_trace_generator.py not found alongside bootstrap.")
        sys.exit(1)
    _apm_SERVICES       = _apm.SERVICES
    _apm_generate_trace = _apm.generate_trace
    _apm_generate_metrics = _apm.generate_metrics

    # ── Load SDG field compiler (backfill_sdg.py) — optional ─────────────────
    # If backfill_sdg.py is present we use its compile_field / make_doc / STREAM_WEIGHTS.
    # If not, we fall back to a minimal inline implementation that handles the
    # static value fields used by mortgage-workshop.yml.
    _sdg = _file_import("backfill_sdg")
    if _sdg is not None:
        _compile_field  = _sdg.compile_field
        _make_doc       = _sdg.make_doc
        _STREAM_WEIGHTS = getattr(_sdg, "STREAM_WEIGHTS", {})
    else:
        _STREAM_WEIGHTS = {}

        def _compile_field(f):
            name  = f.get("name", "")
            ftype = f.get("type", "value")
            if name == "@timestamp" or ftype == "timestamp":
                return (name, None)
            if ftype == "value" or "value" in f:
                v = f.get("value")
                return (name, lambda _v=v: _v)
            return (name, lambda: None)

        def _make_doc(compiled, ts):
            doc = {}
            for key, gen in compiled:
                val = ts if gen is None else gen()
                if val is None:
                    continue
                parts = key.split(".")
                d = doc
                for p in parts[:-1]:
                    d = d.setdefault(p, {})
                d[parts[-1]] = val
            return doc

    # ── Resolve timezone ──────────────────────────────────────────────────────
    tz_name_arg = getattr(args, "timezone", None)
    if tz_name_arg:
        try:
            import zoneinfo
            tz = zoneinfo.ZoneInfo(tz_name_arg)
        except Exception:
            try:
                import pytz
                tz = pytz.timezone(tz_name_arg)
            except Exception:
                tz = timezone.utc
    else:
        try:
            import tzlocal
            tz = tzlocal.get_localzone()
        except Exception:
            offset = -time.timezone if not time.daylight else -time.altzone
            tz = timezone(timedelta(seconds=offset))

    tz_display = getattr(tz, "key", getattr(tz, "zone", str(tz)))

    # ── Parameters ────────────────────────────────────────────────────────────
    days            = args.backfill_days
    sdg_tpd         = args.backfill_sdg_target or 56_000
    apm_tpd         = args.backfill_apm_traces or 4_000
    max_hourly      = 10_000
    sdg_workers     = 6
    apm_workers     = 4
    bulk_size_sdg   = 1_000
    bulk_size_apm   = 300
    pb_threads      = 2
    pb_queue        = 4
    sdg_config      = os.path.join(_HERE, "mortgage-workshop.yml")
    verify_ssl_bool = verify_ssl

    today     = datetime.now(tz).date()
    start_day = today - timedelta(days=days - 1)

    print(f"\n{'='*68}")
    print(f"  Bootstrap — Historical Backfill")
    print(f"{'='*68}")
    print(f"  Host          : {args.host}")
    print(f"  Days          : {days}  ({start_day} → {today})")
    print(f"  SDG target    : {sdg_tpd:,} docs/weekday")
    print(f"  APM target    : {apm_tpd:,} traces/weekday  (~{apm_tpd*6:,} docs)")
    print(f"  Peak cap      : {max_hourly:,} events/hour")
    print(f"  Timezone      : {tz_display}")
    print(f"  Then live     : {args.livedata}")
    print()

    ssl_opts = {"verify_certs": verify_ssl_bool, "ssl_show_warn": False}
    if not verify_ssl_bool:
        ssl_opts["ssl_assert_fingerprint"] = None

    # ── Shared timestamp helper ────────────────────────────────────────────────
    def _timestamps_for_day_capped(day_dt, count):
        """Yield count ISO timestamp strings for day_dt, capped at max_hourly/hr."""
        day_start_local = datetime(day_dt.year, day_dt.month, day_dt.day, tzinfo=tz)
        weights  = hour_weights_for_day(day_dt)
        total_w  = sum(weights)
        counts, allocated = [], 0
        for w in weights:
            n = round(count * w / total_w) if total_w > 0 else 0
            n = min(n, max_hourly)
            counts.append(n)
            allocated += n
        counts[13] = min(counts[13] + (count - allocated), max_hourly)
        for hour, n in enumerate(counts):
            if n <= 0:
                continue
            h_utc = (day_start_local + timedelta(hours=hour)).astimezone(timezone.utc)
            for _ in range(n):
                ts = h_utc + timedelta(seconds=random.uniform(0, 3599))
                yield ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond//1000:03d}Z"

    # ── SDG backfill ──────────────────────────────────────────────────────────
    def run_sdg_backfill(progress_q):
        if not os.path.exists(sdg_config):
            print(f"  ⚠ SDG config not found: {sdg_config} — skipping SDG backfill")
            return

        with open(sdg_config) as fh:
            cfg = yaml.safe_load(fh)

        stream_fields = {}
        for w in cfg.get("workloads", []):
            idx = w.get("indexName", "")
            if idx and idx not in stream_fields:
                stream_fields[idx] = w.get("fields", [])

        compiled = {idx: [_compile_field(f) for f in fields]
                    for idx, fields in stream_fields.items()}
        total_w  = sum(_STREAM_WEIGHTS.get(i, 1.0) for i in stream_fields) or 1
        targets  = {
            idx: max(1, round(sdg_tpd * _STREAM_WEIGHTS.get(idx, 1.0) / total_w))
            for idx in stream_fields
        }

        es = Elasticsearch(args.host, basic_auth=(args.user, args.password), **ssl_opts)

        def _stream_worker(idx):
            for d in range(days):
                day   = start_day + timedelta(days=d)
                count = min(round(targets[idx] * day_volume_factor(day)), max_hourly * 24)
                count = max(1, count)

                def _actions(idx=idx, day=day, count=count):
                    for ts in _timestamps_for_day_capped(day, count):
                        yield {"_op_type": "create", "_index": idx,
                               "_source": _make_doc(compiled[idx], ts)}

                try:
                    for ok, info in parallel_bulk(
                        es, _actions(),
                        thread_count=pb_threads, chunk_size=bulk_size_sdg,
                        queue_size=pb_queue, raise_on_error=False,
                        raise_on_exception=False, request_timeout=120,
                    ):
                        progress_q.put(("SDG", "OK" if ok else f"ERR:{info}"))
                except Exception as e:
                    progress_q.put(("SDG", f"ERR:{idx}:{e}"))

        work_q = Queue()
        for idx in stream_fields:
            work_q.put(idx)

        def _worker():
            while True:
                try:
                    idx = work_q.get_nowait()
                except Empty:
                    return
                try:
                    _stream_worker(idx)
                except Exception as e:
                    progress_q.put(("SDG", f"ERR:{e}"))
                finally:
                    work_q.task_done()

        threads = [threading.Thread(target=_worker, daemon=True)
                   for _ in range(min(sdg_workers, len(stream_fields)))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    # ── APM backfill ───────────────────────────────────────────────────────────
    def run_apm_backfill(progress_q):
        _svc_names   = list(_apm_SERVICES.keys())
        _svc_weights = [40, 20, 15, 15, 10]
        es = Elasticsearch(args.host, basic_auth=(args.user, args.password), **ssl_opts)

        def _day_actions(day_dt, count):
            for ts in _timestamps_for_day_capped(day_dt, count):
                svc     = random.choices(_svc_names, weights=_svc_weights, k=1)[0]
                actions = _apm_generate_trace(svc)
                for action in actions:
                    action["_source"]["@timestamp"] = ts
                    yield action
                if random.random() < 0.02:
                    for msvc in _svc_names:
                        yield from _apm_generate_metrics(msvc, ts_iso=ts)

        work_q = Queue()
        for d in range(days):
            day   = start_day + timedelta(days=d)
            count = min(round(apm_tpd * day_volume_factor(day)), max_hourly * 24)
            work_q.put((day, max(1, count)))

        def _worker():
            while True:
                try:
                    day_dt, count = work_q.get_nowait()
                except Empty:
                    return
                try:
                    for ok, info in parallel_bulk(
                        es, _day_actions(day_dt, count),
                        thread_count=pb_threads, chunk_size=bulk_size_apm,
                        queue_size=pb_queue, raise_on_error=False,
                        raise_on_exception=False, request_timeout=120,
                    ):
                        progress_q.put(("APM", "OK" if ok else f"ERR:{info}"))
                except Exception as e:
                    progress_q.put(("APM", f"ERR:{day_dt}:{e}"))
                finally:
                    work_q.task_done()

        threads = [threading.Thread(target=_worker, daemon=True)
                   for _ in range(min(apm_workers, days))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    # ── Progress printer ──────────────────────────────────────────────────────
    progress_q = Queue()
    sdg_ok = sdg_err = apm_ok = apm_err = 0
    start_time = time.time()
    _last_print = [time.time()]

    def printer():
        nonlocal sdg_ok, sdg_err, apm_ok, apm_err
        while True:
            try:
                item = progress_q.get(timeout=1)
                if item is None:
                    break
                stream, result = item
                if result == "OK":
                    if stream == "SDG": sdg_ok  += 1
                    else:               apm_ok  += 1
                else:
                    if stream == "SDG": sdg_err += 1
                    else:               apm_err += 1
                    if (sdg_err + apm_err) <= 50:
                        print(f"  ⚠ [{stream}] {result[4:]}")
                    elif (sdg_err + apm_err) == 51:
                        print("  (further errors suppressed)")
                now = time.time()
                if now - _last_print[0] >= 10:
                    elapsed = now - start_time
                    total   = sdg_ok + apm_ok
                    rate    = total / elapsed if elapsed > 0 else 0
                    errs    = sdg_err + apm_err
                    print(f"  {total:>12,} docs  |  {rate:>8,.0f}/sec"
                          + (f"  |  {errs} errs" if errs else "")
                          + f"  [SDG {sdg_ok:,}  APM {apm_ok:,}]")
                    _last_print[0] = now
            except Empty:
                continue

    t_print = threading.Thread(target=printer, daemon=True)
    t_print.start()

    # ── Run SDG and APM in parallel ───────────────────────────────────────────
    print("▸ Starting SDG and APM backfills in parallel…\n")

    sdg_thread = threading.Thread(
        target=run_sdg_backfill, args=(progress_q,), daemon=True, name="SDG-backfill"
    )
    apm_thread = threading.Thread(
        target=run_apm_backfill, args=(progress_q,), daemon=True, name="APM-backfill"
    )

    sdg_thread.start()
    apm_thread.start()

    try:
        sdg_thread.join()
        apm_thread.join()
    except KeyboardInterrupt:
        print("\n  Backfill interrupted.")
        sys.exit(0)

    progress_q.put(None)
    t_print.join(timeout=10)

    elapsed = time.time() - start_time
    h, m, s = int(elapsed//3600), int((elapsed%3600)//60), int(elapsed%60)
    total   = sdg_ok + apm_ok
    errs    = sdg_err + apm_err
    rate    = total / elapsed if elapsed > 0 else 0

    print(f"\n{'='*68}")
    print(f"  Backfill complete.  {h:02d}h {m:02d}m {s:02d}s")
    print(f"  SDG : {sdg_ok:>12,} docs" + (f"  [{sdg_err} errors]" if sdg_err else ""))
    print(f"  APM : {apm_ok:>12,} docs" + (f"  [{apm_err} errors]" if apm_err else ""))
    print(f"  Total: {total:>11,} docs  |  {rate:,.0f} docs/sec")
    print(f"{'='*68}\n")

    # ── Post-backfill: start AD datafeeds + create DFA jobs ───────────────────
    # These run inline — no subprocess needed since we are bootstrap.
    print("▸ Post-backfill: starting AD datafeeds…")
    load_anomaly_jobs(
        args.host, auth, verify_ssl,
        args.job_files,
        start_datafeeds=True,
    )

    print("\n▸ Post-backfill: creating DFA jobs…")
    load_dfa_jobs(
        args.host, auth, verify_ssl,
        args.job_files,
        run_dfa=True,
        dfa_types=getattr(args, "dfa_types", ["outlier"]),
    )

    # ── Hand off to live generators if requested ──────────────────────────────
    if args.livedata:
        run_livedata_mode(args, verify_ssl)


# =============================================================================
# LIVEDATA — start run_workshop.py as a subprocess
# =============================================================================

def run_livedata_mode(args, verify_ssl):
    """
    Start the live SDG + APM trace generators via run_workshop.py.
    run_workshop.py is located relative to __file__ so this works regardless
    of what this script is named.
    """
    import subprocess

    _HERE      = os.path.dirname(os.path.abspath(__file__))
    run_script = os.path.join(_HERE, "run_workshop.py")

    if not os.path.exists(run_script):
        print("ERROR: run_workshop.py not found alongside bootstrap.")
        print(f"  Looked in: {_HERE}")
        sys.exit(1)

    print(f"\n▸ Starting live data generators (run_workshop.py)…")
    print(f"  Host         : {args.host}")
    print(f"  APM rate     : {args.livedata_apm_rate} traces/sec")
    print(f"  Anomaly rate : {args.livedata_anomaly_chance}")
    if args.livedata_purge_apm:
        print(f"  APM purge    : yes")
    print()

    cmd = [
        sys.executable, run_script,
        "--host",          args.host,
        "--user",          args.user,
        "--password",      args.password,
        "--apm-rate",      str(args.livedata_apm_rate),
        "--anomaly-chance", str(args.livedata_anomaly_chance),
    ]
    if not verify_ssl:
        cmd.append("--no-verify-ssl")
    if args.livedata_purge_apm:
        cmd.append("--purge-apm")
    if getattr(args, "livedata_sdg_only", False):
        cmd.append("--sdg-only")
    if getattr(args, "livedata_apm_only", False):
        cmd.append("--apm-only")

    try:
        subprocess.run(cmd, cwd=_HERE)
    except KeyboardInterrupt:
        print("\n  Live generators stopped.")


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

  # Purge everything (data, ML jobs, templates, Kibana assets):
  python bootstrap.py --host ... --kibana-host ... --user ... --password ... --purge

  # Purge without confirmation prompt (e.g. in a script):
  python bootstrap.py ... --purge --force

  # Purge ML jobs and data only, keep templates:
  python bootstrap.py ... --purge --purge-skip-templates

  # Purge data streams only (keep ML jobs and templates):
  python bootstrap.py ... --purge --purge-skip-ml --purge-skip-templates --purge-skip-kibana
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
    p.add_argument("--dfa-types", nargs="+",
                   choices=["outlier", "regression", "classification", "all", "none"],
                   default=["outlier"],
                   metavar="TYPE",
                   help=(
                       "Which DFA job types to create and which data views to register. "
                       "Choices: outlier regression classification all none  "
                       "(default: outlier). "
                       "Multiple values allowed, e.g. --dfa-types outlier classification. "
                       "Use 'all' for all three types, 'none' to skip DFA data views entirely."
                   ))
    p.add_argument("--job-files", nargs="+",
                   default=["ml-job-definitions-MLv2-WORKSHOP.json",
                            "ml-job-definitions-integrations-MLv2-WORKSHOP.json"],
                   metavar="FILE",
                   help="ML job definition JSON files to load "
                        "(default: MLv2 WORKSHOP files with shorter bucket spans)")
    # ── Purge flags ────────────────────────────────────────────────────────────
    p.add_argument("--purge", action="store_true",
                   help="Delete all workshop resources (data streams, ML jobs, "
                        "templates, Kibana assets) and exit. "
                        "Prompts for confirmation unless --force is also set.")
    p.add_argument("--force", action="store_true",
                   help="Skip confirmation prompt when used with --purge.")
    p.add_argument("--purge-skip-data",      action="store_true",
                   help="With --purge: keep data streams (delete ML/templates only).")
    p.add_argument("--purge-skip-ml",        action="store_true",
                   help="With --purge: keep ML jobs (delete data/templates only).")
    p.add_argument("--purge-skip-templates", action="store_true",
                   help="With --purge: keep index templates.")
    p.add_argument("--purge-skip-kibana",    action="store_true",
                   help="With --purge: keep Kibana visualizations.")
    p.add_argument("--kibana-host", default="https://localhost:5601",
                   help="Kibana base URL (default: https://localhost:5601)")
    p.add_argument("--fix-datafeeds", action="store_true",
                   help="Scan all datafeeds and fix any whose source index "
                        "does not match the job definition file")
    p.add_argument("--timezone", default=None, metavar="TZ",
                   help="Set timezone for backfill timestamp generation directly "
                        "(skips the interactive picker). "
                        "Example: --timezone America/New_York")
    p.add_argument("--skip-tz-picker", action="store_true",
                   help="Skip the timezone picker and use the system local timezone")
    p.add_argument("--skip-kibana", action="store_true",
                   help="Skip Kibana asset upload (Vega visualizations)")
    p.add_argument("--vega-file", nargs="+",
                   default=[
                       "lendpath-topology.vega.json",
                       "lendpath-network-topology.vega.json",
                   ],
                   metavar="FILE",
                   help="Vega spec files to upload to Kibana "
                        "(default: lendpath-topology.vega.json "
                        "lendpath-network-topology.vega.json)")

    # ── Backfill flags ─────────────────────────────────────────────────────────
    p.add_argument("--backfill", action="store_true",
                   help="Run the SDG and APM historical backfill inline after "
                        "completing the normal bootstrap steps. Both backfills "
                        "run in parallel. Combine with --livedata to "
                        "automatically transition to live generators when done.")
    p.add_argument("--backfill-days", type=int, default=7, metavar="N",
                   help="Number of historical days to generate during backfill "
                        "(default: 7).")
    p.add_argument("--backfill-sdg-target", type=int, default=None, metavar="N",
                   help="Weekday SDG documents/day target for backfill "
                        "(default: 56,000).")
    p.add_argument("--backfill-apm-traces", type=int, default=None, metavar="N",
                   help="Weekday APM traces/day target for backfill "
                        "(default: backfill script default = 4,000). "
                        "Passed through as --apm-traces.")

    # ── Live data flags ────────────────────────────────────────────────────────
    p.add_argument("--livedata", action="store_true",
                   help="Start the live SDG + APM trace generators after "
                        "bootstrap completes. If combined with --backfill, "
                        "live generators start automatically once backfill "
                        "finishes (via --then-run). If used alone, generators "
                        "start immediately without a backfill.")
    p.add_argument("--livedata-apm-rate", type=float, default=2.0, metavar="RATE",
                   help="APM trace generation rate in traces/second "
                        "(default: 2.0). Passed to run_workshop.py --apm-rate.")
    p.add_argument("--livedata-anomaly-chance", type=float, default=0.03,
                   metavar="RATE",
                   help="Geo anomaly injection rate 0.0–1.0 "
                        "(default: 0.03 = 3%%). Set higher (e.g. 0.30) during "
                        "ML demo sessions for stronger anomaly signals.")
    p.add_argument("--livedata-purge-apm", action="store_true",
                   help="Delete existing APM traces before starting live "
                        "generators (clears stale SDG-generated unlinked traces "
                        "that break the APM Service Map).")
    p.add_argument("--livedata-sdg-only", action="store_true",
                   help="Run SDG only during live data phase; skip APM generator.")
    p.add_argument("--livedata-apm-only", action="store_true",
                   help="Run APM generator only during live data phase; skip SDG.")

    args = p.parse_args()

    verify_ssl = not args.no_verify_ssl
    creds = base64.b64encode(
        f"{args.user}:{args.password}".encode()
    ).decode()
    auth = f"Basic {creds}"

    print("\n=== LendPath Mortgage ML Workshop v2 — Bootstrap ===")
    print(f"    Target: {args.host}\n")

    # ── Save config for reuse by backfill scripts ─────────────────────────
    if not args.purge:
        save_workshop_config(args)

    # ── Timezone selection ────────────────────────────────────────────────
    # The selected timezone is passed through to the backfill scripts.
    # It does not affect bootstrap itself (which uses UTC internally) but
    # is stored so the operator knows which tz was chosen for the session.
    if args.timezone:
        # Explicit override — skip picker entirely
        selected_tz_name = args.timezone
        selected_tz_info = _resolve_tzinfo(args.timezone)
        if selected_tz_info is None:
            print(f"  ⚠ Unknown timezone {args.timezone!r} — falling back to UTC")
            selected_tz_name = "UTC"
        else:
            print(f"  Timezone: {selected_tz_name}  (from --timezone flag)")
    elif args.skip_tz_picker or args.purge:
        # Purge mode doesn't need a timezone; skip-tz-picker uses local
        selected_tz_name, selected_tz_info = pick_timezone(prefer_local=True)
        if not args.purge:
            print(f"  Timezone: {selected_tz_name}  (system local — use --timezone to override)")
    else:
        # Interactive picker
        print("  Launching timezone picker…")
        print("  (Use --timezone TZ or --skip-tz-picker to bypass)")
        print()
        selected_tz_name, selected_tz_info = pick_timezone(prefer_local=False)
        print(f"\n  ✓ Timezone selected: {selected_tz_name}")
        print()

    # Store for downstream use and display in summary
    _selected_tz = selected_tz_name
    # Update saved config with the resolved timezone
    if not args.purge:
        save_workshop_config(args, selected_tz=selected_tz_name)

    # ── Purge mode — run and exit ─────────────────────────────────────────────
    if args.purge:
        kibana_auth = auth if not getattr(args, "purge_skip_kibana", False) else None
        kibana_host = args.kibana_host if not getattr(args, "purge_skip_kibana", False) else None
        purge(
            host           = args.host,
            auth           = auth,
            verify_ssl     = verify_ssl,
            kibana_host    = kibana_host,
            kibana_auth    = kibana_auth,
            skip_data      = args.purge_skip_data,
            skip_ml        = args.purge_skip_ml,
            skip_templates = args.purge_skip_templates,
            skip_kibana    = args.purge_skip_kibana,
            force          = args.force,
        )
        return

    # 1. Index templates (always runs)
    setup(args.host, args.user, args.password, verify_ssl)

    # 2. Kibana assets (Vega visualizations) + timezone + DFA data views
    if args.skip_kibana:
        print("\n  (--skip-kibana: Kibana asset upload skipped)")
    else:
        load_kibana_assets(
            args.kibana_host, auth, verify_ssl,
            args.vega_file,
        )
        set_kibana_timezone(args.kibana_host, auth, verify_ssl, _selected_tz)
        create_dfa_data_views(args.kibana_host, auth, verify_ssl,
                              dfa_types=args.dfa_types)

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
            dfa_types=args.dfa_types,
        )
        # Create Kibana data views for DFA result indices so Explore Results works
        if not args.skip_kibana and args.kibana_host:
            kibana_auth = f"Basic {__import__('base64').b64encode(f'{args.user}:{args.password}'.encode()).decode()}"
            create_dfa_data_views(args.kibana_host, kibana_auth, verify_ssl,
                                  dfa_types=args.dfa_types)

    elif args.fix_datafeeds:
        fix_stale_datafeeds(args.host, auth, verify_ssl, args.job_files)

    else:
        # Default — create AD jobs + datafeeds only (safe before SDG runs)
        load_anomaly_jobs(
            args.host, auth, verify_ssl,
            args.job_files,
            start_datafeeds=args.start_datafeeds,
        )

    # 4. Summary
    print("\n" + "=" * 56)
    print("✓ Bootstrap v2 complete.")
    print(f"  Timezone: {_selected_tz}")
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
    print("Workflow (v2 — 7-day backfill):")
    print(f"  1. python bootstrap-MLv2-WORKSHOP.py ...          (this script)")
    print(f"     → Timezone selected: {_selected_tz}")
    print(f"  2. Add --backfill (and optionally --livedata) to the bootstrap command")
    print(f"     → Runs SDG + APM backfill inline, then starts live generators")
    print( "  3. Wait a few minutes for initial data")
    print( "  4. Start AD datafeeds in Kibana: ML → Anomaly Detection → Jobs → ▶")
    print( "  5. python bootstrap-MLv2-WORKSHOP.py --create-dfa ...")
    print( "  6. Follow WORKSHOP_GUIDE.md")
    print()

    # ── 5. Backfill (optional) ────────────────────────────────────────────────
    # --backfill runs the SDG and APM backfills inline in parallel threads,
    # then starts AD datafeeds and DFA jobs, then optionally goes live.
    # If only --livedata is set (no --backfill), generators start immediately.
    if args.backfill:
        run_backfill_mode(args, auth, verify_ssl)
    elif args.livedata:
        # Live-only: no backfill requested, start generators right away
        run_livedata_mode(args, verify_ssl)


if __name__ == "__main__":
    main()
