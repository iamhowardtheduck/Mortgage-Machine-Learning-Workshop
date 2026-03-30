# LendPath Mortgage ML Workshop

> SDG-powered Elastic ML workshop simulating a home mortgage platform (LendPath) across 21 ECS-aligned data streams — nginx, HAProxy, Kafka, Oracle, Akamai, AWS, CoreDNS, and PingOne. Covers every Elastic ML job type including cross-source anomaly detection, DFA outlier/regression/classification, and AIOps tools.

---

## File Inventory

| File | Purpose |
|---|---|
| `sdg-prime.py` | Simple Data Generator — streams synthetic data to Elasticsearch |
| `mortgage-workshop.yml` | SDG config — 21 concurrent ECS-aligned data streams |
| `bootstrap.py` | Creates all index templates & component templates (run first) |
| `ml-job-definitions.json` | Core ML job configs — anomaly detection + DFA (Modules 1–14) |
| `ml-job-definitions-integrations.json` | Integration ML job configs including 9 cross-source jobs (Modules 15–21) |
| `WORKSHOP_GUIDE.md` | Step-by-step instructor/attendee guide — 21 modules + 4 appendices |
| `WORKSHOP_GUIDE.html` | Rendered interactive HTML version with sidebar navigation |
| `WORKSHOP_GUIDE.pdf` | Print-ready PDF version |

---

## Quick Start

```bash
# 1. Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 2. Install dependencies
pip install elasticsearch faker pyyaml

# 3. Bootstrap Elasticsearch with correct index templates (run before generating data)
python bootstrap.py \
    --host https://localhost:9200 \
    --user elastic \
    --password changeme \
    --no-verify-ssl

# 4. Start generating data  (Ctrl+C to stop)
python sdg-prime.py mortgage-workshop.yml

# 5. Let data accumulate for 30–60 minutes, then follow WORKSHOP_GUIDE.md
```

> **License:** Anomaly Detection and Data Frame Analytics require Platinum or Enterprise.
> Start a trial with `POST /_license/start_trial?acknowledge=true`

---

## ML Technique Coverage

### AIOps Labs

| Module | Technique | Primary Data Streams |
|---|---|---|
| 1 | Log Rate Analysis | `logs-nginx.access-mortgage`, `logs-haproxy.log-mortgage` |
| 2 | Log Pattern Analysis | `logs-nginx.error-mortgage`, `logs-aws.waf-mortgage` |
| 3 | Change Point Detection | `logs-mortgage.applications-default`, `metrics-oracle.tablespace-mortgage` |

### Anomaly Detection

| Module | Technique | Primary Data Streams |
|---|---|---|
| 4 | Single Metric | `metrics-nginx.stubstatus-mortgage`, `metrics-haproxy.info-mortgage` |
| 5 | Multi-Metric (no split) | `metrics-nginx.stubstatus-mortgage` |
| 6 | Multi-Metric (with split) | `metrics-mortgage.services-default`, `logs-haproxy.log-mortgage` |
| 7 | Population (no split) | `metrics-mortgage.hosts-default` |
| 8 | Population (with split) | `metrics-mortgage.hosts-default`, `metrics-haproxy.stat-mortgage` |
| 9 | Advanced | `logs-mortgage.applications-default` |
| 10 | Rare | `logs-mortgage.audit-default`, `logs-oracle.database_audit-mortgage`, `logs-ping_one.audit-mortgage` |
| 11 | Geo | `traces-mortgage.spans-default`, `logs-ping_one.audit-mortgage` |

### Data Frame Analytics

| Module | Technique | Primary Data Streams |
|---|---|---|
| 12 | Outlier Detection | `traces-mortgage.spans-default`, `logs-akamai.siem-mortgage` + `logs-aws.waf-mortgage` |
| 13 | Regression | `metrics-mortgage.hosts-default`, `metrics-oracle.sysmetric-mortgage` |
| 14 | Classification | `logs-mortgage.audit-default`, `logs-ping_one.audit-mortgage` + `logs-oracle.database_audit-mortgage` |

### Integration Deep-Dives

| Module | Integration | Techniques |
|---|---|---|
| 15 | Akamai SIEM | Rare, Outlier Detection |
| 16 | AWS VPC Flow + CoreDNS | Rare, cross-source network threat detection |
| 17 | HAProxy | Multi-Metric, Population |
| 18 | Kafka (kafka_otel) | Multi-Metric with split, Population |
| 19 | Oracle | Multi-Metric, Change Point, Regression, Rare |
| 20 | PingOne | Rare, Geo |
| 21 | Cross-Source Reference | All of the above, combined |

---

## Cross-Source ML Jobs

Nine ML jobs span multiple integration data streams in a single datafeed — the most advanced demonstrations in the workshop.

| Job ID | Sources | Technique | What it detects |
|---|---|---|---|
| `mortgage-edge-waf-correlated-rare` | Akamai SIEM + AWS WAF | Rare | Attack IPs triggering both security layers simultaneously |
| `mortgage-network-threat-combined` | AWS VPC Flow + CoreDNS | Rare + High Count | VPC REJECT + DNS NXDOMAIN — C2 beaconing and DNS exfiltration |
| `mortgage-lb-tier-population` | HAProxy Stat + HAProxy Info | Population | Backend pool deviating from all sibling pools |
| `mortgage-kafka-messaging-multi-split` | Kafka Broker + Kafka Partition | Multi-Metric (split) | Per-topic consumer lag accumulation |
| `mortgage-privileged-access-combined-rare` | Oracle DB Audit + PingOne Audit | Rare | IAM role grants correlated with SYSDBA DB actions |
| `mortgage-unified-identity-geo` | PingOne Audit + LendPath Audit | Geo | Unified geo home-range per user across SSO and app layers |
| `mortgage-oracle-db-change-point` | Oracle Sysmetric + Oracle Tablespace | Advanced | Redo spike + tablespace drop = uncontrolled bulk DML |
| `mortgage-multilayer-security-outlier` | Akamai SIEM + AWS WAF | Outlier Detection (DFA) | High bot score + WAF block — multi-layer attack sessions |
| `mortgage-privileged-access-classification` | PingOne Audit + Oracle DB Audit | Classification (DFA) | Cross-layer privileged access risk classification |

---

## Data Stream Architecture

```
LendPath Mortgage Platform
│
├── Edge & Security
│   ├── logs-akamai.siem-mortgage            Akamai WAF/bot events
│   ├── logs-aws.waf-mortgage                AWS WAF (aws_waf_otel)
│   └── logs-aws.vpcflow-mortgage            VPC Flow logs (aws_vpcflow_otel)
│
├── API Gateway & Load Balancing
│   ├── logs-nginx.access-mortgage           nginx access logs
│   ├── logs-nginx.error-mortgage            nginx error logs
│   ├── metrics-nginx.stubstatus-mortgage    nginx stub metrics
│   ├── logs-haproxy.log-mortgage            HAProxy access logs
│   ├── metrics-haproxy.stat-mortgage        HAProxy per-backend stats
│   └── metrics-haproxy.info-mortgage        HAProxy process metrics
│
├── Loan Origination Services
│   ├── logs-mortgage.applications-default   LOS application logs
│   ├── metrics-mortgage.services-default    JVM + HTTP service metrics
│   └── traces-mortgage.spans-default        APM spans + geo
│
├── Messaging  (Kafka / kafka_otel)
│   ├── metrics-kafka.broker-mortgage        Broker throughput per topic
│   └── metrics-kafka.partition-mortgage     Partition offset + lag
│
├── Database  (Oracle)
│   ├── logs-oracle.database_audit-mortgage  DB audit trail
│   ├── metrics-oracle.sysmetric-mortgage    60+ system performance metrics
│   └── metrics-oracle.tablespace-mortgage   Tablespace utilisation
│
├── DNS
│   └── logs-coredns.log-mortgage            CoreDNS query logs (EKS)
│
├── Identity  (PingOne)
│   └── logs-ping_one.audit-mortgage         SSO / MFA / IAM audit
│
└── Infrastructure
    ├── metrics-mortgage.hosts-default        Host CPU / memory / disk / network
    └── logs-mortgage.audit-default           Internal application audit
```

---

## Notes for Instructors

**Bucket span selection:** Use the *Estimate bucket span* feature in the Kibana job wizard. For metrics collected every 10s, Kibana typically suggests 5m or 15m. HAProxy info and Kafka broker use 10–30s intervals; 5m bucket spans work well for both.

**Model memory:** Values in the job definition files are conservative starting points. Increase `model_memory_limit` if a job fails to start — cross-source jobs indexing from multiple large streams may need 100–200 MB.

**Datafeed timing:** Start datafeeds in real-time mode. The SDG keeps `@timestamp` at `now`, so historical analysis needs at least 2–3 hours of data for meaningful anomaly scoring. AIOps tools (Log Rate Analysis, Change Point Detection) can work with less — 30 minutes is usually enough to demonstrate a pattern.

**Cross-source datafeed mechanics:** The Elastic ML datafeed `indices` field accepts a comma-separated list. All specified indices are queried together per bucket. Fields present in only one source are `null` for documents from the other — the ML engine handles sparse features gracefully. Use `partition_field_name: event.dataset` when you want the model to maintain separate baselines per source within the same job.

**Injecting anomalies:** See *Appendix A* of `WORKSHOP_GUIDE.md` for exact YAML changes to inject traffic spikes, error rate spikes, Oracle performance degradation, Kafka consumer lag, bot attack waves, and DNS exfiltration signals on demand.

**DFA jobs:** Data Frame Analytics runs as a batch job, not streaming. You need at least **1,000 documents** in the source index before starting. For classification, aim for **5,000+** for a useful model. Cross-source DFA jobs (Akamai + WAF outlier, PingOne + Oracle classification) may need more data since both sources feed a single combined dataset.

**OTel package note:** `aws_vpcflow_otel`, `aws_waf_otel`, and `kafka_otel` are Kibana-assets-only packages — they ship dashboards and transforms but have no `data_stream` directory of their own. The SDG writes directly to the underlying `aws.vpcflow`, `aws.waf`, and `kafka.*` data streams that those OTel assets are designed to work with.

**License requirements:**

| Feature | Minimum licence |
|---|---|
| Log Rate Analysis, Log Pattern Analysis, Change Point Detection | Basic |
| Anomaly Detection (all job types) | Platinum / Enterprise |
| Data Frame Analytics | Platinum / Enterprise |

Start a trial: `POST /_license/start_trial?acknowledge=true`
