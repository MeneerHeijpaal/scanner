# Architecture

This document describes the scanner's components, its data model, and how the
pieces fit together after the MongoDB → Elasticsearch migration and the addition
of naabu, nuclei, Interactsh, and multi-VPS distribution.

## Components

| Component | Role | Docs |
|-----------|------|------|
| **httpx** | HTTP probing → primary records | [httpx.md](httpx.md) |
| **naabu** | Port scanning + service/version | [naabu.md](naabu.md) |
| **nuclei** | Template-based enrichment (tech-conditional) | [nuclei.md](nuclei.md) |
| **Interactsh** | Out-of-band interaction detection for nuclei | [interactsh.md](interactsh.md) |
| **Elasticsearch** | Single runtime data store for all results | this doc |
| **Flask app** (`Server/`) | Search / filter / label / export UI | this doc |
| **SQLite** (`Server/labels/`) | Hash labels (small, relational) | this doc |
| **Terraform** (`terraform/`) | Provision + distribute across Hetzner VPSes | this doc |

## Pipeline

```
            targets.txt (URLs / hosts)
                     |
      +--------------+------------------------------+
      |                                             |
      v                                             v
  httpx (scanner.py)                          naabu (naabu_scan.py)
      |  results.json                              |  ports.json
      v                                            v
  import_httpx.py                            import_naabu.py
      |                                            |
      v                                            v
  ES index: scanner_records  <---- tech ----  ES index: scanner_ports
      |          ^
      | (tech)   |
      v          |
  nuclei (nuclei_scan.py, --from-elasticsearch)
      |   uses Interactsh (example.com) for OOB
      |   findings.json
      v
  import_nuclei.py
      |
      v
  ES index: scanner_findings

  Flask app (server.py) reads scanner_records for the search UI.
```

- httpx produces the base records. naabu adds open-port/service data. nuclei
  reads the technologies httpx detected and enriches only the URLs that matter,
  confirming blind issues via Interactsh.
- Every stage writes to Elasticsearch through an idempotent, keyed upsert, so
  re-running a stage updates existing documents instead of duplicating them.

## Data model (Elasticsearch indices)

| Index (config key) | Default name | Written by | Document key |
|--------------------|--------------|------------|--------------|
| `index_name` | `scanner_records` | `import_httpx.py` | SHA1(url) |
| `ports_index` | `scanner_ports` | `import_naabu.py` | SHA1(host:ip:port) |
| `findings_index` | `scanner_findings` | `import_nuclei.py` | SHA1(template-id:matched-at) |
| `interactions_index` | `scanner_interactions` | `interactsh_stream.py` | SHA1(unique-id:full-id:…) |

The **Recon Console** dashboard (`/dashboard`, see [dashboard.md](dashboard.md))
reads all four indices and joins them on the host. Its Interactions tab is a live
stream of the `scanner_interactions` index, fed by the `interactsh_stream.py`
collector running against the self-hosted Interactsh server.

The record mapping is defined in `Server/elasticsearch_manager.py`. Key choices:

- **`ip_addr` (`ip` type)** enables native CIDR term queries (e.g.
  `10.0.0.0/24`) — no host expansion needed. **`ip` (`wildcard` type)** holds the
  IP as a string for prefix/wildcard patterns like `12.34.56.x`.
- **`url` / `host` / `path` (`wildcard`)** give fast substring search without the
  full-collection regex scans the old MongoDB path used.
- **`body_decoded` (`text`)** powers phrase body search in a single query;
  **`body` / `raw_header` / `request`** are stored but not indexed (download only).
- **`scheme`, `tech`, `status_code`** are keyword/integer for exact filters and
  facet aggregations (the technology list is a `terms` aggregation).

Because Elasticsearch is now the single store, every filter, count, sort, and
page is **one query against one store**. Body search is no longer a two-step
ES→Mongo id join, so it is not capped at 10,000 ids the way the old design was.

### Why Elasticsearch-only

The previous design ran MongoDB (primary) *and* Elasticsearch (body text only),
which meant two datastores to operate and keep in sync, and body search silently
truncated at 10k ids. Consolidating on Elasticsearch removes the sync problem,
makes IP/URL/CIDR queries first-class, and reduces the moving parts. Trade-offs:
Elasticsearch is not transactional, so treat scan data as re-importable and take
snapshot backups of `Elastic_Data`.

## The Flask application (`Server/`)

| File | Responsibility |
|------|----------------|
| `server.py` | Load config, connect to Elasticsearch (required), init SQLite labels, register routes. |
| `elasticsearch_manager.py` | The store: mapping, indexing, `count`/`search`/`get`/`scan`/`distinct_terms`. |
| `utils.py` | Input validation, base64 decode, SQLite labels, and `build_search_query` (produces ES query DSL). |
| `routes.py` | HTTP endpoints: search API, detail pages, downloads, labels, health. |

`build_search_query` turns UI parameters into an ES `bool` query with `filter`
clauses (IP/CIDR/wildcard, URL substring incl. redirect location, body phrase,
hashes, tech, status, protocol, and label include/exclude). Reads go through the
store; there is no MongoDB at runtime.

### Labels (SQLite)

Hash labels stay in `Server/labels/labels.db` (schema in `schema.sql`). Labels
are small, relational, and portable across datasets, so they remain in SQLite
rather than Elasticsearch. Label include/exclude filters resolve label → hashes
in SQLite, then filter records by those hashes in Elasticsearch.

## Migrating legacy MongoDB data

`Python/migrate_to_elasticsearch.py` is a one-off tool: it reads the **full**
records from the old MongoDB collection and indexes them into `scanner_records`
(keyed by URL, so it is idempotent). Run it once after standing up
Elasticsearch, then retire MongoDB. The `mongodb:` section in `config.yml` is
read only by this script; `pymongo` in `requirements.txt` is needed only for it.

## Distributing load across VPSes (Terraform + Hetzner)

`terraform/` provisions N identical **scanner workers** on Hetzner Cloud:

1. `worker_count` servers are created from `cloud-init.yaml`, which installs
   httpx/naabu/nuclei, nuclei templates, this repo, and a Python venv, and writes
   `/etc/scanner/worker.env` pointing at the central Elasticsearch endpoint and
   the Interactsh server.
2. `Python/distribute_targets.py` shards a target list round-robin across the
   workers and can `scp` each shard to its worker.
3. Each worker scans its shard and ingests into the **shared** Elasticsearch,
   so results from all workers land in the same indices and appear together in
   the Flask UI.

`terraform.tfvars` holds the `hcloud_token` and is **gitignored** — it is never
committed. Copy `terraform.tfvars.example` to `terraform.tfvars` and fill it in.
`nuclei.yaml` limits (concurrency 30, bulk-size 30, rate-limit 200) are applied
**per worker**, so total throughput scales with `worker_count`.

```
                target list
                     |
         distribute_targets.py (round-robin shards)
        /            |             \
   worker-1      worker-2       worker-3     (Hetzner, cloud-init provisioned)
   httpx/naabu/nuclei each, nuclei -> Interactsh (example.com)
        \            |             /
         \           |            /
          central Elasticsearch (scanner_records / _ports / _findings)
                     |
                 Flask UI
```

## Configuration summary (`Server/config.yml`)

- `elasticsearch.*` — host/port, `index_name`, `ports_index`, `findings_index`,
  result window, and body-index cap. Env overrides: `ES_HOST`, `ES_PORT`,
  `ES_INDEX`.
- `flask.*` — host/port/debug/session. Env overrides: `SECRET_KEY`, `FLASK_DEBUG`.
- `validation.*` — input length/paging caps.
- `paths.*` — SQLite labels location.
- `mongodb.*` — legacy; migration script only.
