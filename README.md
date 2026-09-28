# Scanner - Reconnaissance Toolkit

A web-based reconnaissance toolkit built around the ProjectDiscovery stack. It
probes targets with **httpx**, scans ports with **naabu**, enriches results with
**nuclei** (using a self-hosted **Interactsh** server for out-of-band detection),
stores everything in **Elasticsearch**, and can spread the work across multiple
**Hetzner** VPSes with Terraform. A Flask web interface provides fast search and
filtering over the results.

## Features

- **Unified Dashboard**: One console (`/dashboard`) joining httpx, naabu, nuclei and Interactsh on the asset, with a live OOB interaction stream and `/body: /title: /url:` + `*` wildcard search
- **Fast Body Search**: Search response body content in <1 second (Elasticsearch phrase search)
- **Single Store**: Elasticsearch is the one runtime data store — all filters, counts, sorting and pagination run as a single query (no MongoDB at runtime)
- **Advanced Filtering**: IP/URL patterns, native CIDR notation, wildcard matching (e.g., `192.168.x.1`)
- **Technology Detection**: Filter by detected web technologies (Apache, nginx, WordPress, etc.)
- **Port & Service Data**: naabu port/service/version results indexed alongside HTTP records
- **Tech-conditional Enrichment**: nuclei runs a technology's templates only against URLs that expose that technology
- **Out-of-band Detection**: self-hosted Interactsh server for blind SSRF/RCE/etc.
- **Hash Labeling**: Tag and categorize responses using SHA256 hashes (stored in local SQLite)
- **Export Capabilities**: Download URLs, domains, raw responses, and headers
- **Idempotent Import**: Records are keyed by URL, so re-importing a URL updates it in place
- **Scale-out**: Distribute scanning across multiple Hetzner VPSes via Terraform

## Architecture

```
Scanner/
├── Python/                      # Scanners and import scripts
│   ├── scanner.py               # httpx scanner wrapper
│   ├── import_httpx.py          # Import httpx results into Elasticsearch
│   ├── naabu_scan.py            # naabu port scanner wrapper
│   ├── import_naabu.py          # Import naabu results into Elasticsearch
│   ├── nuclei_scan.py           # nuclei enrichment (workflow / tech-aware)
│   ├── import_nuclei.py         # Import nuclei findings into Elasticsearch
│   ├── distribute_targets.py    # Shard a target list across VPS workers
│   └── migrate_to_elasticsearch.py  # One-off: legacy MongoDB -> Elasticsearch
├── Server/                      # Flask web application
│   ├── server.py                # Main application entry point
│   ├── config.yml               # Configuration file
│   ├── routes.py                # HTTP route handlers
│   ├── utils.py                 # Utility functions + ES query builder
│   ├── elasticsearch_manager.py # Elasticsearch data store
│   ├── templates/ static/       # HTML templates and assets
│   └── labels/                  # SQLite labels database
├── config/                      # Tool configuration files
│   ├── httpx-config.yaml        # httpx scanner configuration
│   ├── ports.conf               # naabu ports to scan
│   ├── nuclei.yaml              # nuclei per-VPS settings
│   └── interactsh.config        # self-hosted Interactsh server
├── nuclei-workflows/            # nuclei tech-conditional workflow + detections
├── terraform/                   # Hetzner multi-VPS provisioning
├── Documentation/               # Component + architecture docs
├── bin/                         # Location for the binaries (httpx/naabu/nuclei)
├── Elastic_Data/                # Elasticsearch data directory
├── docker-compose.yml           # Elasticsearch Docker configuration
└── requirements.txt             # Python dependencies
```

The scan pipeline is: **httpx** (probe) → **naabu** (ports) → **nuclei**
(tech-conditional enrichment, with **Interactsh** for out-of-band detection), all
stored in **Elasticsearch** and served by the Flask UI. See
[`Documentation/`](Documentation/) for full details on each component and the
overall architecture — [`Documentation/architecture.md`](Documentation/architecture.md)
is the best starting point.

## Prerequisites

### Required

- **Python 3.8+**
- **Elasticsearch 8.x** — the primary and only runtime data store
- **Docker** (recommended, for running Elasticsearch)
- **httpx** binary ([releases](https://github.com/projectdiscovery/httpx/releases))

### Optional (per feature)

- **naabu** binary ([releases](https://github.com/projectdiscovery/naabu/releases)) — port scanning. Needs `libpcap` for SYN scans.
- **nuclei** binary ([releases](https://github.com/projectdiscovery/nuclei/releases)) — enrichment.
- **Interactsh** server — for nuclei out-of-band detection (see [`Documentation/interactsh.md`](Documentation/interactsh.md)).
- **Terraform** + a **Hetzner Cloud** account — for multi-VPS distribution.
- **MongoDB 4.4+** — only to migrate legacy data into Elasticsearch via `Python/migrate_to_elasticsearch.py`. Not used at runtime.

### System Requirements

**Minimum:** 4 GB RAM, 10 GB free disk.
**Recommended for large datasets (500k+ URLs):** 8 GB+ RAM, 50 GB+ disk, SSD.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/MeneerHeijpaal/scanner.git
cd scanner
```

### 2. Install the ProjectDiscovery binaries

Place the binaries in `bin/` (they are gitignored) or anywhere on your `PATH`.
The wrappers look in `./`, `./bin/`, then `PATH`.

```bash
# httpx (required)
wget https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip
unzip httpx_1.6.9_linux_amd64.zip && mv httpx bin/ && chmod +x bin/httpx

# naabu (optional) and nuclei (optional) — install the same way from their releases pages.
# On Debian/Ubuntu, naabu SYN scanning needs libpcap:  sudo apt-get install -y libpcap-dev
```

### 3. Set up the Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate           # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 4. Start Elasticsearch

```bash
mkdir -p Elastic_Data
# The 777 mode is permissive but avoids Docker volume permission issues;
# tighten it if you prefer.
chmod 777 Elastic_Data

docker compose up -d
curl http://localhost:9200            # verify it is up
```

Without Docker Compose:

```bash
docker run -d --name elasticsearch -p 9200:9200 -p 9300:9300 \
  -e "discovery.type=single-node" -e "xpack.security.enabled=false" \
  -e "ES_JAVA_OPTS=-Xms2g -Xmx2g" \
  -v $(pwd)/Elastic_Data:/usr/share/elasticsearch/data \
  docker.elastic.co/elasticsearch/elasticsearch:8.11.0
```

The application creates its indices automatically on first run and import; there
is no manual index setup.

## Quick Start

```bash
source .venv/bin/activate

# 1. Probe targets with httpx (one URL/host per line in urls.txt)
python3 Python/scanner.py -f urls.txt -o results.json

# 2. Import the results into Elasticsearch
python3 Python/import_httpx.py -f results.json

# 3. Start the web interface
python3 Server/server.py
# Search UI:  http://127.0.0.1:8001
# Dashboard:  http://127.0.0.1:8001/dashboard
```

The **dashboard** (`/dashboard`) joins httpx, naabu, nuclei and Interactsh data
on the asset. Its search bar supports `/body:<str>`, `/title:<str>`, `/url:<str>`
tokens and `*` wildcards, and its Interactions tab is a live OOB stream fed by:

```bash
python3 Python/interactsh_stream.py   # leave running; indexes Interactsh callbacks
```

See [`Documentation/dashboard.md`](Documentation/dashboard.md).

Records are indexed directly into Elasticsearch and keyed by URL, so re-importing
the same URL updates the existing record instead of creating a duplicate.

### Port scanning (naabu)

```bash
# Scan the ports listed in ports.conf against hosts derived from urls.txt,
# then import into Elasticsearch.
python3 Python/naabu_scan.py -l urls.txt -o ports.json --import
```

Edit `config/ports.conf` to change which ports are scanned (default:
`21,22,23,25,110,143,445,993,995,2222`). See
[`Documentation/naabu.md`](Documentation/naabu.md).

### Enrichment (nuclei + Interactsh)

```bash
# Tech-aware: read technologies httpx detected from Elasticsearch and run only
# the matching templates per URL group; import findings when done.
python3 Python/nuclei_scan.py --from-elasticsearch -o findings.json --import

# Or run the tech-conditional workflow over a URL list directly:
python3 Python/nuclei_scan.py -l urls.txt -o findings.json --import
```

`config/nuclei.yaml` holds the per-VPS settings and `config/interactsh.config` the
out-of-band server. See [`Documentation/nuclei.md`](Documentation/nuclei.md) and
[`Documentation/interactsh.md`](Documentation/interactsh.md).

### Migrate legacy MongoDB data (one-off)

If you have data from the old MongoDB-backed version:

```bash
python3 Python/migrate_to_elasticsearch.py
python3 Python/migrate_to_elasticsearch.py --batch-size 1000   # slower systems
```

## Configuration

### Server configuration (`Server/config.yml`)

```yaml
flask:
  host: "127.0.0.1"
  port: 8001
  debug: false

elasticsearch:            # primary and only runtime data store
  enabled: true
  host: "localhost"
  port: 9200
  index_name: "scanner_records"    # httpx records
  ports_index: "scanner_ports"     # naabu results
  findings_index: "scanner_findings"  # nuclei findings
  bulk_batch_size: 5000
  max_result_window: 100000
  max_body_index_chars: 2000000

validation:
  max_query_length: 500
  max_per_page: 1000
  max_body_search_length: 1000

# mongodb: (legacy) read only by Python/migrate_to_elasticsearch.py
```

Environment overrides: `SECRET_KEY`, `ES_HOST`, `ES_PORT`, `ES_INDEX`, `FLASK_DEBUG`.

### Tool configuration (`config/`)

All tool configuration lives in the `config/` folder:

- `config/httpx-config.yaml` — httpx settings (tech detection, threads, rate limit, follow-redirects, etc.); `Python/scanner.py` always runs httpx with this file. See the [httpx docs](https://github.com/projectdiscovery/httpx).
- `config/ports.conf` — ports naabu scans.
- `config/nuclei.yaml` — per-VPS nuclei settings (concurrency 30, bulk-size 30, rate-limit 200, `scan-strategy: host-spray`, `response-size-read` 8 MB).
- `config/interactsh.config` — `server_url` and `server_ip` for the out-of-band server.

(`Server/config.yml` above is the Flask/Elasticsearch app configuration, separate from these tool files.)

## Command Reference

```bash
# httpx
python3 Python/scanner.py -f urls.txt -o results.json      # from a file
python3 Python/scanner.py -u https://example.com -o out.json
python3 Python/import_httpx.py -f results.json [--es-host H --es-port P --es-index I --batch-size N]

# naabu
python3 Python/naabu_scan.py -l urls.txt -o ports.json [--import] [-c ports.conf]
python3 Python/naabu_scan.py -host example.com -o ports.json
python3 Python/import_naabu.py -f ports.json [--es-index scanner_ports]

# nuclei
python3 Python/nuclei_scan.py -l urls.txt -o findings.json [--import]        # workflow mode
python3 Python/nuclei_scan.py --from-elasticsearch -o findings.json [--import]  # tech-aware
python3 Python/import_nuclei.py -f findings.json [--es-index scanner_findings]

# distribute across workers
python3 Python/distribute_targets.py -f targets.txt --workers 3 \
    [--hosts ip1,ip2,ip3 --remote-path /opt/scanner/targets.txt]

# migration (one-off)
python3 Python/migrate_to_elasticsearch.py [--mongo-uri URI --db NAME --collection NAME --batch-size N]
```

## Distributing across multiple VPSes (Terraform + Hetzner)

The `terraform/` module provisions N identical scanner workers on Hetzner Cloud
(cloud-init installs httpx/naabu/nuclei, nuclei templates, this repo, and a venv,
and points each worker at a central Elasticsearch and the Interactsh server).

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # then edit it
# set hcloud_token, worker_count, ssh_public_key_path, ssh_admin_cidrs, es_endpoint
terraform init
terraform apply
```

`terraform.tfvars` holds your Hetzner API token and is **gitignored** — it is
never committed. After apply, read the worker IPs (`terraform output worker_ips`)
and shard your targets across them:

```bash
python3 Python/distribute_targets.py -f targets.txt --workers 3 \
    --hosts 203.0.113.10,203.0.113.11,203.0.113.12
```

All workers ingest into the same Elasticsearch, so their results appear together
in the UI. `nuclei.yaml` limits apply per worker, so throughput scales with
`worker_count`. See [`Documentation/architecture.md`](Documentation/architecture.md).

## Web Interface Features

### Search filters

- **IP Address**: exact match, CIDR ranges (native), wildcards (`192.168.x.x`)
- **URL Pattern**: substring matching in URLs and redirect locations
- **Response Body**: full-text phrase search
- **Body / Header Hash**: SHA256 hash lookups
- **HTTP Status Codes**, **Technologies**, **Protocol** (HTTP/HTTPS/both)
- **Labels**: include/exclude labeled responses

### Export options

- **URLs** (plain text), **Domains** (unique), **Full Data** (JSON), **Headers**

### Label management

- Tag responses by body or header hash; include/exclude in searches. Labels are
  stored in a local SQLite database (`Server/labels/labels.db`).

## Large Datasets

Elasticsearch memory scales with dataset size; adjust the heap in
`docker-compose.yml` (`ES_JAVA_OPTS=-Xmx4g` and up). For 1M+ URLs: use SSD
storage, raise the heap to 8 GB+, import in batches, and monitor with
`docker stats`. Because Elasticsearch is not transactional, treat scan data as
re-importable and take snapshots of `Elastic_Data`.

## Troubleshooting

**Elasticsearch won't start**

```bash
docker compose logs elasticsearch
docker compose down && sudo rm -rf Elastic_Data/* && chmod 777 Elastic_Data && docker compose up -d
```

**App can't reach Elasticsearch**

```bash
curl http://localhost:9200                 # is it up?
# confirm elasticsearch.host/port in Server/config.yml (or ES_HOST/ES_PORT), then restart the server
```

**naabu needs privileges** — SYN scanning requires `libpcap` and root/`CAP_NET_RAW`;
run with `sudo` locally (the Terraform workers run as root).

**Migration fails**

```bash
curl http://localhost:9200/_cluster/health?pretty
python3 Python/migrate_to_elasticsearch.py --batch-size 1000
python3 Python/migrate_to_elasticsearch.py --mongo-uri mongodb://localhost:27017
```

## Development

Extending the web app:

1. **New search filter** — update `Server/templates/index.html` (UI),
   `Server/routes.py` (parameter extraction), and
   `Server/utils.py` `build_search_query()` (add an Elasticsearch clause).
2. **New export format** — add a route in `Server/routes.py` and a button in the template.
3. **New nuclei tech mapping** — extend `TECH_TO_TAGS` / `TECH_TO_TEMPLATES` in
   `Python/nuclei_scan.py`, or add a `detect → subtemplates` pair to
   `nuclei-workflows/tech-conditional-workflow.yaml`.

Quick checks:

```bash
python3 -m py_compile Server/*.py Python/*.py    # byte-compile everything
curl http://localhost:9200                        # Elasticsearch up
./bin/httpx -u https://example.com -json           # httpx works
python3 Server/server.py                           # then visit http://127.0.0.1:8001
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Acknowledgments

- [httpx](https://github.com/projectdiscovery/httpx), [naabu](https://github.com/projectdiscovery/naabu), [nuclei](https://github.com/projectdiscovery/nuclei), and [Interactsh](https://github.com/projectdiscovery/interactsh) by ProjectDiscovery
- [Elasticsearch](https://www.elastic.co/)
- [Flask](https://flask.palletsprojects.com/)
- [Hetzner Cloud](https://www.hetzner.com/cloud) + [Terraform](https://www.terraform.io/)

## Security Note

This tool is designed for **authorized** security testing and reconnaissance.
Always ensure you have explicit permission before scanning any target.
Unauthorized scanning may be illegal in your jurisdiction.
