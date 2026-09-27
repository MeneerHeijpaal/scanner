# Documentation

Technical documentation for the scanner and its major components.

| Document | Covers |
|----------|--------|
| [architecture.md](architecture.md) | How all the parts fit together, the Elasticsearch data model, the indices, the Flask app, MongoDB migration, and multi-VPS distribution. **Start here.** |
| [dashboard.md](dashboard.md) | The unified Recon Console dashboard: search syntax, the live Interactsh stream, and its JSON API. |
| [httpx.md](httpx.md) | HTTP probing and importing records into Elasticsearch. |
| [naabu.md](naabu.md) | Port scanning with `ports.conf` and importing port results. |
| [nuclei.md](nuclei.md) | Tech-conditional enrichment (workflow + tech-aware modes) and `nuclei.yaml`. |
| [interactsh.md](interactsh.md) | The self-hosted out-of-band interaction server used by nuclei. |

## Quick map of the moving parts

- **Storage:** Elasticsearch is the single runtime store. Indices:
  `scanner_records` (httpx), `scanner_ports` (naabu), `scanner_findings` (nuclei).
- **Scanners:** `Python/scanner.py` (httpx), `Python/naabu_scan.py` (naabu),
  `Python/nuclei_scan.py` (nuclei).
- **Importers:** `Python/import_httpx.py`, `Python/import_naabu.py`,
  `Python/import_nuclei.py`.
- **Web UI:** `Server/server.py` (search, filter, label, export).
- **Scale-out:** `terraform/` (Hetzner workers) + `Python/distribute_targets.py`.
