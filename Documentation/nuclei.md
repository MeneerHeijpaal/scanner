# nuclei

[nuclei](https://github.com/projectdiscovery/nuclei) is the template-based
vulnerability / misconfiguration scanner. In the scanner it **enriches** URLs:
rather than firing every template at every URL, it runs a technology's templates
only against URLs that actually expose that technology.

## Files

| File | Purpose |
|------|---------|
| `nuclei.yaml` | Per-VPS nuclei settings applied to every run. |
| `interactsh.config` | Self-hosted Interactsh server (see [interactsh.md](interactsh.md)). |
| `nuclei-workflows/tech-conditional-workflow.yaml` | Native nuclei workflow (detect → run matching templates). |
| `nuclei-workflows/detections/*.yaml` | Lightweight detection templates gating the workflow. |
| `Python/nuclei_scan.py` | Runner (workflow mode and tech-aware mode). |
| `Python/import_nuclei.py` | Imports nuclei findings into Elasticsearch. |
| `bin/nuclei` | The nuclei binary (downloaded by the user; gitignored). |

## nuclei.yaml (per-VPS settings)

Applied via `nuclei -config nuclei.yaml`:

| Setting | Value | Meaning |
|---------|-------|---------|
| `concurrency` | 30 | templates executed in parallel |
| `bulk-size` | 30 | hosts analysed in parallel per template |
| `rate-limit` | 200 | max requests per second |
| `scan-strategy` | `host-spray` | scan host-by-host |
| `response-size-read` | 8388608 | max response body read (8 MB) |

These are **per VPS** — every worker runs with the same limits.

## Running templates only where they matter

There are two complementary ways to ensure a template only runs on relevant URLs.

### 1. Workflow mode (default)

```bash
python3 Python/nuclei_scan.py -l urls.txt -o findings.json
```

Runs `nuclei-workflows/tech-conditional-workflow.yaml`. A nuclei **workflow** runs
a detection template first and only executes its subtemplates when that detection
matches:

```yaml
workflows:
  - template: nuclei-workflows/detections/wordpress-detect.yaml
    subtemplates:
      - tags: wordpress            # WordPress templates only if WordPress detected

  - template: nuclei-workflows/detections/frontpage-detect.yaml
    subtemplates:
      - template: http/cves/2000/CVE-2000-0114.yaml   # FrontPage CVE only if FrontPage detected
```

Extend the workflow with more `detect → subtemplates` pairs as needed.

### 2. Tech-aware mode (uses httpx's detected technologies)

```bash
python3 Python/nuclei_scan.py --from-elasticsearch -o findings.json
```

This reads the technologies **httpx already detected** (the `tech` field stored in
Elasticsearch), groups URLs by technology, and runs nuclei once per group with
just the matching tags/templates. This guarantees "only WordPress templates on
WordPress URLs" from real detection data and avoids wasted requests. The
technology → tag/template mapping lives in `Python/nuclei_scan.py`
(`TECH_TO_TAGS`, `TECH_TO_TEMPLATES`) and is easy to extend.

Both modes apply `nuclei.yaml` and the Interactsh server from `interactsh.config`,
write JSON (`-j -o`), and accept `--import` to ingest results immediately.

## Importing findings

```bash
python3 Python/import_nuclei.py -f findings.json
```

Findings are indexed into `elasticsearch.findings_index` (default
`scanner_findings`), keyed by `template-id` + `matched-at` for idempotent upsert.
Mapped fields include `template-id`, `host`, `matched-at`, `matcher-name`,
`info.severity`, `info.tags`, and `timestamp`.

See [architecture.md](architecture.md) for the full pipeline.
