# httpx

[httpx](https://github.com/projectdiscovery/httpx) is the HTTP probing engine.
It takes a list of URLs/hosts, performs HTTP requests, and emits a rich JSON
record per target (status code, title, technologies, hashes, headers, body,
etc.). httpx is the primary source of records in the scanner.

## Files

| File | Purpose |
|------|---------|
| `Python/scanner.py` | Wrapper that runs the bundled `httpx` binary over a URL file or single URL. |
| `config/httpx-config.yaml` | httpx scan configuration (tech detection, threads, rate limit, etc.). |
| `Python/import_httpx.py` | Imports httpx JSON output into Elasticsearch. |
| `bin/httpx` | The httpx binary — **required**; install per README step 2 (gitignored). |

## Running a scan

```bash
# From a file of URLs/hosts (one per line)
python3 Python/scanner.py -f urls.txt -o results.json

# Single URL
python3 Python/scanner.py -u https://example.com -o results.json
```

`scanner.py` invokes:

```
httpx -config config/httpx-config.yaml -l <input> -j -o <output>
```

`-j` produces JSON output; `-o` writes it to a file.

## Importing results

```bash
python3 Python/import_httpx.py -f results.json
```

The importer:

- Detects NDJSON, a JSON array, or a single JSON object.
- Base64-decodes the `body` field into `body_decoded` for full-text search.
- Bulk-indexes records into the Elasticsearch record index
  (`elasticsearch.index_name`, default `scanner_records`).
- Keys each document by a SHA1 of its URL, so **re-importing the same URL
  updates the existing record** rather than creating a duplicate. This replaces
  the old interactive duplicate prompt and makes imports safe to automate.

Override the Elasticsearch target if needed:

```bash
python3 Python/import_httpx.py -f results.json --es-host 10.0.0.5 --es-port 9200
```

## Record fields (indexed)

The Elasticsearch mapping (see `Server/elasticsearch_manager.py`) maps the httpx
fields the UI searches on:

| Field | ES type | Used for |
|-------|---------|----------|
| `url`, `redirect_location`, `path` | `wildcard` | substring / prefix search |
| `ip` | `wildcard` | IP as string (prefix / wildcard) |
| `ip_addr` | `ip` | exact IP and **native CIDR** queries |
| `host` | `wildcard` | hostname / partial |
| `scheme` | `keyword` | protocol filter (http/https) |
| `tech` | `keyword[]` | technology facet + filter |
| `status_code` | `integer` | status filter |
| `hash.body_sha256`, `hash.header_sha256` | `keyword` | hash lookups / labels |
| `body_decoded` | `text` | full-text (phrase) body search |
| `body`, `raw_header`, `request` | stored, not indexed | download / decode only |

Unknown httpx fields are stored in `_source` (so nothing is lost and they remain
downloadable) but are not indexed, keeping the mapping stable.

See [architecture.md](architecture.md) for how httpx feeds naabu and nuclei.
