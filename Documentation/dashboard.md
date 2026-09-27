# Dashboard

The **Recon Console** is a unified dashboard that joins the Elasticsearch indices
produced by the toolchain into one view, organized around the *asset* (host):
click any host and see its web endpoints (httpx), open ports (naabu), findings
(nuclei) and out-of-band interactions (Interactsh) together.

It is served by the same Flask app as the search UI.

- **Page:** `GET /dashboard`
- **Code:** `Server/dashboard.py` (routes + search parsing), `Server/templates/dashboard.html` (UI)

## Data sources

| Panel | Index | Written by |
|-------|-------|------------|
| Assets / Web endpoints / technologies | `scanner_records` | `import_httpx.py` |
| Ports | `scanner_ports` | `import_naabu.py` |
| Findings / severity | `scanner_findings` | `import_nuclei.py` |
| Interactions (live) | `scanner_interactions` | `interactsh_stream.py` |

## Search syntax

The search bar filters the whole console live as you type. Plain text matches the
host, URL and page title. Prefix tokens narrow the search:

| Token | Matches |
|-------|---------|
| `/body:<STRING>` | text in the decoded response body |
| `/title:<STRING>` | text in the page title |
| `/url:<STRING>` | text in the hostname / URL |
| `*` | wildcard, usable inside any token or plain text (e.g. `wp-*`, `/url:*.acme.com`) |

Tokens combine with AND: `/title:login /url:shop.acme.com` narrows to both.

Behaviour:

- **Live filtering** — results update as you type (debounced).
- **Enter commits** — pressing Enter shows a **Filtered** indicator so it is clear
  the whole view is filtered.
- **Body-match counter** — when a `/body:` search is active, a counter next to the
  **Assets** title shows how many URLs contain that body text (independent of the
  other active filters). It is hidden when no body search is set.
- **External-link icons** — an open-in-new-tab icon sits to the right of each URL
  in the **Assets** table and in the **Web endpoints** section of the asset drawer.

## Live Interactsh stream

The **Interactions** tab is a live feed of out-of-band callbacks. It is fed by a
collector that runs the Interactsh client and indexes each interaction:

```bash
# Point interactsh.config at your server, then run the collector (leave it running)
python3 Python/interactsh_stream.py
```

The collector runs `interactsh-client -server <interactsh.config server_url> -json`
and indexes every DNS/HTTP/SMTP callback into `scanner_interactions`. The dashboard
polls `GET /api/dashboard/interactions?after=<timestamp>` every few seconds and
prepends new events, so the stream updates without a page reload.

## JSON API

All endpoints accept the `q` search parameter described above.

| Endpoint | Returns |
|----------|---------|
| `GET /api/dashboard/summary` | KPIs, severity distribution, top technologies, body-match count |
| `GET /api/dashboard/findings` | findings table (severity-ranked) |
| `GET /api/dashboard/assets` | assets joined with per-host port/finding counts |
| `GET /api/dashboard/ports` | open ports / services |
| `GET /api/dashboard/asset?host=<host>` | one host's endpoints, ports and findings (drawer) |
| `GET /api/dashboard/interactions?after=<ts>` | Interactsh interactions newer than a cursor |

## Notes

- `title` was added to the `scanner_records` mapping so `/title:` search works.
  New httpx imports index it automatically; to make **existing** records
  title-searchable, re-import them (or reindex).
- Findings are marked **OOB confirmed** when the nuclei finding carries an
  Interactsh interaction (`interactsh_protocol`) or an `oob`/`interactsh` tag.
