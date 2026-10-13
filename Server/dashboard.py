"""
Dashboard routes for the Scanner web application.

Serves the unified recon dashboard (``/dashboard``) and its JSON API, which
joins the Elasticsearch indices produced by the toolchain:

    scanner_records       httpx web records        (store.index_name)
    scanner_ports         naabu port/service data  (elasticsearch.ports_index)
    scanner_findings      nuclei findings          (elasticsearch.findings_index)
    scanner_interactions  Interactsh OOB stream    (elasticsearch.interactions_index)

Search syntax (parsed by ``parse_query``):
    plain text        matches host / url / title (and body as a phrase)
    /body:<STRING>    matches text in the decoded response body
    /title:<STRING>   matches text in the page title
    /url:<STRING>     matches text in the hostname / url
    /ip:<STRING>      matches an IP, CIDR range (e.g. 10.0.0.0/24), or wildcard
    /label:<STRING>   matches responses tagged with a hash label
    *                 wildcard, usable inside any of the above (e.g. wp-* )

Tokens combine with AND, so ``/title:login /url:*.acme.com`` narrows to both.
"""

from flask import render_template, request, jsonify
import hashlib
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# nuclei_scan lives in the repo's Python/ dir; make it importable so the
# on-demand per-URL nuclei route can call scan_url().
_PY_DIR = Path(__file__).resolve().parents[1] / "Python"
if str(_PY_DIR) not in sys.path:
    sys.path.insert(0, str(_PY_DIR))
try:
    import nuclei_scan
except Exception as _e:  # pragma: no cover - only if the Python/ dir moves
    nuclei_scan = None
    logger.warning(f"Could not import nuclei_scan; on-demand nuclei disabled: {_e}")


def _finding_doc_id(rec):
    """Stable id for a nuclei finding (template-id + matched-at).

    Mirrors Python/import_nuclei.finding_doc_id so re-running nuclei updates a
    finding in place instead of duplicating it.
    """
    key = f"{rec.get('template-id', rec.get('templateID', ''))}|" \
          f"{rec.get('matched-at', rec.get('matched', rec.get('host', '')))}"
    return hashlib.sha1(key.encode('utf-8', errors='replace')).hexdigest()

TOKEN_RE = re.compile(r'/(body|title|url|ip|label):', re.IGNORECASE)
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}
MATCH_NONE = {"bool": {"must_not": {"match_all": {}}}}


# --------------------------------------------------------------------------- #
# Query parsing
# --------------------------------------------------------------------------- #

def parse_query(q):
    """Split a search string into {general, body, title, url} parts.

    Text before the first ``/token:`` is the general term; each ``/token:``
    captures everything up to the next token.
    """
    parts = {"general": "", "body": "", "title": "", "url": "", "ip": "", "label": ""}
    q = (q or "").strip()
    if not q:
        return parts
    matches = list(TOKEN_RE.finditer(q))
    if not matches:
        parts["general"] = q
        return parts
    if matches[0].start() > 0:
        parts["general"] = q[:matches[0].start()].strip()
    for i, m in enumerate(matches):
        key = m.group(1).lower()
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(q)
        value = q[start:end].strip()
        if value:
            parts[key] = value
    return parts


def _wc_escape(value):
    """Escape ES wildcard metacharacters, keeping the user's ``*``."""
    return value.replace("\\", "\\\\").replace("?", "\\?")


def _wildcard_value(value):
    """A wildcard pattern: substring match unless the user typed a ``*``."""
    esc = _wc_escape(value)
    return esc if "*" in value else f"*{esc}*"


def _wildcard_over(fields, value):
    """Case-insensitive wildcard match of ``value`` across several fields."""
    val = _wildcard_value(value)
    return {"bool": {"should": [
        {"wildcard": {f: {"value": val, "case_insensitive": True}}} for f in fields
    ], "minimum_should_match": 1}}


def _body_clause(value):
    """Body-text clause: phrase match, or a wildcard term when ``*`` is used."""
    if "*" in value:
        return {"wildcard": {"body_decoded": {"value": value.lower(), "case_insensitive": True}}}
    return {"match_phrase": {"body_decoded": value}}


def build_record_query(parsed, utils=None):
    """ES query for the httpx records index from a parsed search.

    ``utils`` (a ScannerUtils instance) is used for the ``/ip:`` clause (reusing
    the IP/CIDR/wildcard logic) and the ``/label:`` clause (resolving a label to
    hashes via the SQLite label store).
    """
    filters = []
    if parsed["url"]:
        filters.append(_wildcard_over(["host", "url"], parsed["url"]))
    if parsed["title"]:
        filters.append({"wildcard": {"title": {"value": _wildcard_value(parsed["title"]),
                                               "case_insensitive": True}}})
    if parsed["body"]:
        filters.append(_body_clause(parsed["body"]))
    if parsed.get("ip") and utils is not None:
        clause, _err = utils._build_ip_clause(parsed["ip"])
        if clause:
            filters.append(clause)
    if parsed.get("label") and utils is not None:
        hashes = utils.get_hashes_by_label(parsed["label"])
        if not hashes:
            # Label requested but unknown / unused -> match nothing.
            return MATCH_NONE
        filters.append({"bool": {"should": [
            {"terms": {"hash.body_sha256": hashes}},
            {"terms": {"hash.header_sha256": hashes}},
        ], "minimum_should_match": 1}})
    if parsed["general"]:
        g = parsed["general"]
        filters.append({"bool": {"should": [
            {"wildcard": {"host": {"value": _wildcard_value(g), "case_insensitive": True}}},
            {"wildcard": {"url": {"value": _wildcard_value(g), "case_insensitive": True}}},
            {"wildcard": {"title": {"value": _wildcard_value(g), "case_insensitive": True}}},
        ], "minimum_should_match": 1}})
    return {"bool": {"filter": filters}} if filters else {"match_all": {}}


# NOTE: the query for the host-keyed indices (ports/findings) is built by the
# request-scoped ``_host_query`` closure in ``register_dashboard_routes`` — it
# needs the store/utils to resolve ``/ip:`` and ``/label:`` to a host set.


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

def _dig(source, path):
    """Read a dotted path from a nested dict, returning '' if absent."""
    cur = source
    for key in path.split("."):
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return ""
    return cur


def _finding_url(host, matched_at):
    """Best-effort clickable URL for a finding."""
    if isinstance(matched_at, str) and matched_at.startswith(("http://", "https://")):
        return matched_at
    return f"https://{host}" if host else ""


def _dedupe(seq):
    """Order-preserving de-duplication."""
    seen, out = set(), []
    for x in seq:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _split_ips(*sources):
    """Split resolved IPs from one or more record sources into (ipv4, ipv6).

    httpx stores IPv4 in ``host_ip`` / ``a`` and IPv6 in ``aaaa`` (the top-level
    ``ip`` field is unused here). IPv6 is distinguished by a ``:`` in the address.
    """
    v4, v6 = [], []
    for source in sources:
        if not isinstance(source, dict):
            continue
        vals = [source.get("host_ip")]
        vals += source.get("a") or []
        vals += source.get("aaaa") or []
        for val in vals:
            if not isinstance(val, str) or not val:
                continue
            (v6 if ":" in val else v4).append(val)
    return _dedupe(v4), _dedupe(v6)


def _dedupe_ports(hits):
    """Collapse naabu port docs to one entry per port number (drops v4/v6 dups).

    Returns a list of {port, service, product} sorted by port, keeping the first
    non-empty service/product seen for each port.
    """
    by_port = {}
    for h in hits:
        s = h.get("_source", {}) if "_source" in h else h
        port = s.get("port")
        if port is None:
            continue
        entry = by_port.setdefault(port, {"port": port, "service": "", "product": ""})
        if not entry["service"]:
            entry["service"] = s.get("name", "") or s.get("service", "")
        if not entry["product"]:
            entry["product"] = s.get("product", "")
    return [by_port[p] for p in sorted(by_port, key=lambda x: (isinstance(x, str), x))]


def _is_oob(source, tags):
    """Whether a finding was confirmed out-of-band (Interactsh)."""
    if source.get("interactsh_protocol") or source.get("interaction"):
        return True
    return any(t in ("oob", "interactsh") for t in (tags or []))


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #

def register_dashboard_routes(app, store, config, utils):
    """Register the dashboard page and its JSON API."""
    es = config.get("elasticsearch", {})
    IDX_RECORDS = store.index_name
    IDX_PORTS = es.get("ports_index", "scanner_ports")
    IDX_FINDINGS = es.get("findings_index", "scanner_findings")
    IDX_INTERACTIONS = es.get("interactions_index", "scanner_interactions")

    def _q():
        return utils.sanitize_string_input(request.args.get("q", ""), max_length=500)

    def _record_host_set(parsed):
        """Hosts matching the record-level filters (``/ip:`` / ``/label:``).

        These filters live on the httpx records index (they need ``ip_addr`` /
        the hash fields, which the host-keyed indices don't carry), so to filter
        ports/findings by them we first resolve the set of hosts they match and
        then constrain by host.

        Returns ``None`` when neither filter is active (no host constraint), or a
        list of matching hosts otherwise — an empty list means "match nothing".
        """
        rfilters = []
        if parsed.get("ip"):
            clause, _err = utils._build_ip_clause(parsed["ip"])
            if not clause:
                return []  # invalid IP pattern -> match nothing
            rfilters.append(clause)
        if parsed.get("label"):
            hashes = utils.get_hashes_by_label(parsed["label"])
            if not hashes:
                return []  # unknown / unused label -> match nothing
            rfilters.append({"bool": {"should": [
                {"terms": {"hash.body_sha256": hashes}},
                {"terms": {"hash.header_sha256": hashes}},
            ], "minimum_should_match": 1}})
        if not rfilters:
            return None
        agg = store.raw_search(IDX_RECORDS, query={"bool": {"filter": rfilters}}, size=0,
                               aggs={"hosts": {"terms": {"field": "host", "size": 10000}}})
        return [b["key"] for b in _dig(agg.get("aggregations", {}), "hosts.buckets") or []]

    def _host_query(parsed):
        """Query for the host-keyed indices (ports/findings), honoring every token.

        ``url`` / ``general`` narrow by host directly; ``/ip:`` and ``/label:`` are
        resolved to a host set via :func:`_record_host_set` so they filter these
        indices too (fixes ports/findings ignoring an ``/ip:`` search).
        """
        filters = []
        term = parsed["url"] or parsed["general"]
        if term:
            filters.append(_wildcard_over(["host"], term))
        hosts = _record_host_set(parsed)
        if hosts is not None:
            if not hosts:
                return MATCH_NONE
            filters.append({"terms": {"host": hosts}})
        return {"bool": {"filter": filters}} if filters else {"match_all": {}}

    @app.route("/")
    @app.route("/dashboard")
    def dashboard_page():
        """Render the unified recon dashboard (the default landing page)."""
        return render_template("dashboard.html")

    @app.route("/api/dashboard/summary")
    def dashboard_summary():
        """KPIs, severity distribution, top technologies, and body-match count."""
        parsed = parse_query(_q())
        rq = build_record_query(parsed, utils)
        hq = _host_query(parsed)

        rec = store.raw_search(IDX_RECORDS, query=rq, size=0, aggs={
            "assets": {"cardinality": {"field": "host"}},
            "tech": {"terms": {"field": "tech", "size": 8}},
        })
        endpoints = _total(rec)
        assets = int(_dig(rec.get("aggregations", {}), "assets.value") or 0)
        tech = [{"name": b["key"], "count": b["doc_count"]}
                for b in _dig(rec.get("aggregations", {}), "tech.buckets") or []]

        fnd = store.raw_search(IDX_FINDINGS, query=hq, size=0, aggs={
            "sev": {"terms": {"field": "info.severity", "size": 10}},
        })
        sev_buckets = {b["key"]: b["doc_count"]
                       for b in _dig(fnd.get("aggregations", {}), "sev.buckets") or []}
        severities = [{"severity": s, "count": sev_buckets.get(s, 0)}
                      for s in SEVERITY_ORDER if s != "unknown"]

        ports_total = store.raw_count(IDX_PORTS, hq)
        interactions_total = store.raw_count(IDX_INTERACTIONS, {"match_all": {}})

        # Body-match counter: how many records contain the /body: string,
        # independent of the other active filters. Only when a body search is set.
        body_count = None
        if parsed["body"]:
            body_count = store.raw_count(IDX_RECORDS, {"bool": {"filter": [_body_clause(parsed["body"])]}})

        return jsonify({
            "kpis": {
                "assets": assets,
                "endpoints": endpoints,
                "ports": ports_total,
                "findings": _total(fnd),
                "critical": sev_buckets.get("critical", 0),
                "high": sev_buckets.get("high", 0),
                "interactions": interactions_total,
            },
            "severities": severities,
            "technologies": tech,
            "body_count": body_count,
            "filtered": any(parsed.values()),
        })

    @app.route("/api/dashboard/findings")
    def dashboard_findings():
        """Findings table, severity-ranked."""
        parsed = parse_query(_q())
        resp = store.raw_search(IDX_FINDINGS, query=_host_query(parsed), size=500,
                                source=["template-id", "info", "matched-at", "host",
                                        "interactsh_protocol", "interaction"])
        rows = []
        for hit in _dig(resp, "hits.hits") or []:
            s = hit.get("_source", {})
            info = s.get("info", {}) or {}
            tags = info.get("tags", []) or []
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",") if t.strip()]
            host = s.get("host", "")
            matched = s.get("matched-at", "")
            rows.append({
                "id": s.get("template-id", ""),
                "name": info.get("name", ""),
                "severity": (info.get("severity") or "unknown").lower(),
                "matched_at": matched,
                "host": host,
                "tags": tags,
                "oob": _is_oob(s, tags),
                "url": _finding_url(host, matched),
            })
        rows.sort(key=lambda r: (SEVERITY_RANK.get(r["severity"], 99), r["host"]))
        return jsonify({"rows": rows, "total": len(rows)})

    @app.route("/api/dashboard/assets")
    def dashboard_assets():
        """Assets table: records joined with per-host port and finding counts."""
        parsed = parse_query(_q())
        rq = build_record_query(parsed, utils)
        hq = _host_query(parsed)

        rec = store.raw_search(IDX_RECORDS, query=rq, size=0, aggs={
            "hosts": {"terms": {"field": "host", "size": 2000, "order": {"_count": "desc"}},
                      "aggs": {"sample": {"top_hits": {"size": 5, "_source": [
                          "url", "scheme", "host_ip", "a", "aaaa", "nuclei_scanned"]}}}},
        })
        port_agg = store.raw_search(IDX_PORTS, query=hq, size=0, aggs={
            "hosts": {"terms": {"field": "host", "size": 2000}}})
        find_agg = store.raw_search(IDX_FINDINGS, query=hq, size=0, aggs={
            "hosts": {"terms": {"field": "host", "size": 2000},
                      "aggs": {"sev": {"terms": {"field": "info.severity", "size": 10}}}}})

        ports_by_host = {b["key"]: b["doc_count"]
                         for b in _dig(port_agg.get("aggregations", {}), "hosts.buckets") or []}
        find_by_host, topsev_by_host = {}, {}
        for b in _dig(find_agg.get("aggregations", {}), "hosts.buckets") or []:
            find_by_host[b["key"]] = b["doc_count"]
            sevs = [sb["key"].lower() for sb in _dig(b, "sev.buckets") or []]
            topsev_by_host[b["key"]] = min(sevs, key=lambda s: SEVERITY_RANK.get(s, 99)) if sevs else "info"

        rows = []
        for b in _dig(rec.get("aggregations", {}), "hosts.buckets") or []:
            host = b["key"]
            samples = [h.get("_source", {}) for h in (_dig(b, "sample.hits.hits") or [])]
            first = samples[0] if samples else {}
            ipv4, ipv6 = _split_ips(*samples)
            # Prefer an https endpoint as the representative URL.
            url = next((s.get("url") for s in samples if s.get("scheme") == "https" and s.get("url")),
                       first.get("url", "")) or (f"https://{host}" if host else "")
            rows.append({
                "host": host,
                "ipv4": ipv4,
                "ipv6": ipv6,
                "url": url,
                "endpoints": b["doc_count"],
                "ports": ports_by_host.get(host, 0),
                "findings": find_by_host.get(host, 0),
                "top_severity": topsev_by_host.get(host, "info"),
                "nuclei_scanned": any(s.get("nuclei_scanned") for s in samples),
            })
        rows.sort(key=lambda r: (-r["findings"], -r["endpoints"], r["host"]))
        return jsonify({"rows": rows, "total": len(rows)})

    @app.route("/api/dashboard/ports")
    def dashboard_ports():
        """Open ports grouped into one row per host (URLs, IPs and ports joined).

        Dual-stack hosts report the same port on both their IPv4 and IPv6
        addresses; those are collapsed to one entry per port number. IPs are split
        into IPv4 / IPv6 for display.
        """
        parsed = parse_query(_q())
        resp = store.raw_search(IDX_PORTS, query=_host_query(parsed), size=10000,
                                sort=[{"host": {"order": "asc"}}, {"port": {"order": "asc"}}],
                                source=["host", "port", "name", "product", "ip"])
        # Group flat port docs by host (top_hits inner window caps at 100, so we
        # group client-side instead).
        grouped = {}
        for h in _dig(resp, "hits.hits") or []:
            s = h.get("_source", {})
            host = s.get("host", "")
            g = grouped.setdefault(host, {"hits": [], "v4": [], "v6": []})
            g["hits"].append(h)
            ip = s.get("ip")
            if isinstance(ip, str) and ip:
                (g["v6"] if ":" in ip else g["v4"]).append(ip)
        rows = [{
            "host": host,
            "ipv4": _dedupe(g["v4"]),
            "ipv6": _dedupe(g["v6"]),
            "ports": _dedupe_ports(g["hits"]),
        } for host, g in sorted(grouped.items())]
        return jsonify({"rows": rows, "total": len(rows)})

    @app.route("/api/dashboard/asset")
    def dashboard_asset():
        """Everything about one host, joined across the tools (drawer view)."""
        host = utils.sanitize_string_input(request.args.get("host", ""), max_length=253)
        if not host:
            return jsonify({"error": "host required"}), 400
        term = {"term": {"host": host}}

        web = store.raw_search(IDX_RECORDS, query=term, size=100,
                               source=["url", "scheme", "status_code", "title", "tech",
                                       "content_length", "host_ip", "a", "aaaa",
                                       "nuclei_scanned", "nuclei_finding_count"])
        ports = store.raw_search(IDX_PORTS, query=term, size=500,
                                 sort=[{"port": {"order": "asc"}}],
                                 source=["port", "name", "product", "ip"])
        finds = store.raw_search(IDX_FINDINGS, query=term, size=200,
                                 source=["template-id", "info", "matched-at",
                                         "interactsh_protocol", "interaction"])

        web_hits = _dig(web, "hits.hits") or []
        endpoints = []
        for h in web_hits:
            s = h["_source"]
            endpoints.append({
                "id": h["_id"],
                "url": s.get("url", ""),
                "scheme": s.get("scheme", ""),
                "status": s.get("status_code", ""),
                "title": s.get("title", ""),
                "tech": s.get("tech", []) or [],
                "nuclei_scanned": bool(s.get("nuclei_scanned")),
                "nuclei_finding_count": s.get("nuclei_finding_count", 0) or 0,
            })
        # Prefer https first, then http, then anything else.
        endpoints.sort(key=lambda e: (0 if e["scheme"] == "https" else 1 if e["scheme"] == "http" else 2,
                                      e["url"]))
        ipv4, ipv6 = _split_ips(*(h["_source"] for h in web_hits))
        port_rows = _dedupe_ports(_dig(ports, "hits.hits") or [])
        finding_rows = []
        for h in _dig(finds, "hits.hits") or []:
            s = h["_source"]
            info = s.get("info", {}) or {}
            tags = info.get("tags", []) or []
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",") if t.strip()]
            finding_rows.append({
                "id": s.get("template-id", ""),
                "name": info.get("name", ""),
                "severity": (info.get("severity") or "unknown").lower(),
                "matched_at": s.get("matched-at", ""),
                "tags": tags,
                "oob": _is_oob(s, tags),
            })
        finding_rows.sort(key=lambda r: SEVERITY_RANK.get(r["severity"], 99))
        return jsonify({"host": host, "endpoints": endpoints, "ipv4": ipv4, "ipv6": ipv6,
                        "ports": port_rows, "findings": finding_rows})

    @app.route("/api/dashboard/record")
    def dashboard_record():
        """Full detail for a single httpx record (the per-URL detail view)."""
        doc_id = utils.validate_doc_id(request.args.get("id", ""))
        if not doc_id:
            return jsonify({"error": "invalid id"}), 400
        item = store.get(doc_id)
        if not item:
            return jsonify({"error": "not found"}), 404

        item = utils.decode_base64_fields(item)
        h = item.get("hash", {}) or {}
        body_hash, header_hash = h.get("body_sha256"), h.get("header_sha256")

        body_count = store.count({"term": {"hash.body_sha256": body_hash}}) if body_hash else 0
        header_count = store.count({"term": {"hash.header_sha256": header_hash}}) if header_hash else 0

        header = item.get("header", {}) or {}
        redirect_location = None
        status_code = item.get("status_code")
        if status_code and 300 <= status_code < 400 and isinstance(header, dict):
            redirect_location = header.get("location") or header.get("Location")

        ip_count = 0
        host = item.get("host") or item.get("ip")
        if host:
            ip_count = store.count({"bool": {"should": [
                {"term": {"ip": host}}, {"term": {"host": host}},
            ], "minimum_should_match": 1}})

        return jsonify({
            "id": item.get("_id"),
            "url": item.get("url", ""),
            "redirect_location": redirect_location,
            "host": item.get("host", ""),
            "ip_count": ip_count,
            "timestamp": item.get("timestamp", ""),
            "status_code": status_code,
            "method": item.get("method", ""),
            "scheme": item.get("scheme", ""),
            "port": item.get("port", ""),
            "path": item.get("path", ""),
            "content_type": item.get("content_type", ""),
            "content_length": item.get("content_length", ""),
            "time": item.get("time", ""),
            "body_sha256": body_hash, "header_sha256": header_hash,
            "body_count": body_count, "header_count": header_count,
            "body_label": utils.get_hash_label(body_hash) if body_hash else None,
            "header_label": utils.get_hash_label(header_hash) if header_hash else None,
            "input": item.get("input", ""),
            "a": item.get("a", []) or [],
            "cname": item.get("cname", []) or [],
            "tech": item.get("tech", []) or [],
            "words": item.get("words", ""),
            "lines": item.get("lines", ""),
            "knowledgebase": item.get("knowledgebase", {}) or {},
            "header": header if isinstance(header, dict) else {},
            "body_decoded": item.get("body_decoded", ""),
            "has_raw_header": bool(item.get("raw_header")),
            "has_request": bool(item.get("request")),
        })

    def _enrich_record(item):
        """Run ``nuclei -as`` for one record's URL, index findings, mark scanned.

        Returns ``(finding_count, indexed, rows)``. Raises if the scan itself
        fails. Findings are host-joined so the drawer / dashboard pick them up
        (nuclei's own host may carry a port or differ slightly).
        """
        doc_id = item.get("_id")
        url = item.get("url")
        host = item.get("host") or item.get("ip") or ""
        findings = nuclei_scan.scan_url(url)
        now = datetime.now(timezone.utc).isoformat()
        indexed, rows = 0, []
        for rec in findings:
            rec.setdefault("timestamp", now)
            if host:
                rec["host"] = host
            if store.index_into(IDX_FINDINGS, _finding_doc_id(rec), rec):
                indexed += 1
            info = rec.get("info", {}) or {}
            rows.append({
                "id": rec.get("template-id", rec.get("templateID", "")),
                "name": info.get("name", ""),
                "severity": (info.get("severity") or "unknown").lower(),
                "matched_at": rec.get("matched-at", ""),
            })
        store.update_document(doc_id, {
            "nuclei_scanned": True,
            "nuclei_scanned_at": now,
            "nuclei_finding_count": len(findings),
        })
        return len(findings), indexed, rows

    @app.route("/api/dashboard/nuclei/<id>", methods=["POST"])
    def dashboard_run_nuclei(id):
        """Run an on-demand ``nuclei -as`` scan for a single URL (by record id).

        Triggered when the user clicks the nuclei icon next to a URL in the asset
        drawer. Runs automatic-scan mode against that URL, indexes any findings,
        and marks the record scanned so the icon renders in its dark state.
        """
        if nuclei_scan is None:
            return jsonify({"error": "nuclei integration unavailable"}), 503
        doc_id = utils.validate_doc_id(id)
        if not doc_id:
            return jsonify({"error": "invalid id"}), 400
        item = store.get(doc_id)
        if not item:
            return jsonify({"error": "not found"}), 404
        if not item.get("url"):
            return jsonify({"error": "record has no url"}), 400

        try:
            count, indexed, rows = _enrich_record(item)
        except Exception as e:
            logger.error(f"nuclei scan failed for {item.get('url')}: {e}")
            return jsonify({"error": f"nuclei scan failed: {e}"}), 500
        rows.sort(key=lambda r: SEVERITY_RANK.get(r["severity"], 99))
        return jsonify({"ok": True, "scanned": True, "id": doc_id, "url": item.get("url"),
                        "host": item.get("host", ""), "finding_count": count,
                        "indexed": indexed, "findings": rows})

    @app.route("/api/dashboard/nuclei-host", methods=["POST"])
    def dashboard_run_nuclei_host():
        """Run ``nuclei -as`` for every URL of a host (the Assets-row trigger).

        Scans each endpoint (e.g. the HTTP and HTTPS URLs) of the host, indexes
        all findings, and marks each record scanned.
        """
        if nuclei_scan is None:
            return jsonify({"error": "nuclei integration unavailable"}), 503
        host = utils.sanitize_string_input(request.args.get("host", ""), max_length=253)
        if not host:
            return jsonify({"error": "host required"}), 400

        records, _ = store.search({"term": {"host": host}}, source=["url", "host"], size=100)
        records = [r for r in records if r.get("url")]
        if not records:
            return jsonify({"error": "no URLs for host"}), 404

        total, scanned, failed = 0, 0, 0
        for item in records:
            try:
                count, _indexed, _rows = _enrich_record(item)
                total += count
                scanned += 1
            except Exception as e:
                failed += 1
                logger.error(f"nuclei scan failed for {item.get('url')}: {e}")
        if scanned == 0:
            return jsonify({"error": "all nuclei scans failed"}), 500
        return jsonify({"ok": True, "scanned": True, "host": host,
                        "urls_scanned": scanned, "urls_failed": failed,
                        "finding_count": total})

    @app.route("/api/dashboard/interactions")
    def dashboard_interactions():
        """Live Interactsh interaction stream, newest first.

        Pass ``after`` (an ISO timestamp) to fetch only interactions newer than a
        cursor — the page polls with the newest timestamp it has seen.
        """
        after = request.args.get("after", "").strip()
        query = {"match_all": {}}
        if after:
            query = {"bool": {"filter": [{"range": {"timestamp": {"gt": after}}}]}}
        resp = store.raw_search(IDX_INTERACTIONS, query=query, size=100,
                                sort=[{"timestamp": {"order": "desc"}}],
                                source=["protocol", "unique-id", "full-id",
                                        "remote-address", "timestamp"])
        rows = [{
            "protocol": h["_source"].get("protocol", ""),
            "unique_id": h["_source"].get("unique-id", ""),
            "full_id": h["_source"].get("full-id", ""),
            "remote": h["_source"].get("remote-address", ""),
            "timestamp": h["_source"].get("timestamp", ""),
        } for h in _dig(resp, "hits.hits") or []]
        return jsonify({"rows": rows, "total": len(rows)})


def _total(resp):
    """Extract hits.total.value from a raw ES response."""
    total = _dig(resp, "hits.total")
    if isinstance(total, dict):
        return int(total.get("value", 0))
    return int(total or 0)
