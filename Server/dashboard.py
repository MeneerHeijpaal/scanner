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
    *                 wildcard, usable inside any of the above (e.g. wp-* )

Tokens combine with AND, so ``/title:login /url:*.acme.com`` narrows to both.
"""

from flask import render_template, request, jsonify
import logging
import re

logger = logging.getLogger(__name__)

TOKEN_RE = re.compile(r'/(body|title|url):', re.IGNORECASE)
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


# --------------------------------------------------------------------------- #
# Query parsing
# --------------------------------------------------------------------------- #

def parse_query(q):
    """Split a search string into {general, body, title, url} parts.

    Text before the first ``/token:`` is the general term; each ``/token:``
    captures everything up to the next token.
    """
    parts = {"general": "", "body": "", "title": "", "url": ""}
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


def build_record_query(parsed):
    """ES query for the httpx records index from a parsed search."""
    filters = []
    if parsed["url"]:
        filters.append(_wildcard_over(["host", "url"], parsed["url"]))
    if parsed["title"]:
        filters.append({"wildcard": {"title": {"value": _wildcard_value(parsed["title"]),
                                               "case_insensitive": True}}})
    if parsed["body"]:
        filters.append(_body_clause(parsed["body"]))
    if parsed["general"]:
        g = parsed["general"]
        filters.append({"bool": {"should": [
            {"wildcard": {"host": {"value": _wildcard_value(g), "case_insensitive": True}}},
            {"wildcard": {"url": {"value": _wildcard_value(g), "case_insensitive": True}}},
            {"wildcard": {"title": {"value": _wildcard_value(g), "case_insensitive": True}}},
        ], "minimum_should_match": 1}})
    return {"bool": {"filter": filters}} if filters else {"match_all": {}}


def build_host_query(parsed):
    """ES query for host-keyed indices (ports/findings/interactions).

    Only host-ish tokens (url / general) narrow these; body/title do not apply.
    """
    term = parsed["url"] or parsed["general"]
    if not term:
        return {"match_all": {}}
    return _wildcard_over(["host"], term)


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

    @app.route("/dashboard")
    def dashboard_page():
        """Render the unified recon dashboard."""
        return render_template("dashboard.html")

    @app.route("/api/dashboard/summary")
    def dashboard_summary():
        """KPIs, severity distribution, top technologies, and body-match count."""
        parsed = parse_query(_q())
        rq = build_record_query(parsed)

        rec = store.raw_search(IDX_RECORDS, query=rq, size=0, aggs={
            "assets": {"cardinality": {"field": "host"}},
            "tech": {"terms": {"field": "tech", "size": 8}},
        })
        endpoints = _total(rec)
        assets = int(_dig(rec.get("aggregations", {}), "assets.value") or 0)
        tech = [{"name": b["key"], "count": b["doc_count"]}
                for b in _dig(rec.get("aggregations", {}), "tech.buckets") or []]

        fnd = store.raw_search(IDX_FINDINGS, query=build_host_query(parsed), size=0, aggs={
            "sev": {"terms": {"field": "info.severity", "size": 10}},
        })
        sev_buckets = {b["key"]: b["doc_count"]
                       for b in _dig(fnd.get("aggregations", {}), "sev.buckets") or []}
        severities = [{"severity": s, "count": sev_buckets.get(s, 0)}
                      for s in SEVERITY_ORDER if s != "unknown"]

        ports_total = store.raw_count(IDX_PORTS, build_host_query(parsed))
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
        resp = store.raw_search(IDX_FINDINGS, query=build_host_query(parsed), size=500,
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
        rq = build_record_query(parsed)

        rec = store.raw_search(IDX_RECORDS, query=rq, size=0, aggs={
            "hosts": {"terms": {"field": "host", "size": 200, "order": {"_count": "desc"}},
                      "aggs": {"sample": {"top_hits": {"size": 1, "_source": ["ip", "url"]}}}},
        })
        port_agg = store.raw_search(IDX_PORTS, query=build_host_query(parsed), size=0, aggs={
            "hosts": {"terms": {"field": "host", "size": 2000}}})
        find_agg = store.raw_search(IDX_FINDINGS, query=build_host_query(parsed), size=0, aggs={
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
            sample = (_dig(b, "sample.hits.hits") or [{}])[0].get("_source", {})
            rows.append({
                "host": host,
                "ip": sample.get("ip", ""),
                "url": sample.get("url", "") or (f"https://{host}" if host else ""),
                "endpoints": b["doc_count"],
                "ports": ports_by_host.get(host, 0),
                "findings": find_by_host.get(host, 0),
                "top_severity": topsev_by_host.get(host, "info"),
            })
        rows.sort(key=lambda r: (-r["findings"], -r["endpoints"], r["host"]))
        return jsonify({"rows": rows, "total": len(rows)})

    @app.route("/api/dashboard/ports")
    def dashboard_ports():
        """Open ports / services table."""
        parsed = parse_query(_q())
        resp = store.raw_search(IDX_PORTS, query=build_host_query(parsed), size=500,
                                sort=[{"host": {"order": "asc"}}, {"port": {"order": "asc"}}],
                                source=["host", "ip", "port", "service", "version"])
        rows = [{
            "host": h["_source"].get("host", ""),
            "ip": h["_source"].get("ip", ""),
            "port": h["_source"].get("port", ""),
            "service": h["_source"].get("service", ""),
            "version": h["_source"].get("version", ""),
        } for h in _dig(resp, "hits.hits") or []]
        return jsonify({"rows": rows, "total": len(rows)})

    @app.route("/api/dashboard/asset")
    def dashboard_asset():
        """Everything about one host, joined across the tools (drawer view)."""
        host = utils.sanitize_string_input(request.args.get("host", ""), max_length=253)
        if not host:
            return jsonify({"error": "host required"}), 400
        term = {"term": {"host": host}}

        web = store.raw_search(IDX_RECORDS, query=term, size=100,
                               source=["url", "status_code", "title", "tech", "content_length"])
        ports = store.raw_search(IDX_PORTS, query=term, size=200,
                                 sort=[{"port": {"order": "asc"}}],
                                 source=["port", "service", "version"])
        finds = store.raw_search(IDX_FINDINGS, query=term, size=200,
                                 source=["template-id", "info", "matched-at",
                                         "interactsh_protocol", "interaction"])

        endpoints = []
        for h in _dig(web, "hits.hits") or []:
            s = h["_source"]
            endpoints.append({
                "url": s.get("url", ""),
                "status": s.get("status_code", ""),
                "title": s.get("title", ""),
                "tech": s.get("tech", []) or [],
            })
        port_rows = [{
            "port": h["_source"].get("port", ""),
            "service": h["_source"].get("service", ""),
            "version": h["_source"].get("version", ""),
        } for h in _dig(ports, "hits.hits") or []]
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
        return jsonify({"host": host, "endpoints": endpoints,
                        "ports": port_rows, "findings": finding_rows})

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
