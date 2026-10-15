"""
Administration routes for the Scanner web application.

Serves the admin console (``/admin``) and its JSON API for whole-system
maintenance:

    GET  /api/admin/status            counts per index + labels, data-present flag
    GET  /api/admin/backup            download a .zip of all Elastic data + labels
    POST /api/admin/clear             wipe all Elastic indices + the labels table
    POST /api/admin/import            restore a backup .zip (mode=overwrite|merge)
    GET  /api/admin/check/terraform   can the user provision agents? (Hetzner auth)
    GET  /api/admin/check/oob         does the Interactsh (OOB) server reply?

A backup .zip contains:
    manifest.json              {version, created, indices:{name:count}, labels:N}
    labels.json                [ {hash,label,hash_type,created_at,updated_at}, ... ]
    mappings/<name>.json       each index's mappings (so restore recreates it)
    indices/<name>.ndjson      one {"_id","_source"} JSON object per line
"""

from flask import render_template, request, jsonify, send_file, current_app
import io
import json
import logging
import shutil
import socket
import sqlite3
import ssl
import subprocess
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# Friendly name -> config key, resolved against the real index names at register.
_INDEX_KEYS = {
    "records": ("index_name", "scanner_records"),
    "ports": ("ports_index", "scanner_ports"),
    "findings": ("findings_index", "scanner_findings"),
    "interactions": ("interactions_index", "scanner_interactions"),
}

# Cap an uploaded backup's total uncompressed size to guard against zip bombs.
MAX_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024  # 1 GiB
HETZNER_API = "https://api.hetzner.cloud/v1/ssh_keys"


def register_admin_routes(app, store, config, utils):
    """Register the admin page and its JSON API."""
    repo_root = Path(__file__).resolve().parents[1]
    es = config.get("elasticsearch", {})
    # Map friendly name -> actual index name (honoring config overrides).
    indices = {name: es.get(key, default) for name, (key, default) in _INDEX_KEYS.items()}

    # ------------------------------------------------------------------ #
    # Labels (SQLite) helpers
    # ------------------------------------------------------------------ #

    def _labels_conn():
        conn = sqlite3.connect(utils.sqlite_db)
        conn.row_factory = sqlite3.Row
        return conn

    def _label_count():
        try:
            conn = _labels_conn()
            n = conn.execute("SELECT COUNT(*) AS c FROM hash_labels").fetchone()["c"]
            conn.close()
            return int(n)
        except Exception as e:
            logger.warning(f"label count failed: {e}")
            return 0

    def _dump_labels():
        try:
            conn = _labels_conn()
            rows = conn.execute(
                "SELECT hash, label, hash_type, created_at, updated_at FROM hash_labels"
            ).fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.warning(f"dump labels failed: {e}")
            return []

    def _clear_labels():
        try:
            conn = _labels_conn()
            conn.execute("DELETE FROM hash_labels")
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"clear labels failed: {e}")
            return False

    def _restore_labels(rows):
        n = 0
        try:
            conn = _labels_conn()
            for r in rows or []:
                h = r.get("hash")
                label = r.get("label")
                htype = r.get("hash_type", "body")
                if not h or not label or htype not in ("body", "header"):
                    continue
                conn.execute(
                    "INSERT OR REPLACE INTO hash_labels "
                    "(hash, label, hash_type, created_at, updated_at) "
                    "VALUES (?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP), COALESCE(?, CURRENT_TIMESTAMP))",
                    (h, label, htype, r.get("created_at"), r.get("updated_at")))
                n += 1
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"restore labels failed: {e}")
        return n

    # ------------------------------------------------------------------ #
    # Page + status
    # ------------------------------------------------------------------ #

    @app.route("/admin")
    def admin_page():
        return render_template("admin.html")

    @app.route("/api/admin/status")
    def admin_status():
        counts = {name: store.raw_count(idx, {"match_all": {}}) for name, idx in indices.items()}
        labels = _label_count()
        total_docs = sum(counts.values())
        return jsonify({
            "indices": counts,
            "labels": labels,
            "total_docs": total_docs,
            "data_present": bool(total_docs or labels),
        })

    # ------------------------------------------------------------------ #
    # Backup
    # ------------------------------------------------------------------ #

    def _build_backup():
        """Return (BytesIO zip, manifest dict)."""
        buf = io.BytesIO()
        manifest = {"version": 1, "created": datetime.now(timezone.utc).isoformat(),
                    "indices": {}, "labels": 0}
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, idx in indices.items():
                mapping = store.get_mapping(idx)
                if mapping is not None:
                    zf.writestr(f"mappings/{name}.json", json.dumps(mapping))
                lines = [json.dumps(doc, default=str) for doc in store.iter_all(idx)]
                zf.writestr(f"indices/{name}.ndjson", "\n".join(lines))
                manifest["indices"][name] = len(lines)
            label_rows = _dump_labels()
            manifest["labels"] = len(label_rows)
            zf.writestr("labels.json", json.dumps(label_rows, default=str))
            zf.writestr("manifest.json", json.dumps(manifest, indent=2))
        buf.seek(0)
        return buf, manifest

    @app.route("/api/admin/backup")
    def admin_backup():
        try:
            buf, _manifest = _build_backup()
        except Exception as e:
            logger.error(f"backup failed: {e}")
            return jsonify({"error": f"backup failed: {e}"}), 500
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        return send_file(buf, mimetype="application/zip", as_attachment=True,
                         download_name=f"scanner-backup-{stamp}.zip")

    # ------------------------------------------------------------------ #
    # Clear
    # ------------------------------------------------------------------ #

    @app.route("/api/admin/clear", methods=["POST"])
    def admin_clear():
        cleared = {}
        for name, idx in indices.items():
            cleared[name] = store.clear_index(idx)
        labels_ok = _clear_labels()
        logger.info(f"Admin clear: {cleared}, labels_cleared={labels_ok}")
        return jsonify({"ok": True, "cleared": cleared, "labels_cleared": labels_ok})

    # ------------------------------------------------------------------ #
    # Import / restore
    # ------------------------------------------------------------------ #

    @app.route("/api/admin/import", methods=["POST"])
    def admin_import():
        upload = request.files.get("file")
        if not upload:
            return jsonify({"error": "no file uploaded"}), 400
        mode = (request.form.get("mode") or "").lower()
        if mode not in ("overwrite", "merge"):
            return jsonify({"error": "mode must be 'overwrite' or 'merge'"}), 400

        try:
            raw = upload.read()
        except Exception as e:
            return jsonify({"error": f"could not read upload: {e}"}), 400

        try:
            zf = zipfile.ZipFile(io.BytesIO(raw))
        except zipfile.BadZipFile:
            return jsonify({"error": "uploaded file is not a valid .zip backup"}), 400

        names = set(zf.namelist())
        if "manifest.json" not in names:
            return jsonify({"error": "not a scanner backup (manifest.json missing)"}), 400
        if sum(i.file_size for i in zf.infolist()) > MAX_UNCOMPRESSED_BYTES:
            return jsonify({"error": "backup too large to import"}), 413
        try:
            manifest = json.loads(zf.read("manifest.json"))
        except Exception as e:
            return jsonify({"error": f"invalid manifest: {e}"}), 400

        if mode == "overwrite":
            for idx in indices.values():
                store.clear_index(idx)
            _clear_labels()

        restored = {}
        for name, idx in indices.items():
            member = f"indices/{name}.ndjson"
            if member not in names:
                continue
            # Ensure the index exists with its backed-up mapping (so aggregations
            # keep working); on merge an existing index is left as-is.
            if not store.index_exists(idx):
                mapping = None
                mmember = f"mappings/{name}.json"
                if mmember in names:
                    try:
                        mapping = json.loads(zf.read(mmember))
                    except Exception:
                        mapping = None
                store.create_index_with(idx, mapping)

            def _docs(member=member):
                for line in zf.read(member).decode("utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                        if isinstance(d, dict) and d.get("_id") is not None:
                            yield d
                    except json.JSONDecodeError:
                        continue

            ok, err = store.bulk_restore(idx, _docs())
            restored[name] = {"indexed": ok, "errors": err}

        labels_restored = 0
        if "labels.json" in names:
            try:
                labels_restored = _restore_labels(json.loads(zf.read("labels.json")))
            except Exception as e:
                logger.warning(f"label restore failed: {e}")

        logger.info(f"Admin import (mode={mode}): {restored}, labels={labels_restored}")
        return jsonify({"ok": True, "mode": mode, "restored": restored,
                        "labels_restored": labels_restored,
                        "backup_created": manifest.get("created")})

    # ------------------------------------------------------------------ #
    # Health checks
    # ------------------------------------------------------------------ #

    def _parse_tfvars_token():
        """Read hcloud_token from terraform/terraform.tfvars, if present."""
        tfvars = repo_root / "terraform" / "terraform.tfvars"
        if not tfvars.exists():
            return None, "terraform/terraform.tfvars not found (copy terraform.tfvars.example)"
        for raw in tfvars.read_text().splitlines():
            line = raw.split("#", 1)[0].strip()
            if line.startswith("hcloud_token"):
                _, _, val = line.partition("=")
                token = val.strip().strip('"').strip("'")
                if not token or token == "REPLACE_WITH_YOUR_HETZNER_CLOUD_API_TOKEN":
                    return None, "hcloud_token is not set in terraform.tfvars"
                return token, None
        return None, "hcloud_token not found in terraform.tfvars"

    @app.route("/api/admin/check/terraform")
    def admin_check_terraform():
        checks = []

        tf = shutil.which("terraform")
        checks.append({"name": "terraform CLI",
                       "status": "ok" if tf else "fail",
                       "detail": tf or "terraform not found on PATH"})

        token, token_err = _parse_tfvars_token()
        checks.append({"name": "Hetzner token (terraform.tfvars)",
                       "status": "ok" if token else "fail",
                       "detail": "configured" if token else token_err})

        # Live check: can we authenticate to the Hetzner Cloud API with that token?
        # The token is sent only to api.hetzner.cloud (the user's own provider).
        if token:
            try:
                req = urllib.request.Request(
                    HETZNER_API, headers={"Authorization": f"Bearer {token}"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    ok = resp.status == 200
                checks.append({"name": "Hetzner Cloud API",
                               "status": "ok" if ok else "fail",
                               "detail": f"authenticated (HTTP {resp.status}) — can provision agents"
                               if ok else f"unexpected HTTP {resp.status}"})
            except urllib.error.HTTPError as e:
                detail = ("invalid or unauthorized token (HTTP 401)" if e.code == 401
                          else f"HTTP {e.code} from Hetzner API")
                checks.append({"name": "Hetzner Cloud API", "status": "fail", "detail": detail})
            except Exception as e:
                checks.append({"name": "Hetzner Cloud API", "status": "fail",
                               "detail": f"could not reach api.hetzner.cloud: {e}"})

        ok = all(c["status"] == "ok" for c in checks)
        return jsonify({"ok": ok, "checks": checks,
                        "summary": "Agents can be provisioned." if ok
                        else "Agent provisioning is not ready — see checks."})

    def _read_interactsh():
        conf = repo_root / "config" / "interactsh.config"
        values = {}
        if conf.exists():
            for raw in conf.read_text().splitlines():
                line = raw.split("#", 1)[0].strip()
                if "=" in line:
                    k, _, v = line.partition("=")
                    values[k.strip()] = v.strip()
        return values

    @app.route("/api/admin/check/oob")
    def admin_check_oob():
        checks = []
        cfg = _read_interactsh()
        server = cfg.get("server_url", "")
        server_ip = cfg.get("server_ip", "")

        configured = bool(server) and server != "example.com"
        checks.append({"name": "Interactsh server configured",
                       "status": "ok" if configured else "fail",
                       "detail": server or "server_url not set in config/interactsh.config"
                       if configured else
                       ("still the placeholder 'example.com'" if server == "example.com"
                        else "server_url not set in config/interactsh.config")})

        if configured:
            # DNS resolution
            try:
                resolved = socket.gethostbyname(server)
                checks.append({"name": "DNS resolution", "status": "ok",
                               "detail": f"{server} -> {resolved}"
                               + (f" (config lists {server_ip})" if server_ip else "")})
            except Exception as e:
                checks.append({"name": "DNS resolution", "status": "fail",
                               "detail": f"could not resolve {server}: {e}"})

            # Does the server reply over HTTPS? An Interactsh server answers on 443.
            try:
                ctx = ssl.create_default_context()
                req = urllib.request.Request(f"https://{server}/",
                                             headers={"User-Agent": "scanner-admin-check"})
                with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                    status = resp.status
                checks.append({"name": "Server reply (HTTPS)", "status": "ok",
                               "detail": f"replied with HTTP {status}"})
            except urllib.error.HTTPError as e:
                # Any HTTP status means the server replied.
                checks.append({"name": "Server reply (HTTPS)", "status": "ok",
                               "detail": f"replied with HTTP {e.code}"})
            except Exception as e:
                checks.append({"name": "Server reply (HTTPS)", "status": "fail",
                               "detail": f"no reply from {server}: {e}"})

        ok = all(c["status"] == "ok" for c in checks)
        return jsonify({"ok": ok, "checks": checks,
                        "summary": "OOB server is reachable and replying." if ok
                        else "OOB server did not respond as expected — see checks."})
