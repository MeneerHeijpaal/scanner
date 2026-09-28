#!/usr/bin/env python3
"""
Stream Interactsh interactions into Elasticsearch for the live dashboard.

Runs ``interactsh-client`` against the self-hosted server defined in
``interactsh.config`` and indexes every out-of-band interaction (DNS/HTTP/SMTP
callbacks) into the ``scanner_interactions`` index as it arrives. The dashboard's
Interactions tab polls that index to render a live stream.

Usage:
    python3 Python/interactsh_stream.py
    python3 Python/interactsh_stream.py --server example.com --token <auth-token>

Leave it running (e.g. under systemd/tmux) alongside your scans.
"""

import argparse
import hashlib
import json
import logging
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml
from elasticsearch import Elasticsearch, helpers  # noqa: F401  (helpers reserved)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

INTERACTIONS_MAPPING = {
    "mappings": {
        "dynamic": "true",
        "properties": {
            "protocol": {"type": "keyword"},
            "unique-id": {"type": "keyword"},
            "full-id": {"type": "keyword"},
            "remote-address": {"type": "keyword"},
            "timestamp": {"type": "date", "ignore_malformed": True},
        },
    }
}


def load_config():
    """Load config/server-config.yaml (elasticsearch section) and interactsh.config."""
    root = Path(__file__).parent.parent
    es_cfg = {}
    try:
        cfg = yaml.safe_load((root / "config" / "server-config.yaml").read_text()) or {}
        es_cfg = cfg.get("elasticsearch", {})
    except Exception as e:
        logger.warning(f"Could not load server-config.yaml: {e}")

    server = {}
    conf = root / "config" / "interactsh.config"
    if conf.exists():
        for raw in conf.read_text().splitlines():
            line = raw.split("#", 1)[0].strip()
            if "=" in line:
                k, _, v = line.partition("=")
                server[k.strip()] = v.strip()
    return es_cfg, server


def find_client(root):
    """Locate the interactsh-client binary."""
    import shutil
    for cand in (root / "interactsh-client", root / "bin" / "interactsh-client"):
        if cand.exists():
            return str(cand)
    on_path = shutil.which("interactsh-client")
    if on_path:
        return on_path
    logger.error("interactsh-client not found at ./, ./bin/, or on PATH")
    sys.exit(2)


def interaction_id(rec):
    """Stable id per interaction event."""
    key = f"{rec.get('unique-id','')}|{rec.get('full-id','')}|{rec.get('protocol','')}|{rec.get('timestamp','')}|{rec.get('remote-address','')}"
    return hashlib.sha1(key.encode("utf-8", errors="replace")).hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Stream Interactsh interactions into Elasticsearch")
    parser.add_argument("--server", help="Interactsh server URL (default: interactsh.config)")
    parser.add_argument("--token", help="Interactsh server auth token, if configured")
    parser.add_argument("--es-host", help="Elasticsearch host (default: config/server-config.yaml)")
    parser.add_argument("--es-port", type=int, help="Elasticsearch port (default: config/server-config.yaml)")
    parser.add_argument("--es-index", help="Interactions index (default: config/server-config.yaml)")
    args = parser.parse_args()

    root = Path(__file__).parent.parent
    es_cfg, server_cfg = load_config()
    server = args.server or server_cfg.get("server_url", "")
    if not server:
        logger.error("No Interactsh server set (pass --server or set server_url in interactsh.config)")
        sys.exit(2)

    host = args.es_host or es_cfg.get("host", "localhost")
    port = args.es_port or es_cfg.get("port", 9200)
    index = args.es_index or es_cfg.get("interactions_index", "scanner_interactions")

    client = Elasticsearch([f"http://{host}:{port}"], request_timeout=30,
                           retry_on_timeout=True, max_retries=3)
    if not client.ping():
        logger.error(f"Failed to connect to Elasticsearch at {host}:{port}")
        sys.exit(1)
    if not client.indices.exists(index=index):
        client.indices.create(index=index, mappings=INTERACTIONS_MAPPING["mappings"])
        logger.info(f"Created interactions index '{index}'")

    binary = find_client(root)
    cmd = [binary, "-server", server, "-json"]
    if args.token:
        cmd += ["-token", args.token]
    logger.info(f"Streaming interactions from {server} -> index '{index}'")
    logger.info(f"Running: {' '.join(cmd)}")

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                # interactsh-client prints its banner / non-JSON notices too.
                continue
            rec.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
            try:
                client.index(index=index, id=interaction_id(rec), document=rec)
                logger.info(f"{rec.get('protocol','?').upper():5} {rec.get('full-id','')} "
                            f"from {rec.get('remote-address','')}")
            except Exception as e:
                logger.warning(f"Failed to index interaction: {e}")
    except KeyboardInterrupt:
        logger.info("Stopping interaction stream")
    finally:
        proc.terminate()


if __name__ == "__main__":
    main()
