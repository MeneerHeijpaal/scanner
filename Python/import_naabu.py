#!/usr/bin/env python3
"""
Import naabu JSON output into Elasticsearch.

naabu emits one JSON object per open port (with service discovery / version when
run with -sD/-sV). This importer indexes those records into a dedicated
Elasticsearch index (``elasticsearch.ports_index``, default ``scanner_ports``),
separate from the httpx record index.

Documents are keyed by host:ip:port so re-scanning updates existing entries in
place instead of duplicating them.

Usage:
    python3 Python/import_naabu.py -f ports.json
    python3 Python/import_naabu.py -f ports.json --es-index scanner_ports
"""

import argparse
import hashlib
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml
from elasticsearch import Elasticsearch, helpers

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


def load_es_config():
    """Return the elasticsearch section of Server/config.yml (best effort)."""
    config_file = Path(__file__).parent.parent / 'Server' / 'config.yml'
    try:
        if config_file.exists():
            with open(config_file, 'r') as f:
                return (yaml.safe_load(f) or {}).get('elasticsearch', {})
    except Exception as e:
        logger.warning(f"Could not load config.yml: {e}")
    return {}


def port_doc_id(rec):
    """Stable id from host/ip/port so re-scans upsert."""
    key = f"{rec.get('host', '')}|{rec.get('ip', '')}|{rec.get('port', '')}"
    return hashlib.sha1(key.encode('utf-8', errors='replace')).hexdigest()


def iter_records(path):
    """Yield naabu records from NDJSON or a JSON array."""
    with open(path, 'r', encoding='utf-8') as f:
        first = f.readline().strip()
        if not first:
            return
        f.seek(0)
        try:
            json.loads(first)
            ndjson = True
        except json.JSONDecodeError:
            ndjson = False
        if ndjson:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Skipping malformed line: {e}")
        else:
            f.seek(0)
            data = json.load(f)
            if isinstance(data, list):
                for rec in data:
                    if isinstance(rec, dict):
                        yield rec
            elif isinstance(data, dict):
                yield data


PORTS_MAPPING = {
    "mappings": {
        "dynamic": "true",
        "properties": {
            "host": {"type": "keyword"},
            "ip": {"type": "ip", "ignore_malformed": True},
            "port": {"type": "integer"},
            "protocol": {"type": "keyword"},
            "service": {"type": "keyword"},
            "version": {"type": "keyword"},
            "timestamp": {"type": "date", "ignore_malformed": True},
        },
    }
}


def main():
    parser = argparse.ArgumentParser(description="Import naabu JSON output into Elasticsearch")
    parser.add_argument('-f', '--file', required=True, help='Path to the naabu JSON file')
    parser.add_argument('--es-host', help='Elasticsearch host (overrides config.yml)')
    parser.add_argument('--es-port', type=int, help='Elasticsearch port (overrides config.yml)')
    parser.add_argument('--es-index', help='Ports index name (overrides config.yml)')
    parser.add_argument('--batch-size', type=int, default=1000, help='Bulk index batch size')
    args = parser.parse_args()

    input_file = Path(args.file)
    if not input_file.is_file():
        logger.error(f"Input file not found: {input_file}")
        sys.exit(1)

    es_cfg = load_es_config()
    host = args.es_host or es_cfg.get('host', 'localhost')
    port = args.es_port or es_cfg.get('port', 9200)
    index = args.es_index or es_cfg.get('ports_index', 'scanner_ports')

    client = Elasticsearch([f"http://{host}:{port}"], request_timeout=30,
                           retry_on_timeout=True, max_retries=3)
    if not client.ping():
        logger.error(f"Failed to connect to Elasticsearch at {host}:{port}")
        sys.exit(1)

    if not client.indices.exists(index=index):
        client.indices.create(index=index, mappings=PORTS_MAPPING["mappings"])
        logger.info(f"Created ports index '{index}'")

    now = datetime.now(timezone.utc).isoformat()

    def actions():
        for rec in iter_records(input_file):
            rec.setdefault('timestamp', now)
            yield {"_index": index, "_id": port_doc_id(rec), "_source": rec}

    success, errors = helpers.bulk(client, actions(), chunk_size=args.batch_size,
                                   raise_on_error=False, raise_on_exception=False)
    error_count = len(errors) if isinstance(errors, list) else 0
    logger.info(f"Import completed: {success} port records indexed into '{index}', "
                f"{error_count} errors")


if __name__ == '__main__':
    main()
