#!/usr/bin/env python3
"""
Import httpx JSON output into Elasticsearch.

As of the MongoDB -> Elasticsearch migration this importer writes directly to
Elasticsearch. Records are keyed by a hash of their URL, so re-importing the same
URL updates the existing record in place (idempotent upsert) instead of prompting
about duplicates. This makes the importer safe to run unattended.

Supported input formats:
  - NDJSON (one JSON object per line) -- httpx default with ``-j``
  - JSON array of objects
  - A single JSON object

Usage:
    python3 Python/import_httpx.py -f results.json
    python3 Python/import_httpx.py -f results.json --batch-size 1000
    python3 Python/import_httpx.py -f results.json --es-host 10.0.0.5 --es-port 9200
"""

import argparse
import base64
import json
import logging
import sys
import yaml
from pathlib import Path

# Import the Elasticsearch store from the Server package.
sys.path.insert(0, str(Path(__file__).parent.parent / 'Server'))
from elasticsearch_manager import ElasticsearchManager  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


def load_config():
    """Load config/server-config.yaml (best effort). Returns a dict (possibly empty)."""
    config_file = Path(__file__).parent.parent / 'config' / 'server-config.yaml'
    try:
        if config_file.exists():
            with open(config_file, 'r') as f:
                cfg = yaml.safe_load(f) or {}
            logger.info(f"Loaded configuration from {config_file}")
            return cfg
    except Exception as e:
        logger.warning(f"Could not load config/server-config.yaml: {e}")
    return {}


def decode_body_field(doc):
    """Decode the base64 ``body`` field into ``body_decoded`` for text search."""
    if 'body' in doc and doc['body']:
        try:
            decoded = base64.b64decode(doc['body']).decode('utf-8', errors='ignore')
            if decoded and decoded.strip():
                doc['body_decoded'] = decoded
        except Exception as e:
            logger.debug(f"Could not decode body field: {e}")
    return doc


def iter_records(path):
    """Yield record dicts from an httpx output file (NDJSON, array, or object)."""
    with open(path, 'r', encoding='utf-8') as infile:
        first_line = infile.readline().strip()
        if not first_line:
            logger.error("Input file is empty")
            return
        infile.seek(0)

        # Detect NDJSON: the first non-empty line parses as a standalone object.
        is_ndjson = False
        try:
            json.loads(first_line)
            is_ndjson = True
        except json.JSONDecodeError:
            is_ndjson = False

        if is_ndjson:
            line_number = 0
            for line in infile:
                line_number += 1
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse JSON on line {line_number}: {e}")
        else:
            infile.seek(0)
            try:
                data = json.load(infile)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON file: {e}")
                return
            if isinstance(data, list):
                for rec in data:
                    if isinstance(rec, dict):
                        yield rec
            elif isinstance(data, dict):
                yield data
            else:
                logger.error(f"Unexpected JSON format: {type(data)}")


def main():
    parser = argparse.ArgumentParser(description="Import httpx JSON output into Elasticsearch")
    parser.add_argument("-f", "--file", required=True, help="Path to the httpx JSON file")
    parser.add_argument("--es-host", help="Elasticsearch host (overrides config/server-config.yaml)")
    parser.add_argument("--es-port", type=int, help="Elasticsearch port (overrides config/server-config.yaml)")
    parser.add_argument("--es-index", help="Elasticsearch index name (overrides config/server-config.yaml)")
    parser.add_argument("--batch-size", type=int, default=1000, help="Bulk index batch size")
    args = parser.parse_args()

    input_file = Path(args.file)
    if not input_file.is_file():
        logger.error(f"Input file not found: {input_file}")
        sys.exit(1)

    config = load_config()
    config.setdefault('elasticsearch', {})
    config['elasticsearch']['enabled'] = True
    if args.es_host:
        config['elasticsearch']['host'] = args.es_host
    if args.es_port:
        config['elasticsearch']['port'] = args.es_port
    if args.es_index:
        config['elasticsearch']['index_name'] = args.es_index

    store = ElasticsearchManager(config)
    if not store.is_connected:
        es = config['elasticsearch']
        logger.error(f"Failed to connect to Elasticsearch at "
                     f"{es.get('host', 'localhost')}:{es.get('port', 9200)}")
        sys.exit(1)
    store.create_index()
    logger.info(f"Importing into Elasticsearch index '{store.index_name}'")

    indexed = 0
    errors = 0
    batch = []

    def flush():
        nonlocal indexed, errors
        if not batch:
            return
        ok, err = store.bulk_index(batch)
        indexed += ok
        errors += err
        batch.clear()
        logger.info(f"Indexed {indexed} records so far ({errors} errors)")

    for rec in iter_records(input_file):
        batch.append(decode_body_field(rec))
        if len(batch) >= args.batch_size:
            flush()
    flush()

    logger.info("=" * 60)
    logger.info(f"Import completed: {indexed} records indexed, {errors} errors")
    stats = store.get_index_stats()
    if stats:
        logger.info(f"Index now holds {stats['document_count']} documents "
                    f"({stats['size_mb']} MB)")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
