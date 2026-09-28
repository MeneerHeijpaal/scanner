#!/usr/bin/env python3
"""
One-off migration: copy legacy MongoDB records into Elasticsearch.

Before the MongoDB -> Elasticsearch migration, MongoDB was the primary store and
Elasticsearch held only decoded body content. This script reads the FULL records
from the old MongoDB collection and indexes them into the new Elasticsearch
record index (``elasticsearch.index_name``, default ``scanner_records``).

Run it once, after standing up Elasticsearch, to bring existing data across.
Afterwards MongoDB can be retired; the importer and web app use Elasticsearch
only.

Usage:
    python3 Python/migrate_to_elasticsearch.py
    python3 Python/migrate_to_elasticsearch.py --mongo-uri mongodb://localhost:27017 --db urls --collection data
    python3 Python/migrate_to_elasticsearch.py --batch-size 1000
"""

import argparse
import base64
import logging
import sys
import yaml
from pathlib import Path

from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

sys.path.insert(0, str(Path(__file__).parent.parent / 'Server'))
from elasticsearch_manager import ElasticsearchManager, doc_id_for  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


def load_config():
    """Load config/server-config.yaml. Exits on failure."""
    config_file = Path(__file__).parent.parent / 'config' / 'server-config.yaml'
    try:
        with open(config_file, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        logger.error(f"Configuration file not found: {config_file}")
        sys.exit(1)
    except yaml.YAMLError as e:
        logger.error(f"Error parsing configuration file: {e}")
        sys.exit(1)


def ensure_body_decoded(doc):
    """Ensure a legacy doc has body_decoded (older docs may lack it)."""
    if not doc.get('body_decoded') and doc.get('body'):
        try:
            decoded = base64.b64decode(doc['body']).decode('utf-8', errors='ignore')
            if decoded and decoded.strip():
                doc['body_decoded'] = decoded
        except Exception:
            pass
    return doc


def migrate(mongo_collection, store, batch_size=2000):
    """Copy all MongoDB documents into Elasticsearch. Returns (indexed, errors)."""
    total = mongo_collection.count_documents({})
    logger.info(f"Found {total} documents in MongoDB to migrate")
    if total == 0:
        return (0, 0)

    indexed = 0
    errors = 0
    batch = []
    for doc in mongo_collection.find({}):
        # Preserve a stable id: reuse the URL-derived id so re-runs are idempotent.
        doc.pop('_id', None)
        doc = ensure_body_decoded(doc)
        doc['_id'] = doc_id_for(doc)
        batch.append(doc)
        if len(batch) >= batch_size:
            ok, err = store.bulk_index(batch)
            indexed += ok
            errors += err
            batch = []
            logger.info(f"Progress: {indexed}/{total} ({indexed / total * 100:.1f}%)")
    if batch:
        ok, err = store.bulk_index(batch)
        indexed += ok
        errors += err

    return (indexed, errors)


def main():
    parser = argparse.ArgumentParser(description="Migrate legacy MongoDB records into Elasticsearch")
    parser.add_argument("--mongo-uri", default="mongodb://localhost:27017", help="MongoDB URI")
    parser.add_argument("--db", help="MongoDB database name (default: config mongodb.database)")
    parser.add_argument("--collection", help="MongoDB collection (default: config mongodb.collection)")
    parser.add_argument("--batch-size", type=int, default=2000, help="Bulk index batch size")
    args = parser.parse_args()

    config = load_config()
    mongo_cfg = config.get('mongodb', {})
    db_name = args.db or mongo_cfg.get('database', 'urls')
    collection_name = args.collection or mongo_cfg.get('collection', 'data')

    try:
        logger.info(f"Connecting to MongoDB at {args.mongo_uri}")
        mongo_client = MongoClient(args.mongo_uri, serverSelectionTimeoutMS=5000)
        mongo_client.admin.command('ping')
        logger.info("MongoDB connection successful")
    except (ConnectionFailure, ServerSelectionTimeoutError) as e:
        logger.error(f"Failed to connect to MongoDB: {e}")
        sys.exit(1)

    collection = mongo_client[db_name][collection_name]

    config.setdefault('elasticsearch', {})['enabled'] = True
    store = ElasticsearchManager(config)
    if not store.is_connected:
        logger.error("Failed to connect to Elasticsearch")
        sys.exit(1)
    store.create_index()

    try:
        logger.info(f"Starting migration (batch size {args.batch_size})...")
        indexed, errors = migrate(collection, store, batch_size=args.batch_size)
        logger.info("=" * 60)
        logger.info(f"Migration completed: {indexed} indexed, {errors} errors")
        stats = store.get_index_stats()
        if stats:
            logger.info(f"Elasticsearch index now holds {stats['document_count']} "
                        f"documents ({stats['size_mb']} MB)")
        logger.info("=" * 60)
    except KeyboardInterrupt:
        logger.warning("Migration interrupted by user")
        sys.exit(130)
    finally:
        mongo_client.close()


if __name__ == "__main__":
    main()
