#!/usr/bin/env python3
"""
Migration Script: Index Existing MongoDB Documents in Elasticsearch

This script indexes all existing documents from MongoDB into Elasticsearch
to enable fast body content search. It should be run once after setting up
Elasticsearch integration.

Usage:
    python3 Python/migrate_to_elasticsearch.py [options]

Options:
    --mongo-uri URI     MongoDB connection URI (default: mongodb://localhost:27017)
    --db NAME           Database name (default: urls)
    --collection NAME   Collection name (default: data)
    --batch-size N      Number of documents to process per batch (default: 5000)
    --skip-existing     Skip documents already indexed in Elasticsearch
"""

import argparse
import logging
import sys
import yaml
from pathlib import Path
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from bson import ObjectId

# Add parent directory to path to import elasticsearch_manager
sys.path.insert(0, str(Path(__file__).parent.parent / 'Server'))
from elasticsearch_manager import ElasticsearchManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


def load_config():
    """
    Load configuration from config.yml.

    Returns:
        Configuration dictionary
    """
    config_file = Path(__file__).parent.parent / 'Server' / 'config.yml'
    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
        logger.info(f"Loaded configuration from {config_file}")
        return config
    except FileNotFoundError:
        logger.error(f"Configuration file not found: {config_file}")
        sys.exit(1)
    except yaml.YAMLError as e:
        logger.error(f"Error parsing configuration file: {e}")
        sys.exit(1)


def migrate_documents(mongo_collection, es_manager, batch_size=5000, skip_existing=False):
    """
    Migrate all documents from MongoDB to Elasticsearch.

    Args:
        mongo_collection: MongoDB collection object
        es_manager: ElasticsearchManager instance
        batch_size: Number of documents to process per batch
        skip_existing: Skip documents already in Elasticsearch

    Returns:
        Tuple of (indexed_count, skipped_count, error_count)
    """
    # Count total documents with body_decoded field
    total_count = mongo_collection.count_documents({'body_decoded': {'$exists': True}})
    logger.info(f"Found {total_count} documents with body_decoded field to index")

    if total_count == 0:
        logger.warning("No documents with body_decoded field found. Have you run imports after updating to the latest version?")
        return (0, 0, 0)

    indexed_count = 0
    skipped_count = 0
    error_count = 0

    # Process documents in batches
    batch_num = 0
    cursor = mongo_collection.find(
        {'body_decoded': {'$exists': True}},
        {'_id': 1, 'body_decoded': 1, 'url': 1, 'timestamp': 1}
    ).batch_size(batch_size)

    batch = []
    for doc in cursor:
        # Prepare document for Elasticsearch
        es_doc = {
            'doc_id': str(doc['_id']),
            'body_decoded': doc.get('body_decoded', ''),
            'url': doc.get('url', ''),
            'timestamp': doc.get('timestamp')
        }

        batch.append(es_doc)

        # Process batch when it reaches batch_size
        if len(batch) >= batch_size:
            batch_num += 1
            success, errors = es_manager.bulk_index_documents(batch)
            indexed_count += success
            error_count += errors

            progress_pct = (indexed_count / total_count) * 100
            logger.info(f"Batch {batch_num}: Indexed {success} documents (Progress: {indexed_count}/{total_count} = {progress_pct:.1f}%)")

            batch = []

    # Process remaining documents
    if batch:
        batch_num += 1
        success, errors = es_manager.bulk_index_documents(batch)
        indexed_count += success
        error_count += errors

        progress_pct = (indexed_count / total_count) * 100
        logger.info(f"Batch {batch_num}: Indexed {success} documents (Progress: {indexed_count}/{total_count} = {progress_pct:.1f}%)")

    return (indexed_count, skipped_count, error_count)


def main():
    parser = argparse.ArgumentParser(
        description="Migrate existing MongoDB documents to Elasticsearch",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage (uses config.yml settings)
  python3 Python/migrate_to_elasticsearch.py

  # Custom MongoDB settings
  python3 Python/migrate_to_elasticsearch.py --mongo-uri mongodb://localhost:27017 --db urls --collection data

  # Smaller batch size for limited memory
  python3 Python/migrate_to_elasticsearch.py --batch-size 1000
        """
    )
    parser.add_argument("--mongo-uri", default="mongodb://localhost:27017", help="MongoDB URI")
    parser.add_argument("--db", default="urls", help="Database name")
    parser.add_argument("--collection", default="data", help="Collection name")
    parser.add_argument("--batch-size", type=int, default=5000, help="Batch size for bulk indexing")
    parser.add_argument("--skip-existing", action="store_true", help="Skip documents already in Elasticsearch")
    args = parser.parse_args()

    # Load configuration
    config = load_config()

    # Connect to MongoDB
    try:
        logger.info(f"Connecting to MongoDB at {args.mongo_uri}")
        mongo_client = MongoClient(args.mongo_uri, serverSelectionTimeoutMS=5000)
        mongo_client.admin.command('ping')
        logger.info("MongoDB connection successful")
    except (ConnectionFailure, ServerSelectionTimeoutError) as e:
        logger.error(f"Failed to connect to MongoDB: {e}")
        logger.error("Please ensure MongoDB is running at the specified URI")
        sys.exit(1)

    db = mongo_client[args.db]
    collection = db[args.collection]

    # Initialize Elasticsearch
    es_config = config.get('elasticsearch', {})
    if not es_config.get('enabled', False):
        logger.error("Elasticsearch is disabled in config.yml")
        logger.error("Please set elasticsearch.enabled to true before running migration")
        sys.exit(1)

    try:
        es_manager = ElasticsearchManager(config)
        if not es_manager.is_connected:
            logger.error("Failed to connect to Elasticsearch")
            logger.error(f"Please ensure Elasticsearch is running at {es_config.get('host')}:{es_config.get('port')}")
            sys.exit(1)

        logger.info("Elasticsearch connection successful")

        # Create index if it doesn't exist
        es_manager.create_index()

        # Get current index stats
        stats = es_manager.get_index_stats()
        if stats:
            logger.info(f"Current Elasticsearch index: {stats['document_count']} documents, {stats['size_mb']} MB")

    except Exception as e:
        logger.error(f"Failed to initialize Elasticsearch: {e}")
        sys.exit(1)

    # Run migration
    try:
        logger.info("Starting migration...")
        logger.info(f"Batch size: {args.batch_size}")

        indexed, skipped, errors = migrate_documents(
            collection,
            es_manager,
            batch_size=args.batch_size,
            skip_existing=args.skip_existing
        )

        logger.info("=" * 60)
        logger.info("Migration completed!")
        logger.info(f"  Indexed: {indexed} documents")
        logger.info(f"  Skipped: {skipped} documents")
        logger.info(f"  Errors:  {errors} documents")
        logger.info("=" * 60)

        # Get final index stats
        final_stats = es_manager.get_index_stats()
        if final_stats:
            logger.info(f"Final Elasticsearch index: {final_stats['document_count']} documents, {final_stats['size_mb']} MB")

        logger.info("\nBody search is now available!")
        logger.info("You can search response bodies at http://127.0.0.1:8001")

    except KeyboardInterrupt:
        logger.warning("\nMigration interrupted by user")
        logger.info(f"Partial progress: {indexed} documents indexed so far")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        sys.exit(1)
    finally:
        mongo_client.close()


if __name__ == "__main__":
    main()
