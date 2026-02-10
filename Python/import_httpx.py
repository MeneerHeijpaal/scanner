import argparse
import base64
import json
import logging
import sys
import yaml
from pathlib import Path
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError, BulkWriteError
import bson

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

# MongoDB document size limit (16MB)
MAX_BSON_SIZE = 16 * 1024 * 1024

# Global decision tracking for duplicate handling
DUPLICATE_DECISION = None  # None, 'update_all', or 'keep_all'

def check_url_exists(collection, url):
    """
    Check if a URL already exists in the MongoDB collection.

    Args:
        collection: MongoDB collection object
        url: URL string to check (exact match including scheme)

    Returns:
        Document if found, None otherwise
    """
    return collection.find_one({'url': url})

def prompt_user_for_duplicate(url, existing_doc):
    """
    Prompt user for action when duplicate URL is found.

    Args:
        url: The duplicate URL
        existing_doc: The existing document in database

    Returns:
        Action string: 'update', 'keep', 'update_all', 'keep_all'
    """
    global DUPLICATE_DECISION

    # If user already made a global decision, return it
    if DUPLICATE_DECISION == 'update_all':
        return 'update'
    elif DUPLICATE_DECISION == 'keep_all':
        return 'keep'

    print(f"\n⚠️  Duplicate URL found: {url}")
    print(f"   Existing document ID: {existing_doc.get('_id')}")
    print("\nWhat would you like to do?")
    print("  (u) Update the URL with the new one")
    print("  (k) Keep the URL in the database")
    print("  (a) Update all the URL's in this import and don't ask again")
    print("  (n) Keep all the URL's in the database and don't ask again")

    while True:
        try:
            choice = input("\nYour choice [u/k/a/n]: ").strip().lower()

            if choice == 'u':
                return 'update'
            elif choice == 'k':
                return 'keep'
            elif choice == 'a':
                DUPLICATE_DECISION = 'update_all'
                logger.info("✓ Will update all duplicate URLs for the rest of this import")
                return 'update'
            elif choice == 'n':
                DUPLICATE_DECISION = 'keep_all'
                logger.info("✓ Will keep all existing URLs for the rest of this import")
                return 'keep'
            else:
                print("Invalid choice. Please enter u, k, a, or n.")
        except (EOFError, KeyboardInterrupt):
            print("\n\nImport interrupted by user")
            sys.exit(130)

def handle_duplicate_url(collection, doc, line_number=None):
    """
    Check for duplicate URL and handle according to user choice.

    Args:
        collection: MongoDB collection
        doc: Document to insert
        line_number: Optional line number for logging

    Returns:
        Tuple of (should_insert, should_update, existing_doc_id)
        - should_insert: Boolean, whether to insert new document
        - should_update: Boolean, whether to update existing document
        - existing_doc_id: ObjectId of existing document if updating, None otherwise
    """
    url = doc.get('url')
    if not url:
        # No URL field, allow insertion
        return True, False, None

    existing_doc = check_url_exists(collection, url)
    if not existing_doc:
        # No duplicate, allow insertion
        return True, False, None

    # Duplicate found
    location = f"line {line_number}" if line_number else "document"
    logger.warning(f"Duplicate URL found at {location}: {url}")

    action = prompt_user_for_duplicate(url, existing_doc)

    if action == 'update':
        logger.info(f"→ Updating existing document")
        return False, True, existing_doc['_id']
    else:  # keep
        logger.info(f"→ Keeping existing document, skipping new data")
        return False, False, None

def truncate_large_fields(doc, target_size):
    """
    Truncate large text fields in a document to fit within target_size.

    This function progressively truncates fields that commonly contain large data
    (body, raw_header, request) until the document fits within the size limit.

    Args:
        doc: The document dictionary to truncate
        target_size: Maximum size in bytes for the BSON-encoded document

    Returns:
        Tuple of (truncated_doc, was_truncated)
    """
    # Fields to truncate, in order of priority (least important first)
    truncatable_fields = ['body', 'raw_header', 'request']

    doc_copy = doc.copy()
    was_truncated = False

    for field in truncatable_fields:
        # Check current size
        try:
            current_size = len(bson.BSON.encode(doc_copy))
        except Exception as e:
            logger.warning(f"Failed to encode document for size check: {e}")
            return doc_copy, was_truncated

        if current_size <= target_size:
            break

        # If still too large, truncate this field
        if field in doc_copy and doc_copy[field]:
            original_length = len(str(doc_copy[field]))

            # Try truncating to 50% first, then 25%, then 10%, then remove entirely
            for reduction_factor in [0.5, 0.25, 0.1, 0]:
                if reduction_factor == 0:
                    # Remove the field entirely and add a marker
                    doc_copy[f'{field}_truncated'] = f'[Field removed: original size {original_length} characters]'
                    del doc_copy[field]
                    was_truncated = True
                    logger.warning(f"Removed field '{field}' entirely (original size: {original_length} chars)")
                else:
                    # Truncate to a percentage
                    new_length = int(original_length * reduction_factor)
                    doc_copy[field] = str(doc_copy[field])[:new_length]
                    doc_copy[f'{field}_truncated'] = f'[Truncated from {original_length} to {new_length} characters]'
                    was_truncated = True
                    logger.warning(f"Truncated field '{field}' from {original_length} to {new_length} chars")

                # Check if it fits now
                try:
                    new_size = len(bson.BSON.encode(doc_copy))
                    if new_size <= target_size:
                        logger.info(f"Document now fits: {new_size} bytes (was {current_size} bytes)")
                        break
                except Exception:
                    continue

    return doc_copy, was_truncated

def decode_body_field(doc):
    """
    Decode Base64-encoded body field and store as body_decoded for text search.

    Args:
        doc: The document dictionary

    Returns:
        Modified document with body_decoded field added (if applicable)
    """
    if 'body' in doc and doc['body']:
        try:
            # Decode Base64 body
            decoded_bytes = base64.b64decode(doc['body'])
            # Try UTF-8 decoding, ignore errors for binary content
            decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
            # Only store if we got reasonable text (not empty and not all null bytes)
            if decoded_text and decoded_text.strip():
                doc['body_decoded'] = decoded_text
                logger.debug(f"Decoded body field ({len(decoded_text)} characters)")
        except Exception as e:
            # If decode fails, skip body_decoded field
            logger.debug(f"Could not decode body field: {e}")

    return doc

def index_document_in_elasticsearch(es_manager, doc_id, doc):
    """
    Index a document in Elasticsearch for body search.

    Args:
        es_manager: ElasticsearchManager instance
        doc_id: MongoDB document ID (as string)
        doc: Document dictionary with body_decoded field

    Returns:
        bool: True if indexed successfully, False otherwise
    """
    if not es_manager or not es_manager.is_connected:
        return False

    # Only index if document has decoded body content
    if 'body_decoded' not in doc or not doc['body_decoded']:
        return False

    try:
        url = doc.get('url', '')
        timestamp = doc.get('timestamp')
        body_decoded = doc['body_decoded']

        return es_manager.index_document(
            doc_id=str(doc_id),
            body_decoded=body_decoded,
            url=url,
            timestamp=timestamp
        )
    except Exception as e:
        logger.warning(f"Failed to index document in Elasticsearch: {e}")
        return False

def check_and_fix_document_size(doc, line_number=None):
    """
    Check if a document exceeds MongoDB size limit and truncate if necessary.

    Args:
        doc: The document dictionary to check
        line_number: Optional line number for logging

    Returns:
        Tuple of (document, was_truncated)
    """
    try:
        encoded = bson.BSON.encode(doc)
        size = len(encoded)

        if size > MAX_BSON_SIZE:
            location = f"line {line_number}" if line_number else "document"
            logger.warning(f"Document at {location} exceeds 16MB limit: {size} bytes - attempting to truncate")

            # Truncate to fit within limit (with some buffer)
            target_size = int(MAX_BSON_SIZE * 0.95)  # 95% of limit to be safe
            truncated_doc, was_truncated = truncate_large_fields(doc, target_size)

            # Verify it fits now
            final_size = len(bson.BSON.encode(truncated_doc))
            if final_size > MAX_BSON_SIZE:
                logger.error(f"Failed to truncate document at {location} to acceptable size: {final_size} bytes")
                return None, False

            logger.info(f"Successfully truncated document at {location}: {size} -> {final_size} bytes")
            return truncated_doc, True

        return doc, False

    except Exception as e:
        location = f"line {line_number}" if line_number else "document"
        logger.error(f"Failed to check document size at {location}: {e}")
        return doc, False

def main():
    parser = argparse.ArgumentParser(description="Import httpx JSON output to MongoDB")
    parser.add_argument("-f", "--file", required=True, help="Path to the httpx JSON file")
    parser.add_argument("--mongo-uri", default="mongodb://localhost:27017", help="MongoDB URI")
    parser.add_argument("--db", default="urls", help="Database name")
    parser.add_argument("--collection", default="data", help="Collection name")
    parser.add_argument("--no-elasticsearch", action="store_true", help="Disable Elasticsearch indexing")
    args = parser.parse_args()

    # Load configuration for Elasticsearch
    config_file = Path(__file__).parent.parent / 'Server' / 'config.yml'
    config = {}
    try:
        if config_file.exists():
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            logger.info(f"Loaded configuration from {config_file}")
    except Exception as e:
        logger.warning(f"Could not load config.yml: {e}")

    # Validate input file exists
    input_file = Path(args.file)
    if not input_file.exists():
        logger.error(f"Input file not found: {input_file}")
        sys.exit(1)

    if not input_file.is_file():
        logger.error(f"Path is not a file: {input_file}")
        sys.exit(1)

    # Connect to MongoDB with timeout and error handling
    try:
        logger.info(f"Connecting to MongoDB at {args.mongo_uri}")
        client = MongoClient(args.mongo_uri, serverSelectionTimeoutMS=5000)
        # Test connection
        client.admin.command('ping')
        logger.info("MongoDB connection successful")
    except (ConnectionFailure, ServerSelectionTimeoutError) as e:
        logger.error(f"Failed to connect to MongoDB: {e}")
        logger.error("Please ensure MongoDB is running at the specified URI")
        sys.exit(1)

    db = client[args.db]
    collection = db[args.collection]

    # Initialize Elasticsearch if enabled
    es_manager = None
    if not args.no_elasticsearch and config:
        try:
            es_manager = ElasticsearchManager(config)
            if es_manager.is_connected:
                es_manager.create_index()
                logger.info("Elasticsearch integration enabled - documents will be indexed for search")
            else:
                logger.warning("Elasticsearch not available - documents will only be imported to MongoDB")
                es_manager = None
        except Exception as e:
            logger.warning(f"Failed to initialize Elasticsearch: {e}")
            es_manager = None
    else:
        if args.no_elasticsearch:
            logger.info("Elasticsearch indexing disabled by --no-elasticsearch flag")
        else:
            logger.info("No config file found - Elasticsearch indexing disabled")

    try:
        with open(args.file, "r", encoding='utf-8') as infile:
            # Read first line to determine format
            first_line = infile.readline().strip()
            if not first_line:
                logger.error("Input file is empty")
                sys.exit(1)

            # Reset to beginning
            infile.seek(0)

            # Try to detect if it's NDJSON or JSON array
            is_ndjson = False
            try:
                json.loads(first_line)
                is_ndjson = True
            except json.JSONDecodeError:
                # Might be JSON array, try to load entire file
                is_ndjson = False

            if is_ndjson:
                # NDJSON: each line is a JSON object
                logger.info("Detected NDJSON format")
                imported_count = 0
                updated_count = 0
                skipped_count = 0
                error_count = 0
                truncated_count = 0
                line_number = 0

                for line in infile:
                    line_number += 1
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        doc = json.loads(line)

                        # Decode body field for text search
                        doc = decode_body_field(doc)

                        # Check and fix document size if needed
                        fixed_doc, was_truncated = check_and_fix_document_size(doc, line_number)

                        if fixed_doc is None:
                            logger.error(f"Skipping document on line {line_number}: could not reduce size")
                            error_count += 1
                            continue

                        if was_truncated:
                            truncated_count += 1

                        # Check for duplicate URL
                        should_insert, should_update, existing_id = handle_duplicate_url(collection, fixed_doc, line_number)

                        if should_insert:
                            result = collection.insert_one(fixed_doc)
                            imported_count += 1
                            # Index in Elasticsearch
                            if es_manager:
                                index_document_in_elasticsearch(es_manager, result.inserted_id, fixed_doc)
                        elif should_update:
                            collection.replace_one({'_id': existing_id}, fixed_doc)
                            updated_count += 1
                            # Update in Elasticsearch
                            if es_manager:
                                index_document_in_elasticsearch(es_manager, existing_id, fixed_doc)
                        else:
                            # Keep existing, count as skipped
                            skipped_count += 1

                        if (imported_count + updated_count) % 100 == 0:
                            logger.info(f"Processed {imported_count + updated_count} documents...")
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse JSON on line {line_number}: {e}")
                        error_count += 1
                    except Exception as e:
                        logger.warning(f"Failed to insert document on line {line_number}: {e}")
                        error_count += 1

                logger.info(f"Import completed: {imported_count} inserted, {updated_count} updated, {skipped_count} skipped, {truncated_count} truncated, {error_count} errors")
            else:
                # JSON array: entire file is one JSON array
                logger.info("Detected JSON array format")
                infile.seek(0)
                try:
                    docs = json.load(infile)

                    if isinstance(docs, list):
                        if len(docs) == 0:
                            logger.warning("JSON array is empty")
                            sys.exit(0)

                        logger.info(f"Checking and importing {len(docs)} documents...")

                        # Check and fix document sizes, handle duplicates
                        truncated_count = 0
                        skipped_count = 0
                        updated_count = 0
                        inserted_count = 0

                        for idx, doc in enumerate(docs, 1):
                            # Decode body field for text search
                            doc = decode_body_field(doc)

                            fixed_doc, was_truncated = check_and_fix_document_size(doc, idx)

                            if fixed_doc is None:
                                logger.error(f"Skipping document {idx}: could not reduce size")
                                skipped_count += 1
                                continue

                            if was_truncated:
                                truncated_count += 1

                            # Check for duplicate URL and handle
                            should_insert, should_update, existing_id = handle_duplicate_url(collection, fixed_doc, idx)

                            if should_insert:
                                result = collection.insert_one(fixed_doc)
                                inserted_count += 1
                                # Index in Elasticsearch
                                if es_manager:
                                    index_document_in_elasticsearch(es_manager, result.inserted_id, fixed_doc)
                            elif should_update:
                                collection.replace_one({'_id': existing_id}, fixed_doc)
                                updated_count += 1
                                # Update in Elasticsearch
                                if es_manager:
                                    index_document_in_elasticsearch(es_manager, existing_id, fixed_doc)
                            else:
                                # Keep existing, count as skipped
                                skipped_count += 1

                        logger.info(f"Import completed: {inserted_count} inserted, {updated_count} updated, {truncated_count} truncated, {skipped_count} skipped")

                    elif isinstance(docs, dict):
                        # Single document
                        # Decode body field for text search
                        docs = decode_body_field(docs)

                        fixed_doc, was_truncated = check_and_fix_document_size(docs)

                        if fixed_doc is None:
                            logger.error("Document exceeds size limit and could not be truncated")
                            sys.exit(1)

                        if was_truncated:
                            logger.info("Document was truncated to fit size limit")

                        # Check for duplicate URL
                        should_insert, should_update, existing_id = handle_duplicate_url(collection, fixed_doc)

                        if should_insert:
                            result = collection.insert_one(fixed_doc)
                            logger.info("Import completed: 1 document imported")
                            # Index in Elasticsearch
                            if es_manager:
                                index_document_in_elasticsearch(es_manager, result.inserted_id, fixed_doc)
                        elif should_update:
                            collection.replace_one({'_id': existing_id}, fixed_doc)
                            logger.info("Import completed: 1 document updated")
                            # Update in Elasticsearch
                            if es_manager:
                                index_document_in_elasticsearch(es_manager, existing_id, fixed_doc)
                        else:
                            logger.info("Import completed: Kept existing document, skipped new data")
                    else:
                        logger.error(f"Unexpected JSON format: {type(docs)}")
                        sys.exit(1)
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse JSON file: {e}")
                    sys.exit(1)

    except FileNotFoundError:
        logger.error(f"File not found: {args.file}")
        sys.exit(1)
    except PermissionError:
        logger.error(f"Permission denied reading file: {args.file}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error during import: {e}")
        sys.exit(1)
    finally:
        client.close()
        logger.info("MongoDB connection closed")

if __name__ == "__main__":
    main()
