"""
Scanner Web Application - Main Server File

This is the main Flask application server for the Scanner HTTP reconnaissance tool.
It provides a web interface for searching and analyzing httpx scan results stored in MongoDB.

Features:
- Search by IP address, CIDR range, URL pattern, hashes, technologies, and labels
- Live counter updates with filter selections
- Hash labeling system using SQLite
- Download URLs and domains functionality
- Detailed views for individual scan results

Configuration is loaded from config.yml.
Routes are defined in routes.py.
Utility functions are in utils.py.
"""

from flask import Flask
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
import logging
import os
import secrets
import sys
import yaml
from pathlib import Path

# Add Server directory to Python path for imports
sys.path.insert(0, str(Path(__file__).parent))

# Import local modules
from utils import ScannerUtils
from elasticsearch_manager import ElasticsearchManager
import routes

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


def load_config(config_path='config.yml'):
    """Load configuration from YAML file with environment variable overrides.

    Reads config.yml and applies environment variable overrides for:
    - SECRET_KEY: Flask secret key
    - MONGO_URI: MongoDB connection string
    - DB_NAME: Database name
    - COLLECTION_NAME: Collection name
    - FLASK_DEBUG: Debug mode flag

    Args:
        config_path: Path to config.yml file (default 'config.yml')

    Examples:
        config = load_config()
        config = load_config('custom_config.yml')

    Returns configuration dictionary.
    """
    # Load YAML config file
    config_file = Path(__file__).parent / config_path
    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
        logger.info(f"Loaded configuration from {config_file}")
    except FileNotFoundError:
        logger.error(f"Configuration file not found: {config_file}")
        sys.exit(1)
    except yaml.YAMLError as e:
        logger.error(f"Error parsing configuration file: {e}")
        sys.exit(1)

    # Apply environment variable overrides
    if os.getenv('SECRET_KEY'):
        config['flask']['secret_key'] = os.getenv('SECRET_KEY')
    if os.getenv('MONGO_URI'):
        config['mongodb']['uri'] = os.getenv('MONGO_URI')
    if os.getenv('DB_NAME'):
        config['mongodb']['database'] = os.getenv('DB_NAME')
    if os.getenv('COLLECTION_NAME'):
        config['mongodb']['collection'] = os.getenv('COLLECTION_NAME')
    if os.getenv('FLASK_DEBUG'):
        config['flask']['debug'] = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'

    return config


def init_labels_database(labels_dir, sqlite_db, schema_file):
    """Initialize SQLite database for hash labels if it doesn't exist.

    Creates the labels directory and database file using schema from schema.sql.

    Args:
        labels_dir: Path to labels directory
        sqlite_db: Path to SQLite database file
        schema_file: Path to SQL schema file

    Examples:
        init_labels_database(Path("labels"), Path("labels/labels.db"), Path("labels/schema.sql"))

    Returns None.
    """
    if not sqlite_db.exists():
        logger.info(f"Creating labels database at {sqlite_db}")
        labels_dir.mkdir(exist_ok=True)

        # Create database with schema
        if schema_file.exists():
            import sqlite3
            with open(schema_file, 'r') as f:
                schema_sql = f.read()

            conn = sqlite3.connect(sqlite_db)
            cursor = conn.cursor()
            cursor.executescript(schema_sql)
            conn.commit()
            conn.close()
            logger.info("Labels database created successfully")
        else:
            logger.error(f"Schema file not found at {schema_file}")
            sys.exit(1)
    else:
        logger.info(f"Using existing labels database at {sqlite_db}")


def create_mongodb_indexes(collection, indexes_config):
    """Create MongoDB indexes for performance optimization.

    Creates indexes defined in config.yml to speed up queries.

    Args:
        collection: MongoDB collection object
        indexes_config: List of index configurations from config.yml

    Examples:
        create_mongodb_indexes(collection, config['indexes'])

    Returns None.
    """
    try:
        for index_def in indexes_config:
            field = index_def['field']
            name = index_def['name']
            index_type = index_def.get('type', 'ascending')

            if index_type == 'text':
                # Create text index for full-text search
                collection.create_index([(field, 'text')], name=name)
            else:
                # Create regular index
                order = index_def.get('order', 1)
                collection.create_index([(field, order)], name=name)
        logger.info("MongoDB indexes created successfully")
    except Exception as e:
        logger.warning(f'Could not create MongoDB indexes: {e}')


def create_app(config):
    """Create and configure Flask application instance.

    Sets up Flask app with:
    - Session configuration
    - MongoDB connection
    - SQLite labels database
    - Utility functions
    - Route handlers

    Args:
        config: Configuration dictionary from load_config()

    Examples:
        config = load_config()
        app = create_app(config)

    Returns Flask application instance.
    """
    app = Flask(__name__)

    # Flask session configuration
    app.secret_key = config['flask'].get('secret_key') or secrets.token_hex(32)
    app.config['SESSION_TYPE'] = config['flask']['session_type']
    app.config['SESSION_PERMANENT'] = config['flask']['session_permanent']
    app.config['SESSION_USE_SIGNER'] = config['flask']['session_use_signer']

    # Connect to MongoDB with error handling
    mongo_uri = config['mongodb']['uri']
    db_name = config['mongodb']['database']
    collection_name = config['mongodb']['collection']
    timeout = config['mongodb']['timeout']

    try:
        logger.info(f"Connecting to MongoDB at {mongo_uri}")
        mongo_client = MongoClient(mongo_uri, serverSelectionTimeoutMS=timeout)
        # Test connection
        mongo_client.admin.command('ping')
        logger.info("MongoDB connection successful")
        db = mongo_client[db_name]
        collection = db[collection_name]
    except (ConnectionFailure, ServerSelectionTimeoutError) as e:
        logger.error(f"Failed to connect to MongoDB: {e}")
        logger.error("Please ensure MongoDB is running at the specified URI")
        sys.exit(1)

    # Initialize SQLite database for hash labels
    labels_dir = Path(__file__).parent / config['paths']['labels_dir']
    sqlite_db = labels_dir / config['paths']['sqlite_db']
    schema_file = labels_dir / config['paths']['schema_file']
    init_labels_database(labels_dir, sqlite_db, schema_file)

    # Create MongoDB indexes for performance
    create_mongodb_indexes(collection, config['indexes'])

    # Initialize Elasticsearch manager
    es_manager = ElasticsearchManager(config)
    if es_manager.is_connected:
        # Create index if it doesn't exist
        es_manager.create_index()
        logger.info("Elasticsearch integration enabled")
    else:
        logger.warning("Elasticsearch not available - body search will use MongoDB regex fallback")

    # Initialize utility functions
    utils = ScannerUtils(config, collection, sqlite_db, es_manager)

    # Register routes
    routes.register_routes(app, collection, config, utils)

    return app


if __name__ == '__main__':
    """Application entry point.

    Loads configuration, creates Flask app, and starts the development server.
    """
    # Load configuration
    config = load_config()

    # Create Flask application
    app = create_app(config)

    # Start server
    debug_mode = config['flask']['debug']
    host = config['flask']['host']
    port = config['flask']['port']

    logger.info(f"Starting Flask server (debug={debug_mode})")
    app.run(debug=debug_mode, host=host, port=port)
