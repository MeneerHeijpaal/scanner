"""
Scanner Web Application - Main Server File

Flask application server for the Scanner reconnaissance tool. It provides a web
interface for searching and analyzing scan results stored in Elasticsearch.

As of the MongoDB -> Elasticsearch migration, Elasticsearch is the single data
store. Hash labels are still kept in a local SQLite database.

Configuration is loaded from config.yml. Routes are defined in routes.py.
Utility functions are in utils.py.
"""

from flask import Flask
import logging
import os
import secrets
import sys
import yaml
from pathlib import Path

# Add Server directory to Python path for imports
sys.path.insert(0, str(Path(__file__).parent))

from utils import ScannerUtils
from elasticsearch_manager import ElasticsearchManager
import routes

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


def load_config(config_path='config.yml'):
    """Load configuration from YAML with environment variable overrides.

    Environment overrides:
        SECRET_KEY, ES_HOST, ES_PORT, ES_INDEX, FLASK_DEBUG
    """
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

    config.setdefault('elasticsearch', {})
    if os.getenv('SECRET_KEY'):
        config['flask']['secret_key'] = os.getenv('SECRET_KEY')
    if os.getenv('ES_HOST'):
        config['elasticsearch']['host'] = os.getenv('ES_HOST')
    if os.getenv('ES_PORT'):
        config['elasticsearch']['port'] = int(os.getenv('ES_PORT'))
    if os.getenv('ES_INDEX'):
        config['elasticsearch']['index_name'] = os.getenv('ES_INDEX')
    if os.getenv('FLASK_DEBUG'):
        config['flask']['debug'] = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'

    return config


def init_labels_database(labels_dir, sqlite_db, schema_file):
    """Create the SQLite labels database from schema.sql if it does not exist."""
    if not sqlite_db.exists():
        logger.info(f"Creating labels database at {sqlite_db}")
        labels_dir.mkdir(exist_ok=True)
        if schema_file.exists():
            import sqlite3
            with open(schema_file, 'r') as f:
                schema_sql = f.read()
            conn = sqlite3.connect(sqlite_db)
            conn.cursor().executescript(schema_sql)
            conn.commit()
            conn.close()
            logger.info("Labels database created successfully")
        else:
            logger.error(f"Schema file not found at {schema_file}")
            sys.exit(1)
    else:
        logger.info(f"Using existing labels database at {sqlite_db}")


def create_app(config):
    """Create and configure the Flask application instance."""
    app = Flask(__name__)

    app.secret_key = config['flask'].get('secret_key') or secrets.token_hex(32)
    app.config['SESSION_TYPE'] = config['flask']['session_type']
    app.config['SESSION_PERMANENT'] = config['flask']['session_permanent']
    app.config['SESSION_USE_SIGNER'] = config['flask']['session_use_signer']

    # Connect to Elasticsearch (the primary data store).
    store = ElasticsearchManager(config)
    if not store.is_connected:
        es = config.get('elasticsearch', {})
        logger.error(
            f"Failed to connect to Elasticsearch at {es.get('host', 'localhost')}:"
            f"{es.get('port', 9200)}. Please ensure Elasticsearch is running.")
        sys.exit(1)
    store.create_index()
    logger.info(f"Elasticsearch connected; using index '{store.index_name}'")

    # Initialize SQLite database for hash labels.
    labels_dir = Path(__file__).parent / config['paths']['labels_dir']
    sqlite_db = labels_dir / config['paths']['sqlite_db']
    schema_file = labels_dir / config['paths']['schema_file']
    init_labels_database(labels_dir, sqlite_db, schema_file)

    utils = ScannerUtils(config, store, sqlite_db)
    routes.register_routes(app, store, config, utils)
    return app


if __name__ == '__main__':
    config = load_config()
    app = create_app(config)

    debug_mode = config['flask']['debug']
    host = config['flask']['host']
    port = config['flask']['port']

    logger.info(f"Starting Flask server (debug={debug_mode})")
    app.run(debug=debug_mode, host=host, port=port)
