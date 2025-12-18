"""
Elasticsearch Manager Module

This module provides Elasticsearch integration for the Scanner application,
enabling fast full-text search on response body content.

Architecture:
- Elasticsearch stores only body_decoded content and document IDs for search
- MongoDB remains the primary data store for all other fields
- Search queries route through Elasticsearch, then fetch full docs from MongoDB

Classes:
    ElasticsearchManager: Manages Elasticsearch connection, indexing, and search
"""

import logging
from typing import List, Dict, Optional, Any
from elasticsearch import Elasticsearch, helpers
from elasticsearch.exceptions import ConnectionError as ESConnectionError

logger = logging.getLogger(__name__)


class ElasticsearchManager:
    """
    Manages Elasticsearch operations for body content search.

    This class handles:
    - Connection to Elasticsearch cluster
    - Index creation with proper mappings
    - Bulk indexing of documents
    - Full-text search queries
    - Error handling and fallback behavior
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Elasticsearch manager.

        Args:
            config: Configuration dictionary with Elasticsearch settings
        """
        self.config = config
        self.es_config = config.get('elasticsearch', {})
        self.enabled = self.es_config.get('enabled', False)
        self.host = self.es_config.get('host', 'localhost')
        self.port = self.es_config.get('port', 9200)
        self.index_name = self.es_config.get('index_name', 'scanner_bodies')
        self.timeout = self.es_config.get('timeout', 30)
        self.bulk_batch_size = self.es_config.get('bulk_batch_size', 5000)

        self.client: Optional[Elasticsearch] = None
        self.is_connected = False

        if self.enabled:
            self._connect()

    def _connect(self) -> bool:
        """
        Establish connection to Elasticsearch.

        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            self.client = Elasticsearch(
                [f"http://{self.host}:{self.port}"],
                request_timeout=self.timeout,
                retry_on_timeout=True,
                max_retries=3
            )

            # Test connection
            if self.client.ping():
                self.is_connected = True
                logger.info(f"Connected to Elasticsearch at {self.host}:{self.port}")
                return True
            else:
                logger.warning(f"Could not ping Elasticsearch at {self.host}:{self.port}")
                self.is_connected = False
                return False

        except ESConnectionError as e:
            logger.warning(f"Elasticsearch connection failed: {e}")
            self.is_connected = False
            return False
        except Exception as e:
            logger.error(f"Unexpected error connecting to Elasticsearch: {e}")
            self.is_connected = False
            return False

    def create_index(self) -> bool:
        """
        Create Elasticsearch index with proper mappings.

        The index is optimized for phrase matching on body content:
        - body_decoded: Full-text field with standard analyzer
        - doc_id: Keyword field for MongoDB _id reference
        - url: Keyword field for reference
        - timestamp: Date field for sorting/filtering

        Returns:
            bool: True if index created or already exists, False on error
        """
        if not self.is_connected or not self.client:
            logger.warning("Cannot create index: Elasticsearch not connected")
            return False

        try:
            # Check if index already exists
            if self.client.indices.exists(index=self.index_name):
                logger.info(f"Index '{self.index_name}' already exists")
                return True

            # Define index mapping
            mapping = {
                "settings": {
                    "number_of_shards": self.es_config.get('number_of_shards', 1),
                    "number_of_replicas": self.es_config.get('number_of_replicas', 0),
                    "max_result_window": 10000,
                    "analysis": {
                        "analyzer": {
                            "default": {
                                "type": "standard"
                            }
                        }
                    }
                },
                "mappings": {
                    "properties": {
                        "doc_id": {
                            "type": "keyword"
                        },
                        "body_decoded": {
                            "type": "text",
                            "analyzer": "standard"
                        },
                        "url": {
                            "type": "keyword"
                        },
                        "timestamp": {
                            "type": "date"
                        }
                    }
                }
            }

            # Create index
            self.client.indices.create(index=self.index_name, body=mapping)
            logger.info(f"Created Elasticsearch index '{self.index_name}'")
            return True

        except Exception as e:
            logger.error(f"Failed to create index: {e}")
            return False

    def index_document(self, doc_id: str, body_decoded: str, url: str = "", timestamp: Any = None) -> bool:
        """
        Index a single document in Elasticsearch.

        Args:
            doc_id: MongoDB document _id (as string)
            body_decoded: Decoded response body content
            url: URL for reference (optional)
            timestamp: Document timestamp (optional)

        Returns:
            bool: True if indexed successfully, False otherwise
        """
        if not self.is_connected or not self.client:
            return False

        try:
            doc = {
                "doc_id": doc_id,
                "body_decoded": body_decoded,
                "url": url,
                "timestamp": timestamp
            }

            self.client.index(index=self.index_name, id=doc_id, document=doc)
            return True

        except Exception as e:
            logger.warning(f"Failed to index document {doc_id}: {e}")
            return False

    def bulk_index_documents(self, documents: List[Dict[str, Any]]) -> tuple[int, int]:
        """
        Bulk index multiple documents for better performance.

        Args:
            documents: List of dicts with keys: doc_id, body_decoded, url, timestamp

        Returns:
            tuple: (success_count, error_count)
        """
        if not self.is_connected or not self.client:
            logger.warning("Cannot bulk index: Elasticsearch not connected")
            return (0, len(documents))

        try:
            # Prepare bulk actions
            actions = []
            for doc in documents:
                if 'doc_id' not in doc or 'body_decoded' not in doc:
                    continue

                action = {
                    "_index": self.index_name,
                    "_id": doc['doc_id'],
                    "_source": {
                        "doc_id": doc['doc_id'],
                        "body_decoded": doc['body_decoded'],
                        "url": doc.get('url', ''),
                        "timestamp": doc.get('timestamp')
                    }
                }
                actions.append(action)

            if not actions:
                return (0, 0)

            # Execute bulk operation
            success, errors = helpers.bulk(
                self.client,
                actions,
                chunk_size=self.bulk_batch_size,
                raise_on_error=False,
                raise_on_exception=False
            )

            error_count = len(errors) if isinstance(errors, list) else 0
            logger.info(f"Bulk indexed {success} documents, {error_count} errors")

            return (success, error_count)

        except Exception as e:
            logger.error(f"Bulk indexing failed: {e}")
            return (0, len(documents))

    def search_body(self, query: str, size: int = 10000) -> List[str]:
        """
        Search for documents containing the query phrase in body content.

        This performs a phrase match query for exact substring matching,
        similar to the MongoDB regex approach but much faster.

        Args:
            query: Search query string (phrase to find)
            size: Maximum number of results to return

        Returns:
            List of MongoDB document IDs (as strings) that match the query
        """
        if not self.is_connected or not self.client:
            logger.warning("Cannot search: Elasticsearch not connected")
            return []

        try:
            # Use match_phrase for exact phrase matching
            search_query = {
                "query": {
                    "match_phrase": {
                        "body_decoded": {
                            "query": query
                        }
                    }
                },
                "size": size,
                "_source": ["doc_id"]
            }

            response = self.client.search(index=self.index_name, body=search_query)

            # Extract document IDs
            doc_ids = []
            for hit in response['hits']['hits']:
                doc_id = hit['_source']['doc_id']
                doc_ids.append(doc_id)

            logger.info(f"Elasticsearch found {len(doc_ids)} matches for query: {query[:50]}...")
            return doc_ids

        except Exception as e:
            logger.error(f"Search failed: {e}")
            return []

    def delete_document(self, doc_id: str) -> bool:
        """
        Delete a document from the index.

        Args:
            doc_id: MongoDB document _id (as string)

        Returns:
            bool: True if deleted successfully, False otherwise
        """
        if not self.is_connected or not self.client:
            return False

        try:
            self.client.delete(index=self.index_name, id=doc_id, ignore=[404])
            return True
        except Exception as e:
            logger.warning(f"Failed to delete document {doc_id}: {e}")
            return False

    def get_index_stats(self) -> Optional[Dict[str, Any]]:
        """
        Get statistics about the Elasticsearch index.

        Returns:
            Dict with index stats or None if unavailable
        """
        if not self.is_connected or not self.client:
            return None

        try:
            stats = self.client.indices.stats(index=self.index_name)
            doc_count = stats['_all']['primaries']['docs']['count']
            size_bytes = stats['_all']['primaries']['store']['size_in_bytes']

            return {
                'document_count': doc_count,
                'size_bytes': size_bytes,
                'size_mb': round(size_bytes / (1024 * 1024), 2)
            }
        except Exception:
            return None
