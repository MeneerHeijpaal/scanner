"""
Elasticsearch Manager Module

This module provides the primary Elasticsearch data store for the Scanner
application. As of the MongoDB -> Elasticsearch migration, Elasticsearch is the
single store for all httpx scan records (and, later, naabu/nuclei enrichment).
MongoDB is no longer used at runtime; it survives only in the one-off migration
script (Python/migrate_to_elasticsearch.py) that copies legacy data across.

Design:
- One index (``elasticsearch.index_name``, default ``scanner_records``) holds the
  full record. Fields are mapped for the exact queries the UI performs:
    * ``ip`` (wildcard string) + ``ip_addr`` (ip type)  -> exact / prefix / CIDR / wildcard
    * ``host`` (wildcard)                               -> hostname / partial
    * ``url`` / ``redirect_location`` (wildcard)        -> substring search
    * ``scheme`` (keyword)                              -> protocol filter
    * ``tech`` (keyword[])                              -> facet + filter
    * ``status_code`` (integer)                         -> filter
    * ``hash.body_sha256`` / ``hash.header_sha256``     -> exact term
    * ``body_decoded`` (text)                           -> match_phrase body search
    * ``body`` / ``raw_header`` / ``request``           -> stored, not indexed
- Document ``_id`` is derived from the URL (sha1) so re-importing a URL updates
  the record in place instead of creating duplicates.

Classes:
    ElasticsearchManager: connection, index management, indexing, and search.
"""

import hashlib
import logging
from typing import Any, Dict, Iterable, List, Optional, Tuple

from elasticsearch import Elasticsearch, helpers
from elasticsearch.exceptions import ConnectionError as ESConnectionError
from elasticsearch.exceptions import NotFoundError

logger = logging.getLogger(__name__)

# Fields decoded from base64 for display / download. Stored in _source but not indexed.
STORED_ONLY_FIELDS = ["body", "raw_header", "request"]


def doc_id_for(record: Dict[str, Any]) -> str:
    """Return a stable document id for a record.

    Keyed on the URL so re-importing the same URL updates in place. Falls back to
    a hash of the whole record when no URL is present.

    Examples:
        {"url": "https://example.com"} -> "sha1 of the url"
        {"ip": "1.1.1.1"}              -> "sha1 of the json"
    """
    url = record.get("url")
    if url:
        return hashlib.sha1(url.encode("utf-8", errors="replace")).hexdigest()
    # No URL: hash a stable representation so identical records collapse.
    basis = repr(sorted((k, str(v)) for k, v in record.items() if k != "_id"))
    return hashlib.sha1(basis.encode("utf-8", errors="replace")).hexdigest()


class ElasticsearchManager:
    """Primary Elasticsearch store for scan records."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize the Elasticsearch manager from the app config dict."""
        self.config = config
        self.es_config = config.get("elasticsearch", {})
        self.enabled = self.es_config.get("enabled", True)
        self.host = self.es_config.get("host", "localhost")
        self.port = self.es_config.get("port", 9200)
        # ``index_name`` now holds the full record. ``scanner_bodies`` was the old
        # body-only index; default to ``scanner_records`` for the full store.
        self.index_name = self.es_config.get("index_name", "scanner_records")
        self.timeout = self.es_config.get("timeout", 30)
        self.bulk_batch_size = self.es_config.get("bulk_batch_size", 5000)
        # Hard ceiling for how much decoded body we index for full-text search.
        self.max_body_index_chars = self.es_config.get("max_body_index_chars", 2_000_000)
        # Max hits ES will return in a single search page (index setting).
        self.max_result_window = self.es_config.get("max_result_window", 100000)

        self.client: Optional[Elasticsearch] = None
        self.is_connected = False

        if self.enabled:
            self._connect()

    # ------------------------------------------------------------------ #
    # Connection & index management
    # ------------------------------------------------------------------ #

    def _connect(self) -> bool:
        """Establish and verify a connection to Elasticsearch."""
        try:
            self.client = Elasticsearch(
                [f"http://{self.host}:{self.port}"],
                request_timeout=self.timeout,
                retry_on_timeout=True,
                max_retries=3,
            )
            if self.client.ping():
                self.is_connected = True
                logger.info(f"Connected to Elasticsearch at {self.host}:{self.port}")
                return True
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

    def ping(self) -> bool:
        """Return True if the cluster answers a ping."""
        try:
            return bool(self.client and self.client.ping())
        except Exception:
            return False

    def _mapping(self) -> Dict[str, Any]:
        """Return the index settings + mappings for the full record."""
        stored_only = {f: {"type": "text", "index": False} for f in STORED_ONLY_FIELDS}
        return {
            "settings": {
                "number_of_shards": self.es_config.get("number_of_shards", 1),
                "number_of_replicas": self.es_config.get("number_of_replicas", 0),
                "max_result_window": self.max_result_window,
                "analysis": {"analyzer": {"default": {"type": "standard"}}},
            },
            "mappings": {
                # Unknown httpx fields are stored but not indexed, keeping the
                # mapping stable while preserving the full record in _source.
                "dynamic": "false",
                "properties": {
                    "url": {"type": "wildcard"},
                    "redirect_location": {"type": "wildcard"},
                    "title": {"type": "wildcard"},
                    "input": {"type": "keyword"},
                    "ip": {"type": "wildcard"},
                    "ip_addr": {"type": "ip", "ignore_malformed": True},
                    "host": {"type": "wildcard"},
                    "port": {"type": "keyword"},
                    "scheme": {"type": "keyword"},
                    "path": {"type": "wildcard"},
                    "method": {"type": "keyword"},
                    "status_code": {"type": "integer"},
                    "content_length": {"type": "long"},
                    "content_type": {"type": "keyword"},
                    "cname": {"type": "keyword"},
                    "tech": {"type": "keyword"},
                    "words": {"type": "long"},
                    "lines": {"type": "long"},
                    "time": {"type": "keyword"},
                    "timestamp": {"type": "date", "ignore_malformed": True},
                    "hash": {
                        "type": "object",
                        "properties": {
                            "body_sha256": {"type": "keyword"},
                            "header_sha256": {"type": "keyword"},
                            "body_mmh3": {"type": "keyword"},
                            "header_mmh3": {"type": "keyword"},
                        },
                    },
                    "body_decoded": {"type": "text", "analyzer": "standard"},
                    **stored_only,
                },
            },
        }

    def create_index(self) -> bool:
        """Create the record index with the full mapping if it does not exist."""
        if not self.is_connected or not self.client:
            logger.warning("Cannot create index: Elasticsearch not connected")
            return False
        try:
            if self.client.indices.exists(index=self.index_name):
                logger.info(f"Index '{self.index_name}' already exists")
                return True
            body = self._mapping()
            self.client.indices.create(
                index=self.index_name,
                settings=body["settings"],
                mappings=body["mappings"],
            )
            logger.info(f"Created Elasticsearch index '{self.index_name}'")
            return True
        except Exception as e:
            logger.error(f"Failed to create index: {e}")
            return False

    # ------------------------------------------------------------------ #
    # Indexing
    # ------------------------------------------------------------------ #

    def ensure_mappings(self) -> None:
        """Add fields that may be missing from an already-created index.

        ``title`` was added after the initial mapping; PUT it onto an existing
        index so new documents index it. Existing documents need a reindex to
        become title-searchable, but this is idempotent and safe to call on boot.
        """
        if not self.is_connected or not self.client:
            return
        try:
            self.client.indices.put_mapping(
                index=self.index_name,
                properties={"title": {"type": "wildcard"}},
            )
        except Exception as e:
            logger.debug(f"ensure_mappings: {e}")

    # ------------------------------------------------------------------ #
    # Generic multi-index reads (used by the dashboard across records,
    # ports, findings and interactions indices).
    # ------------------------------------------------------------------ #

    def raw_count(self, index: str, query: Dict[str, Any]) -> int:
        """Count documents matching a query in an arbitrary index."""
        if not self.is_connected or not self.client:
            return 0
        try:
            return int(self.client.count(index=index, query=query).get("count", 0))
        except Exception as e:
            logger.debug(f"raw_count on {index}: {e}")
            return 0

    def raw_search(self, index: str, *, query: Optional[Dict[str, Any]] = None,
                   aggs: Optional[Dict[str, Any]] = None, size: int = 0, from_: int = 0,
                   sort: Optional[List[Any]] = None, source: Optional[List[str]] = None,
                   track_total_hits: bool = True) -> Dict[str, Any]:
        """Run a search against an arbitrary index and return the raw response."""
        if not self.is_connected or not self.client:
            return {}
        kwargs: Dict[str, Any] = {"index": index, "size": size, "from_": from_,
                                  "track_total_hits": track_total_hits}
        if query is not None:
            kwargs["query"] = query
        if aggs is not None:
            kwargs["aggs"] = aggs
        if sort is not None:
            kwargs["sort"] = sort
        if source is not None:
            kwargs["source"] = source
        try:
            return dict(self.client.search(**kwargs))
        except Exception as e:
            logger.debug(f"raw_search on {index}: {e}")
            return {}

    def _prepare_source(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Return a copy of a record ready to index (adds derived fields)."""
        source = dict(record)
        source.pop("_id", None)

        # Numeric IP copy for CIDR / range queries.
        ip_value = source.get("ip")
        if ip_value:
            source["ip_addr"] = ip_value

        # Precompute redirect location so URL search can match it.
        header = source.get("header")
        if isinstance(header, dict):
            loc = header.get("location") or header.get("Location")
            if loc:
                source["redirect_location"] = loc

        # Cap the indexed body size to keep the index bounded.
        body_decoded = source.get("body_decoded")
        if body_decoded and len(body_decoded) > self.max_body_index_chars:
            source["body_decoded"] = body_decoded[: self.max_body_index_chars]

        return source

    def index_document(self, record: Dict[str, Any], doc_id: Optional[str] = None) -> bool:
        """Index (upsert) a single full record."""
        if not self.is_connected or not self.client:
            return False
        try:
            source = self._prepare_source(record)
            _id = doc_id or doc_id_for(record)
            self.client.index(index=self.index_name, id=_id, document=source)
            return True
        except Exception as e:
            logger.warning(f"Failed to index document: {e}")
            return False

    def bulk_index(self, records: Iterable[Dict[str, Any]]) -> Tuple[int, int]:
        """Bulk upsert full records. Returns (success_count, error_count)."""
        if not self.is_connected or not self.client:
            logger.warning("Cannot bulk index: Elasticsearch not connected")
            records = list(records)
            return (0, len(records))

        def actions():
            for rec in records:
                _id = rec.get("_id") or doc_id_for(rec)
                yield {
                    "_index": self.index_name,
                    "_id": _id,
                    "_source": self._prepare_source(rec),
                }

        try:
            success, errors = helpers.bulk(
                self.client,
                actions(),
                chunk_size=self.bulk_batch_size,
                raise_on_error=False,
                raise_on_exception=False,
            )
            error_count = len(errors) if isinstance(errors, list) else 0
            if error_count:
                logger.warning(f"Bulk index: {success} ok, {error_count} errors")
            return (success, error_count)
        except Exception as e:
            logger.error(f"Bulk indexing failed: {e}")
            return (0, 0)

    def delete_document(self, doc_id: str) -> bool:
        """Delete a document by id (ignores 404)."""
        if not self.is_connected or not self.client:
            return False
        try:
            self.client.delete(index=self.index_name, id=doc_id)
            return True
        except NotFoundError:
            return True
        except Exception as e:
            logger.warning(f"Failed to delete document {doc_id}: {e}")
            return False

    # ------------------------------------------------------------------ #
    # Reads
    # ------------------------------------------------------------------ #

    def count(self, query: Dict[str, Any]) -> int:
        """Return the number of documents matching an ES query."""
        if not self.is_connected or not self.client:
            return 0
        try:
            resp = self.client.count(index=self.index_name, query=query)
            return int(resp.get("count", 0))
        except Exception as e:
            logger.error(f"Count failed: {e}")
            return 0

    def search(
        self,
        query: Dict[str, Any],
        source: Optional[List[str]] = None,
        sort: Optional[List[Any]] = None,
        from_: int = 0,
        size: int = 50,
        track_total_hits: bool = True,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Run a search and return (hits, total).

        Each hit is the ``_source`` dict with ``_id`` injected.
        """
        if not self.is_connected or not self.client:
            return [], 0
        try:
            kwargs: Dict[str, Any] = {
                "index": self.index_name,
                "query": query,
                "from_": from_,
                "size": size,
                "track_total_hits": track_total_hits,
            }
            if source is not None:
                kwargs["source"] = source
            if sort is not None:
                kwargs["sort"] = sort
            resp = self.client.search(**kwargs)
            hits = []
            for hit in resp["hits"]["hits"]:
                doc = dict(hit.get("_source", {}))
                doc["_id"] = hit["_id"]
                hits.append(doc)
            total = resp["hits"]["total"]
            total_val = total["value"] if isinstance(total, dict) else int(total)
            return hits, int(total_val)
        except Exception as e:
            logger.error(f"Search failed: {e}")
            return [], 0

    def get(self, doc_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single document by id, with ``_id`` injected, or None."""
        if not self.is_connected or not self.client:
            return None
        try:
            resp = self.client.get(index=self.index_name, id=doc_id)
            doc = dict(resp.get("_source", {}))
            doc["_id"] = resp["_id"]
            return doc
        except NotFoundError:
            return None
        except Exception as e:
            logger.warning(f"Get failed for {doc_id}: {e}")
            return None

    def scan(
        self,
        query: Dict[str, Any],
        source: Optional[List[str]] = None,
        sort: Optional[List[Any]] = None,
    ) -> Iterable[Dict[str, Any]]:
        """Yield every document matching a query (uses the scroll/scan helper).

        Use for exports where the full result set is needed regardless of size.
        """
        if not self.is_connected or not self.client:
            return
        body: Dict[str, Any] = {"query": query}
        if sort is not None:
            body["sort"] = sort
        try:
            for hit in helpers.scan(
                self.client,
                index=self.index_name,
                query=body,
                _source=source if source is not None else True,
                preserve_order=sort is not None,
            ):
                doc = dict(hit.get("_source", {}))
                doc["_id"] = hit["_id"]
                yield doc
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            return

    def distinct_terms(self, field: str, size: int = 1000) -> List[str]:
        """Return distinct values for a keyword field via a terms aggregation."""
        if not self.is_connected or not self.client:
            return []
        try:
            resp = self.client.search(
                index=self.index_name,
                size=0,
                aggs={"values": {"terms": {"field": field, "size": size}}},
            )
            buckets = resp["aggregations"]["values"]["buckets"]
            return sorted(b["key"] for b in buckets if b.get("key"))
        except Exception as e:
            logger.error(f"Aggregation on {field} failed: {e}")
            return []

    def get_index_stats(self) -> Optional[Dict[str, Any]]:
        """Return document count and size for the index, or None."""
        if not self.is_connected or not self.client:
            return None
        try:
            stats = self.client.indices.stats(index=self.index_name)
            primaries = stats["_all"]["primaries"]
            size_bytes = primaries["store"]["size_in_bytes"]
            return {
                "document_count": primaries["docs"]["count"],
                "size_bytes": size_bytes,
                "size_mb": round(size_bytes / (1024 * 1024), 2),
            }
        except Exception:
            return None
