"""
Utility functions for the Scanner web application.

This module contains helper functions for:
- Input validation and sanitization
- Base64 decoding
- Hash label management (SQLite operations)
- Elasticsearch query building
- IP/CIDR expansion
- Pagination

As of the MongoDB -> Elasticsearch migration, ``build_search_query`` produces an
Elasticsearch query DSL dict (a ``bool`` query) rather than a MongoDB filter, and
all record reads go through the Elasticsearch store passed in as ``store``.
"""

import base64
import ipaddress
import logging
import re
import sqlite3

logger = logging.getLogger(__name__)

# ES ``match_all`` — the query used when no filters are supplied.
MATCH_ALL: dict = {"match_all": {}}
# A query that matches nothing (used when a filter can have no result).
MATCH_NONE: dict = {"bool": {"must_not": {"match_all": {}}}}


class ScannerUtils:
    """Utility class containing helper functions for the Scanner web application."""

    def __init__(self, config, store, sqlite_db_path):
        """Initialize ScannerUtils.

        Args:
            config: Configuration dictionary from config/server-config.yaml
            store: ElasticsearchManager instance (the primary data store)
            sqlite_db_path: Path to SQLite labels database
        """
        self.config = config
        self.store = store
        self.sqlite_db = sqlite_db_path
        self.max_query_length = config['validation']['max_query_length']
        self.max_cidr_hosts = config['validation']['max_cidr_hosts']
        self.allowed_hash_types = set(config['validation']['allowed_hash_types'])

    # ------------------------------------------------------------------ #
    # Input validation
    # ------------------------------------------------------------------ #

    def sanitize_string_input(self, value, max_length=None):
        """Sanitize string input: strip, cap length, drop control characters."""
        if not value:
            return ""
        if max_length is None:
            max_length = self.max_query_length
        value = str(value).strip()
        if len(value) > max_length:
            logger.warning(f"Input exceeds max length ({max_length}): truncating")
            value = value[:max_length]
        value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', value)
        return value

    def escape_regex_special_chars(self, value):
        """Escape regex special characters for literal matching."""
        if not value:
            return ""
        return re.escape(value)

    def validate_doc_id(self, id_string):
        """Validate an Elasticsearch document id.

        ES ids are opaque strings. We accept a bounded, printable token and reject
        anything with whitespace/control characters or an unreasonable length.

        Returns the sanitized id string or None if invalid.
        """
        if not id_string:
            return None
        id_string = str(id_string).strip()
        if not id_string or len(id_string) > 512:
            return None
        if re.search(r'\s', id_string):
            return None
        return id_string

    def validate_integer(self, value, min_val=1, max_val=None, default=1):
        """Validate/clamp an integer input within [min_val, max_val]."""
        try:
            result = int(value)
            if result < min_val:
                return min_val
            if max_val and result > max_val:
                return max_val
            return result
        except (ValueError, TypeError):
            return default

    def validate_hash_type(self, hash_type):
        """Validate hash type is 'body' or 'header'; return it or None."""
        if hash_type not in self.allowed_hash_types:
            logger.warning(f"Invalid hash type: {hash_type}")
            return None
        return hash_type

    # ------------------------------------------------------------------ #
    # Base64 decoding
    # ------------------------------------------------------------------ #

    def decode_base64_fields(self, item):
        """Decode base64 body/raw_header/request fields into ``*_decoded`` keys."""
        base64_fields = ['body', 'raw_header', 'request']
        decoded_item = dict(item)
        if '_id' in decoded_item:
            decoded_item['_id'] = str(decoded_item['_id'])
        for field in base64_fields:
            if field in decoded_item and decoded_item[field]:
                try:
                    decoded_item[f'{field}_decoded'] = base64.b64decode(
                        decoded_item[field]).decode('utf-8', errors='replace')
                except Exception as e:
                    decoded_item[f'{field}_decoded'] = f'Error decoding {field}: {str(e)}'
        return decoded_item

    # ------------------------------------------------------------------ #
    # SQLite label management (unchanged store)
    # ------------------------------------------------------------------ #

    def get_labels_db_connection(self):
        """Open a SQLite connection to the labels DB with Row factory."""
        conn = sqlite3.connect(self.sqlite_db)
        conn.row_factory = sqlite3.Row
        return conn

    def get_hash_label(self, hash_value):
        """Return the label for a hash, or None."""
        try:
            conn = self.get_labels_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT label FROM hash_labels WHERE hash = ?', (hash_value,))
            result = cursor.fetchone()
            conn.close()
            return result['label'] if result else None
        except Exception as e:
            logger.error(f"Error getting label for hash {hash_value}: {e}")
            return None

    def get_all_labels(self):
        """Return all distinct label names, sorted."""
        try:
            conn = self.get_labels_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT DISTINCT label FROM hash_labels ORDER BY label')
            results = cursor.fetchall()
            conn.close()
            return [r['label'] for r in results]
        except Exception as e:
            logger.error(f"Error getting all labels: {e}")
            return []

    def get_hashes_by_label(self, label):
        """Return all hash values associated with a label."""
        try:
            conn = self.get_labels_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT hash FROM hash_labels WHERE label = ?', (label,))
            results = cursor.fetchall()
            conn.close()
            return [r['hash'] for r in results]
        except Exception as e:
            logger.error(f"Error getting hashes for label {label}: {e}")
            return []

    def set_hash_label(self, hash_value, label, hash_type='body'):
        """Insert or replace a label for a hash. Returns True on success."""
        sanitized_label = self.sanitize_string_input(label, max_length=100)
        if not sanitized_label:
            return False
        try:
            conn = self.get_labels_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                'INSERT OR REPLACE INTO hash_labels (hash, label, hash_type, updated_at) '
                'VALUES (?, ?, ?, CURRENT_TIMESTAMP)',
                (hash_value, sanitized_label, hash_type)
            )
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"Error setting label for hash {hash_value}: {e}")
            return False

    def delete_hash_label(self, hash_value):
        """Delete a hash's label. Returns True if a row was removed."""
        try:
            conn = self.get_labels_db_connection()
            cursor = conn.cursor()
            cursor.execute('DELETE FROM hash_labels WHERE hash = ?', (hash_value,))
            deleted = cursor.rowcount > 0
            conn.commit()
            conn.close()
            return deleted
        except Exception as e:
            logger.error(f"Error deleting label for hash {hash_value}: {e}")
            return False

    # ------------------------------------------------------------------ #
    # IP / CIDR helpers
    # ------------------------------------------------------------------ #

    def wildcard_ip_glob(self, ip_pattern):
        """Convert an 'x'-wildcard IP pattern to an ES wildcard glob.

        Examples:
            "12.34.56.x"  -> "12.34.56.*"
            "12.34.x.78"  -> "12.34.*.78"
            "12.x.x.x"    -> None   (more than 2 wildcards)
            "12.34.56.999"-> None   (invalid octet)
        """
        octets = ip_pattern.strip().lower().split('.')
        if len(octets) != 4:
            return None
        if sum(1 for o in octets if o == 'x') > 2:
            return None
        parts = []
        for octet in octets:
            if octet == 'x':
                parts.append('*')
            else:
                try:
                    num = int(octet)
                except ValueError:
                    return None
                if num < 0 or num > 255:
                    return None
                parts.append(str(num))
        return '.'.join(parts)

    def expand_cidr_hosts(self, cidr_str, max_hosts=None):
        """Expand a CIDR into host IP strings (kept for callers/tests).

        Returns (hosts_list, error_message):
            invalid CIDR   -> (None, 'invalid')
            too large      -> ([], 'CIDR range too large ...')
            success        -> (list of IPs, None)

        Note: the Elasticsearch query builder uses native CIDR term queries and
        does not expand ranges; this helper remains for compatibility.
        """
        if max_hosts is None:
            max_hosts = self.max_cidr_hosts
        cidr_str = cidr_str.strip()
        try:
            net = ipaddress.ip_network(cidr_str, strict=False)
        except ValueError:
            return None, 'invalid'
        hosts = [str(h) for h in net.hosts()]
        if not hosts:
            hosts = [str(h) for h in net]
        if len(hosts) > max_hosts:
            return [], f'CIDR range too large ({len(hosts)} addresses). Please narrow the network.'
        return hosts, None

    @staticmethod
    def _wildcard_escape(value):
        """Escape ES wildcard metacharacters (* ? \\) in a literal value."""
        return value.replace('\\', '\\\\').replace('*', '\\*').replace('?', '\\?')

    def _ip_host_wildcard(self, glob):
        """Wildcard match ``glob`` against both the ip-string and host fields."""
        return {"bool": {"should": [
            {"wildcard": {"ip": {"value": glob, "case_insensitive": True}}},
            {"wildcard": {"host": {"value": glob, "case_insensitive": True}}},
        ], "minimum_should_match": 1}}

    def _build_ip_clause(self, ip_query):
        """Build the ES clause for the IP search box. Returns (clause, error)."""
        if '/' in ip_query:
            # CIDR notation: use the native ip-type field.
            try:
                ipaddress.ip_network(ip_query, strict=False)
                return {"term": {"ip_addr": ip_query}}, None
            except ValueError:
                # Not a valid CIDR: fall back to a substring wildcard.
                glob = f"*{self._wildcard_escape(ip_query)}*"
                return self._ip_host_wildcard(glob), None

        if 'x' in ip_query.lower():
            glob = self.wildcard_ip_glob(ip_query)
            if glob:
                return self._ip_host_wildcard(glob), None
            return None, 'Invalid IP wildcard pattern. Use "x" for wildcards (max 2, e.g., 12.34.x.x)'

        octets = ip_query.split('.')
        if len(octets) == 4 and all(o.isdigit() and 0 <= int(o) <= 255 for o in octets):
            # Exact dotted-quad IP.
            return {"bool": {"should": [
                {"term": {"ip_addr": ip_query}},
                {"term": {"host": ip_query}},
            ], "minimum_should_match": 1}}, None

        # Partial / prefix string match.
        glob = f"{self._wildcard_escape(ip_query)}*"
        return self._ip_host_wildcard(glob), None

    # ------------------------------------------------------------------ #
    # Elasticsearch query building
    # ------------------------------------------------------------------ #

    def get_all_technologies(self):
        """Return all distinct detected technologies, sorted."""
        try:
            return self.store.distinct_terms('tech', size=2000)
        except Exception as e:
            logger.error(f"Error getting technologies: {e}")
            return []

    def build_search_query(self, ip_query='', url_query='', body_search='', body_hash_query='',
                           header_hash_query='', include_labels=None, exclude_labels=None,
                           protocol_filter='both', tech_filters=None, status_codes=None):
        """Build an Elasticsearch query DSL dict from search parameters.

        Supports IP exact/CIDR/wildcard/prefix, URL substring (incl. redirect
        location), body phrase search, body/header hash, technology, status code,
        protocol, and label include/exclude filters.

        Returns tuple (query_dict, error_message) where query_dict is an ES query
        (a ``bool`` with ``filter`` clauses, or ``match_all``).
        """
        filters = []
        error = None

        if ip_query:
            clause, ip_err = self._build_ip_clause(ip_query)
            if ip_err:
                error = ip_err
            if clause:
                filters.append(clause)

        if url_query:
            glob = f"*{self._wildcard_escape(url_query)}*"
            filters.append({"bool": {"should": [
                {"wildcard": {"url": {"value": glob, "case_insensitive": True}}},
                {"wildcard": {"redirect_location": {"value": glob, "case_insensitive": True}}},
            ], "minimum_should_match": 1}})

        if body_search:
            # Exact phrase match on the analyzed decoded body.
            filters.append({"match_phrase": {"body_decoded": body_search}})

        if body_hash_query:
            filters.append({"term": {"hash.body_sha256": body_hash_query}})

        if header_hash_query:
            filters.append({"term": {"hash.header_sha256": header_hash_query}})

        if protocol_filter == 'https':
            filters.append({"term": {"scheme": "https"}})
        elif protocol_filter == 'http':
            filters.append({"term": {"scheme": "http"}})

        if tech_filters:
            filters.append({"terms": {"tech": list(tech_filters)}})

        if status_codes:
            status_code_ints = []
            for code in status_codes:
                try:
                    status_code_ints.append(int(code))
                except (ValueError, TypeError):
                    continue
            if status_code_ints:
                filters.append({"terms": {"status_code": status_code_ints}})

        if include_labels:
            included_hashes = set()
            for label in include_labels:
                included_hashes.update(self.get_hashes_by_label(self.sanitize_string_input(label)))
            if included_hashes:
                hashes = list(included_hashes)
                filters.append({"bool": {"should": [
                    {"terms": {"hash.body_sha256": hashes}},
                    {"terms": {"hash.header_sha256": hashes}},
                ], "minimum_should_match": 1}})
            else:
                # Labels requested but none map to a hash -> no results.
                return MATCH_NONE, error

        if exclude_labels:
            excluded_hashes = set()
            for label in exclude_labels:
                excluded_hashes.update(self.get_hashes_by_label(self.sanitize_string_input(label)))
            if excluded_hashes:
                hashes = list(excluded_hashes)
                filters.append({"bool": {"must_not": [
                    {"terms": {"hash.body_sha256": hashes}},
                    {"terms": {"hash.header_sha256": hashes}},
                ]}})

        if not filters:
            return MATCH_ALL, error
        return {"bool": {"filter": filters}}, error

    # ------------------------------------------------------------------ #
    # Pagination
    # ------------------------------------------------------------------ #

    def get_paginated_results(self, query, page, per_page=50, sort_by='', sort_order='asc'):
        """Return (results, total_pages, total_count) from Elasticsearch.

        ``sort_by`` may be 'ip', 'url', 'body_hash', or 'header_hash'. IP sorting
        uses the numeric ``ip_addr`` field so it orders correctly.
        """
        order = 'desc' if sort_order == 'desc' else 'asc'
        sort = None
        sort_field_map = {
            'ip': 'ip_addr',
            'url': 'url',
            'body_hash': 'hash.body_sha256',
            'header_hash': 'hash.header_sha256',
        }
        if sort_by in sort_field_map:
            sort = [{sort_field_map[sort_by]: {"order": order, "missing": "_last"}}]

        from_ = per_page * (page - 1)
        results, total = self.store.search(query, sort=sort, from_=from_, size=per_page)
        total_pages = (total + per_page - 1) // per_page
        return results, total_pages, total
