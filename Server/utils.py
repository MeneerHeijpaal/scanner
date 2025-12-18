"""
Utility functions for the Scanner web application.

This module contains helper functions for:
- Input validation and sanitization
- Base64 decoding
- Hash label management (SQLite operations)
- MongoDB query building
- IP/CIDR expansion
- Pagination
"""

import base64
import ipaddress
import logging
import re
import sqlite3
from bson.objectid import ObjectId
from bson.errors import InvalidId
from pathlib import Path

logger = logging.getLogger(__name__)


class ScannerUtils:
    """Utility class containing helper functions for Scanner web application.

    This class encapsulates all utility functions and maintains references
    to configuration and database connections.
    """

    def __init__(self, config, collection, sqlite_db_path, es_manager=None):
        """Initialize ScannerUtils with configuration and database connections.

        Args:
            config: Configuration dictionary from config.yml
            collection: MongoDB collection object
            sqlite_db_path: Path to SQLite labels database
            es_manager: ElasticsearchManager instance (optional)

        Examples:
            utils = ScannerUtils(config_dict, mongo_collection, Path("labels/labels.db"))
            utils = ScannerUtils(config_dict, mongo_collection, Path("labels/labels.db"), es_manager)

        Returns ScannerUtils instance.
        """
        self.config = config
        self.collection = collection
        self.sqlite_db = sqlite_db_path
        self.es_manager = es_manager
        self.max_query_length = config['validation']['max_query_length']
        self.max_cidr_hosts = config['validation']['max_cidr_hosts']
        self.allowed_hash_types = set(config['validation']['allowed_hash_types'])


    # Input validation functions

    def sanitize_string_input(self, value, max_length=None):
        """Sanitize and validate string input to prevent injection attacks.

        Removes control characters, strips whitespace, and limits length.

        Args:
            value: Input string to sanitize
            max_length: Maximum allowed length (uses config default if None)

        Examples:
            "  hello  " -> "hello"
            "test\x00data" -> "testdata"
            "a" * 1000 -> truncated to max_length

        Returns sanitized string or empty string if input is invalid.
        """
        if not value:
            return ""

        if max_length is None:
            max_length = self.max_query_length

        # Convert to string and strip whitespace
        value = str(value).strip()

        # Limit length
        if len(value) > max_length:
            logger.warning(f"Input exceeds max length ({max_length}): truncating")
            value = value[:max_length]

        # Remove null bytes and other control characters
        value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', value)

        return value


    def escape_regex_special_chars(self, value):
        """Escape special regex characters for literal string matching.

        Args:
            value: String containing potential regex special characters

        Examples:
            "test.com" -> "test\\.com"
            "192.168.1.1" -> "192\\.168\\.1\\.1"
            "" -> ""

        Returns escaped string safe for use in regex patterns.
        """
        if not value:
            return ""
        # Escape all regex special characters
        return re.escape(value)


    def validate_objectid(self, id_string):
        """Validate and convert string to MongoDB ObjectId.

        Args:
            id_string: String representation of MongoDB ObjectId

        Examples:
            "507f1f77bcf86cd799439011" -> ObjectId("507f1f77bcf86cd799439011")
            "invalid" -> None
            "" -> None

        Returns ObjectId instance or None if invalid.
        """
        try:
            return ObjectId(id_string)
        except (InvalidId, TypeError, ValueError):
            logger.warning(f"Invalid ObjectId: {id_string}")
            return None


    def validate_integer(self, value, min_val=1, max_val=None, default=1):
        """Validate and sanitize integer input with bounds checking.

        Args:
            value: Value to convert to integer
            min_val: Minimum allowed value (default 1)
            max_val: Maximum allowed value (default None = no limit)
            default: Default value if conversion fails (default 1)

        Examples:
            "42" -> 42
            "-5" with min_val=1 -> 1
            "9999" with max_val=100 -> 100
            "invalid" -> default (1)

        Returns validated integer within bounds or default value.
        """
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
        """Validate hash type parameter is 'body' or 'header'.

        Args:
            hash_type: String to validate as hash type

        Examples:
            "body" -> "body"
            "header" -> "header"
            "invalid" -> None

        Returns validated hash type string or None if invalid.
        """
        if hash_type not in self.allowed_hash_types:
            logger.warning(f"Invalid hash type: {hash_type}")
            return None
        return hash_type


    # Base64 decoding function

    def decode_base64_fields(self, item):
        """Decode base64-encoded fields in a MongoDB document.

        Decodes body, raw_header, and request fields from base64 to UTF-8 strings.
        Converts ObjectId to string for JSON serialization.
        Adds {field}_decoded keys with decoded content.

        Args:
            item: MongoDB document dictionary

        Examples:
            {"body": "SGVsbG8="} -> {"body": "SGVsbG8=", "body_decoded": "Hello"}
            {"_id": ObjectId("...")} -> {"_id": "507f1f77bcf86cd799439011"}

        Returns document dictionary with decoded fields added.
        """
        base64_fields = ['body', 'raw_header', 'request']
        decoded_item = dict(item)

        # Convert ObjectId to string for JSON serialization
        if '_id' in decoded_item:
            decoded_item['_id'] = str(decoded_item['_id'])

        for field in base64_fields:
            if field in decoded_item and decoded_item[field]:
                try:
                    decoded_item[f'{field}_decoded'] = base64.b64decode(decoded_item[field]).decode('utf-8', errors='replace')
                except Exception as e:
                    decoded_item[f'{field}_decoded'] = f'Error decoding {field}: {str(e)}'

        return decoded_item


    # SQLite label management functions

    def get_labels_db_connection(self):
        """Get a connection to the SQLite labels database.

        Creates a connection with row_factory set to sqlite3.Row for dict-like access.

        Examples:
            conn = get_labels_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM hash_labels")

        Returns sqlite3.Connection object.
        """
        conn = sqlite3.connect(self.sqlite_db)
        conn.row_factory = sqlite3.Row
        return conn


    def get_hash_label(self, hash_value):
        """Get label for a specific hash value from SQLite database.

        Args:
            hash_value: SHA256 hash string

        Examples:
            "abc123def456..." -> "WordPress"
            "nonexistent" -> None

        Returns label string or None if not found.
        """
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
        """Get all unique label names from SQLite database, sorted alphabetically.

        Examples:
            get_all_labels() -> ["Admin", "Login", "WordPress"]
            get_all_labels() -> [] (if no labels exist)

        Returns list of label strings.
        """
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
        """Get all hash values associated with a specific label.

        Args:
            label: Label name to search for

        Examples:
            "WordPress" -> ["abc123...", "def456..."]
            "NonExistent" -> []

        Returns list of hash strings.
        """
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
        """Set or update a label for a hash value in SQLite database.

        Uses INSERT OR REPLACE to update existing labels.

        Args:
            hash_value: SHA256 hash string
            label: Label text to assign
            hash_type: 'body' or 'header' (default 'body')

        Examples:
            ("abc123", "WordPress", "body") -> True
            ("", "label", "body") -> False (empty hash)

        Returns True if successful, False otherwise.
        """
        sanitized_label = self.sanitize_string_input(label, max_length=100)
        if not sanitized_label:
            return False
        try:
            conn = self.get_labels_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                'INSERT OR REPLACE INTO hash_labels (hash, label, hash_type, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)',
                (hash_value, sanitized_label, hash_type)
            )
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"Error setting label for hash {hash_value}: {e}")
            return False


    def delete_hash_label(self, hash_value):
        """Delete a label for a hash value from SQLite database.

        Args:
            hash_value: SHA256 hash string to remove label from

        Examples:
            "abc123def456..." -> True (if label existed)
            "nonexistent" -> False (no label to delete)

        Returns True if label was deleted, False if not found or error.
        """
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


    # IP and CIDR functions

    def expand_wildcard_ip(self, ip_pattern):
        """Expand IP pattern with x wildcards to regex pattern.

        Supports wildcard notation using 'x' for any octet (0-255).
        Maximum 2 wildcards allowed (equivalent to /16 CIDR).

        Args:
            ip_pattern: IP pattern string with 'x' wildcards

        Examples:
            "12.34.56.x" -> regex pattern matching 12.34.56.0-255
            "12.34.x.78" -> regex pattern matching 12.34.0-255.78
            "12.x.x.x" -> None (too many wildcards)
            "12.34.56.999" -> None (invalid octet)

        Returns regex pattern string or None if invalid.
        """
        ip_pattern = ip_pattern.strip().lower()

        # Split by dots
        octets = ip_pattern.split('.')
        if len(octets) != 4:
            return None

        # Count x wildcards
        wildcard_count = sum(1 for octet in octets if octet == 'x')

        # Validate max /16 (2 wildcards maximum)
        if wildcard_count > 2:
            return None

        # Build regex pattern
        regex_parts = []
        for octet in octets:
            if octet == 'x':
                # Match any number 0-255
                regex_parts.append(r'(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])')
            else:
                # Validate it's a valid number
                try:
                    num = int(octet)
                    if num < 0 or num > 255:
                        return None
                    regex_parts.append(str(num))
                except ValueError:
                    return None

        return r'^' + r'\.'.join(regex_parts) + r'$'


    def expand_cidr_hosts(self, cidr_str, max_hosts=None):
        """Expand a CIDR notation string into a list of individual host IPs.

        Args:
            cidr_str: CIDR notation string (e.g., "192.168.1.0/24")
            max_hosts: Maximum allowed hosts (uses config default if None)

        Examples:
            "192.168.1.0/30" -> (["192.168.1.0", "192.168.1.1", ...], None)
            "10.0.0.0/8" -> ([], "CIDR range too large (16777216 addresses)...")
            "invalid" -> (None, "invalid")

        Returns tuple (hosts_list, error_message).
            If parsing fails: (None, 'invalid')
            If range too large: ([], error description)
            If success: (list of IP strings, None)
        """
        if max_hosts is None:
            max_hosts = self.max_cidr_hosts

        cidr_str = cidr_str.strip()
        try:
            net = ipaddress.ip_network(cidr_str, strict=False)
        except ValueError:
            return None, 'invalid'

        # For small networks, use hosts(); for /32 or /128 hosts() may be empty so fallback to list(net)
        hosts = [str(h) for h in net.hosts()]
        if not hosts:
            hosts = [str(h) for h in net]

        if len(hosts) > max_hosts:
            return [], f'CIDR range too large ({len(hosts)} addresses). Please narrow the network.'

        return hosts, None


    # MongoDB query functions

    def get_all_technologies(self):
        """Get all unique technologies from MongoDB tech array field.

        Uses aggregation pipeline to unwind tech arrays and collect unique values.

        Examples:
            get_all_technologies() -> ["Apache", "nginx", "PHP", "WordPress"]
            get_all_technologies() -> [] (if no tech data or error)

        Returns list of technology name strings, sorted alphabetically.
        """
        try:
            # Aggregate to get all unique technologies from the tech array field
            pipeline = [
                {'$unwind': '$tech'},
                {'$group': {'_id': '$tech'}},
                {'$sort': {'_id': 1}}
            ]
            result = list(self.collection.aggregate(pipeline))
            return [item['_id'] for item in result if item.get('_id')]
        except Exception as e:
            logger.error(f"Error getting technologies: {e}")
            return []


    def build_search_query(self, ip_query='', url_query='', body_search='', body_hash_query='', header_hash_query='',
                           include_labels=None, exclude_labels=None, protocol_filter='both',
                           tech_filters=None, status_codes=None):
        """Build MongoDB query dictionary from search parameters.

        Constructs complex MongoDB query supporting:
        - IP exact match, CIDR ranges, wildcard patterns
        - URL substring matching
        - Body text search (full-text search in decoded bodies)
        - Hash filtering (body and header)
        - Label-based filtering (include/exclude)
        - Protocol filtering (http/https/both)
        - Technology filtering
        - HTTP status code filtering

        Args:
            ip_query: IP address, CIDR range, or wildcard pattern
            url_query: URL substring to search
            body_search: Text to search in decoded response bodies
            body_hash_query: Body SHA256 hash
            header_hash_query: Header SHA256 hash
            include_labels: List of labels to include (OR logic)
            exclude_labels: List of labels to exclude (AND logic)
            protocol_filter: 'https', 'http', or 'both'
            tech_filters: List of technologies to filter by
            status_codes: List of HTTP status codes to filter by

        Examples:
            (ip_query="192.168.1.1") -> ({"$or": [{"ip": "192.168.1.1"}, ...]}, None)
            (ip_query="10.0.0.0/28") -> ({"$or": [{"ip": {"$in": [...]}}...]}, None)
            (status_codes=["200", "301"]) -> ({"status_code": {"$in": [200, 301]}}, None)

        Returns tuple (query_dict, error_message).
            query_dict: MongoDB query dictionary
            error_message: String error or None if no errors
        """
        query_parts = []
        error = None

        # Build query: support plain IP, CIDR, or wildcard (x notation) for the ip field
        if ip_query:
            if '/' in ip_query:
                # CIDR notation
                hosts, cidr_err = self.expand_cidr_hosts(ip_query)
                if hosts is None and cidr_err == 'invalid':
                    # invalid CIDR string — fall back to regex search
                    query_parts.append({'$or': [
                        {'ip': {'$regex': ip_query, '$options': 'i'}},
                        {'host': {'$regex': ip_query, '$options': 'i'}}
                    ]})
                else:
                    if cidr_err and hosts == []:
                        error = cidr_err

                    if hosts:
                        query_parts.append({'$or': [
                            {'ip': {'$in': hosts}},
                            {'host': {'$in': hosts}}
                        ]})
                    else:
                        # empty hosts due to size cap — match nothing
                        query_parts.append({'$or': [{'ip': None}, {'host': None}]})
            elif 'x' in ip_query.lower():
                # Wildcard notation (e.g., 12.34.56.x or 12.x.56.78)
                regex_pattern = self.expand_wildcard_ip(ip_query)
                if regex_pattern:
                    query_parts.append({'$or': [
                        {'ip': {'$regex': regex_pattern}},
                        {'host': {'$regex': regex_pattern}}
                    ]})
                else:
                    error = 'Invalid IP wildcard pattern. Use "x" for wildcards (max 2, e.g., 12.34.x.x)'
            else:
                # Exact IP or partial string match
                # Check if it looks like an exact IP
                octets = ip_query.split('.')
                if len(octets) == 4 and all(o.isdigit() and 0 <= int(o) <= 255 for o in octets):
                    # Exact IP match
                    query_parts.append({'$or': [
                        {'ip': ip_query},
                        {'host': ip_query}
                    ]})
                else:
                    # Partial string search (for backwards compatibility)
                    query_parts.append({'$or': [
                        {'ip': {'$regex': f'^{re.escape(ip_query)}', '$options': 'i'}},
                        {'host': {'$regex': f'^{re.escape(ip_query)}', '$options': 'i'}}
                    ]})

        # Add URL query
        if url_query:
            escaped_url = self.escape_regex_special_chars(url_query)
            query_parts.append({'$or': [
                {'url': {'$regex': escaped_url, '$options': 'i'}},
                {'header.location': {'$regex': escaped_url, '$options': 'i'}},
                {'header.Location': {'$regex': escaped_url, '$options': 'i'}}
            ]})

        # Add body search query
        # Use Elasticsearch if available for fast search, otherwise fall back to MongoDB regex
        if body_search:
            # Try Elasticsearch first (much faster)
            if self.es_manager and self.es_manager.is_connected:
                try:
                    # Get document IDs from Elasticsearch
                    doc_ids = self.es_manager.search_body(body_search)
                    if doc_ids:
                        # Convert string IDs to ObjectId
                        object_ids = []
                        for doc_id in doc_ids:
                            try:
                                object_ids.append(ObjectId(doc_id))
                            except InvalidId:
                                logger.warning(f"Invalid ObjectId from Elasticsearch: {doc_id}")
                                continue

                        if object_ids:
                            # Add filter to match these document IDs
                            query_parts.append({'_id': {'$in': object_ids}})
                            logger.info(f"Using Elasticsearch: found {len(object_ids)} matches for body search")
                        else:
                            # No valid IDs, return empty result
                            query_parts.append({'_id': None})
                    else:
                        # No results from Elasticsearch, return empty result
                        query_parts.append({'_id': None})
                except Exception as e:
                    logger.warning(f"Elasticsearch search failed, falling back to MongoDB regex: {e}")
                    # Fall back to MongoDB regex
                    escaped_body = self.escape_regex_special_chars(body_search)
                    query_parts.append({'body_decoded': {'$regex': escaped_body, '$options': 'i'}})
            else:
                # Elasticsearch not available, use MongoDB regex
                logger.debug("Using MongoDB regex for body search (Elasticsearch not available)")
                escaped_body = self.escape_regex_special_chars(body_search)
                query_parts.append({'body_decoded': {'$regex': escaped_body, '$options': 'i'}})

        # Add body hash query
        if body_hash_query:
            query_parts.append({'hash.body_sha256': body_hash_query})

        # Add header hash query
        if header_hash_query:
            query_parts.append({'hash.header_sha256': header_hash_query})

        # Add protocol filter
        if protocol_filter == 'https':
            query_parts.append({'url': {'$regex': '^https://', '$options': 'i'}})
        elif protocol_filter == 'http':
            query_parts.append({'url': {'$regex': '^http://', '$options': 'i'}})

        # Add technology filters
        if tech_filters and len(tech_filters) > 0:
            query_parts.append({'tech': {'$in': tech_filters}})

        # Add status code filters
        if status_codes and len(status_codes) > 0:
            # Convert to integers
            status_code_ints = []
            for code in status_codes:
                try:
                    status_code_ints.append(int(code))
                except (ValueError, TypeError):
                    continue
            if status_code_ints:
                query_parts.append({'status_code': {'$in': status_code_ints}})

        # Add label filtering
        if include_labels:
            included_hashes = set()
            for label in include_labels:
                hashes = self.get_hashes_by_label(self.sanitize_string_input(label))
                included_hashes.update(hashes)
            if included_hashes:
                query_parts.append({'$or': [
                    {'hash.body_sha256': {'$in': list(included_hashes)}},
                    {'hash.header_sha256': {'$in': list(included_hashes)}}
                ]})

        if exclude_labels:
            excluded_hashes = set()
            for label in exclude_labels:
                hashes = self.get_hashes_by_label(self.sanitize_string_input(label))
                excluded_hashes.update(hashes)
            if excluded_hashes:
                query_parts.append({'$and': [
                    {'hash.body_sha256': {'$nin': list(excluded_hashes)}},
                    {'hash.header_sha256': {'$nin': list(excluded_hashes)}}
                ]})

        # Combine all query parts
        if len(query_parts) > 1:
            query = {'$and': query_parts}
        elif len(query_parts) == 1:
            query = query_parts[0]
        else:
            query = {}

        return query, error


    # Pagination function

    def get_paginated_results(self, query, page, per_page=50, sort_by='', sort_order='asc'):
        """Get paginated results from MongoDB with optional sorting.

        Handles special case for IP sorting (numeric sorting done in Python).
        For other fields, uses MongoDB server-side sorting.

        Args:
            query: MongoDB query dictionary
            page: Page number (1-indexed)
            per_page: Results per page (default 50)
            sort_by: Field to sort by ('ip', 'url', 'body_hash', 'header_hash', or '')
            sort_order: 'asc' or 'desc' (default 'asc')

        Examples:
            ({"ip": "10.0.0.1"}, 1, 50, "url", "asc") -> ([{...}, ...], 5, 237)
            ({}, 2, 100, "ip", "desc") -> ([{...}, ...], 10, 952)

        Returns tuple (results_list, total_pages, total_count).
        """
        total = self.collection.count_documents(query)
        total_pages = (total + per_page - 1) // per_page

        # Special handling for IP sorting (needs to be done in Python for proper numeric sorting)
        if sort_by == 'ip':
            # Fetch all results for IP sorting (we need to sort before pagination)
            all_results = list(self.collection.find(query))

            # Sort by IP address numerically
            def ip_sort_key(doc):
                ip_str = doc.get('ip') or doc.get('host') or ''
                try:
                    return ipaddress.ip_address(ip_str)
                except ValueError:
                    # If not a valid IP, sort it to the end
                    return ipaddress.ip_address('255.255.255.255') if sort_order == 'asc' else ipaddress.ip_address('0.0.0.0')

            all_results.sort(key=ip_sort_key, reverse=(sort_order == 'desc'))

            # Apply pagination manually
            skips = per_page * (page - 1)
            results = all_results[skips:skips + per_page]
        else:
            # For other fields, use MongoDB sorting
            from pymongo import ASCENDING
            skips = per_page * (page - 1)
            cursor = self.collection.find(query)

            # Apply sorting if specified
            if sort_by:
                # Map sort_by values to actual database fields
                sort_field_map = {
                    'url': 'url',
                    'body_hash': 'hash.body_sha256',
                    'header_hash': 'hash.header_sha256'
                }
                db_field = sort_field_map.get(sort_by)
                if db_field:
                    direction = ASCENDING if sort_order == 'asc' else -1  # -1 is DESCENDING
                    cursor = cursor.sort(db_field, direction)

            cursor = cursor.skip(skips).limit(per_page)
            results = list(cursor)

        return results, total_pages, total
