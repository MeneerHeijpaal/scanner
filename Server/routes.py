"""
Flask route handlers for the Scanner web application.

This module contains all HTTP route handlers including:
- Main search interface
- API endpoints for searching and downloading
- Detail pages for URLs, IPs, and hashes
- Label management endpoints
- Health check endpoint
"""

from flask import render_template, request, session, send_file, send_from_directory, abort, make_response
from pymongo import ASCENDING
import base64
import json
import io
import logging
import re

logger = logging.getLogger(__name__)


def register_routes(app, collection, config, utils):
    """Register all application routes with the Flask app.

    Args:
        app: Flask application instance
        collection: MongoDB collection object
        config: Configuration dictionary from config.yml
        utils: Utility functions module containing validation and query building functions

    Examples:
        app = Flask(__name__)
        register_routes(app, db_collection, config_dict, utils_module)

    Returns None.
    """

    @app.route('/favicon.ico')
    def favicon():
        """Serve favicon from static folder.

        Examples:
            GET /favicon.ico -> returns favicon.ico file

        Returns static file response with favicon icon.
        """
        return send_from_directory(app.static_folder, 'favicon.ico', mimetype='image/vnd.microsoft.icon')


    @app.route('/', methods=['GET'])
    def index():
        """Main search page with live counter and filter interface.

        Displays the primary search interface with:
        - Total URL count
        - Filter sections for IP, URL, technologies, labels, status codes
        - Live updating counter based on filter selections

        Examples:
            GET / -> renders index.html with total URL count

        Returns rendered HTML template.
        """
        try:
            # Get total count of all URLs in database
            total_urls = collection.count_documents({})

            # Get all available labels for the filter
            all_labels = utils.get_all_labels()

            # Get all available technologies for the filter
            all_technologies = utils.get_all_technologies()

            return render_template('index.html',
                                 total_urls=total_urls,
                                 all_labels=all_labels,
                                 all_technologies=all_technologies)

        except Exception as e:
            logger.error(f"Error in index route: {e}")
            return render_template('index.html',
                                 total_urls=0,
                                 all_labels=[],
                                 all_technologies=[],
                                 error='An error occurred loading the page.')


    @app.route('/api/count', methods=['POST'])
    def api_count():
        """API endpoint to get count of URLs matching search criteria.

        Accepts JSON payload with search filters:
        - ip: IP address, CIDR, or wildcard pattern
        - url: URL substring to search
        - technologies: Array of technology names
        - include_labels: Array of labels to include
        - status_codes: Array of HTTP status codes

        Examples:
            POST /api/count with {"ip": "192.168.1.1"} -> {"count": 5}
            POST /api/count with {"status_codes": ["200", "301"]} -> {"count": 1234}

        Returns JSON with count and optional error message.
        """
        try:
            data = request.get_json()

            # Extract and sanitize parameters
            ip_query = utils.sanitize_string_input(data.get('ip', ''))
            url_query = utils.sanitize_string_input(data.get('url', ''))
            body_search = utils.sanitize_string_input(data.get('body_search', ''), max_length=config['validation']['max_body_search_length'])
            body_hash_query = utils.sanitize_string_input(data.get('body_hash', ''), max_length=128)
            header_hash_query = utils.sanitize_string_input(data.get('header_hash', ''), max_length=128)
            include_labels = data.get('include_labels', [])
            exclude_labels = data.get('exclude_labels', [])
            protocol_filter = data.get('protocol_filter', 'both')
            tech_filters = data.get('technologies', [])
            status_codes = data.get('status_codes', [])

            # Validate hash formats
            if body_hash_query and not re.match(r'^[a-fA-F0-9]+$', body_hash_query):
                body_hash_query = ""
            if header_hash_query and not re.match(r'^[a-fA-F0-9]+$', header_hash_query):
                header_hash_query = ""

            # Validate protocol filter
            if protocol_filter not in ['https', 'http', 'both']:
                protocol_filter = 'both'

            # Build query
            query, error = utils.build_search_query(
                ip_query=ip_query,
                url_query=url_query,
                body_search=body_search,
                body_hash_query=body_hash_query,
                header_hash_query=header_hash_query,
                include_labels=include_labels,
                exclude_labels=exclude_labels,
                protocol_filter=protocol_filter,
                tech_filters=tech_filters,
                status_codes=status_codes
            )

            # Get count
            count = collection.count_documents(query)

            return json.dumps({'count': count, 'error': error})

        except Exception as e:
            logger.error(f"Error in /api/count: {e}")
            return json.dumps({'count': 0, 'error': str(e)}), 500


    @app.route('/api/urls', methods=['POST'])
    def api_urls():
        """API endpoint to get paginated list of URLs matching search criteria.

        Accepts JSON payload with search filters and pagination parameters:
        - Search filters (same as /api/count)
        - page: Page number (default 1)
        - per_page: Results per page (default 100, max 1000)

        Examples:
            POST /api/urls with {"page": 1, "per_page": 50} -> {"urls": [...], "total_pages": 10}
            POST /api/urls with {"ip": "10.0.0.1", "page": 2} -> {"urls": [...], "total_pages": 3}

        Returns JSON with URLs array, pagination info, and optional error message.
        """
        try:
            data = request.get_json()

            # Extract and sanitize parameters
            ip_query = utils.sanitize_string_input(data.get('ip', ''))
            url_query = utils.sanitize_string_input(data.get('url', ''))
            body_search = utils.sanitize_string_input(data.get('body_search', ''), max_length=config['validation']['max_body_search_length'])
            body_hash_query = utils.sanitize_string_input(data.get('body_hash', ''), max_length=128)
            header_hash_query = utils.sanitize_string_input(data.get('header_hash', ''), max_length=128)
            include_labels = data.get('include_labels', [])
            exclude_labels = data.get('exclude_labels', [])
            protocol_filter = data.get('protocol_filter', 'both')
            tech_filters = data.get('technologies', [])
            status_codes = data.get('status_codes', [])

            # Pagination parameters
            page = utils.validate_integer(data.get('page', 1), min_val=1, default=1)
            per_page = utils.validate_integer(data.get('per_page', 100), min_val=1, max_val=1000, default=100)

            # Validate hash formats
            if body_hash_query and not re.match(r'^[a-fA-F0-9]+$', body_hash_query):
                body_hash_query = ""
            if header_hash_query and not re.match(r'^[a-fA-F0-9]+$', header_hash_query):
                header_hash_query = ""

            # Validate protocol filter
            if protocol_filter not in ['https', 'http', 'both']:
                protocol_filter = 'both'

            # Build query
            query, error = utils.build_search_query(
                ip_query=ip_query,
                url_query=url_query,
                body_search=body_search,
                body_hash_query=body_hash_query,
                header_hash_query=header_hash_query,
                include_labels=include_labels,
                exclude_labels=exclude_labels,
                protocol_filter=protocol_filter,
                tech_filters=tech_filters,
                status_codes=status_codes
            )

            # Get total count
            total_count = collection.count_documents(query)

            # Get paginated results - only fetch url, ip, and status_code fields
            skip = (page - 1) * per_page
            cursor = collection.find(query, {'url': 1, 'ip': 1, 'host': 1, 'status_code': 1, '_id': 1}).skip(skip).limit(per_page)

            urls = []
            for doc in cursor:
                urls.append({
                    'id': str(doc.get('_id')),
                    'url': doc.get('url', ''),
                    'ip': doc.get('ip') or doc.get('host', ''),
                    'status_code': doc.get('status_code', '')
                })

            total_pages = (total_count + per_page - 1) // per_page

            return json.dumps({
                'urls': urls,
                'total_count': total_count,
                'page': page,
                'per_page': per_page,
                'total_pages': total_pages,
                'error': error
            })

        except Exception as e:
            logger.error(f"Error in /api/urls: {e}")
            return json.dumps({'urls': [], 'total_count': 0, 'error': str(e)}), 500


    @app.route('/api/download-urls', methods=['POST'])
    def api_download_urls():
        """API endpoint to download all URLs matching search criteria as text file.

        Accepts JSON payload with search filters and download options:
        - Search filters (same as /api/count)
        - domains_only: Boolean, if true extracts only domains (default false)

        Examples:
            POST /api/download-urls with {"ip": "10.0.0.1"} -> urls.txt file download
            POST /api/download-urls with {"domains_only": true} -> domains.txt file download

        Returns text file download with URLs or domains (one per line).
        """
        try:
            data = request.get_json()

            # Extract and sanitize parameters
            ip_query = utils.sanitize_string_input(data.get('ip', ''))
            url_query = utils.sanitize_string_input(data.get('url', ''))
            body_search = utils.sanitize_string_input(data.get('body_search', ''), max_length=config['validation']['max_body_search_length'])
            body_hash_query = utils.sanitize_string_input(data.get('body_hash', ''), max_length=128)
            header_hash_query = utils.sanitize_string_input(data.get('header_hash', ''), max_length=128)
            include_labels = data.get('include_labels', [])
            exclude_labels = data.get('exclude_labels', [])
            protocol_filter = data.get('protocol_filter', 'both')
            tech_filters = data.get('technologies', [])
            status_codes = data.get('status_codes', [])
            domains_only = data.get('domains_only', False)

            # Validate hash formats
            if body_hash_query and not re.match(r'^[a-fA-F0-9]+$', body_hash_query):
                body_hash_query = ""
            if header_hash_query and not re.match(r'^[a-fA-F0-9]+$', header_hash_query):
                header_hash_query = ""

            # Validate protocol filter
            if protocol_filter not in ['https', 'http', 'both']:
                protocol_filter = 'both'

            # Build query
            query, error = utils.build_search_query(
                ip_query=ip_query,
                url_query=url_query,
                body_search=body_search,
                body_hash_query=body_hash_query,
                header_hash_query=header_hash_query,
                include_labels=include_labels,
                exclude_labels=exclude_labels,
                protocol_filter=protocol_filter,
                tech_filters=tech_filters,
                status_codes=status_codes
            )

            # Get all URLs (no pagination limit for download)
            cursor = collection.find(query, {'url': 1, '_id': 0})

            # Extract URLs or domains
            if domains_only:
                # Extract unique domains
                domains = set()
                for doc in cursor:
                    url = doc.get('url', '')
                    if url:
                        try:
                            # Parse URL to extract domain
                            from urllib.parse import urlparse
                            parsed = urlparse(url)
                            domain = parsed.netloc or parsed.path.split('/')[0]
                            if domain:
                                domains.add(domain)
                        except Exception:
                            continue

                # Create text content with one domain per line
                content = '\n'.join(sorted(domains))
                filename = 'domains.txt'
            else:
                # Extract all URLs
                urls = [doc.get('url', '') for doc in cursor if doc.get('url')]
                content = '\n'.join(urls)
                filename = 'urls.txt'

            # Create response with text file
            response = make_response(content)
            response.headers['Content-Type'] = 'text/plain'
            response.headers['Content-Disposition'] = f'attachment; filename={filename}'

            return response

        except Exception as e:
            logger.error(f"Error in /api/download-urls: {e}")
            return json.dumps({'error': str(e)}), 500


    @app.route('/download_urls')
    def download_urls():
        """Download all URLs matching current search query from session as text file.

        Uses search parameters stored in session to build query.
        Legacy endpoint for backwards compatibility.

        Examples:
            GET /download_urls -> urls.txt file download

        Returns text file download with URLs (one per line, sorted and deduplicated).
        """
        try:
            # Get search parameters from session
            filters = session.get('search_filters', {})
            ip_query = filters.get('ip', '')
            url_query = filters.get('url', '')
            body_hash_query = filters.get('body_hash', '')
            header_hash_query = filters.get('header_hash', '')
            include_labels = filters.get('include_labels', [])
            exclude_labels = filters.get('exclude_labels', [])
            protocol_filter = filters.get('protocol_filter', 'https')

            # Validate hash formats if provided
            if body_hash_query and not re.match(r'^[a-fA-F0-9]+$', body_hash_query):
                body_hash_query = ""
            if header_hash_query and not re.match(r'^[a-fA-F0-9]+$', header_hash_query):
                header_hash_query = ""

            # Build the same query as index route
            query_parts = []
            max_cidr_hosts = config['validation']['max_cidr_hosts']

            if ip_query and '/' in ip_query:
                hosts, cidr_err = utils.expand_cidr_hosts(ip_query, max_hosts=max_cidr_hosts)
                if hosts is None and cidr_err == 'invalid':
                    query_parts.append({'$or': [
                        {'ip': {'$regex': ip_query, '$options': 'i'}},
                        {'host': {'$regex': ip_query, '$options': 'i'}}
                    ]})
                else:
                    if hosts:
                        query_parts.append({'$or': [
                            {'ip': {'$in': hosts}},
                            {'host': {'$in': hosts}}
                        ]})
                    else:
                        query_parts.append({'$or': [ {'ip': None}, {'host': None} ]})
            elif ip_query:
                query_parts.append({'$or': [
                    {'ip': {'$regex': ip_query, '$options': 'i'}},
                    {'host': {'$regex': ip_query, '$options': 'i'}}
                ]})

            if url_query:
                escaped_url = utils.escape_regex_special_chars(url_query)
                query_parts.append({'$or': [
                    {'url': {'$regex': escaped_url, '$options': 'i'}},
                    {'header.location': {'$regex': escaped_url, '$options': 'i'}},
                    {'header.Location': {'$regex': escaped_url, '$options': 'i'}}
                ]})

            if body_hash_query:
                query_parts.append({'hash.body_sha256': body_hash_query})

            if header_hash_query:
                query_parts.append({'hash.header_sha256': header_hash_query})

            # Add protocol filter
            if protocol_filter == 'https':
                query_parts.append({'url': {'$regex': '^https://', '$options': 'i'}})
            elif protocol_filter == 'http':
                query_parts.append({'url': {'$regex': '^http://', '$options': 'i'}})

            # Add label filtering
            if include_labels:
                # Get all hashes with the included labels
                included_hashes = set()
                for label in include_labels:
                    hashes = utils.get_hashes_by_label(utils.sanitize_string_input(label))
                    included_hashes.update(hashes)
                if included_hashes:
                    query_parts.append({'$or': [
                        {'hash.body_sha256': {'$in': list(included_hashes)}},
                        {'hash.header_sha256': {'$in': list(included_hashes)}}
                    ]})

            if exclude_labels:
                # Get all hashes with the excluded labels
                excluded_hashes = set()
                for label in exclude_labels:
                    hashes = utils.get_hashes_by_label(utils.sanitize_string_input(label))
                    excluded_hashes.update(hashes)
                if excluded_hashes:
                    query_parts.append({'$nor': [
                        {'hash.body_sha256': {'$in': list(excluded_hashes)}},
                        {'hash.header_sha256': {'$in': list(excluded_hashes)}}
                    ]})

            # Combine all query parts
            if len(query_parts) > 1:
                query = {'$and': query_parts}
            elif len(query_parts) == 1:
                query = query_parts[0]
            else:
                query = {}

            # Fetch ALL matching URLs (no pagination)
            cursor = collection.find(query, {'url': 1, '_id': 0}).sort('url', ASCENDING)

            # Extract URLs and deduplicate
            urls = []
            seen_urls = set()
            for doc in cursor:
                url = doc.get('url', '')
                if url and url not in seen_urls:
                    urls.append(url)
                    seen_urls.add(url)

            # Create response with URLs as plain text
            response_text = '\n'.join(urls)

            response = make_response(response_text)
            response.headers['Content-Type'] = 'text/plain'
            response.headers['Content-Disposition'] = 'attachment; filename=urls.txt'

            logger.info(f"Downloaded {len(urls)} unique URLs")
            return response

        except Exception as e:
            logger.error(f"Error in download_urls route: {e}")
            abort(500, description='An error occurred while generating the download')


    @app.route('/set_label', methods=['POST'])
    def set_label():
        """Set or update a label for a hash value.

        Accepts form data:
        - hash: SHA256 hash value (required)
        - label: Label text to assign (required)
        - hash_type: 'body' or 'header' (default 'body')

        Examples:
            POST /set_label with {hash: "abc123", label: "WordPress"} -> {"success": true}
            POST /set_label with {hash: "def456", label: "Admin", hash_type: "header"} -> {"success": true}

        Returns JSON with success status and error message if failed.
        """
        try:
            hash_value = utils.sanitize_string_input(request.form.get('hash', ''), max_length=128)
            label = utils.sanitize_string_input(request.form.get('label', ''), max_length=100)
            hash_type = utils.sanitize_string_input(request.form.get('hash_type', 'body'))

            if not hash_value or not label:
                return json.dumps({'success': False, 'error': 'Hash and label are required'}), 400

            if not re.match(r'^[a-fA-F0-9]+$', hash_value):
                return json.dumps({'success': False, 'error': 'Invalid hash format'}), 400

            success = utils.set_hash_label(hash_value, label, hash_type)
            if success:
                logger.info(f"Set label '{label}' for hash {hash_value[:16]}...")
                return json.dumps({'success': True, 'label': label})
            else:
                return json.dumps({'success': False, 'error': 'Failed to set label'}), 500

        except Exception as e:
            logger.error(f"Error in set_label route: {e}")
            return json.dumps({'success': False, 'error': str(e)}), 500


    @app.route('/delete_label', methods=['POST'])
    def delete_label():
        """Delete a label for a hash value.

        Accepts form data:
        - hash: SHA256 hash value (required)

        Examples:
            POST /delete_label with {hash: "abc123"} -> {"success": true}
            POST /delete_label with {hash: "invalid"} -> {"success": false, "error": "Label not found"}

        Returns JSON with success status and error message if failed.
        """
        try:
            hash_value = utils.sanitize_string_input(request.form.get('hash', ''), max_length=128)

            if not hash_value:
                return json.dumps({'success': False, 'error': 'Hash is required'}), 400

            if not re.match(r'^[a-fA-F0-9]+$', hash_value):
                return json.dumps({'success': False, 'error': 'Invalid hash format'}), 400

            success = utils.delete_hash_label(hash_value)
            if success:
                logger.info(f"Deleted label for hash {hash_value[:16]}...")
                return json.dumps({'success': True})
            else:
                return json.dumps({'success': False, 'error': 'Label not found'}), 404

        except Exception as e:
            logger.error(f"Error in delete_label route: {e}")
            return json.dumps({'success': False, 'error': str(e)}), 500


    @app.route('/details/<id>')
    def details(id):
        """Show detailed information for a specific scan result by document ID.

        Displays complete scan information including:
        - URL, IP, status code, headers
        - Decoded body, raw headers, request
        - Hash values and labels
        - Redirect locations for 3xx responses

        Examples:
            GET /details/507f1f77bcf86cd799439011 -> renders url_details.html
            GET /details/invalid_id -> 400 error

        Returns rendered HTML template or error response.
        """
        try:
            # Validate ObjectId
            obj_id = utils.validate_objectid(id)
            if not obj_id:
                logger.warning(f"Invalid ObjectId in details route: {id}")
                abort(400, description='Invalid document ID')

            item = collection.find_one({'_id': obj_id})
            if not item:
                logger.info(f"Document not found: {id}")
                abort(404, description='Item not found')

            # Decode base64 fields
            decoded_item = utils.decode_base64_fields(item)

            # Preserve caller's search parameters
            ip_query = utils.sanitize_string_input(request.args.get('ip', ''))
            url_query = utils.sanitize_string_input(request.args.get('url', ''))
            body_hash_query = utils.sanitize_string_input(request.args.get('body_hash', ''), max_length=128)
            header_hash_query = utils.sanitize_string_input(request.args.get('header_hash', ''), max_length=128)
            page_num = utils.validate_integer(request.args.get('page', 1), min_val=1, default=1)

            # Compute how many documents share the same body/header hashes
            body_count = 0
            header_count = 0
            body_label = None
            header_label = None
            try:
                h = decoded_item.get('hash', {})
                body_hash = h.get('body_sha256')
                header_hash = h.get('header_sha256')
                if body_hash:
                    body_count = collection.count_documents({'hash.body_sha256': body_hash})
                    body_label = utils.get_hash_label(body_hash)
                if header_hash:
                    header_count = collection.count_documents({'hash.header_sha256': header_hash})
                    header_label = utils.get_hash_label(header_hash)
            except Exception as e:
                logger.warning(f"Failed to count hash duplicates: {e}")
                body_count = header_count = 0

            # Extract redirect location for 3xx status codes
            redirect_location = None
            status_code = decoded_item.get('status_code')
            if status_code and 300 <= status_code < 400 and decoded_item.get('header'):
                header = decoded_item.get('header', {})
                if isinstance(header, dict):
                    redirect_location = header.get('location') or header.get('Location')

            # Count how many URLs are hosted on the same IP
            ip_count = 0
            ip_address = decoded_item.get('host') or decoded_item.get('ip')
            if ip_address:
                try:
                    ip_count = collection.count_documents({'$or': [{'ip': ip_address}, {'host': ip_address}]})
                except Exception as e:
                    logger.warning(f"Failed to count URLs on IP {ip_address}: {e}")
                    ip_count = 0

            return render_template('url_details.html', item=decoded_item, body_count=body_count,
                                 header_count=header_count, ip_query=ip_query,
                                 url_query=url_query, body_hash_query=body_hash_query,
                                 header_hash_query=header_hash_query, page=page_num,
                                 body_label=body_label, header_label=header_label,
                                 redirect_location=redirect_location, ip_count=ip_count)
        except Exception as e:
            logger.error(f"Error in details route: {e}")
            abort(500, description='An error occurred retrieving the details')


    @app.route('/ip/<path:ip>')
    def ip_hosts(ip):
        """Show all URLs hosted on a specific IP address or hostname.

        Displays table with:
        - All URLs found on the IP/host
        - Status codes and redirect locations
        - Body and header hashes with labels
        - Hash duplicate counts

        Examples:
            GET /ip/192.168.1.1 -> renders ip_details.html with all URLs on that IP
            GET /ip/example.com -> renders ip_details.html with all URLs on that host

        Returns rendered HTML template.
        """
        try:
            # Sanitize IP input
            ip = utils.sanitize_string_input(ip)

            cursor = collection.find({'$or': [{'ip': ip}, {'host': ip}]}, {'url': 1, 'hash': 1, 'status_code': 1, 'header': 1})
            hosts = list(cursor)

            # Normalize ids and ensure url field exists
            for h in hosts:
                if '_id' in h:
                    h['_id'] = str(h['_id'])
                if 'url' not in h:
                    h['url'] = h.get('host') or ''

                # Extract redirect location for 3xx status codes
                status_code = h.get('status_code')
                if status_code and 300 <= status_code < 400 and h.get('header'):
                    header = h.get('header', {})
                    if isinstance(header, dict):
                        h['redirect_location'] = header.get('location') or header.get('Location')
                    else:
                        h['redirect_location'] = None
                else:
                    h['redirect_location'] = None

                # Compute counts for body/header hash duplicates and add labels
                try:
                    hh = h.get('hash', {})
                    bh = hh.get('body_sha256')
                    hhv = hh.get('header_sha256')
                    h['body_count'] = collection.count_documents({'hash.body_sha256': bh}) if bh else 0
                    h['header_count'] = collection.count_documents({'hash.header_sha256': hhv}) if hhv else 0
                    # Add labels
                    h['body_label'] = utils.get_hash_label(bh) if bh else None
                    h['header_label'] = utils.get_hash_label(hhv) if hhv else None
                except Exception as e:
                    logger.debug(f"Failed to count hash duplicates for host: {e}")
                    h['body_count'] = 0
                    h['header_count'] = 0

            # Preserve search parameters from the original search
            ip_query = utils.sanitize_string_input(request.args.get('ip', ''))
            url_query = utils.sanitize_string_input(request.args.get('url', ''))
            body_hash_query = utils.sanitize_string_input(request.args.get('body_hash', ''), max_length=128)
            header_hash_query = utils.sanitize_string_input(request.args.get('header_hash', ''), max_length=128)
            page_num = utils.validate_integer(request.args.get('page', 1), min_val=1, default=1)

            all_labels = utils.get_all_labels()
            return render_template('ip_details.html', ip=ip, hosts=hosts,
                                 ip_query=ip_query, url_query=url_query,
                                 body_hash_query=body_hash_query, header_hash_query=header_hash_query,
                                 page=page_num, all_labels=all_labels)
        except Exception as e:
            logger.error(f"Error in ip_hosts route: {e}")
            return render_template('ip_details.html', ip=ip, hosts=[])


    @app.route('/hash/<hash_type>/<hash_value>')
    def hash_details(hash_type, hash_value):
        """Show all URLs that share a specific body or header hash.

        Displays table with all documents matching the hash:
        - URL, IP address
        - Body and header hashes with labels
        - Links to individual detail pages

        Examples:
            GET /hash/body/abc123def456... -> all URLs with matching body hash
            GET /hash/header/789ghi012jkl... -> all URLs with matching header hash
            GET /hash/invalid/xyz -> 400 error

        Returns rendered HTML template or error response.
        """
        try:
            # Validate hash type
            hash_type = utils.validate_hash_type(hash_type)
            if not hash_type:
                abort(400, description='Invalid hash type. Must be "body" or "header"')

            # Sanitize hash value (should be hex string)
            hash_value = utils.sanitize_string_input(hash_value, max_length=128)
            if not re.match(r'^[a-fA-F0-9]+$', hash_value):
                logger.warning(f"Invalid hash format: {hash_value}")
                abort(400, description='Invalid hash format')

            field_map = {
                'body': 'hash.body_sha256',
                'header': 'hash.header_sha256'
            }
            field = field_map[hash_type]

            cursor = collection.find({field: hash_value}, {'url': 1, 'hash': 1, 'ip': 1, 'host': 1})
            docs = list(cursor)

            for d in docs:
                if '_id' in d:
                    d['_id'] = str(d['_id'])
                if 'url' not in d:
                    d['url'] = d.get('host') or ''
                # Add labels for body and header hashes
                if d.get('hash'):
                    body_hash = d['hash'].get('body_sha256')
                    header_hash = d['hash'].get('header_sha256')
                    d['body_label'] = utils.get_hash_label(body_hash) if body_hash else None
                    d['header_label'] = utils.get_hash_label(header_hash) if header_hash else None

            # Preserve optional search params
            ip_query = utils.sanitize_string_input(request.args.get('ip', ''))
            url_query = utils.sanitize_string_input(request.args.get('url', ''))
            body_hash_query = utils.sanitize_string_input(request.args.get('body_hash', ''), max_length=128)
            header_hash_query = utils.sanitize_string_input(request.args.get('header_hash', ''), max_length=128)
            page_num = utils.validate_integer(request.args.get('page', 1), min_val=1, default=1)

            all_labels = utils.get_all_labels()
            return render_template('hash_details.html', docs=docs, hash_type=hash_type,
                                 hash_value=hash_value, ip_query=ip_query,
                                 url_query=url_query, body_hash_query=body_hash_query,
                                 header_hash_query=header_hash_query, page=page_num,
                                 all_labels=all_labels)
        except Exception as e:
            logger.error(f"Error in hash_details route: {e}")
            abort(500, description='An error occurred retrieving hash details')


    @app.route('/details/<id>/download/<dtype>')
    def download_raw(id, dtype):
        """Download raw data fields from a scan result.

        Supports downloading:
        - json: Full document as JSON
        - raw_header: Base64-decoded HTTP headers
        - request: Base64-decoded HTTP request

        Examples:
            GET /details/507f1f77bcf86cd799439011/download/json -> document.json download
            GET /details/507f1f77bcf86cd799439011/download/raw_header -> raw-header.txt download
            GET /details/507f1f77bcf86cd799439011/download/request -> raw-request.txt download

        Returns file download response or error.
        """
        try:
            # Validate ObjectId
            obj_id = utils.validate_objectid(id)
            if not obj_id:
                logger.warning(f"Invalid ObjectId in download route: {id}")
                abort(400, description='Invalid document ID')

            # Validate download type
            allowed_types = {'json', 'raw_header', 'request'}
            if dtype not in allowed_types:
                logger.warning(f"Invalid download type: {dtype}")
                abort(400, description='Invalid download type')

            item = collection.find_one({'_id': obj_id})
            if not item:
                logger.info(f"Document not found for download: {id}")
                abort(404, description='Item not found')

            # Full raw JSON
            if dtype == 'json':
                data = json.dumps(item, default=str, indent=2)
                buf = io.BytesIO()
                buf.write(data.encode('utf-8'))
                buf.seek(0)
                filename = f"{id}-document.json"
                return send_file(buf, as_attachment=True, download_name=filename, mimetype='application/json')

            # Raw header
            if dtype == 'raw_header':
                raw = item.get('raw_header')
                if not raw:
                    abort(404, description='raw_header not available')
                try:
                    payload = base64.b64decode(raw)
                    buf = io.BytesIO(payload)
                    buf.seek(0)
                    filename = f"{id}-raw-header.txt"
                    return send_file(buf, as_attachment=True, download_name=filename, mimetype='text/plain')
                except Exception as e:
                    logger.warning(f"Failed to decode raw_header: {e}")
                    buf = io.BytesIO(str(raw).encode('utf-8'))
                    buf.seek(0)
                    filename = f"{id}-raw-header.bin"
                    return send_file(buf, as_attachment=True, download_name=filename, mimetype='application/octet-stream')

            # Raw request
            if dtype == 'request':
                raw = item.get('request')
                if not raw:
                    abort(404, description='request not available')
                try:
                    payload = base64.b64decode(raw)
                    buf = io.BytesIO(payload)
                    buf.seek(0)
                    filename = f"{id}-raw-request.txt"
                    return send_file(buf, as_attachment=True, download_name=filename, mimetype='text/plain')
                except Exception as e:
                    logger.warning(f"Failed to decode request: {e}")
                    buf = io.BytesIO(str(raw).encode('utf-8'))
                    buf.seek(0)
                    filename = f"{id}-raw-request.bin"
                    return send_file(buf, as_attachment=True, download_name=filename, mimetype='application/octet-stream')

        except Exception as e:
            logger.error(f"Error in download_raw route: {e}")
            abort(500, description='An error occurred during download')


    @app.route('/health')
    def health():
        """Health check endpoint for monitoring application and database status.

        Tests MongoDB connectivity and returns status.

        Examples:
            GET /health -> {"status": "healthy", "database": "connected"}
            GET /health (when DB down) -> {"status": "unhealthy", "database": "disconnected"}

        Returns JSON with status (200 if healthy, 503 if unhealthy).
        """
        try:
            # Test MongoDB connection
            from pymongo import MongoClient
            mongo_uri = config['mongodb']['uri']
            client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
            client.admin.command('ping')
            return {'status': 'healthy', 'database': 'connected'}, 200
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {'status': 'unhealthy', 'database': 'disconnected', 'error': str(e)}, 503
