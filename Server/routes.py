"""
Flask route handlers for the Scanner web application.

This module contains all HTTP route handlers including:
- Main search interface
- API endpoints for searching and downloading
- Detail pages for URLs, IPs, and hashes
- Label management endpoints
- Health check endpoint

All record reads go through the Elasticsearch store (``store``); MongoDB is no
longer used at runtime.
"""

from flask import render_template, request, session, send_file, send_from_directory, abort, make_response
import base64
import json
import io
import logging
import re

logger = logging.getLogger(__name__)

MATCH_ALL = {"match_all": {}}
# Upper bound on rows returned for the per-IP / per-hash detail tables.
DETAIL_MAX_ROWS = 2000


def register_routes(app, store, config, utils):
    """Register all application routes with the Flask app.

    Args:
        app: Flask application instance
        store: ElasticsearchManager instance (primary data store)
        config: Configuration dictionary from config.yml
        utils: ScannerUtils instance
    """

    def _extract_filters(data):
        """Extract, sanitize, and validate common search filters from a payload."""
        ip_query = utils.sanitize_string_input(data.get('ip', ''))
        url_query = utils.sanitize_string_input(data.get('url', ''))
        body_search = utils.sanitize_string_input(
            data.get('body_search', ''),
            max_length=config['validation']['max_body_search_length'])
        body_hash_query = utils.sanitize_string_input(data.get('body_hash', ''), max_length=128)
        header_hash_query = utils.sanitize_string_input(data.get('header_hash', ''), max_length=128)
        include_labels = data.get('include_labels', [])
        exclude_labels = data.get('exclude_labels', [])
        protocol_filter = data.get('protocol_filter', 'both')
        tech_filters = data.get('technologies', [])
        status_codes = data.get('status_codes', [])

        if body_hash_query and not re.match(r'^[a-fA-F0-9]+$', body_hash_query):
            body_hash_query = ""
        if header_hash_query and not re.match(r'^[a-fA-F0-9]+$', header_hash_query):
            header_hash_query = ""
        if protocol_filter not in ['https', 'http', 'both']:
            protocol_filter = 'both'

        return utils.build_search_query(
            ip_query=ip_query, url_query=url_query, body_search=body_search,
            body_hash_query=body_hash_query, header_hash_query=header_hash_query,
            include_labels=include_labels, exclude_labels=exclude_labels,
            protocol_filter=protocol_filter, tech_filters=tech_filters,
            status_codes=status_codes)

    @app.route('/favicon.ico')
    def favicon():
        """Serve favicon from the static folder."""
        return send_from_directory(app.static_folder, 'favicon.ico',
                                   mimetype='image/vnd.microsoft.icon')

    @app.route('/', methods=['GET'])
    def index():
        """Main search page with live counter and filter interface."""
        try:
            total_urls = store.count(MATCH_ALL)
            all_labels = utils.get_all_labels()
            all_technologies = utils.get_all_technologies()
            return render_template('index.html', total_urls=total_urls,
                                   all_labels=all_labels, all_technologies=all_technologies)
        except Exception as e:
            logger.error(f"Error in index route: {e}")
            return render_template('index.html', total_urls=0, all_labels=[],
                                   all_technologies=[], error='An error occurred loading the page.')

    @app.route('/api/count', methods=['POST'])
    def api_count():
        """Return the count of records matching the search criteria."""
        try:
            data = request.get_json()
            query, error = _extract_filters(data)
            count = store.count(query)
            return json.dumps({'count': count, 'error': error})
        except Exception as e:
            logger.error(f"Error in /api/count: {e}")
            return json.dumps({'count': 0, 'error': str(e)}), 500

    @app.route('/api/urls', methods=['POST'])
    def api_urls():
        """Return a paginated list of records matching the search criteria."""
        try:
            data = request.get_json()
            query, error = _extract_filters(data)

            page = utils.validate_integer(data.get('page', 1), min_val=1, default=1)
            per_page = utils.validate_integer(data.get('per_page', 100), min_val=1,
                                              max_val=1000, default=100)
            skip = (page - 1) * per_page

            hits, total_count = store.search(
                query, source=['url', 'ip', 'host', 'status_code'],
                from_=skip, size=per_page)

            urls = []
            for doc in hits:
                urls.append({
                    'id': doc.get('_id'),
                    'url': doc.get('url', ''),
                    'ip': doc.get('ip') or doc.get('host', ''),
                    'status_code': doc.get('status_code', ''),
                })

            total_pages = (total_count + per_page - 1) // per_page
            return json.dumps({
                'urls': urls, 'total_count': total_count, 'page': page,
                'per_page': per_page, 'total_pages': total_pages, 'error': error,
            })
        except Exception as e:
            logger.error(f"Error in /api/urls: {e}")
            return json.dumps({'urls': [], 'total_count': 0, 'error': str(e)}), 500

    @app.route('/api/download-urls', methods=['POST'])
    def api_download_urls():
        """Download all URLs (or unique domains) matching the search criteria."""
        try:
            data = request.get_json()
            query, error = _extract_filters(data)
            domains_only = data.get('domains_only', False)

            cursor = store.scan(query, source=['url'])
            if domains_only:
                from urllib.parse import urlparse
                domains = set()
                for doc in cursor:
                    url = doc.get('url', '')
                    if not url:
                        continue
                    try:
                        parsed = urlparse(url)
                        domain = parsed.netloc or parsed.path.split('/')[0]
                        if domain:
                            domains.add(domain)
                    except Exception:
                        continue
                content = '\n'.join(sorted(domains))
                filename = 'domains.txt'
            else:
                urls = [doc.get('url', '') for doc in cursor if doc.get('url')]
                content = '\n'.join(urls)
                filename = 'urls.txt'

            response = make_response(content)
            response.headers['Content-Type'] = 'text/plain'
            response.headers['Content-Disposition'] = f'attachment; filename={filename}'
            return response
        except Exception as e:
            logger.error(f"Error in /api/download-urls: {e}")
            return json.dumps({'error': str(e)}), 500

    @app.route('/download_urls')
    def download_urls():
        """Download all URLs matching the search filters stored in the session."""
        try:
            filters = session.get('search_filters', {})
            query, _ = utils.build_search_query(
                ip_query=utils.sanitize_string_input(filters.get('ip', '')),
                url_query=utils.sanitize_string_input(filters.get('url', '')),
                body_hash_query=utils.sanitize_string_input(filters.get('body_hash', ''), max_length=128),
                header_hash_query=utils.sanitize_string_input(filters.get('header_hash', ''), max_length=128),
                include_labels=filters.get('include_labels', []),
                exclude_labels=filters.get('exclude_labels', []),
                protocol_filter=filters.get('protocol_filter', 'both'))

            urls = []
            seen = set()
            for doc in store.scan(query, source=['url'], sort=[{"url": {"order": "asc"}}]):
                url = doc.get('url', '')
                if url and url not in seen:
                    urls.append(url)
                    seen.add(url)

            response = make_response('\n'.join(urls))
            response.headers['Content-Type'] = 'text/plain'
            response.headers['Content-Disposition'] = 'attachment; filename=urls.txt'
            logger.info(f"Downloaded {len(urls)} unique URLs")
            return response
        except Exception as e:
            logger.error(f"Error in download_urls route: {e}")
            abort(500, description='An error occurred while generating the download')

    @app.route('/set_label', methods=['POST'])
    def set_label():
        """Set or update a label for a hash value."""
        try:
            hash_value = utils.sanitize_string_input(request.form.get('hash', ''), max_length=128)
            label = utils.sanitize_string_input(request.form.get('label', ''), max_length=100)
            hash_type = utils.sanitize_string_input(request.form.get('hash_type', 'body'))

            if not hash_value or not label:
                return json.dumps({'success': False, 'error': 'Hash and label are required'}), 400
            if not re.match(r'^[a-fA-F0-9]+$', hash_value):
                return json.dumps({'success': False, 'error': 'Invalid hash format'}), 400

            if utils.set_hash_label(hash_value, label, hash_type):
                logger.info(f"Set label '{label}' for hash {hash_value[:16]}...")
                return json.dumps({'success': True, 'label': label})
            return json.dumps({'success': False, 'error': 'Failed to set label'}), 500
        except Exception as e:
            logger.error(f"Error in set_label route: {e}")
            return json.dumps({'success': False, 'error': str(e)}), 500

    @app.route('/delete_label', methods=['POST'])
    def delete_label():
        """Delete a label for a hash value."""
        try:
            hash_value = utils.sanitize_string_input(request.form.get('hash', ''), max_length=128)
            if not hash_value:
                return json.dumps({'success': False, 'error': 'Hash is required'}), 400
            if not re.match(r'^[a-fA-F0-9]+$', hash_value):
                return json.dumps({'success': False, 'error': 'Invalid hash format'}), 400

            if utils.delete_hash_label(hash_value):
                logger.info(f"Deleted label for hash {hash_value[:16]}...")
                return json.dumps({'success': True})
            return json.dumps({'success': False, 'error': 'Label not found'}), 404
        except Exception as e:
            logger.error(f"Error in delete_label route: {e}")
            return json.dumps({'success': False, 'error': str(e)}), 500

    @app.route('/details/<id>')
    def details(id):
        """Show detailed information for a single record by document id."""
        try:
            doc_id = utils.validate_doc_id(id)
            if not doc_id:
                logger.warning(f"Invalid document id in details route: {id}")
                abort(400, description='Invalid document ID')

            item = store.get(doc_id)
            if not item:
                logger.info(f"Document not found: {id}")
                abort(404, description='Item not found')

            decoded_item = utils.decode_base64_fields(item)

            ip_query = utils.sanitize_string_input(request.args.get('ip', ''))
            url_query = utils.sanitize_string_input(request.args.get('url', ''))
            body_hash_query = utils.sanitize_string_input(request.args.get('body_hash', ''), max_length=128)
            header_hash_query = utils.sanitize_string_input(request.args.get('header_hash', ''), max_length=128)
            page_num = utils.validate_integer(request.args.get('page', 1), min_val=1, default=1)

            body_count = header_count = 0
            body_label = header_label = None
            try:
                h = decoded_item.get('hash', {}) or {}
                body_hash = h.get('body_sha256')
                header_hash = h.get('header_sha256')
                if body_hash:
                    body_count = store.count({"term": {"hash.body_sha256": body_hash}})
                    body_label = utils.get_hash_label(body_hash)
                if header_hash:
                    header_count = store.count({"term": {"hash.header_sha256": header_hash}})
                    header_label = utils.get_hash_label(header_hash)
            except Exception as e:
                logger.warning(f"Failed to count hash duplicates: {e}")

            redirect_location = None
            status_code = decoded_item.get('status_code')
            if status_code and 300 <= status_code < 400 and decoded_item.get('header'):
                header = decoded_item.get('header', {})
                if isinstance(header, dict):
                    redirect_location = header.get('location') or header.get('Location')

            ip_count = 0
            ip_address = decoded_item.get('host') or decoded_item.get('ip')
            if ip_address:
                try:
                    ip_count = store.count({"bool": {"should": [
                        {"term": {"ip": ip_address}},
                        {"term": {"host": ip_address}},
                    ], "minimum_should_match": 1}})
                except Exception as e:
                    logger.warning(f"Failed to count URLs on IP {ip_address}: {e}")

            return render_template('url_details.html', item=decoded_item, body_count=body_count,
                                   header_count=header_count, ip_query=ip_query, url_query=url_query,
                                   body_hash_query=body_hash_query, header_hash_query=header_hash_query,
                                   page=page_num, body_label=body_label, header_label=header_label,
                                   redirect_location=redirect_location, ip_count=ip_count)
        except Exception as e:
            logger.error(f"Error in details route: {e}")
            abort(500, description='An error occurred retrieving the details')

    @app.route('/ip/<path:ip>')
    def ip_hosts(ip):
        """Show all URLs hosted on a specific IP address or hostname."""
        try:
            ip = utils.sanitize_string_input(ip)
            query = {"bool": {"should": [
                {"term": {"ip": ip}},
                {"term": {"host": ip}},
            ], "minimum_should_match": 1}}
            hosts, _ = store.search(
                query, source=['url', 'hash', 'status_code', 'header', 'host', 'ip'],
                size=DETAIL_MAX_ROWS)

            for h in hosts:
                h['_id'] = str(h.get('_id', ''))
                if 'url' not in h:
                    h['url'] = h.get('host') or ''
                status_code = h.get('status_code')
                if status_code and 300 <= status_code < 400 and isinstance(h.get('header'), dict):
                    h['redirect_location'] = h['header'].get('location') or h['header'].get('Location')
                else:
                    h['redirect_location'] = None
                try:
                    hh = h.get('hash', {}) or {}
                    bh = hh.get('body_sha256')
                    hhv = hh.get('header_sha256')
                    h['body_count'] = store.count({"term": {"hash.body_sha256": bh}}) if bh else 0
                    h['header_count'] = store.count({"term": {"hash.header_sha256": hhv}}) if hhv else 0
                    h['body_label'] = utils.get_hash_label(bh) if bh else None
                    h['header_label'] = utils.get_hash_label(hhv) if hhv else None
                except Exception as e:
                    logger.debug(f"Failed to count hash duplicates for host: {e}")
                    h['body_count'] = 0
                    h['header_count'] = 0

            ip_query = utils.sanitize_string_input(request.args.get('ip', ''))
            url_query = utils.sanitize_string_input(request.args.get('url', ''))
            body_hash_query = utils.sanitize_string_input(request.args.get('body_hash', ''), max_length=128)
            header_hash_query = utils.sanitize_string_input(request.args.get('header_hash', ''), max_length=128)
            page_num = utils.validate_integer(request.args.get('page', 1), min_val=1, default=1)

            all_labels = utils.get_all_labels()
            return render_template('ip_details.html', ip=ip, hosts=hosts, ip_query=ip_query,
                                   url_query=url_query, body_hash_query=body_hash_query,
                                   header_hash_query=header_hash_query, page=page_num,
                                   all_labels=all_labels)
        except Exception as e:
            logger.error(f"Error in ip_hosts route: {e}")
            return render_template('ip_details.html', ip=ip, hosts=[])

    @app.route('/hash/<hash_type>/<hash_value>')
    def hash_details(hash_type, hash_value):
        """Show all URLs that share a specific body or header hash."""
        try:
            hash_type = utils.validate_hash_type(hash_type)
            if not hash_type:
                abort(400, description='Invalid hash type. Must be "body" or "header"')

            hash_value = utils.sanitize_string_input(hash_value, max_length=128)
            if not re.match(r'^[a-fA-F0-9]+$', hash_value):
                logger.warning(f"Invalid hash format: {hash_value}")
                abort(400, description='Invalid hash format')

            field = {'body': 'hash.body_sha256', 'header': 'hash.header_sha256'}[hash_type]
            docs, _ = store.search(
                {"term": {field: hash_value}},
                source=['url', 'hash', 'ip', 'host'], size=DETAIL_MAX_ROWS)

            for d in docs:
                d['_id'] = str(d.get('_id', ''))
                if 'url' not in d:
                    d['url'] = d.get('host') or ''
                if d.get('hash'):
                    body_hash = d['hash'].get('body_sha256')
                    header_hash = d['hash'].get('header_sha256')
                    d['body_label'] = utils.get_hash_label(body_hash) if body_hash else None
                    d['header_label'] = utils.get_hash_label(header_hash) if header_hash else None

            ip_query = utils.sanitize_string_input(request.args.get('ip', ''))
            url_query = utils.sanitize_string_input(request.args.get('url', ''))
            body_hash_query = utils.sanitize_string_input(request.args.get('body_hash', ''), max_length=128)
            header_hash_query = utils.sanitize_string_input(request.args.get('header_hash', ''), max_length=128)
            page_num = utils.validate_integer(request.args.get('page', 1), min_val=1, default=1)

            all_labels = utils.get_all_labels()
            return render_template('hash_details.html', docs=docs, hash_type=hash_type,
                                   hash_value=hash_value, ip_query=ip_query, url_query=url_query,
                                   body_hash_query=body_hash_query, header_hash_query=header_hash_query,
                                   page=page_num, all_labels=all_labels)
        except Exception as e:
            logger.error(f"Error in hash_details route: {e}")
            abort(500, description='An error occurred retrieving hash details')

    @app.route('/details/<id>/download/<dtype>')
    def download_raw(id, dtype):
        """Download raw data fields (json/raw_header/request) from a record."""
        try:
            doc_id = utils.validate_doc_id(id)
            if not doc_id:
                logger.warning(f"Invalid document id in download route: {id}")
                abort(400, description='Invalid document ID')

            allowed_types = {'json', 'raw_header', 'request'}
            if dtype not in allowed_types:
                logger.warning(f"Invalid download type: {dtype}")
                abort(400, description='Invalid download type')

            item = store.get(doc_id)
            if not item:
                logger.info(f"Document not found for download: {id}")
                abort(404, description='Item not found')

            if dtype == 'json':
                data = json.dumps(item, default=str, indent=2)
                buf = io.BytesIO(data.encode('utf-8'))
                buf.seek(0)
                return send_file(buf, as_attachment=True, download_name=f"{id}-document.json",
                                 mimetype='application/json')

            field = 'raw_header' if dtype == 'raw_header' else 'request'
            raw = item.get(field)
            if not raw:
                abort(404, description=f'{field} not available')
            try:
                buf = io.BytesIO(base64.b64decode(raw))
                buf.seek(0)
                return send_file(buf, as_attachment=True,
                                 download_name=f"{id}-{field.replace('_', '-')}.txt",
                                 mimetype='text/plain')
            except Exception as e:
                logger.warning(f"Failed to decode {field}: {e}")
                buf = io.BytesIO(str(raw).encode('utf-8'))
                buf.seek(0)
                return send_file(buf, as_attachment=True,
                                 download_name=f"{id}-{field.replace('_', '-')}.bin",
                                 mimetype='application/octet-stream')
        except Exception as e:
            logger.error(f"Error in download_raw route: {e}")
            abort(500, description='An error occurred during download')

    @app.route('/health')
    def health():
        """Health check endpoint: reports Elasticsearch connectivity."""
        try:
            if store.ping():
                return {'status': 'healthy', 'database': 'connected'}, 200
            return {'status': 'unhealthy', 'database': 'disconnected'}, 503
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {'status': 'unhealthy', 'database': 'disconnected', 'error': str(e)}, 503
