# Scanner - HTTP Reconnaissance Tool

A powerful web-based HTTP reconnaissance tool that combines httpx scanning with an intuitive Flask interface for analyzing scan results. Features fast body content search powered by Elasticsearch and comprehensive filtering capabilities.

## Features

- **Standalone**: Just clone this repository and follow the setup (no files in ~/, /etc, /opt.. etc)
- **Fast Body Search**: Search response body content in <1 second (Elasticsearch-powered, 30-100x faster than regex)
- **Advanced Filtering**: IP/URL patterns, CIDR notation, wildcard matching (e.g., `192.168.x.1`)
- **Technology Detection**: Filter by detected web technologies (Apache, nginx, WordPress, etc.)
- **Hash Labeling**: Tag and categorize responses using SHA256 hashes
- **HTTP Status Filtering**: Filter by response codes (200, 301, 404, etc.)
- **Export Capabilities**: Download URLs, domains, raw responses, and headers
- **Live Counter**: Real-time result count updates as you filter
- **Graceful Fallback**: Works without Elasticsearch (uses MongoDB regex, slower but functional)

## Architecture

```
Scanner/
├── Python/                      # Scanner and import scripts
│   ├── scanner.py               # httpx scanner wrapper
│   ├── import_httpx.py          # Import scan results to MongoDB
│   └── migrate_to_elasticsearch.py  # Index existing data in Elasticsearch
├── Server/                      # Flask web application
│   ├── server.py                # Main application entry point
│   ├── config.yml               # Configuration file
│   ├── routes.py                # HTTP route handlers
│   ├── utils.py                 # Utility functions
│   ├── elasticsearch_manager.py # Elasticsearch integration
│   ├── templates/               # HTML templates
│   ├── static/                  # CSS and static assets
│   └── labels/                  # SQLite labels database (Some hashes of httpx are already in the database)
├── bin/                         # Location for the binaries
├── Database/                    # Location for the MongoDB Database
├── Elastic_Data/                # Location for the Elastic Search Database
├── httpx-config.yaml            # httpx scanner configuration
├── docker-compose.yml           # Elasticsearch Docker configuration
└── requirements.txt             # Python dependencies
```

## Prerequisites

### Required

- **Python 3.8+**
- **MongoDB 4.4+** ([Download for your platform](https://www.mongodb.com/try/download/community))
- **httpx** binary ([Download releases](https://github.com/projectdiscovery/httpx/releases))
- **Docker** (for Elasticsearch - optional but recommended)

### Optional

- **Elasticsearch 8.x** (for fast body search)

### System Requirements

**Minimum:**
- 4GB RAM
- 10GB free disk space

**Recommended for large datasets (500k+ URLs):**
- 8GB+ RAM
- 50GB+ free disk space
- SSD for database storage

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/MeneerHeijpaal/scanner.git
cd scanner
```

### 2. Install MongoDB

Download MongoDB Community Server for your platform:
- **macOS**: https://www.mongodb.com/try/download/community (select macOS)
- **Linux**: https://www.mongodb.com/try/download/community (select Linux)
- **Windows**: https://www.mongodb.com/try/download/community (select Windows)

Extract the MongoDB binaries to the `bin/` directory:

```bash
# Example for macOS (adjust version as needed)
curl -O https://fastdl.mongodb.org/osx/mongodb-macos-x86_64-7.0.4.tgz
tar -zxvf mongodb-macos-x86_64-7.0.4.tgz
cp mongodb-macos-x86_64-7.0.4/bin/{mongod,mongosh} bin/
```

### 3. Install httpx

Download httpx binary for your platform:
- **macOS/Linux/Windows**: https://github.com/projectdiscovery/httpx/releases

Place the `httpx` binary in the `bin/` directory:

```bash
# Example for macOS/Linux
wget https://github.com/projectdiscovery/httpx/releases/download/v1.3.7/httpx_1.3.7_macOS_amd64.zip
unzip httpx_1.3.7_macOS_amd64.zip
mv httpx bin/
chmod +x bin/httpx
```

### 4. Set Up Python Environment

```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
# On macOS/Linux:
source .venv/bin/activate

# On Windows:
# .venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt
```

### 5. Set Up Elasticsearch (Optional but Recommended)

Elasticsearch provides 30-100x faster body content search.

```bash
# Create data directory (if it's not already there)
mkdir -p Elastic_Data

# Give the directorty the correct rights for docker.
# The 777 setup is dangerous, but works all the time
# You may want to set the rights stricter if you like.
chmod 777 Elastic_Data

# Start Elasticsearch using Docker Compose
docker compose up -d

# Verify Elasticsearch is running
curl http://localhost:9200
```

**Without Docker Compose:**
```bash
docker run -d \
  --name elasticsearch \
  -p 9200:9200 \
  -p 9300:9300 \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  -e "ES_JAVA_OPTS=-Xms2g -Xmx2g" \
  -v $(pwd)/Elastic_Data:/usr/share/elasticsearch/data \
  docker.elastic.co/elasticsearch/elasticsearch:8.11.0
```

## Quick Start

### 1. Start MongoDB

```bash
# Create database directory (if it's not already there)
mkdir -p Database

# Start MongoDB
./bin/mongod --dbpath ./Database --bind_ip 127.0.0.1 --port 27017 --logpath ./Database/mongodb.log
```

### 2. Start Elasticsearch (Optional)

```bash
docker compose up -d
```

### 3. Run a Scan

Create a file `urls.txt` with URLs to scan (one per line):

```
example.com
https://test.com
192.168.1.1
subdomain.example.com/path
```

Run the scanner:

```bash
# Activate virtual environment if not already active
source .venv/bin/activate

# Run scan
python3 Python/scanner.py -f urls.txt -o results.json
```

### 4. Import Scan Results

```bash
python3 Python/import_httpx.py -f results.json --db urls --collection data
```

### 5. Start Web Interface

```bash
# In a new terminal, activate virtual environment
source .venv/bin/activate

# Start Flask server
python3 Server/server.py
```

### 6. Access Web Interface

Open your browser and navigate to:
```
http://127.0.0.1:8001
```

### 7. Index in Elasticsearch (First Time Only)

If you have existing data and just enabled Elasticsearch:

```bash
python3 Python/migrate_to_elasticsearch.py
```

This typically takes 30-60 minutes for 600k documents.

## Configuration

### Server Configuration

Edit `Server/config.yml` to customize:

```yaml
# Flask server settings
flask:
  host: "127.0.0.1"
  port: 8001
  debug: false

# MongoDB settings
mongodb:
  uri: "mongodb://localhost:27017/"
  database: "urls"
  collection: "data"

# Elasticsearch settings (optional)
elasticsearch:
  enabled: true
  host: "localhost"
  port: 9200
  index_name: "scanner_bodies"
  bulk_batch_size: 5000

# Validation limits
validation:
  max_query_length: 500
  max_per_page: 1000
  max_body_search_length: 1000
```

### httpx Configuration

Edit `httpx-config.yaml` to customize scanning behavior:

```yaml
# Enable technology detection
tech-detect: true

# Performance settings
threads: 80
rate-limit: 250
timeout: 10

# Request settings
follow-redirects: true
status-code: true
```

See [httpx documentation](https://github.com/projectdiscovery/httpx) for all options.

## Usage Examples

### Basic Scanning

```bash
# Scan single URL
python3 Python/scanner.py -u https://example.com -o output.json

# Scan from file
python3 Python/scanner.py -f urls.txt -o results.json

# Scan with custom httpx config
python3 Python/scanner.py -f urls.txt -o results.json -c httpx-config.yaml
```

### Importing Results

```bash
# Basic import
python3 Python/import_httpx.py -f results.json

# Custom database
python3 Python/import_httpx.py -f results.json --db mydb --collection scans

# Disable Elasticsearch indexing during import
python3 Python/import_httpx.py -f results.json --no-elasticsearch
```

### Elasticsearch Management

```bash
# Index existing MongoDB data
python3 Python/migrate_to_elasticsearch.py

# Custom batch size (for slower systems)
python3 Python/migrate_to_elasticsearch.py --batch-size 1000

# Delete and reindex
curl -X DELETE http://localhost:9200/scanner_bodies
python3 Python/migrate_to_elasticsearch.py
```

## Limits and Considerations for Large Datasets

### MongoDB Document Size Limit

MongoDB has a **16MB document size limit**. The import script automatically:
- Detects oversized documents
- Truncates large fields (body, headers) to fit
- Logs truncated documents

**Workaround**: For extremely large responses (>16MB), consider:
- Storing bodies externally (filesystem, S3)
- Increasing truncation threshold in import script

### Elasticsearch Memory Requirements

**Memory usage scales with dataset size:**

| Documents | Index Size | Recommended RAM |
|-----------|------------|-----------------|
| 100k | ~5GB | 4GB |
| 500k | ~25GB | 8GB |
| 1M+ | ~50GB+ | 16GB+ |

**Memory settings in docker-compose.yml:**
```yaml
environment:
  - "ES_JAVA_OPTS=-Xms4g -Xmx4g"  # Adjust as needed
```

### Search Performance

**Body search performance:**
- **With Elasticsearch**: 50-500ms (recommended for 100k+ documents)
- **Without Elasticsearch**: 5-15 seconds (MongoDB regex fallback)

**Other queries** (IP, URL, hash, status):
- Indexed in MongoDB: 5-50ms regardless of dataset size

### Disk Space Requirements

**Estimate for 500k URLs:**
- MongoDB: ~30GB (with bodies)
- Elasticsearch: ~25GB (body content only)
- **Total**: ~55GB

**Growth rate**: ~100KB per URL (average)

### Migration Time

**Elasticsearch indexing speed:**
- ~10,000-20,000 documents/minute
- **100k documents**: ~5-10 minutes
- **500k documents**: ~25-50 minutes
- **1M documents**: ~50-100 minutes

### Recommended Deployment for Large Datasets

**For 1M+ URLs:**

1. **Use SSD storage** for databases
2. **Increase Elasticsearch heap**: 8GB+ (`ES_JAVA_OPTS=-Xms8g -Xmx8g`)
3. **Increase MongoDB cache**: Add to `mongod` command: `--wiredTigerCacheSizeGB 4`
4. **Split imports**: Import in batches instead of one large file
5. **Monitor resources**: Use `docker stats` and `top` to monitor usage

## Troubleshooting

### MongoDB won't start

```bash
# Check if port 27017 is in use
lsof -i :27017

# Try different port
./bin/mongod --dbpath ./Database --bind_ip 127.0.0.1 --port 27018

# Update Server/config.yml with new port
```

### Elasticsearch won't start

```bash
# Check Docker logs
docker compose logs elasticsearch

# Common fix: Remove data and restart
docker compose down
sudo rm -rf Elastic_Data/*
chmod 777 Elastic_Data
docker compose up -d
```

### Elasticsearch permission errors

```bash
# Fix permissions
chmod 777 Elastic_Data
docker compose restart
```

### Search not using Elasticsearch

1. Check Elasticsearch is running: `curl http://localhost:9200`
2. Check server logs for "Elasticsearch integration enabled"
3. Verify config.yml has `elasticsearch.enabled: true`
4. Restart Flask server

### Migration fails

```bash
# Check Elasticsearch health
curl http://localhost:9200/_cluster/health?pretty

# Reduce batch size
python3 Python/migrate_to_elasticsearch.py --batch-size 1000

# Check MongoDB connection
python3 Python/migrate_to_elasticsearch.py --mongo-uri mongodb://localhost:27017
```

## Web Interface Features

### Search Filters

- **IP Address**: Exact match, CIDR ranges, wildcards (192.168.x.x)
- **URL Pattern**: Substring matching in URLs and redirect locations
- **Response Body**: Full-text phrase search (with Elasticsearch)
- **Body Hash**: SHA256 hash of response body
- **Header Hash**: SHA256 hash of response headers
- **HTTP Status Codes**: Filter by response codes
- **Technologies**: Filter by detected technologies (Apache, nginx, etc.)
- **Labels**: Include/exclude labeled responses
- **Protocol**: HTTP, HTTPS, or both

### Export Options

- **URLs**: Plain text list of URLs
- **Domains**: Unique domain list
- **Full Data**: JSON export with all fields
- **Headers Only**: Response headers export

### Label Management

- Tag responses by body or header hash
- Include/exclude labeled items in searches
- Persistent labels stored in SQLite

## Development

### Project Structure

```
Server/
├── server.py                 # Flask app initialization
├── routes.py                 # HTTP route handlers
├── utils.py                  # Utility functions (ScannerUtils class)
├── elasticsearch_manager.py  # Elasticsearch integration
├── config.yml                # Configuration
├── templates/                # Jinja2 HTML templates
│   ├── index.html            # Main search page
│   └── url_details.html      # URL details view
├── static/                   # Static assets
│   └── styles.css            # CSS styles
└── labels/                   # SQLite database
    ├── schema.sql            # Database schema
    └── labels.db             # Labels database (created at runtime)
```

### Adding New Features

1. **New search filter**:
   - Update `Server/templates/index.html` (add filter UI)
   - Update `Server/routes.py` (add parameter extraction)
   - Update `Server/utils.py` `build_search_query()` (add query logic)

2. **New export format**:
   - Add route in `Server/routes.py`
   - Add button in `Server/templates/index.html`

3. **New technology detection**:
   - Update `httpx-config.yaml` (add new patterns)
   - Re-scan URLs to detect new technologies

### Running Tests

```bash
# Test MongoDB connection
python3 -c "from pymongo import MongoClient; print(MongoClient('mongodb://localhost:27017').admin.command('ping'))"

# Test Elasticsearch connection
curl http://localhost:9200

# Test httpx
./bin/httpx -u https://example.com -json

# Test Flask server
python3 Server/server.py
# Then visit http://127.0.0.1:8001
```

## Performance Benchmarks

### Query Performance (500k documents)

| Query Type | Elasticsearch | MongoDB Only |
|------------|--------------|--------------|
| Body search | 50-500ms | 5-15 seconds |
| IP lookup | 10-50ms | 10-50ms |
| URL pattern | 10-50ms | 10-50ms |
| Hash lookup | 5-20ms | 5-20ms |
| Combined filters | 100-300ms | 200-500ms |

### Resource Usage (500k documents)

| Component | RAM | Disk | CPU |
|-----------|-----|------|-----|
| MongoDB | 1-2GB | 30GB | Low |
| Elasticsearch | 4-8GB | 25GB | Low |
| Flask | <500MB | - | Low |
| **Total** | **6-11GB** | **55GB** | **Low** |

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License - see LICENSE file for details

## Support

For issues, questions, or feature requests, please open an issue on GitHub.

## Acknowledgments

- [httpx](https://github.com/projectdiscovery/httpx) by ProjectDiscovery
- [MongoDB](https://www.mongodb.com/)
- [Elasticsearch](https://www.elastic.co/)
- [Flask](https://flask.palletsprojects.com/)

## Security Note

This tool is designed for authorized security testing and reconnaissance. Always ensure you have permission before scanning any targets. Unauthorized scanning may be illegal in your jurisdiction.
