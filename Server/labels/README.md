# Hash Labels Database

This directory contains the portable SQLite database for storing hash labels.

## Overview

Hash labels are stored separately from the MongoDB database to make them **portable** across different MongoDB instances. This allows you to:
- Use the same labels with different MongoDB databases
- Backup and restore labels independently
- Share labels across different scanning projects
- Version control your labels

## Files

- **`labels.db`** - SQLite database file containing all hash labels (auto-created on first run)
- **`schema.sql`** - Database schema definition
- **`README.md`** - This file

**Note:** The database is automatically initialized by the Flask server (via `server.py`) on startup if it doesn't exist. No separate initialization script is needed.

## Database Schema

The `hash_labels` table contains:
- `hash` (TEXT, PRIMARY KEY) - The SHA256 hash value
- `label` (TEXT, NOT NULL) - The label name
- `hash_type` (TEXT, NOT NULL) - Either 'body' or 'header'
- `created_at` (TIMESTAMP) - When the label was first created
- `updated_at` (TIMESTAMP) - When the label was last updated

## Database Initialization

The database is **automatically initialized** when the Flask server starts (via the `init_labels_database()` function in `server.py`).

The server will:
1. Check if `labels.db` exists
2. If not, create the directory structure
3. Read the schema from `schema.sql`
4. Create the database with the schema
5. Log the initialization to the console

No manual initialization is required - just start the server!

## Backup and Restore

### Backup
Simply copy the `labels.db` file:
```bash
cp labels.db labels.db.backup
```

### Restore
Replace the current database with your backup:
```bash
cp labels.db.backup labels.db
```

## Portability

To use your labels with a different MongoDB database:

1. Keep the `labels/` folder with your `labels.db` file
2. Update MongoDB connection settings in `Server/config.yml` or via environment variables
   - `MONGO_URI` for connection string
   - `DB_NAME` for database name
   - `COLLECTION_NAME` for collection name
3. Restart the Flask application

Your labels will work with the new MongoDB database immediately!

## Manual Database Access

You can query the labels database directly using SQLite:

```bash
sqlite3 labels.db
```

Example queries:
```sql
-- Show all labels
SELECT DISTINCT label FROM hash_labels ORDER BY label;

-- Count labels
SELECT COUNT(*) FROM hash_labels;

-- Find all hashes with a specific label
SELECT * FROM hash_labels WHERE label = 'malware';

-- Show recent labels
SELECT * FROM hash_labels ORDER BY created_at DESC LIMIT 10;
```

## Integration with Flask Application

The labels system is fully integrated into the refactored Flask application:

### Configuration
Labels database location is defined in `Server/config.yml`:
```yaml
paths:
  labels_dir: "labels"
  sqlite_db: "labels.db"
  schema_file: "schema.sql"
```

### Initialization
The `server.py` file automatically initializes the labels database on startup:
```python
# From server.py
labels_dir = Path(__file__).parent / config['paths']['labels_dir']
sqlite_db = labels_dir / config['paths']['sqlite_db']
schema_file = labels_dir / config['paths']['schema_file']
init_labels_database(labels_dir, sqlite_db, schema_file)
```

### Utility Functions
All label operations are handled by the `ScannerUtils` class in `Server/utils.py`:

- `get_hash_label(hash_value)` - Retrieve label for a hash
- `get_all_labels()` - Get all unique labels (sorted alphabetically)
- `get_hashes_by_label(label)` - Find all hashes with a specific label
- `set_hash_label(hash_value, label, hash_type)` - Set/update a label
- `delete_hash_label(hash_value)` - Remove a label

### Route Handlers
Label management routes are defined in `Server/routes.py`:

- `POST /set_label` - Set or update a label for a hash
- `POST /delete_label` - Delete a label for a hash

### Web Interface
Labels are displayed and managed throughout the web interface:

1. **Main Search Page**: Filter by labels using the label checkboxes
2. **Detail Pages**: View and edit labels for body and header hashes
3. **IP View**: See labels for all URLs on a specific IP
4. **Hash View**: See labels for all URLs sharing the same hash
5. **Selected Display**: Blue badges show selected labels in filter interface

## Troubleshooting

### Database not created
- Ensure `schema.sql` exists in the labels directory
- Check file permissions on the labels directory
- Review Flask application logs for initialization messages
- Server logs will show: "Creating labels database at..." or "Using existing labels database at..."

### Labels not appearing in web interface
- Restart the Flask application
- Check `labels.db` exists and is not empty: `ls -lh Server/labels/labels.db`
- Verify SQLite file permissions (should be readable/writable by Flask app)
- Check browser console for JavaScript errors
- Verify the label was saved: `sqlite3 Server/labels/labels.db "SELECT * FROM hash_labels;"`
