#!/usr/bin/env python3
"""
Initialize the SQLite labels database with the schema.
This script can be run standalone to create an empty labels database.

Usage:
    python init_database.py
"""

import sqlite3
import sys
from pathlib import Path

LABELS_DIR = Path(__file__).parent
SQLITE_DB = LABELS_DIR / 'labels.db'
SCHEMA_FILE = LABELS_DIR / 'schema.sql'


def init_database():
    """Initialize the SQLite database with schema."""
    print("=" * 60)
    print("Initializing SQLite Labels Database")
    print("=" * 60)
    print()

    # Check if database already exists
    if SQLITE_DB.exists():
        response = input(f"Database already exists at {SQLITE_DB}. Recreate? (y/N): ")
        if response.lower() != 'y':
            print("Initialization cancelled")
            return False
        print("Removing existing database...")
        SQLITE_DB.unlink()

    # Check if schema file exists
    if not SCHEMA_FILE.exists():
        print(f"❌ Schema file not found at {SCHEMA_FILE}")
        return False

    print(f"✓ Schema file found at {SCHEMA_FILE}")

    # Read schema
    with open(SCHEMA_FILE, 'r') as f:
        schema_sql = f.read()

    # Create database
    print(f"Creating database at {SQLITE_DB}...")
    conn = sqlite3.connect(SQLITE_DB)
    cursor = conn.cursor()
    cursor.executescript(schema_sql)
    conn.commit()
    conn.close()

    print("✓ Database created successfully")
    print()
    print("=" * 60)
    print(f"Database ready at: {SQLITE_DB}")
    print("=" * 60)
    return True


if __name__ == '__main__':
    success = init_database()
    sys.exit(0 if success else 1)
