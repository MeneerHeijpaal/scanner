-- Schema for hash labels SQLite database
-- This database stores labels for body and header hashes independently from MongoDB
-- Making it portable across different MongoDB databases

CREATE TABLE IF NOT EXISTS hash_labels (
    hash TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    hash_type TEXT NOT NULL CHECK(hash_type IN ('body', 'header')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index for fast label lookups
CREATE INDEX IF NOT EXISTS idx_label ON hash_labels(label);

-- Index for efficient label+hash lookups
CREATE INDEX IF NOT EXISTS idx_label_hash ON hash_labels(label, hash);

-- Index for hash_type queries
CREATE INDEX IF NOT EXISTS idx_hash_type ON hash_labels(hash_type);
