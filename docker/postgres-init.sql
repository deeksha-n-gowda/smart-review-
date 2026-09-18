-- docker/postgres-init.sql
-- ===========================
-- Run once on first container startup to set up the PostgreSQL database.
-- PostgreSQL's docker-entrypoint-initdb.d mechanism runs this automatically.

-- Ensure the database exists (idempotent)
SELECT 'CREATE DATABASE code_review_db'
WHERE NOT EXISTS (
    SELECT FROM pg_database WHERE datname = 'code_review_db'
)\gexec

-- Grant all privileges to the codelens user
GRANT ALL PRIVILEGES ON DATABASE code_review_db TO codelens;

-- Enable the pg_trgm extension for fast text search (optional but useful)
\c code_review_db
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
