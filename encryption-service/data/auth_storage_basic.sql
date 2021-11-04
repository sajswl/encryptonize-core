-- Auth Storage schema for CockroachDB / PostgreSQL

CREATE TABLE IF NOT EXISTS users  (
    id UUID PRIMARY KEY,
    data BYTEA NOT NULL,
    key BYTEA NOT NULL,
    deleted_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS groups  (
    id UUID PRIMARY KEY,
    data BYTEA NOT NULL,
    key BYTEA NOT NULL,
    deleted_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS access_objects  (
    id UUID PRIMARY KEY,
    data BYTEA NOT NULL,
    key BYTEA NOT NULL
);
