-- Auth Storage schema for CockroachDB / PostgreSQL

CREATE TABLE IF NOT EXISTS users  (
    id UUID PRIMARY KEY,
    data BYTEA,
    key BYTEA
);

CREATE TABLE IF NOT EXISTS access_objects  (
    id UUID PRIMARY KEY,
    data BYTEA NOT NULL,
    tag BYTEA NOT NULL
);
