-- Auth Storage schema for CockroachDB / PostgreSQL

CREATE TABLE IF NOT EXISTS users  (
    id UUID PRIMARY KEY,
    data BYTES,
    key BYTES
);

CREATE TABLE IF NOT EXISTS access_objects  (
    id UUID PRIMARY KEY,
    data BYTES NOT NULL,
    tag BYTES NOT NULL
);

-- Enable audit logs
ALTER TABLE users EXPERIMENTAL_AUDIT SET READ WRITE;
ALTER TABLE access_objects EXPERIMENTAL_AUDIT SET READ WRITE;
