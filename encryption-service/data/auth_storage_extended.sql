-- Auth Storage schema extensions for CockroachDB

-- Enable audit logs
ALTER TABLE users EXPERIMENTAL_AUDIT SET READ WRITE;
ALTER TABLE access_objects EXPERIMENTAL_AUDIT SET READ WRITE;
