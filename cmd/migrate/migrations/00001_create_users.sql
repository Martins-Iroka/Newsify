-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS citext;
CREATE TABLE IF NOT EXISTS users(
    id bigserial PRIMARY KEY,
    email citext UNIQUE NOT NULL,
    username varchar(255) UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_verified boolean NOT NULL DEFAULT FALSE,
    role TEXT NOT NULL,
    create_at timestamp(0) with time zone NOT NULL DEFAULT NOW()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS users;
-- +goose StatementEnd
