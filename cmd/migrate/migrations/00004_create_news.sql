-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS news_article(
    id bigserial PRIMARY KEY,
    title TEXT NOT NULL UNIQUE,
    content TEXT NOT NULL,
    creator_id bigserial NOT NULL,
    created_at timestamp(0) with time zone NOT NULL DEFAULT NOW()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS news;
-- +goose StatementEnd
