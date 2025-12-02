-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS users_verification_tracking(
    token bytea PRIMARY KEY,
    user_id bigserial NOT NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS users_verification_tracking;
-- +goose StatementEnd
