include .envrc

MIGRATIONS_PATH = ./cmd/migrate/migrations

.PHONY: goose-create
goose-create:
	@goose create -s -dir $(MIGRATIONS_PATH) $(filter-out $@,$(MAKECMDGOALS)) sql

.PHONY: goose-up
goose-up:
	@goose -dir $(MIGRATIONS_PATH) $(DB_ADDR) up

.PHONY: goose-down
goose-down:
	@goose $(GOOSE_DRIVER) $(DB_ADDR) down

.PHONY: gen-docs
gen-docs:
	@swag init -d cmd,internal && swag fmt

%:
	@: