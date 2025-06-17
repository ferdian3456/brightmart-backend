export $(shell sed 's/=.*//' .env)
include .env

.PHONY: migrate-create
migrate-create:
	@ migrate create -ext sql -dir db/migrations -seq $(name)

.PHONY: migrate-up
migrate-up:
	@ migrate -database ${POSTGRES_URL} -path db/migrations up

.PHONY: migrate-down
migrate-down:
	@ migrate -database ${POSTGRES_URL} -path db/migrations down