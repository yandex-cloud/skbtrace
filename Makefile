MOD ?= github.com/yandex-cloud/skbtrace
OUT ?= ./build/skbtrace

.PHONY: all
all: lint mod unit-test cli-test skbtrace

.PHONY: clean
clean:
	go clean -i $(MOD)

.PHONY: mod
mod:
	go mod tidy

.PHONY: unit-test
unit-test:
	go test -test.v $(MOD)

.PHONY: cli-test
cli-test:
	go test -test.v $(MOD)/pkg/cli/testing

.PHONY: skbtrace
skbtrace:
	go build -o $(OUT) "./cmd"

.PHONY: lint
lint:
	go get github.com/mgechev/revive ||:
	go run github.com/mgechev/revive -config revive.toml

.PHONY: generate-md-docs
generate-md-docs: skbtrace
	./build/skbtrace generate-md-docs ./docs
