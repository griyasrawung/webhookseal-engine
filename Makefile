generate:
	cp webhookseal-providers/providers/*.yaml internal/specs/providers/
	cp webhookseal-providers/fixtures/*.fixtures.json internal/fixtures/providers/

test: generate
	go test ./... -v

build: generate
	go build ./...
