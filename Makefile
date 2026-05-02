generate:
	cp webhookseal-providers/providers/*.yaml internal/specs/providers/

test: generate
	go test ./... -v

build: generate
	go build ./...
