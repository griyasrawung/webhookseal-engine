generate:
	cp webhookseal-providers/providers/*.yaml internal/specs/providers/
	cp webhookseal-providers/fixtures/*.fixtures.json internal/fixtures/providers/

test: generate
	go test ./... -v -race -coverprofile=coverage.txt

build: generate
	go build ./...

vet:
	go vet ./...

fixtures:
	go test ./... -run TestProviderFixtures -v

clean-generated:
	rm -f internal/specs/providers/*.yaml
	rm -f internal/fixtures/providers/*.fixtures.json
