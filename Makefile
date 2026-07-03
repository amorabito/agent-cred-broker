.PHONY: build test vet lint clean

build:
	go build -o bin/broker ./cmd/broker
	go build -o bin/acb-verify ./cmd/acb-verify

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf bin/
