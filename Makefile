.PHONY: build test vet lint clean

build:
	go build -o bin/broker ./cmd/broker
	go build -o bin/acb-verify ./cmd/acb-verify
	go build -o bin/ha-notify-proxy ./cmd/ha-notify-proxy
	go build -o bin/acb-playground ./cmd/acb-playground

test:
	go test ./...

vet:
	go vet ./...

lint:
	test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
	go vet ./...

clean:
	rm -rf bin/
