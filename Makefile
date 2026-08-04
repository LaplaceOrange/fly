.PHONY: web build test race clean

web:
	npm --prefix web ci
	npm --prefix web run build

build: web
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/chinese-can-fly .

test:
	go test ./...
	npm --prefix web test
	npm --prefix web run typecheck

race:
	go test -race ./...

clean:
	rm -rf bin web/dist

