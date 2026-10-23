# Fortik developer entry points. `make ci` is what CI runs.
export FORTIK_TEST_PG_URL ?= postgres://postgres@127.0.0.1:55432/postgres?sslmode=disable

.PHONY: build dev-up serve test test-race policy-test policy-fmt vet bench demo ci clean

build:
	go build -o bin/fortik ./cmd/fortik

dev-up:
	./scripts/dev-up.sh

serve: build
	bin/fortik serve -config configs/fortik.dev.yaml

vet:
	go vet ./...

policy-fmt:
	opa fmt --fail -l policies

policy-test:
	opa test policies -v --coverage --threshold 95 >/dev/null && opa test policies

test:
	go test -count=1 ./...

test-race:
	go test -race -count=1 ./...

bench:
	go test -run XXX -bench . -benchtime 3s ./internal/policy ./internal/decide

demo:
	./scripts/demo-phase1-accident.sh

ci: vet policy-fmt policy-test test-race

clean:
	rm -rf bin
