all: build

build: # uses `CGO_ENABLED=0` to avoid platform-specific C dependencies.
	CGO_ENABLED=0 go build -ldflags "-s -w -X github.com/meha555/crypto-tool/cmd.version=$(shell git symbolic-ref HEAD | cut -b 12-)-$(shell git describe --tags --always --dirty --abbrev=7 2>/dev/null || echo dev)"

debug:
	CGO_ENABLED=0 go build -gcflags="all=-N -l"

install:
	go install

clean:
	go clean

.PHONY: all build install clean debug