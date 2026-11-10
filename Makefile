BIN := sinty-parentald
PREFIX ?= /usr

.PHONY: all build static test vet install clean

all: build

build:
	go build -o $(BIN) ./cmd/sinty-parentald

static:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o $(BIN) ./cmd/sinty-parentald

test:
	go test ./...

vet:
	go vet ./...

install: static
	install -Dm755 $(BIN) $(DESTDIR)$(PREFIX)/libexec/$(BIN)
	install -Dm644 packaging/sinty-parentald.conf $(DESTDIR)$(PREFIX)/share/dbus-1/system.d/sinty-parentald.conf
	install -Dm644 packaging/dev.sinty.Parental1.service $(DESTDIR)$(PREFIX)/share/dbus-1/system-services/dev.sinty.Parental1.service

clean:
	rm -f $(BIN)
