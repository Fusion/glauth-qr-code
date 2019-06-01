# Build variables
BUILD_FILES=main.go

all: setup build

build:
	GOOS=linux GOARCH=amd64 go build -o bin/ws ${BUILD_FILES}

run:
	./bin/ws

setup: getdeps qr sqlite uuid log toml

getdeps:
	go get -d ./...

qr:
	go get -u github.com/skip2/go-qrcode/...

sqlite:
	go get -u github.com/mattn/go-sqlite3/...

uuid:
	go get -u github.com/satori/go.uuid/...

log:
	go get -u github.com/op/go-logging/...

toml:
	go get -u github.com/BurntSushi/toml/...
