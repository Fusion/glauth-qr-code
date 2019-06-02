# Build variables
BUILD_FILES=main.go

all: setup build

build:
	GOOS=linux GOARCH=amd64 go build -o bin/ws ${BUILD_FILES}

run:
	./bin/ws serve

setup: getdeps getdepqr getdepsqlite getdepuuid getdeplog getdeptoml getdepcli getdepgit

getdeps:
	go get -d ./...

getdepqr:
	go get -u github.com/skip2/go-qrcode/...

getdepsqlite:
	go get -u github.com/mattn/go-sqlite3/...

getdepuuid:
	go get -u github.com/satori/go.uuid/...

getdeplog:
	go get -u github.com/op/go-logging/...

getdeptoml:
	go get -u github.com/BurntSushi/toml/...

getdepcli:
	go get -u github.com/urfave/cli/...

getdepgit:
	go get -u gopkg.in/src-d/go-git.v4/...
