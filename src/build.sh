#!/bin/sh
# Neosilil autotools :(
GOPATH="$(pwd)/.gopath"
mkdir -p $GOPATH
go get -u github.com/hashicorp/consul/api
go get -u github.com/rjeczalik/notify
go get -u github.com/chifflier/nflog-go/nflog
go get -u github.com/google/gopacket
go test ./befw/
go test ./puppetdbsync/
go build -o ../befw-firewalld befw-firewalld.go recovery.go
go build -o ../befw-cli befw-cli.go recovery.go
go build -o ../befw-sync befw-sync.go recovery.go
strip ../befw-firewalld
strip ../befw-cli
strip ../befw-sync
