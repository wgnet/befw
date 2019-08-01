#!/bin/sh
# Neosilil autotools :(
go get github.com/hashicorp/consul/api
go get github.com/rjeczalik/notify
go get github.com/chifflier/nflog-go/nflog
go get github.com/google/gopacket
go get gopkg.in/mcuadros/go-syslog.v2
go test ./befw/
go test ./puppetdbsync/
go build -o ../befw-firewalld befw-firewalld.go recovery.go
go build -o ../befw-cli befw-cli.go recovery.go
go build -o ../befw-sync befw-sync.go recovery.go
strip ../befw-firewalld
strip ../befw-cli
strip ../befw-sync
