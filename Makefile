export GO111MODULE=on

install:
	go mod download
	go install ./cmd/befw-cli
	go install ./cmd/befw-firewalld
	go install ./cmd/befw-sync
