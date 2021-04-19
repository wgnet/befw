export GO111MODULE=on

install:
	go install -mod=vendor ./cmd/befw-cli
	go install -mod=vendor ./cmd/befw-firewalld
	go install -mod=vendor ./cmd/befw-sync
	go install -mod=vendor ./cmd/befw-deny
