all: clean build

build:
	protoc --proto_path=. --go_out=. --go_opt=paths=source_relative ./record.proto

clean:
	rm -f *.pb.go
	rm -f *.go

.PHONY: all build clean