PB = $(wildcard *.proto)
GO = $(PB:.proto=.pb.go)

all: $(GO)

build-deps-osx:
	# for protoc
	brew install protobuf
	# for the gogofast plugin
	go get github.com/gogo/protobuf/protoc-gen-gogofast

%.pb.go: %.proto
	protoc --proto_path=$(GOPATH)/src:. --gogofast_out=. $<

clean:
	rm -f *.go
