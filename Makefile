NAME=proxypool

BINDIR=bin
VERSION=$(shell git describe --tags || echo "unknown version")

LDFLAGS=" \
	-X 'main.version=$(VERSION)' \
	-w -s \
"

GOBUILD=CGO_ENABLED=0 go build -trimpath -ldflags $(LDFLAGS)

PLATFORM_LIST = \
	darwin-amd64 \
	linux-386 \
	linux-amd64 \
	linux-armv5 \
	linux-armv6 \
	linux-armv7 \
	linux-armv8 \
	linux-mips-softfloat \
	linux-mips-hardfloat \
	linux-mipsle-softfloat \
	linux-mipsle-hardfloat \
	linux-mips64 \
	linux-mips64le \
	freebsd-386 \
	freebsd-amd64


all: linux-amd64 darwin-amd64 linux-armv8

docker2:
	docker run --rm -v `go env GOPATH`:/go \
		-v "$(shell PWD)":/go/src/$(NAME) \
		-w /go/src/$(NAME) \
		golang:1.17.6-alpine \
		sh -c "$(GOBUILD) -o $(BINDIR)/$(NAME)-$@"

docker:
	$(GOBUILD) -o $(BINDIR)/$(NAME)-$@

darwin-amd64:
	GOARCH=amd64 GOOS=darwin $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-386:
	GOARCH=386 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-amd64:
	GOARCH=amd64 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-armv5:
	GOARCH=arm GOOS=linux GOARM=5 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-armv6:
	GOARCH=arm GOOS=linux GOARM=6 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-armv7:
	GOARCH=arm GOOS=linux GOARM=7 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-armv8:
	GOARCH=arm64 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mips-softfloat:
	GOARCH=mips GOMIPS=softfloat GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mips-hardfloat:
	GOARCH=mips GOMIPS=hardfloat GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mipsle-softfloat:
	GOARCH=mipsle GOMIPS=softfloat GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mipsle-hardfloat:
	GOARCH=mipsle GOMIPS=hardfloat GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mips64:
	GOARCH=mips64 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mips64le:
	GOARCH=mips64le GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

freebsd-386:
	GOARCH=386 GOOS=freebsd $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

freebsd-amd64:
	GOARCH=amd64 GOOS=freebsd $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

gz_releases=$(addsuffix .gz, $(PLATFORM_LIST))

$(gz_releases): %.gz : %
	chmod +x $(BINDIR)/$(NAME)-$(basename $@)
	gzip -f -S -$(VERSION).gz $(BINDIR)/$(NAME)-$(basename $@)

all-arch: $(PLATFORM_LIST)

releases: $(gz_releases)
clean:
	rm $(BINDIR)/*

dockerhub:
	@go mod vendor
	docker buildx build --platform linux/amd64,linux/arm64/v8 -f Dockerfile -t bineyond/proxypool:$(VERSION) -t bineyond/proxypool:latest .  --push
	@rm -r vendor

dockerhub-amd64:
	@go mod vendor
	docker buildx build --platform linux/amd64 -f Dockerfile -t bineyond/proxypool:amd64 -t bineyond/proxypool:latest .  --push
	@rm -r vendor

dockerhub-arm64:
	@go mod vendor
	docker buildx build --platform linux/arm64/v8 -f Dockerfile -t bineyond/proxypool:arm64 -t bineyond/proxypool:latest .  --push
	@rm -r vendor