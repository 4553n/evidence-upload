#!/bin/bash
set -e

VERSION=$(grep 'const Version' version.go | sed 's/.*"\(.*\)".*/\1/')
echo "Building v${VERSION}..."

GOOS=linux GOARCH=amd64 /usr/local/go/bin/go build -o "evidence-upload-v${VERSION}-linux-amd64" .
GOOS=darwin GOARCH=amd64 /usr/local/go/bin/go build -o "evidence-upload-v${VERSION}-macos-amd64" .
GOOS=darwin GOARCH=arm64 /usr/local/go/bin/go build -o "evidence-upload-v${VERSION}-macos-arm64" .
GOOS=windows GOARCH=amd64 /usr/local/go/bin/go build -o "evidence-upload-v${VERSION}-windows-amd64.exe" .

echo "Done. Binaries:"
ls -lh evidence-upload-v${VERSION}*
