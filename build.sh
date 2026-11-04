#!/bin/bash
set -e

VERSION=$(grep 'const Version' version.go | sed 's/.*"\(.*\)".*/\1/')
echo "Building v${VERSION}..."

GOOS=linux GOARCH=amd64 /usr/local/go/bin/go build -o "evidence-upload-v${VERSION}-linux-amd64" .
GOOS=darwin GOARCH=amd64 /usr/local/go/bin/go build -o "evidence-upload-v${VERSION}-macos-amd64" .
GOOS=darwin GOARCH=arm64 /usr/local/go/bin/go build -o "evidence-upload-v${VERSION}-macos-arm64" .
GOOS=windows GOARCH=amd64 /usr/local/go/bin/go build -o "evidence-upload-v${VERSION}-windows-amd64.exe" .

# Package Unix binaries as tar.gz. HTTP downloads strip the executable bit from
# bare binaries (zsh: permission denied), but tar archives preserve it.
for target in linux-amd64 macos-amd64 macos-arm64; do
  bin="evidence-upload-v${VERSION}-${target}"
  tar -czf "${bin}.tar.gz" "${bin}"
done

echo "Done. Binaries:"
ls -lh evidence-upload-v${VERSION}*
echo ""
echo "Upload the .tar.gz archives (and the .exe) to the GitHub release."
echo "Do NOT upload bare Unix binaries: downloads lose the executable bit."
