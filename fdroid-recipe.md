# F-Droid Build Recipe — `paulvers-ui/usque`

> **Type:** Go CLI / Android binary (no APK — produces a native binary, not an Android app)  
> **F-Droid note:** F-Droid proper only distributes APKs. This recipe is for
> [fdroidserver](https://gitlab.com/fdroid/fdroidserver) used in a custom or
> self-hosted repo, OR as documentation for reproducible builds.  
> If you want this in a real F-Droid repo, package it inside an APK wrapper.

---

## Metadata file: `metadata/github.paulvers-ui.usque.yml`

```yaml
Categories:
  - Internet
  - Security

License: MIT

WebSite: https://github.com/paulvers-ui/usque
SourceCode: https://github.com/paulvers-ui/usque
IssueTracker: https://github.com/paulvers-ui/usque/issues

AutoName: usque

Summary: Cloudflare WARP SOCKS5 proxy for Android (MASQUE/QUIC)
Description: |-
  usque is a Go-based command-line tool that connects to Cloudflare WARP
  using the MASQUE (HTTP/3 CONNECT-UDP) protocol and exposes a local
  SOCKS5 proxy. Designed to be embedded in Android apps (e.g. Rethink Fork)
  as a native arm64 binary (libusque.so).

RepoType: git
Repo: https://github.com/paulvers-ui/usque

Builds:
  - versionName: '0.1.0'
    versionCode: 1
    commit: v0.1.0          # replace with the actual tag/commit you want to build
    subdir: .
    sudo:
      - apt-get install -y golang-go
    prebuild:
      - export GOPATH=$HOME/go
      - export PATH=$PATH:$GOPATH/bin
      - go version
    build:
      # Android arm64 binary (no CGO — pure Go)
      - export GOOS=android
      - export GOARCH=arm64
      - export CGO_ENABLED=0
      - go build
          -trimpath
          -ldflags "-s -w
            -X github.com/Diniboy1123/usque/cmd.version=$$VERSION$$
            -X github.com/Diniboy1123/usque/cmd.commit=$$COMMIT$$
            -X github.com/Diniboy1123/usque/cmd.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
          -o usque-arm64
          .
    ndk: r26b      # only needed if CGO is ever enabled; currently not used

AutoUpdateMode: Version
UpdateCheckMode: Tags
CurrentVersion: '0.1.0'
CurrentVersionCode: 1
```

---

## Manual build steps (local / CI)

```bash
# Prerequisites
go version   # needs Go 1.22+

git clone https://github.com/paulvers-ui/usque
cd usque

# Android arm64 (what rethink-app embeds as libusque.so)
GOOS=android GOARCH=arm64 CGO_ENABLED=0 \
  go build -trimpath \
    -ldflags "-s -w \
      -X github.com/Diniboy1123/usque/cmd.version=$(git describe --tags) \
      -X github.com/Diniboy1123/usque/cmd.commit=$(git rev-parse --short HEAD) \
      -X github.com/Diniboy1123/usque/cmd.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o libusque.so \
    .

# Linux amd64 (local testing)
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go build -trimpath \
    -ldflags "-s -w" \
    -o usque \
    .
```

## Goreleaser (full multi-arch release)

```bash
# Requires: goreleaser v2+, Go 1.22+
goreleaser release --clean
# or dry-run:
goreleaser build --clean --snapshot
```

Targets produced by goreleaser (from `goreleaser.yml`):
| GOOS    | GOARCH  | GOARM | Use                        |
|---------|---------|-------|----------------------------|
| android | arm64   | —     | Android arm64 (libusque.so)|
| linux   | amd64   | —     | Server / desktop           |
| linux   | arm     | 5/6/7 | Embedded Linux             |
| linux   | arm64   | —     | Linux arm64                |
| linux   | mips*   | —     | Routers                    |
| windows | amd64   | —     | Windows                    |
| windows | arm64   | —     | Windows arm64              |
