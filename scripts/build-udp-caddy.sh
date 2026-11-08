#!/usr/bin/env bash
# Build/test against exactly the patched Caddy used by production CI.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
staging=$(mktemp -d "${TMPDIR:-/tmp}/forwardproxy-udp.XXXXXX")
trap 'rm -rf "$staging"' EXIT
output=${1:-$root/caddy}
if [[ "$output" != /* ]]; then output="$PWD/$output"; fi
version=$(cat "$root/CADDY_VERSION")
git clone --quiet --depth 1 --branch "$version" https://github.com/caddyserver/caddy.git "$staging/caddy"
git -C "$staging/caddy" apply "$root/caddy-sing-quic-bbrv1.patch" "$root/caddy-read-idle-timeout.patch" "$root/caddy-connect-udp.patch"
mkdir "$staging/build"
cat > "$staging/build/main.go" <<'GO'
package main
import (
 caddycmd "github.com/caddyserver/caddy/v2/cmd"
 _ "github.com/caddyserver/caddy/v2/modules/standard"
 _ "github.com/caddyserver/forwardproxy"
)
func main(){caddycmd.Main()}
GO
cd "$staging/build"
go mod init udp-caddy-build
go mod edit -require="github.com/caddyserver/caddy/v2@$version" -require=github.com/caddyserver/forwardproxy@v0.0.0 -replace=github.com/caddyserver/caddy/v2="$staging/caddy" -replace=github.com/caddyserver/forwardproxy="$root"
GOWORK=off go mod tidy
GOWORK=off go build -p 2 -o "$output" .
# Run all tests with the same Caddy replacement; never test the plugin against
# an unpatched dependency with a different HTTP/3 implementation.
cd "$staging"
GOWORK=off go work init "$staging/caddy" "$root"
cd "$root"
export XDG_CONFIG_HOME="$staging/config" XDG_DATA_HOME="$staging/data"
test_flags=()
if [[ "$(uname -s)" == Darwin ]]; then
  echo 'macOS: running UDP tests; legacy suite requires additional 127.x loopback aliases.'
  test_flags=(-run 'TestUDP|TestHTTP3UDP')
fi
GOWORK="$staging/go.work" go test -race -p 2 -timeout 5m "${test_flags[@]}" ./...

GOWORK="$staging/go.work" go vet ./...
