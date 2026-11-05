#!/usr/bin/env bash
# Download the agentgateway release Fortik is pinned to (v1.6.0, see
# internal/agentgw.AgentGatewayVersion) into spikes/agentgateway/bin, and
# verify it against the release's published .sha256. On macOS arm64 the
# checksum must also equal the one Fortik pinned in code.
#
# Used by scripts/demo-agentgateway.sh and TestEndToEndAgentgateway.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION=v1.6.0
PINNED_DARWIN_ARM64=6cebe8bd57262edce23a65a376d2f5a27b97cdfef609740642edbe75e1e9c685
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) asset=agentgateway-darwin-arm64 ;;
  Linux-x86_64) asset=agentgateway-linux-amd64 ;;
  Linux-aarch64 | Linux-arm64) asset=agentgateway-linux-arm64 ;;
  *) echo "no agentgateway $VERSION build for $(uname -sm)"; exit 2 ;;
esac
dir="$ROOT/spikes/agentgateway/bin"
mkdir -p "$dir"
base="https://github.com/agentgateway/agentgateway/releases/download/$VERSION"
echo "downloading $asset $VERSION..."
curl -fsSL -o "$dir/agentgateway.tmp" "$base/$asset"
curl -fsSL -o "$dir/agentgateway.sha256" "$base/$asset.sha256"
want="$(awk '{print $1}' "$dir/agentgateway.sha256")"
got="$(shasum -a 256 "$dir/agentgateway.tmp" | awk '{print $1}')"
if [ "$want" != "$got" ]; then rm -f "$dir/agentgateway.tmp"; echo "checksum mismatch: got $got, release says $want"; exit 1; fi
if [ "$asset" = agentgateway-darwin-arm64 ] && [ "$got" != "$PINNED_DARWIN_ARM64" ]; then
  rm -f "$dir/agentgateway.tmp"; echo "checksum $got is not the one Fortik pinned ($PINNED_DARWIN_ARM64)"; exit 1
fi
mv "$dir/agentgateway.tmp" "$dir/agentgateway"
chmod +x "$dir/agentgateway"
echo "agentgateway $VERSION ready: $dir/agentgateway (sha256 $got)"
