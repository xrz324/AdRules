#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_ROOT="$(mktemp -d)"

cleanup() {
    local status=$?
    trap - EXIT
    rm -rf "$TEST_ROOT"
    exit "$status"
}
trap cleanup EXIT

# Detailed download behaviour is covered by injectable Python tests.  This
# regression only verifies the canonical Python CLI and pure normalization
# helpers without making a network request.
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$ROOT_DIR" python3 - <<'PY'
import re

from script.upstream_pipeline import get_download_filename, normalize_download_bytes

expected_suffixes = {
    "https://example.test/SMAdHosts": "SMAdHosts.txt",
    "https://example.test/hosts": "hosts.txt",
    "https://example.test/rules.txt": "rules.txt",
    "https://example.test/list?format=hosts": "list.txt",
}
for url, suffix in expected_suffixes.items():
    actual = get_download_filename(url)
    if re.fullmatch(r"[0-9a-f]{8}_" + re.escape(suffix), actual) is None:
        raise SystemExit(f"unexpected filename for {url}: {actual}")

normalized = normalize_download_bytes(
    b"\xef\xbb\xbf! Title\r\n||example.test^\r\n"
)
if normalized != b"! Title\n||example.test^\n":
    raise SystemExit("download normalization failed")
PY

(
    cd "$ROOT_DIR"
    python3 -m script.upstream_pipeline --help >/dev/null
)
printf '%s\n' 'upstream Python CLI regression tests passed'
