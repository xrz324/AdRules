#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_TMP="$(mktemp -d)"

cleanup() {
    local rc=$?
    trap - EXIT
    rm -rf "$TEST_TMP"
    exit "$rc"
}
trap cleanup EXIT

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    return 1
}

project_dir="$TEST_TMP/project"
mkdir -p "$project_dir/script" "$project_dir/config"
cp "$ROOT_DIR/script/__init__.py" "$project_dir/script/"
cp "$ROOT_DIR/script/autoupdate_config.py" "$project_dir/script/"
cp "$ROOT_DIR/script/publish_pipeline.py" "$project_dir/script/"
cp "$ROOT_DIR/script/common.py" "$project_dir/script/"

cat > "$project_dir/config/autoupdate.json" <<'JSON'
{
  "version": 1,
  "environment": {},
  "runtime": {
    "dns_prune_cache": "dns_prune_cache.json",
    "dns_prune_log": "tmp/dns-prune.log",
    "download_failed_log": "download_failed.log"
  },
  "artifacts": [
    {"name": "adblock", "path": "adblock.txt", "kind": "adblock", "required": true},
    {"name": "dns", "path": "dns.txt", "kind": "dns", "required": true},
    {"name": "singbox", "path": "rules.srs", "kind": "binary", "required": false},
    {"name": "mihomo_mrs", "path": "rules.mrs", "kind": "binary", "required": false},
    {"name": "mihomo_yaml", "path": "rules.yaml", "kind": "yaml", "required": false}
  ]
}
JSON

printf 'old adblock\n' > "$project_dir/adblock.txt"
printf 'old dns\n' > "$project_dir/dns.txt"
printf 'old singbox\n' > "$project_dir/rules.srs"
printf 'old mrs\n' > "$project_dir/rules.mrs"
printf 'old yaml\n' > "$project_dir/rules.yaml"
printf 'old failure\n' > "$project_dir/download_failed.log"

(
    cd "$project_dir"
    git init -q
    git config user.name test
    git config user.email test@example.com
    git config commit.gpgsign false
    git add .
    git commit -qm baseline
)

printf 'new adblock\n' > "$project_dir/adblock.txt"
printf 'new dns\n' > "$project_dir/dns.txt"
printf 'new singbox\n' > "$project_dir/rules.srs"
rm "$project_dir/rules.mrs"

(
    cd "$project_dir"
    python3 -m script.publish_pipeline --config config/autoupdate.json

    staged="$(git diff --cached --name-status)"
    grep -Fqx $'M\tadblock.txt' <<< "$staged" || fail 'required adblock output was not staged'
    grep -Fqx $'M\tdns.txt' <<< "$staged" || fail 'required DNS output was not staged'
    grep -Fqx $'M\trules.srs' <<< "$staged" || fail 'existing optional output was not staged'
    grep -Fqx $'D\trules.mrs' <<< "$staged" || fail 'stale optional output was not removed'
    grep -Fqx $'D\tdownload_failed.log' <<< "$staged" || fail 'tracked failure log was not removed'

    rm dns.txt
    if python3 -m script.publish_pipeline --config config/autoupdate.json > missing.log 2>&1; then
        fail 'missing required output did not fail staging'
    fi
    grep -Fq 'missing required output: dns.txt' missing.log || \
        fail 'missing required output error was not reported'
)

printf 'PASS: publish Python CLI regression tests\n'
