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

mkdir -p \
    "$TEST_ROOT/script" \
    "$TEST_ROOT/mod/rules" \
    "$TEST_ROOT/mod/title" \
    "$TEST_ROOT/tmp/content"
cp \
    "$ROOT_DIR/script/__init__.py" \
    "$ROOT_DIR/script/content_pipeline.py" \
    "$ROOT_DIR/script/content_minimizer.py" \
    "$ROOT_DIR/script/content_cosmetic.py" \
    "$ROOT_DIR/script/content_models.py" \
    "$ROOT_DIR/script/content_network.py" \
    "$ROOT_DIR/script/dns_minimizer.py" \
    "$ROOT_DIR/script/rule_canonical.py" \
    "$ROOT_DIR/script/common.py" \
    "$TEST_ROOT/script/"

printf '%s\n' '[Adblock Plus 2.0]' '! Fixture title' > \
    "$TEST_ROOT/mod/title/adblock-title.txt"
printf '%s\n' \
    '! ordinary comment' \
    '||example.com^' \
    '||example.com^$badfilter' \
    '||child.example.com^' \
    '||active.test^' \
    '||child.active.test^' \
    '||removed.test^' > "$TEST_ROOT/mod/rules/adblock-rules.txt"
printf '%s\n' '||removed.test^' > \
    "$TEST_ROOT/mod/rules/adblock-need-remove.txt"
printf '%s\n' \
    '##.sponsor' \
    'example.test##.sponsor' \
    'not-a-comment' > "$TEST_ROOT/tmp/content/source.txt"

(
    cd "$TEST_ROOT"
    python3 -m script.content_pipeline --root "$TEST_ROOT"
)

grep -Fqx '[Adblock Plus 2.0]' "$TEST_ROOT/adblock.txt"
grep -Fqx '! Total count: 6' "$TEST_ROOT/adblock.txt"
if grep -Fqx '||example.com^' "$TEST_ROOT/adblock.txt"; then
    printf '%s\n' 'badfilter-disabled target was not removed' >&2
    exit 1
fi
grep -Fqx '||example.com^$badfilter' "$TEST_ROOT/adblock.txt"
grep -Fqx '||child.example.com^' "$TEST_ROOT/adblock.txt"
grep -Fqx '||active.test^' "$TEST_ROOT/adblock.txt"
if grep -Fqx '||child.active.test^' "$TEST_ROOT/adblock.txt"; then
    printf '%s\n' 'covered child domain was not removed' >&2
    exit 1
fi
grep -Fqx 'example.test##.sponsor' "$TEST_ROOT/adblock.txt"
grep -Fqx '##.sponsor' "$TEST_ROOT/adblock.txt"
grep -Fqx 'not-a-comment' "$TEST_ROOT/adblock.txt"

if find "$TEST_ROOT" -maxdepth 2 \( -name '*.tmp' -o -name 'content_final.txt' -o -name 'content_plain_domains.txt' \) | grep -q .; then
    printf '%s\n' 'content build left intermediate files' >&2
    exit 1
fi

printf '%s\n' 'PASS: content Python CLI regression tests'
