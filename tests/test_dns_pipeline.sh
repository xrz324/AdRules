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

setup_project() {
    local project_dir="$1"

    mkdir -p \
        "$project_dir/script" \
        "$project_dir/config" \
        "$project_dir/mod/rules" \
        "$project_dir/mod/title" \
        "$project_dir/tmp/dns" \
        "$project_dir/tmp/tools"

    cp "$ROOT_DIR/script/__init__.py" "$project_dir/script/__init__.py"
    cp "$ROOT_DIR/script/compressor.py" "$project_dir/script/compressor.py"
    cp "$ROOT_DIR/script/remove.py" "$project_dir/script/remove.py"
    cp "$ROOT_DIR/script/dns_pipeline.py" "$project_dir/script/dns_pipeline.py"
    cp "$ROOT_DIR/script/dns_output.py" "$project_dir/script/dns_output.py"
    cp "$ROOT_DIR/script/dns_coverage.py" "$project_dir/script/dns_coverage.py"
    cp "$ROOT_DIR/script/dns_regex_coverage.py" "$project_dir/script/dns_regex_coverage.py"
    cp "$ROOT_DIR/script/dns_prune_pipeline.py" "$project_dir/script/dns_prune_pipeline.py"
    cp "$ROOT_DIR/script/dns_prune.py" "$project_dir/script/dns_prune.py"
    cp "$ROOT_DIR/script/dns_prune_model.py" "$project_dir/script/dns_prune_model.py"
    cp "$ROOT_DIR/script/dns_prune_cache.py" "$project_dir/script/dns_prune_cache.py"
    cp "$ROOT_DIR/script/dns_prune_rules.py" "$project_dir/script/dns_prune_rules.py"
    cp "$ROOT_DIR/script/dns_prune_resolver.py" "$project_dir/script/dns_prune_resolver.py"
    cp "$ROOT_DIR/script/dns_prune_config.py" "$project_dir/script/dns_prune_config.py"
    cp "$ROOT_DIR/script/dns_prune_probe.py" "$project_dir/script/dns_prune_probe.py"
    cp "$ROOT_DIR/script/dns_prune_scheduler.py" "$project_dir/script/dns_prune_scheduler.py"
    cp "$ROOT_DIR/script/inactive_domain_cache.py" "$project_dir/script/inactive_domain_cache.py"
    cp "$ROOT_DIR/script/inactive_domain_model.py" "$project_dir/script/inactive_domain_model.py"
    cp "$ROOT_DIR/script/inactive_domain_repository.py" "$project_dir/script/inactive_domain_repository.py"
    cp "$ROOT_DIR/script/dns_minimizer.py" "$project_dir/script/dns_minimizer.py"
    cp "$ROOT_DIR/script/rule_canonical.py" "$project_dir/script/rule_canonical.py"
    cp "$ROOT_DIR/script/common.py" "$project_dir/script/common.py"
    cp "$ROOT_DIR/script/dns_converter.py" "$project_dir/script/dns_converter.py"
    cp "$ROOT_DIR/script/dns_converter_model.py" "$project_dir/script/dns_converter_model.py"
    cp "$ROOT_DIR/script/dns_converter_config.py" "$project_dir/script/dns_converter_config.py"
    cp "$ROOT_DIR/script/dns_converter_io.py" "$project_dir/script/dns_converter_io.py"
    cp "$ROOT_DIR/script/dns_converter_rules.py" "$project_dir/script/dns_converter_rules.py"
    cp "$ROOT_DIR/script/dns_converter_tools.py" "$project_dir/script/dns_converter_tools.py"
    cp "$ROOT_DIR/script/download.py" "$project_dir/script/download.py"
    cp "$ROOT_DIR/script/logging_utils.py" "$project_dir/script/logging_utils.py"
    cp "$ROOT_DIR/script/upstream_pipeline.py" "$project_dir/script/upstream_pipeline.py"
    cp "$ROOT_DIR/script/mihomo_classical.awk" "$project_dir/script/mihomo_classical.awk"
    cp "$ROOT_DIR/script/singbox_preprocess.awk" "$project_dir/script/singbox_preprocess.awk"
    cp "$ROOT_DIR/script/mihomo_payload.awk" "$project_dir/script/mihomo_payload.awk"
    cp "$ROOT_DIR/config/converter.json" "$project_dir/config/converter.json"

    printf '! Test DNS rules\n' > "$project_dir/mod/title/dns-title.txt"
    printf '# test allowlist\n' > "$project_dir/mod/rules/dns-allowlist.txt"
    : > "$project_dir/mod/rules/dns-rules.txt"

    cat > "$project_dir/tmp/tools/sing-box" <<'SH'
#!/bin/bash
set -euo pipefail

input_file="$3"
output_file=""
while [[ $# -gt 0 ]]; do
    if [[ "$1" == "--output" ]]; then
        output_file="$2"
        break
    fi
    shift
done

cp "$input_file" "$SINGBOX_CAPTURE"
printf 'sing-box stub\n' > "$output_file"
SH

    cat > "$project_dir/tmp/tools/mihomo" <<'SH'
#!/bin/bash
set -euo pipefail

if [[ "${1:-}" != "convert-ruleset" ]]; then
    exit 2
fi

cp "$4" "$MIHOMO_CAPTURE"
output_file="${!#}"
printf 'mihomo stub\n' > "$output_file"
SH

    chmod +x "$project_dir/tmp/tools/sing-box" "$project_dir/tmp/tools/mihomo"
}

run_update() {
    local project_dir="$1"
    local log_file="$2"
    shift 2

    (
        cd "$project_dir"
        export DNS_PRUNE_ENABLED=false
        export MIHOMO_CAPTURE="$project_dir/mihomo-domain-input.txt"
        export SINGBOX_CAPTURE="$project_dir/singbox-input.txt"
        export STRICT_DNS_CONVERTER=true
        for assignment in "$@"; do
            export "$assignment"
        done

        dns_ip_cidr_file="$project_dir/tmp/dns_ip_cidr_rules.txt"
        cleanup_sidecar() {
            rm -f "$dns_ip_cidr_file"
        }
        trap cleanup_sidecar EXIT

        python3 -m script.dns_pipeline \
            --root "$project_dir" \
            --output "$project_dir/dns.txt" \
            --ip-cidr-output "$dns_ip_cidr_file"

        if [[ "${DNS_PRUNE_ENABLED:-false}" == true ]]; then
            python3 -m script.dns_prune_pipeline \
                --root "$project_dir" \
                --input "$project_dir/dns.txt"
        else
            python3 -m script.dns_prune_pipeline \
                --root "$project_dir" \
                --input "$project_dir/dns.txt" \
                --coverage-only
        fi

        python3 -m script.dns_output \
            --input "$project_dir/dns.txt" \
            --title "$project_dir/mod/title/dns-title.txt" \
            --output "$project_dir/dns.txt"

        python3 -m script.dns_converter \
            --root "$project_dir" \
            --input "$project_dir/dns.txt" \
            --ip-cidr-input "$dns_ip_cidr_file" \
            --config "$project_dir/config/converter.json"
    ) > "$log_file" 2>&1
}

test_rule_semantics() {
    local project_dir="$TEST_TMP/rule-semantics"
    local log_file="$project_dir/update.log"

    setup_project "$project_dir"
    cat > "$project_dir/mod/rules/dns-rules.txt" <<'RULES'
||example.com^
||example.com^$badfilter
||sub.example.com^
||keep.test^
||mmstat.com^
||*.mmstat.com^
||ad-*.com^
||ad-*.amazonaws.com^
||ad.*^
||ad.example^
||sub.ad.example^
||*.wild.example^
||bet.championat.com^
||bet.championat.com^$important
/(https?:\/\/)104\.154\..{100,}/
/^192\.0\.2\.1$/
192.0.2.1/24
192.0.2.0/24
192.0.2.0/33
RULES
    if ! run_update "$project_dir" "$log_file" STRICT_MIHOMO_MODIFIERS=true; then
        cat "$log_file" >&2
        fail 'offline DNS update failed unexpectedly'
    fi

    grep -Fxq '||sub.example.com^' "$project_dir/dns.txt" || \
        fail 'badfilter-disabled parent compressed its active child rule'
    if grep -Fxq '||example.com^' "$project_dir/dns.txt"; then
        fail 'dns.txt retained a base rule disabled by badfilter'
    fi
    grep -Fxq '||example.com^$badfilter' "$project_dir/dns.txt" || \
        fail 'badfilter rule was not retained in dns.txt'
    if grep -Fxq '||*.mmstat.com^' "$project_dir/dns.txt"; then
        fail 'wildcard covered by a pure parent domain was retained'
    fi
    if grep -Fxq '||ad-*.amazonaws.com^' "$project_dir/dns.txt"; then
        fail 'wildcard covered by a broader wildcard was retained'
    fi
    if grep -Fxq '||ad.example^' "$project_dir/dns.txt"; then
        fail 'ABP wildcard covered exact rule was retained'
    fi
    if grep -Fxq '||sub.ad.example^' "$project_dir/dns.txt"; then
        fail 'ABP wildcard covered descendant rule was retained'
    fi
    if grep -Fxq '||bet.championat.com^' "$project_dir/dns.txt"; then
        fail 'plain rule covered by active important rule was retained'
    fi
    grep -Fxq '||bet.championat.com^$important' "$project_dir/dns.txt" || \
        fail 'active important rule was removed'
    grep -Fq 'DOMAIN-WILDCARD,ad.*' "$project_dir/adrules-mihomo.yaml" || \
        fail 'ABP wildcard base hostname was not preserved in Mihomo output'
    grep -Fq 'DOMAIN-WILDCARD,*.ad.*' "$project_dir/adrules-mihomo.yaml" || \
        fail 'ABP wildcard descendant coverage was not preserved in Mihomo output'
    if grep -Fq 'DOMAIN-REGEX,(^|\.)ad\..*$' "$project_dir/adrules-mihomo.yaml"; then
        fail 'ABP wildcard unnecessarily fell back to DOMAIN-REGEX'
    fi
    if grep -Fxq '*.wild.example' "$project_dir/mihomo-domain-input.txt"; then
        fail 'Mihomo wildcard was downgraded to single-label MRS syntax'
    fi
    grep -Fxq '.wild.example' "$project_dir/mihomo-domain-input.txt" || \
        fail 'Mihomo wildcard was not converted to multi-level MRS syntax'

    if grep -Fxq '||example.com^' "$project_dir/singbox-input.txt"; then
        fail 'sing-box input contains a base rule disabled by badfilter'
    fi
    if grep -Fxq '||example.com^$badfilter' "$project_dir/singbox-input.txt"; then
        fail 'sing-box input contains unsupported badfilter syntax'
    fi
    grep -Fxq '||sub.example.com^' "$project_dir/singbox-input.txt" || \
        fail 'sing-box input lost the active child rule'

    if grep -Fq 'IP-CIDR,104.154.0.0/16' "$project_dir/adrules-mihomo.yaml"; then
        fail 'URL regex was widened to an IPv4 /16'
    fi
    grep -Fq 'IP-CIDR,192.0.2.1/32' "$project_dir/adrules-mihomo.yaml" || \
        fail 'fully anchored exact IP regex was not converted'
    grep -Fq 'IP-CIDR,192.0.2.0/24' "$project_dir/adrules-mihomo.yaml" || \
        fail 'bare IPv4 CIDR was not converted'
    if grep -Fq 'IP-CIDR,192.0.2.1/24' "$project_dir/adrules-mihomo.yaml"; then
        fail 'IPv4 CIDR host bits were not normalized'
    fi
    if grep -Fq '192.0.2.0/33' "$project_dir/adrules-mihomo.yaml"; then
        fail 'invalid IPv4 CIDR was not rejected'
    fi
    if grep -Fxq '192.0.2.0/24' "$project_dir/dns.txt"; then
        fail 'bare IPv4 CIDR leaked into AdGuard dns.txt'
    fi
    if grep -Fxq '192.0.2.0/24' "$project_dir/singbox-input.txt"; then
        fail 'bare IPv4 CIDR leaked into sing-box input'
    fi
}

test_rule_pipeline_input_error() {
    local project_dir="$TEST_TMP/filter-error"
    local log_file="$project_dir/update.log"
    local rc=0

    setup_project "$project_dir"
    printf '||keep.test^\n' > "$project_dir/mod/rules/dns-rules.txt"
    rm -f "$project_dir/mod/rules/dns-allowlist.txt"

    run_update "$project_dir" "$log_file" || rc=$?

    if [[ $rc -ne 1 ]]; then
        fail "DNS pipeline input failure was not propagated (actual rc=$rc)"
    fi
    grep -Fq 'DNS pipeline: DNS allowlist file not found' "$log_file" || \
        fail 'DNS pipeline input failure was not diagnosed'
}

test_prune_pipeline_uses_in_memory_coverage_boundary() {
    local project_dir="$TEST_TMP/prune-pipeline"
    local log_file="$project_dir/update.log"

    setup_project "$project_dir"
    cat > "$project_dir/mod/rules/dns-rules.txt" <<'RULES'
||*.example.com^
||sub.example.com^
||keep.test^
RULES

    run_update "$project_dir" "$log_file" \
        DNS_PRUNE_ENABLED=true \
        DNS_PRUNE_RESOLVERS_CN= \
        DNS_PRUNE_RESOLVERS_GLOBAL= \
        STRICT_DNS_PRUNE=false \
        DNS_PRUNE_CACHE_FILE="$project_dir/prune-cache.json" \
        DNS_PRUNE_REMOVED_LOG="$project_dir/prune-removed.log"

    if grep -Fxq '||sub.example.com^' "$project_dir/dns.txt"; then
        fail 'coverage boundary left a covered exact rule in dns.txt'
    fi
    grep -Fq 'Coverage analysis complete' "$log_file" || \
        fail 'prune pipeline did not run coverage analysis'
    if [[ -e "$project_dir/tmp/dns_prune_skip_domains.txt" ]]; then
        fail 'legacy skip-domains temporary file was created'
    fi
}

test_rule_semantics
test_rule_pipeline_input_error
test_prune_pipeline_uses_in_memory_coverage_boundary

printf 'DNS Python stage regression tests passed\n'
