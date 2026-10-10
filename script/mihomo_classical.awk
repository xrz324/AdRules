        function trim(s) {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", s)
            return s
        }

        function base_rule_for_target(target,    rule, regex, mask, split_pos) {
            if (target ~ /\*/) {
                if (target ~ /^[[:alnum:]*.-]+$/) {
                    rule = "DOMAIN-WILDCARD," target
                } else {
                    regex = target
                    gsub(/\./, "\\.", regex)
                    gsub(/\*/, ".*", regex)
                    if (target ~ /^\*/) {
                        rule = "DOMAIN-REGEX,^" regex "$"
                    } else {
                        rule = "DOMAIN-REGEX,(^|\\.)" regex "$"
                    }
                }
            } else if (target ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$/ ||
                       target ~ /^[0-9a-fA-F:]+(\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?$/) {
                if (target ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$/) {
                    split_pos = index(target, "/")
                    if (split_pos > 0) {
                        mask = substr(target, split_pos + 1)
                    } else {
                        mask = "32"
                    }
                    rule = "IP-CIDR," target
                    if (split_pos == 0) {
                        rule = rule "/" mask
                    }
                } else {
                    split_pos = index(target, "/")
                    if (split_pos > 0) {
                        mask = substr(target, split_pos + 1)
                    } else {
                        mask = "128"
                    }
                    rule = "IP-CIDR6," target
                    if (split_pos == 0) {
                        rule = rule "/" mask
                    }
                }
            } else {
                rule = "DOMAIN-SUFFIX," target
            }
            return rule
        }

        function companion_rule_for_target(target) {
            # Mihomo WILDCARD 匹配完整 hostname；补充前导 *. 才能保留 ABP ||
            # 从任意子域边界开始匹配的语义。
            if (target ~ /\*/ && target !~ /^\*/ && target ~ /^[[:alnum:]*.-]+$/) {
                return "DOMAIN-WILDCARD,*." target
            }
            return ""
        }

        function clear_array(arr,    k) {
            for (k in arr) {
                delete arr[k]
            }
        }

        function ipv4_to_int(a, b, c, d) {
            return a * 16777216 + b * 65536 + c * 256 + d
        }

        function int_to_ipv4(v,    a, b, c, d, r) {
            a = int(v / 16777216)
            r = v - a * 16777216
            b = int(r / 65536)
            r = r - b * 65536
            c = int(r / 256)
            d = r - c * 256
            return a "." b "." c "." d
        }

        function append_cidr_rule(rule) {
            if (!(rule in cidr_seen)) {
                cidr_seen[rule] = 1
                cidr_rules[++cidr_count] = rule
            }
        }

        function append_port_rule(rule) {
            if (!(rule in port_seen)) {
                port_seen[rule] = 1
                port_rules[++port_count] = rule
            }
        }

        function emit_port_range(start_port, end_port) {
            if (start_port <= 0 || end_port > 65535 || start_port > end_port) {
                return
            }
            if (start_port == end_port) {
                append_port_rule("DST-PORT," start_port)
            } else {
                append_port_rule("DST-PORT," start_port "-" end_port)
            }
        }

        function range_to_cidr_rules(start_ip, end_ip,    block, remain, p2, prefix) {
            while (start_ip <= end_ip) {
                block = 1
                while ((start_ip % (block * 2) == 0) && (block * 2 > 0)) {
                    block *= 2
                }

                remain = end_ip - start_ip + 1
                while (block > remain) {
                    block /= 2
                }

                prefix = 32
                p2 = block
                while (p2 > 1) {
                    p2 /= 2
                    prefix--
                }

                append_cidr_rule("IP-CIDR," int_to_ipv4(start_ip) "/" prefix)
                start_ip += block
            }
        }

        function collect_octet_values(token, out_values,    v, expr, cnt) {
            clear_array(out_values)
            token = trim(token)
            if (token == "") {
                return 0
            }

            if (token ~ /^[0-9]{1,3}$/) {
                v = token + 0
                if (v < 0 || v > 255) {
                    return 0
                }
                out_values[v] = 1
                return 1
            }

            if (token == "\\d{1,3}" || token == "\\d{3}" || token == "\\d+" ||
                token == "[0-9]{1,3}" || token == "[0-9]{3}" || token == "[0-9]+") {
                for (v = 0; v <= 255; v++) {
                    out_values[v] = 1
                }
                return 1
            }

            expr = token
            gsub(/\\d/, "[0-9]", expr)
            if (expr ~ /\\[A-CE-Za-ce-z]/) {
                return 0
            }

            cnt = 0
            for (v = 0; v <= 255; v++) {
                if (sprintf("%d", v) ~ ("^(" expr ")$")) {
                    out_values[v] = 1
                    cnt++
                }
            }
            return cnt > 0
        }

        function collect_port_values(token, out_values,    v, expr, cnt) {
            clear_array(out_values)
            token = trim(token)
            if (token == "") {
                return 0
            }

            if (substr(token, 1, 1) == "(" && substr(token, length(token), 1) == ")") {
                token = trim(substr(token, 2, length(token) - 2))
            }
            if (token == "") {
                return 0
            }

            if (token ~ /^[0-9]{1,5}$/) {
                v = token + 0
                if (v <= 0 || v > 65535) {
                    return 0
                }
                out_values[v] = 1
                return 1
            }

            if (token == "\\d{1,5}" || token == "\\d+" ||
                token == "[0-9]{1,5}" || token == "[0-9]+") {
                for (v = 1; v <= 65535; v++) {
                    out_values[v] = 1
                }
                return 1
            }

            expr = token
            gsub(/\\d/, "[0-9]", expr)
            if (expr ~ /\\[A-CE-Za-ce-z]/) {
                return 0
            }

            cnt = 0
            for (v = 1; v <= 65535; v++) {
                if (sprintf("%d", v) ~ ("^(" expr ")$")) {
                    out_values[v] = 1
                    cnt++
                }
            }
            return cnt > 0
        }

        function port_values_to_rules(values,    v, in_range, start_v) {
            in_range = 0

            for (v = 1; v <= 65535; v++) {
                if (v in values) {
                    if (!in_range) {
                        in_range = 1
                        start_v = v
                    }
                } else if (in_range) {
                    emit_port_range(start_v, v - 1)
                    in_range = 0
                }
            }

            if (in_range) {
                emit_port_range(start_v, 65535)
            }
        }

        function values_to_ranges(values, out_starts, out_ends,    v, in_range, start_v, n) {
            clear_array(out_starts)
            clear_array(out_ends)
            in_range = 0
            n = 0

            for (v = 0; v <= 255; v++) {
                if (v in values) {
                    if (!in_range) {
                        in_range = 1
                        start_v = v
                    }
                } else if (in_range) {
                    n++
                    out_starts[n] = start_v
                    out_ends[n] = v - 1
                    in_range = 0
                }
            }

            if (in_range) {
                n++
                out_starts[n] = start_v
                out_ends[n] = 255
            }
            return n
        }

        function octet_rectangle_is_contiguous(a_start, a_end, b_start, b_end, c_start, c_end, d_start, d_end) {
            if (a_start < a_end) {
                return (b_start == 0 && b_end == 255 &&
                        c_start == 0 && c_end == 255 &&
                        d_start == 0 && d_end == 255)
            }
            if (b_start < b_end) {
                return (c_start == 0 && c_end == 255 &&
                        d_start == 0 && d_end == 255)
            }
            if (c_start < c_end) {
                return (d_start == 0 && d_end == 255)
            }
            return 1
        }

        function regex_to_precise_ip_rule(regex,    normalized, parts, n, suffix, port_expr, colon_pos, a, b, c, d, i1, i2, i3, i4, n1, n2, n3, n4, start_ip, end_ip) {
            cidr_count = 0
            clear_array(cidr_rules)
            clear_array(cidr_seen)
            port_count = 0
            clear_array(port_rules)
            clear_array(port_seen)

            if (regex == "") {
                return 0
            }
            if (substr(regex, 1, 1) != "^") {
                return 0
            }

            normalized = substr(regex, 2)
            if (substr(normalized, length(normalized), 1) != "$") {
                return 0
            }
            normalized = substr(normalized, 1, length(normalized) - 1)
            gsub(/\\\./, ".", normalized)

            if (normalized ~ /^[0-9A-Fa-f:]+$/ && normalized ~ /:/) {
                if (normalized !~ /:::/) {
                    append_cidr_rule("IP-CIDR6," normalized "/128")
                    return 1
                }
                return 0
            }

            n = split(normalized, parts, ".")
            if (n != 4) {
                return 0
            }

            suffix = ""
            colon_pos = index(parts[4], ":")
            if (colon_pos > 0) {
                suffix = substr(parts[4], colon_pos)
                parts[4] = substr(parts[4], 1, colon_pos - 1)
            }
            if (parts[4] == "") {
                return 0
            }
            if (suffix != "") {
                if (suffix == ":") {
                    # 仅匹配 host:，不附加端口条件
                } else {
                    if (substr(suffix, 1, 1) != ":") {
                        return 0
                    }
                    port_expr = substr(suffix, 2)
                    if (!collect_port_values(port_expr, port_values)) {
                        return 0
                    }
                    port_values_to_rules(port_values)
                    if (port_count == 0) {
                        return 0
                    }
                }
            }

            if (!collect_octet_values(parts[1], octet_values_1) ||
                !collect_octet_values(parts[2], octet_values_2) ||
                !collect_octet_values(parts[3], octet_values_3) ||
                !collect_octet_values(parts[4], octet_values_4)) {
                return 0
            }

            n1 = values_to_ranges(octet_values_1, octet_start_1, octet_end_1)
            n2 = values_to_ranges(octet_values_2, octet_start_2, octet_end_2)
            n3 = values_to_ranges(octet_values_3, octet_start_3, octet_end_3)
            n4 = values_to_ranges(octet_values_4, octet_start_4, octet_end_4)
            if (n1 == 0 || n2 == 0 || n3 == 0 || n4 == 0) {
                return 0
            }

            for (i1 = 1; i1 <= n1; i1++) {
                for (i2 = 1; i2 <= n2; i2++) {
                    for (i3 = 1; i3 <= n3; i3++) {
                        for (i4 = 1; i4 <= n4; i4++) {
                            if (!octet_rectangle_is_contiguous(octet_start_1[i1], octet_end_1[i1], octet_start_2[i2], octet_end_2[i2], octet_start_3[i3], octet_end_3[i3], octet_start_4[i4], octet_end_4[i4])) {
                                return 0
                            }

                            a = octet_start_1[i1]
                            b = octet_start_2[i2]
                            c = octet_start_3[i3]
                            d = octet_start_4[i4]
                            start_ip = ipv4_to_int(a, b, c, d)

                            a = octet_end_1[i1]
                            b = octet_end_2[i2]
                            c = octet_end_3[i3]
                            d = octet_end_4[i4]
                            end_ip = ipv4_to_int(a, b, c, d)

                            if (start_ip > end_ip) {
                                return 0
                            }
                            range_to_cidr_rules(start_ip, end_ip)
                        }
                    }
                }
            }

            if (cidr_count == 0) {
                return 0
            }
            return 1
        }

        function regex_looks_domain_related(regex, normalized, probe) {
            if (regex == "") {
                return 0
            }
            normalized = regex
            gsub(/\\\//, "/", normalized)

            if (normalized ~ /\//) {
                return 0
            }
            if (normalized ~ /\$[[:alnum:]_-]+([=,]|$)/) {
                return 0
            }
            if (normalized ~ /,replace=/) {
                return 0
            }
            if (normalized ~ /(https?|ftp|wss?):\/\//) {
                return 0
            }
            if (normalized ~ /:/) {
                return 0
            }
            if (normalized ~ /\\x[0-9a-fA-F]{2}/) {
                return 0
            }

            probe = normalized
            gsub(/\\[dDsSwWbB]/, "", probe)

            if (probe !~ /[A-Za-z]/) {
                return 0
            }
            return 1
        }

        function parse_line(line,    mods, core, caret_pos, suffix, mod_sep, search_from, rel_pos) {
            p_type = ""
            p_core = ""
            p_mods = ""
            p_regex = ""
            p_domain = ""

            line = trim(line)
            if (line == "" || line ~ /^(!|\[)/) {
                return 0
            }

            if (line ~ /^\/.*\/(\$.*)?$/) {
                mods = ""
                core = line
                mod_sep = 0
                search_from = 1
                while (1) {
                    rel_pos = index(substr(line, search_from), "/$")
                    if (rel_pos == 0) {
                        break
                    }
                    mod_sep = search_from + rel_pos - 1
                    search_from = mod_sep + 2
                }
                if (mod_sep > 0) {
                    core = substr(line, 1, mod_sep)
                    mods = substr(line, mod_sep + 1)
                }

                if (substr(core, 1, 1) != "/" || substr(core, length(core), 1) != "/") {
                    return 0
                }
                p_type = "regex"
                p_core = core
                p_mods = mods
                p_regex = substr(core, 2, length(core) - 2)
                return 1
            }

            if (line ~ /^\|\|.+\^(\$.*)?$/) {
                mods = ""
                caret_pos = index(line, "^")
                if (caret_pos <= 3) {
                    return 0
                }

                p_domain = trim(substr(line, 3, caret_pos - 3))
                suffix = substr(line, caret_pos + 1)
                if (substr(suffix, 1, 1) == "$") {
                    mods = suffix
                }
                if (p_domain == "" || p_domain ~ /[[:space:]]/) {
                    return 0
                }

                p_type = "domain"
                p_core = substr(line, 1, caret_pos)
                p_mods = mods
                return 1
            }

            if (line ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}\/([0-9]|[1-2][0-9]|3[0-2])$/) {
                p_type = "ip_cidr"
                p_core = line
                p_domain = line
                return 1
            }

            if (line ~ /^[[:alnum:]_-]+([.-][[:alnum:]_-]+)+$/) {
                p_type = "plain"
                p_core = line
                p_domain = line
                return 1
            }

            return 0
        }

        function analyze_modifiers(mods,    raw, tokens, n, i, token, name, value) {
            m_badfilter = 0
            m_unsupported = 0
            m_denyallow = ""

            if (mods == "" || mods == "$") {
                return
            }

            raw = substr(mods, 2)
            n = split(raw, tokens, /,/)

            for (i = 1; i <= n; i++) {
                token = trim(tokens[i])
                if (token == "") {
                    continue
                }

                name = token
                sub(/=.*/, "", name)
                if (substr(name, 1, 1) == "~") {
                    name = substr(name, 2)
                }

                if (name == "badfilter") {
                    m_badfilter = 1
                    continue
                }

                if (name == "important") {
                    continue
                }

                if (name == "denyallow") {
                    if (token !~ /^[^=]+=.+$/) {
                        m_unsupported = 1
                        continue
                    }
                    value = token
                    sub(/^[^=]*=/, "", value)
                    if (value == "") {
                        m_unsupported = 1
                        continue
                    }
                    m_denyallow = value
                    continue
                }

                if (name == "client" || name == "ctag" || name == "dnstype" || name == "dnsrewrite") {
                    m_unsupported = 1
                    continue
                }

                m_unsupported = 1
            }
        }

        function canonical_modifiers(mods, drop_badfilter,    raw, tokens, n, i, j, token, count, result) {
            raw = substr(mods, 2)
            n = split(raw, tokens, /,/)
            count = 0
            for (i = 1; i <= n; i++) {
                token = trim(tokens[i])
                if (token == "" || (drop_badfilter && tolower(token) == "badfilter")) {
                    continue
                }
                count++
                tokens[count] = token
            }
            for (i = 2; i <= count; i++) {
                token = tokens[i]
                j = i - 1
                while (j >= 1 && tokens[j] > token) {
                    tokens[j + 1] = tokens[j]
                    j--
                }
                tokens[j + 1] = token
            }
            if (count == 0) {
                return ""
            }
            result = "$" tokens[1]
            for (i = 2; i <= count; i++) {
                result = result "," tokens[i]
            }
            return result
        }

        function denyallow_expr_from_value(deny_raw,    parts, i, item, piece, companion, allow_expr, count) {
            count = split(deny_raw, parts, /\|/)
            allow_expr = ""

            for (i = 1; i <= count; i++) {
                item = trim(parts[i])
                if (item == "" || item ~ /^~/) {
                    continue
                }
                piece = base_rule_for_target(item)
                if (piece == "") {
                    continue
                }
                companion = companion_rule_for_target(item)
                if (companion != "") {
                    piece = "OR,((" piece "),(" companion "))"
                }
                if (allow_expr != "") {
                    allow_expr = allow_expr ","
                }
                allow_expr = allow_expr "(" piece ")"
            }

            if (allow_expr == "") {
                return ""
            }
            return "NOT,(" allow_expr ")"
        }

        function join_logic_expr(op, terms, term_count,    expr, i) {
            if (term_count <= 0) {
                return ""
            }
            expr = terms[1]
            for (i = 2; i <= term_count; i++) {
                expr = op ",((" expr "),(" terms[i] "))"
            }
            return expr
        }

        function build_port_expr(    terms, i) {
            if (port_count <= 0) {
                return ""
            }
            clear_array(terms)
            for (i = 1; i <= port_count; i++) {
                terms[i] = port_rules[i]
            }
            return join_logic_expr("OR", terms, port_count)
        }

        function combine_with_and(base_expr, extra_expr, deny_expr,    terms, count) {
            clear_array(terms)
            count = 0
            if (base_expr != "") {
                terms[++count] = base_expr
            }
            if (extra_expr != "") {
                terms[++count] = extra_expr
            }
            if (deny_expr != "") {
                terms[++count] = deny_expr
            }
            if (count == 0) {
                return ""
            }
            if (count == 1) {
                return terms[1]
            }
            return join_logic_expr("AND", terms, count)
        }

        {
            lines[++total] = $0
        }

        END {
            for (i = 1; i <= total; i++) {
                if (!parse_line(lines[i])) {
                    continue
                }
                analyze_modifiers(p_mods)
                if (m_badfilter == 1) {
                    disabled[p_core SUBSEP canonical_modifiers(p_mods, 1)] = 1
                }
            }

            for (i = 1; i <= total; i++) {
                if (!parse_line(lines[i])) {
                    continue
                }
                analyze_modifiers(p_mods)

                if (m_badfilter == 1) {
                    skipped_badfilter++
                    continue
                }
                if (disabled[p_core SUBSEP canonical_modifiers(p_mods, 0)] == 1) {
                    skipped_badfilter++
                    continue
                }
                if (m_unsupported == 1) {
                    skipped_unsupported++
                    continue
                }

                companion_rule = ""

                if (p_type == "regex") {
                    if (p_regex == "") {
                        continue
                    }
                    ip_rule_mode = ""
                    if (regex_to_precise_ip_rule(p_regex)) {
                        ip_rule_mode = "precise"
                    }

                    if (ip_rule_mode != "") {
                        converted_ip_regex++
                        deny_expr = ""
                        if (m_denyallow != "") {
                            deny_expr = denyallow_expr_from_value(m_denyallow)
                            if (deny_expr == "") {
                                skipped_unsupported++
                                continue
                            }
                        }
                        port_expr = ""
                        if (ip_rule_mode == "precise" && port_count > 0) {
                            port_expr = build_port_expr()
                            if (port_expr == "") {
                                skipped_unsupported++
                                continue
                            }
                            converted_ip_port_regex++
                        }

                        for (r = 1; r <= cidr_count; r++) {
                            final_rule = combine_with_and(cidr_rules[r], port_expr, deny_expr)
                            if (final_rule == "") {
                                skipped_unsupported++
                                continue
                            }
                            print final_rule
                        }
                        continue
                    } else {
                        if (!regex_looks_domain_related(p_regex)) {
                            skipped_non_domain_regex++
                            continue
                        }
                        base_rule = "DOMAIN-REGEX," p_regex
                    }
                } else if (p_type == "domain" || p_type == "plain" || p_type == "ip_cidr") {
                    base_rule = base_rule_for_target(p_domain)
                    if (base_rule == "") {
                        skipped_unsupported++
                        continue
                    }
                    companion_rule = companion_rule_for_target(p_domain)
                } else {
                    continue
                }

                if (m_denyallow != "") {
                    deny_expr = denyallow_expr_from_value(m_denyallow)
                    if (deny_expr == "") {
                        skipped_unsupported++
                        continue
                    }
                    if (companion_rule != "") {
                        base_rule = "OR,((" base_rule "),(" companion_rule "))"
                    }
                    print combine_with_and(base_rule, "", deny_expr)
                } else {
                    print base_rule
                    if (companion_rule != "") {
                        print companion_rule
                    }
                }
            }

            if (skipped_unsupported > 0) {
                print "[INFO] Mihomo skipped unsupported modifiers: " skipped_unsupported > "/dev/stderr"
                if (ENVIRON["STRICT_MIHOMO_MODIFIERS"] == "true") {
                    print "[ERROR] STRICT_MIHOMO_MODIFIERS=true; unsupported modifiers detected; aborting Mihomo conversion" > "/dev/stderr"
                    exit 2
                }
            }
            if (skipped_badfilter > 0) {
                print "[INFO] Mihomo skipped badfilter rules: " skipped_badfilter > "/dev/stderr"
            }
            if (skipped_non_domain_regex > 0) {
                print "[INFO] Mihomo skipped non-domain regex rules: " skipped_non_domain_regex > "/dev/stderr"
            }
            if (converted_ip_regex > 0 || converted_ip_port_regex > 0) {
                print "[INFO] Mihomo converted IP regex rules: CIDR=" converted_ip_regex " CIDR+PORT=" converted_ip_port_regex > "/dev/stderr"
            }
        }
