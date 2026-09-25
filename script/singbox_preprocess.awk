        function trim(s) {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", s)
            return s
        }

        function modifiers_supported(mods,    raw, parts, n, i, token, name) {
            mods = trim(mods)
            if (mods == "") {
                return 1
            }
            if (substr(mods, 1, 1) != "$") {
                return 0
            }

            raw = substr(mods, 2)
            if (raw == "") {
                return 0
            }

            n = split(raw, parts, /,/)
            for (i = 1; i <= n; i++) {
                token = trim(parts[i])
                if (token == "") {
                    continue
                }
                if (substr(token, 1, 1) == "~") {
                    return 0
                }

                name = token
                sub(/=.*/, "", name)

                if (name == "important") {
                    continue
                }
                if (name == "dnsrewrite") {
                    if (token == "dnsrewrite=0.0.0.0") {
                        continue
                    }
                    return 0
                }
                return 0
            }
            return 1
        }

        function badfilter_target(line,    mods, core, mod_sep, search_from, rel_pos, caret_pos, suffix, raw, parts, n, i, token, remaining, found_badfilter) {
            line = trim(line)
            mods = ""
            core = line

            if (line ~ /^\/.*\/(\$[^[:space:]]+)?$/) {
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
                if (mod_sep <= 0) {
                    return ""
                }
                core = substr(line, 1, mod_sep)
                mods = substr(line, mod_sep + 1)
            } else if (line ~ /^\|\|.+\^(\$[^[:space:]]+)?$/) {
                caret_pos = index(line, "^")
                if (caret_pos <= 3) {
                    return ""
                }
                suffix = substr(line, caret_pos + 1)
                if (substr(suffix, 1, 1) != "$") {
                    return ""
                }
                core = substr(line, 1, caret_pos)
                mods = suffix
            } else {
                return ""
            }

            raw = substr(mods, 2)
            n = split(raw, parts, /,/)
            remaining = ""
            found_badfilter = 0
            for (i = 1; i <= n; i++) {
                token = trim(parts[i])
                if (tolower(token) == "badfilter") {
                    found_badfilter = 1
                    continue
                }
                if (token == "") {
                    continue
                }
                if (remaining != "") {
                    remaining = remaining ","
                }
                remaining = remaining token
            }

            if (!found_badfilter) {
                return ""
            }
            if (remaining == "") {
                return core
            }
            return core "$" remaining
        }

        function regex_is_ip_related(regex,    normalized, compact) {
            normalized = trim(regex)
            compact = normalized
            gsub(/\\\./, ".", compact)
            gsub(/\\d/, "0", compact)

            if (normalized ~ /(^|[^[:alnum:]_])[0-9]{1,3}\\\.[0-9]{1,3}\\\./) {
                return 1
            }
            if (compact ~ /(^|[^[:alnum:]_])[0-9]{1,3}\.[0-9]{1,3}\./) {
                return 1
            }
            if (compact ~ /(^|[^[:alnum:]_])[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,}/) {
                return 1
            }

            if (compact ~ /^[\^$0-9A-Fa-f.,:[\]{}()|+*?-]+$/) {
                if (compact ~ /[0-9]/ && (compact ~ /\./ || compact ~ /:/)) {
                    return 1
                }
            }
            return 0
        }

        NR == FNR {
            disabled_rule = badfilter_target($0)
            if (disabled_rule != "") {
                disabled[disabled_rule] = 1
            }
            next
        }

        {
            line = trim($0)
            sub(/\r$/, "", line)
            if (line == "" || line ~ /^!/) {
                next
            }

            if (line ~ /^\/.*\/(\$[^[:space:]]+)?$/) {
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

                if (line in disabled) {
                    skipped_badfilter_targets++
                    next
                }

                if (!modifiers_supported(mods)) {
                    skipped_modifiers++
                    next
                }

                regex = substr(core, 2, length(core) - 2)
                if (regex_is_ip_related(regex)) {
                    skipped_ip_regex++
                    next
                }

                print line
                kept_rules++
                next
            }

            if (line ~ /^\|\|.+\^(\$[^[:space:]]+)?$/) {
                mods = ""
                caret_pos = index(line, "^")
                if (caret_pos <= 3) {
                    skipped_unknown++
                    next
                }

                suffix = substr(line, caret_pos + 1)
                if (substr(suffix, 1, 1) == "$") {
                    mods = suffix
                }

                if (line in disabled) {
                    skipped_badfilter_targets++
                    next
                }

                if (mods != "" && !modifiers_supported(mods)) {
                    skipped_modifiers++
                    next
                }

                print line
                kept_rules++
                next
            }

            if (line ~ /^[[:alnum:]_-]+([.-][[:alnum:]_-]+)+$/) {
                print line
                kept_rules++
                next
            }

            skipped_unknown++
        }

        END {
            print "[INFO] sing-box preprocessing: kept=" kept_rules " skipped-modifier=" skipped_modifiers " skipped-badfilter-target=" skipped_badfilter_targets " skipped-ip=" skipped_ip_regex " skipped-unknown=" skipped_unknown > "/dev/stderr"
        }
