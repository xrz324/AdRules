        function trim(s) {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", s)
            return s
        }

        {
            line = trim($0)
            if (line == "") {
                next
            }

            if (line ~ /^DOMAIN-SUFFIX,/) {
                value = trim(substr(line, length("DOMAIN-SUFFIX,") + 1))
                if (value != "") {
                    print "+." value >> domain_file
                }
                next
            }

            if (line ~ /^DOMAIN-WILDCARD,/) {
                value = trim(substr(line, length("DOMAIN-WILDCARD,") + 1))
                if (value != "") {
                    # Classical DOMAIN-WILDCARD 的 * 可跨点匹配任意字符；domain
                    # rule-set 用前导 . 表示任意层级子域且不包含根域。
                    if (value ~ /^\*\.[[:alnum:]_-]+([.-][[:alnum:]_-]+)+$/) {
                        print substr(value, 2) >> domain_file
                    } else {
                        print line >> yaml_raw_file
                    }
                }
                next
            }

            if (line ~ /^DOMAIN,/) {
                value = trim(substr(line, length("DOMAIN,") + 1))
                if (value != "") {
                    print value >> domain_file
                }
                next
            }

            print line >> yaml_raw_file
        }
