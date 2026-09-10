# Adblock-Rules

English | [简体中文](README_zh-CN.md)

## Rules

- Content filtering
  - `adblock.txt`
- DNS filtering (ABP syntax)
  - `dns.txt`
- Rulesets for proxy tools
  - `adrules-singbox.srs`
  - `adrules-mihomo.mrs`
- Mihomo supplements (for rules that cannot be expressed in MRS)
  - `adrules-mihomo.yaml`

## Notes

- When `dns.txt` is simplified, rules disabled by an equivalent `$badfilter` rule are intentionally omitted.
- Mihomo should load both `adrules-mihomo.mrs` and `adrules-mihomo.yaml`. The latter is a supplement only and cannot be used as a complete ruleset.
- This project includes some relatively aggressive blocking rules. Review them before deciding whether to use them.

## License

This project is licensed under the [GPL-3.0](LICENSE).

The rule data is derived from various upstream filter lists; the most restrictive upstream license is GPL-3.0 (copyleft). See [Source.md](Source.md) for the upstream sources and their respective licenses. EasyList-derived content is attributed to "The EasyList authors (https://easylist.to/)".

`script/compressor.py` is derived from, and `script/remove.py` is inspired by, [Cats-Team/AdRules](https://github.com/Cats-Team/AdRules) (script branch, 0BSD).
