# Adblock-Rules

[English](README.md) | 简体中文

## 规则

- 内容过滤
  - `adblock.txt`
- DNS 过滤（ABP 语法）
  - `dns.txt`
- 代理工具规则集
  - `adrules-singbox.srs`
  - `adrules-mihomo.mrs`
- Mihomo 补充（用于覆盖 MRS 无法表达的规则）
  - `adrules-mihomo.yaml`

## 注意事项

- `dns.txt` 简化时，被等价 `$badfilter` 禁用的规则会被有意省略。
- Mihomo 应同时加载 `adrules-mihomo.mrs` 和 `adrules-mihomo.yaml`，后者仅为补充文件，不能作为完整规则使用。
- 本项目添加了一些较为激进的拦截规则，请评估后决定是否使用。

## 许可证

本项目以 [GPL-3.0](LICENSE) 许可发布。

规则数据由多个上游列表派生而来，其中最严格的上游许可是 GPL-3.0（copyleft）。上游来源及各自许可证见 [Source.md](Source.md)。源自 EasyList 的内容依其要求署名 "The EasyList authors (https://easylist.to/)"。

`script/compressor.py` 衍生自，`script/remove.py` 参考了 [Cats-Team/AdRules](https://github.com/Cats-Team/AdRules)（script 分支，0BSD）。
