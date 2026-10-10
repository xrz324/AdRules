import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from script import remove


class RemoveWhitelistTest(unittest.TestCase):
    def load_entries(self, content: str):
        with tempfile.TemporaryDirectory() as tmp_dir:
            whitelist_path = Path(tmp_dir) / "allowlist.txt"
            whitelist_path.write_text(content, encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                return remove.load_whitelist(str(whitelist_path))

    def clean_rules(self, whitelist: str, rules: str) -> str:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            whitelist_path = tmp_path / "allowlist.txt"
            blacklist_path = tmp_path / "blocklist.txt"
            whitelist_path.write_text(whitelist, encoding="utf-8")
            blacklist_path.write_text(rules, encoding="utf-8")

            with contextlib.redirect_stdout(io.StringIO()):
                plain_domains, regex_rules = remove.load_whitelist(str(whitelist_path))
                remove.clean_blacklist(
                    str(blacklist_path),
                    plain_domains,
                    regex_rules,
                )
            return blacklist_path.read_text(encoding="utf-8")

    def test_plain_domain_is_normalized_for_exact_matching(self):
        result = self.clean_rules(
            "Allowed.Example.\n",
            "||ALLOWED.EXAMPLE.^\n||unrelated.test^\n",
        )

        self.assertEqual(result, "||unrelated.test^\n")

    def test_abp_domain_does_not_match_unrelated_domains(self):
        plain_domains, regex_rules = self.load_entries("||allowed.example^\n")

        self.assertEqual(plain_domains, {"allowed.example"})
        self.assertEqual(regex_rules, [])
        result = self.clean_rules(
            "||allowed.example^\n",
            "||allowed.example^\n||unrelated.test^\n",
        )
        self.assertEqual(result, "||unrelated.test^\n")

    def test_exception_abp_domain_is_supported(self):
        plain_domains, regex_rules = self.load_entries("@@||Allowed.Example.^\n")

        self.assertEqual(plain_domains, {"allowed.example"})
        self.assertEqual(regex_rules, [])

    def test_delimited_regex_matches_only_its_domain_pattern(self):
        result = self.clean_rules(
            "/^ads\\.[^.]+\\.example$/\n",
            "||ads.mobile.example^\n||xads.mobile.example^\n",
        )

        self.assertEqual(result, "||xads.mobile.example^\n")

    def test_invalid_and_empty_matching_regexes_are_rejected(self):
        plain_domains, regex_rules = self.load_entries(
            "/.*/\n/[unterminated/\n//\n"
        )

        self.assertEqual(plain_domains, set())
        self.assertEqual(regex_rules, [])

    def test_wildcard_is_not_accepted_as_an_exact_domain(self):
        plain_domains, regex_rules = self.load_entries(
            "*.example.com\n||*.example.com^\n"
        )

        self.assertEqual(plain_domains, set())
        self.assertEqual(regex_rules, [])

    def test_missing_allowlist_raises_library_error(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            with self.assertRaises(remove.RemoveError):
                remove.load_whitelist(str(Path(tmp_dir) / "missing.txt"))


if __name__ == "__main__":
    unittest.main()
