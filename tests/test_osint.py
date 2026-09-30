import ipaddress
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit

import osint


class UpdaterTests(unittest.TestCase):
    def test_new_release_uses_release_archive(self):
        result = type("Result", (), {"returncode": 0})()
        with patch.object(osint, "installed_commit_sha", return_value=None), patch.object(
            osint, "fetch_json", return_value={"tag_name": "v9.0.0"}
        ) as fetch, patch.object(osint.subprocess, "run", return_value=result) as install:
            self.assertEqual(osint.update_application(), 0)
        fetch.assert_called_once_with(osint.GITHUB_RELEASE_API, 15)
        self.assertTrue(install.call_args.args[0][-1].endswith("/refs/tags/v9.0.0.zip"))

    def test_same_version_updates_when_main_has_newer_commit(self):
        commit_sha = "a" * 40
        responses = [
            {"tag_name": f"v{osint.__version__}"},
            {"ahead_by": 2, "commits": [{"sha": "b" * 40}, {"sha": commit_sha}]},
            {"sha": commit_sha},
        ]
        with patch.object(osint, "installed_commit_sha", return_value=None), patch.object(
            osint, "fetch_json", side_effect=responses
        ), patch.object(
            osint.subprocess,
            "run",
            return_value=type("Result", (), {"returncode": 0})(),
        ) as install:
            self.assertEqual(osint.update_application(), 0)
        self.assertEqual(install.call_args.args[0][-1], osint.GITHUB_COMMIT_ARCHIVE_URL.format(sha=commit_sha))

    def test_same_version_and_commit_does_not_install(self):
        responses = [{"tag_name": f"v{osint.__version__}"}, {"ahead_by": 0, "commits": []}]
        with patch.object(osint, "installed_commit_sha", return_value=None), patch.object(
            osint, "fetch_json", side_effect=responses
        ), patch.object(osint.subprocess, "run") as install:
            self.assertEqual(osint.update_application(), 0)
        install.assert_not_called()

    def test_installed_commit_is_comparison_base_and_is_not_reinstalled(self):
        installed_sha = "c" * 40
        responses = [{"tag_name": f"v{osint.__version__}"}, {"ahead_by": 0, "commits": []}]
        with patch.object(osint, "installed_commit_sha", return_value=installed_sha), patch.object(
            osint, "fetch_json", side_effect=responses
        ) as fetch, patch.object(osint.subprocess, "run") as install:
            self.assertEqual(osint.update_application(), 0)
        self.assertEqual(
            fetch.call_args_list[1].args[0],
            osint.GITHUB_COMPARE_API.format(base=installed_sha),
        )
        install.assert_not_called()

    def test_commit_is_read_from_pip_direct_url_metadata(self):
        commit_sha = "d" * 40
        distribution = type(
            "Distribution",
            (),
            {
                "read_text": lambda self, name: json.dumps(
                    {"url": f"https://github.com/example/repo/archive/{commit_sha}.zip"}
                )
            },
        )()
        with patch.object(osint.metadata, "distribution", return_value=distribution):
            self.assertEqual(osint.installed_commit_sha(), commit_sha)


class ShodanTests(unittest.TestCase):
    def setUp(self):
        self.api_key = "test-key-that-must-not-be-saved"
        self.first_ip = int(ipaddress.IPv4Address("8.8.8.1"))

    def page(self, page_number, count=100):
        return {
            "total": 250,
            "matches": [
                {
                    "ip_str": str(ipaddress.IPv4Address(self.first_ip + (page_number - 1) * 100 + index)),
                    "org": "Example ISP",
                    "port": 443,
                    "data": "banner must be filtered",
                }
                for index in range(count)
            ],
        }

    def test_range_validation_and_asn_normalization(self):
        self.assertEqual(osint.valid_public_network("8.8.8.7/24"), "8.8.8.0/24")
        self.assertEqual(osint.valid_public_network("2606:4700::1/120"), "2606:4700::/120")
        self.assertEqual(osint.valid_asn("as15169"), "AS15169")
        for invalid_range in ("10.0.0.0/24", "8.8.0.0/16", "2001:db8::/120"):
            with self.subTest(network=invalid_range), self.assertRaises(osint.argparse.ArgumentTypeError):
                osint.valid_public_network(invalid_range)

    def test_search_paginates_and_filters_sensitive_fields(self):
        def fetch(url, timeout):
            page_number = int(parse_qs(urlsplit(url).query)["page"][0])
            return self.page(page_number, 50 if page_number == 3 else 100)

        with patch.object(osint, "fetch_json", side_effect=fetch) as request:
            report = osint.build_shodan_search_report(
                "8.8.8.0/24", "net:8.8.8.0/24", "ip_range", self.api_key, 5, 250, 0
            )
        self.assertEqual(request.call_count, 3)
        self.assertEqual(report["pages_fetched"], 3)
        self.assertEqual(report["returned_matches"], 250)
        self.assertNotIn("port", report["results"][0])
        self.assertNotIn("banner must be filtered", json.dumps(report))
        self.assertNotIn(self.api_key, json.dumps(report))

    def test_rate_limit_returns_partial_results(self):
        def fetch(url, timeout):
            page_number = int(parse_qs(urlsplit(url).query)["page"][0])
            if page_number == 1:
                return self.page(1)
            raise HTTPError(url, 429, "rate limited", {}, None)

        with patch.object(osint, "fetch_json", side_effect=fetch):
            report = osint.build_shodan_search_report(
                "8.8.8.0/24", "net:8.8.8.0/24", "ip_range", self.api_key, 5, 250, 0
            )
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["returned_matches"], 100)
        self.assertIn("rate limit", report["warning"])

    def test_search_cache_hit_and_key_is_not_persisted(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache_dir = Path(temporary_directory)
            with patch.object(osint, "fetch_json", return_value=self.page(1)) as request:
                first = osint.build_shodan_search_report(
                    "8.8.8.0/24", "net:8.8.8.0/24", "ip_range", self.api_key, 5, 10, 300, cache_dir
                )
                second = osint.build_shodan_search_report(
                    "8.8.8.0/24", "net:8.8.8.0/24", "ip_range", self.api_key, 5, 10, 300, cache_dir
                )
            self.assertEqual(request.call_count, 1)
            self.assertEqual(first["cache"]["status"], "miss")
            self.assertEqual(second["cache"]["status"], "hit")
            for cache_file in cache_dir.glob("*.json"):
                self.assertNotIn(self.api_key, cache_file.name + cache_file.read_text(encoding="utf-8"))
            with patch.object(osint.time, "time", return_value=2_000_000_000):
                self.assertIsNone(
                    osint._read_shodan_cache("ip_range:net:8.8.8.0/24", self.api_key, 10, 300, cache_dir)
                )

    def test_zero_cache_ttl_does_not_write_files(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            cache_dir = Path(temporary_directory)
            with patch.object(osint, "fetch_json", return_value=self.page(1)) as request:
                for _ in range(2):
                    osint.build_shodan_search_report(
                        "8.8.8.0/24", "net:8.8.8.0/24", "ip_range", self.api_key, 5, 10, 0, cache_dir
                    )
            self.assertEqual(request.call_count, 2)
            self.assertEqual(list(cache_dir.iterdir()), [])

    def test_api_key_check_redacts_key_and_unrelated_fields(self):
        response = {
            "plan": "dev",
            "query_credits": 4,
            "scan_credits": 1,
            "api_key": self.api_key,
        }
        with patch.object(osint, "fetch_json", return_value=response):
            report = osint.verify_shodan_api_key(self.api_key)
        self.assertEqual(report["account"], {"plan": "dev", "query_credits": 4, "scan_credits": 1})
        self.assertNotIn(self.api_key, json.dumps(report))


class ReportComparisonTests(unittest.TestCase):
    def test_diff_ignores_timestamps_and_cache_metadata(self):
        before = {
            "target": "example.org",
            "generated_at": "old",
            "cache": {"status": "miss"},
            "sources": {"dns": {"A": ["1.1.1.1"]}, "rdap": {"name": "Example"}},
        }
        after = {
            "target": "example.org",
            "generated_at": "new",
            "cache": {"status": "hit"},
            "sources": {"dns": {"A": ["8.8.8.8"]}, "rdap": {"name": "Example", "country": "US"}},
        }
        report = osint.build_report_diff(before, after)
        self.assertEqual(report["summary"]["changed_fields"], 2)
        self.assertEqual(
            {change["field"] for change in report["changed_fields"]},
            {"sources.dns.A", "sources.rdap.country"},
        )


if __name__ == "__main__":
    unittest.main()
