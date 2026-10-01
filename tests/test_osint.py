import ipaddress
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit

import osint


class PublicLookupTests(unittest.TestCase):
    def test_dns_falls_back_to_google(self):
        response = {"Status": 0, "Answer": [{"data": "93.184.216.34"}, "invalid"]}
        with patch.object(
            osint,
            "fetch_json",
            side_effect=[URLError("Cloudflare unavailable"), response],
        ) as fetch:
            result = osint.lookup_dns("example.org", "A", 5)
        self.assertEqual(fetch.call_count, 2)
        self.assertIn("dns.google", fetch.call_args_list[1].args[0])
        self.assertEqual(result["provider"], "Google")
        self.assertEqual(result["answers"], ["93.184.216.34"])

    def test_certificate_lookup_falls_back_to_cert_spotter(self):
        response = [{
            "id": "123",
            "dns_names": ["example.org", "www.example.org"],
            "issuer": {"name": "Example CA"},
            "not_before": "2026-01-01T00:00:00Z",
            "not_after": "2026-04-01T00:00:00Z",
        }]
        error = HTTPError("https://crt.sh", 502, "Bad Gateway", {}, None)
        with patch.object(osint, "fetch_json", side_effect=[error, response]) as fetch:
            result = osint.lookup_certificates("example.org", 5)
        self.assertEqual(fetch.call_count, 2)
        self.assertIn("api.certspotter.com", fetch.call_args_list[1].args[0])
        self.assertEqual(result["provider"], "Cert Spotter")
        self.assertEqual(result["records"][0]["issuer"], "Example CA")
        self.assertEqual(result["records"][0]["names"], ["example.org", "www.example.org"])

    def test_crt_sh_response_is_normalized(self):
        response = [{
            "id": 123,
            "name_value": "example.org\nwww.example.org",
            "issuer_name": "Example CA",
            "not_before": "2026-01-01",
            "not_after": "2026-04-01",
        }]
        with patch.object(osint, "fetch_json", return_value=response):
            result = osint.lookup_certificates("example.org", 5)
        self.assertEqual(result["provider"], "crt.sh")
        self.assertEqual(result["records"][0]["names"], ["example.org", "www.example.org"])


class ProfileTests(unittest.TestCase):
    def test_bug_bounty_providers_require_exact_username(self):
        cases = {
            "Bugcrowd": ("username", "Researcher"),
            "YesWeHack": ("slug", "Researcher"),
            "Intigriti": ("userName", "Researcher"),
        }
        for provider, (field, returned_name) in cases.items():
            with patch.object(osint, "fetch_json", return_value={field: returned_name}):
                self.assertTrue(osint.lookup_bug_bounty_profile(provider, "researcher", 5))
            with patch.object(osint, "fetch_json", return_value={field: "another-user"}):
                self.assertFalse(osint.lookup_bug_bounty_profile(provider, "researcher", 5))

    def test_hackerone_requires_exact_https_profile_response(self):
        class Headers:
            def get_content_type(self):
                return self.content_type

            def __init__(self, content_type):
                self.content_type = content_type

        class Response:
            status = 200

            def __init__(self, url, content_type="text/html"):
                self.url = url
                self.headers = Headers(content_type)

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def geturl(self):
                return self.url

        cases = (
            ("https://hackerone.com/researcher?type=user", "text/html", True),
            ("https://hackerone.com/another-user?type=user", "text/html", False),
            ("https://example.org/researcher?type=user", "text/html", False),
            ("http://hackerone.com/researcher?type=user", "text/html", False),
            ("https://hackerone.com/researcher?type=user", "application/json", False),
        )
        for final_url, content_type, expected in cases:
            response = Response(final_url, content_type)
            with patch.object(osint, "urlopen", return_value=response):
                actual = osint.lookup_bug_bounty_profile("HackerOne", "researcher", 5)
            self.assertEqual(actual, expected, final_url)

    def test_missing_hackerone_profile_is_not_reported(self):
        error = HTTPError("https://hackerone.com/missing", 404, "Not Found", {}, None)
        with patch.object(osint, "urlopen", side_effect=error):
            self.assertFalse(osint.lookup_bug_bounty_profile("HackerOne", "missing", 5))

    def test_missing_bug_bounty_profile_is_not_reported(self):
        error = HTTPError("https://example.test", 404, "Not Found", {}, None)
        with patch.object(osint, "fetch_json", side_effect=error):
            self.assertFalse(osint.lookup_bug_bounty_profile("Bugcrowd", "missing", 5))

    def test_username_search_uses_current_bug_bounty_paths(self):
        report = osint.build_search_report("researcher", "username")
        queries = {item["source"]: item["query"] for item in report["searches"]}
        self.assertEqual(queries["Bugcrowd"], "site:bugcrowd.com/h/researcher")
        self.assertEqual(queries["YesWeHack"], "site:yeswehack.com/hunters/researcher")
        self.assertEqual(queries["Intigriti"], "site:app.intigriti.com/profile/researcher")


class LocalReportTests(unittest.TestCase):
    def test_indicator_classification_and_privacy_guards(self):
        self.assertEqual(osint.classify_indicator("example.org"), ("domain", "example.org"))
        self.assertEqual(osint.classify_indicator("8.8.8.8"), ("ip", "8.8.8.8"))
        self.assertEqual(osint.classify_indicator("A" * 64), ("hash", "a" * 64))
        self.assertEqual(osint.classify_indicator("https://example.org/path"), ("url", "https://example.org/path"))
        for unsafe in (
            "https://user:password@example.org/",
            "https://example.org/?token=secret",
            "https://127.0.0.1/",
        ):
            with self.assertRaises(osint.argparse.ArgumentTypeError):
                osint.classify_indicator(unsafe)

    def test_phone_report_uses_only_local_numbering_metadata(self):
        report = osint.build_phone_report("+14155552671")
        self.assertEqual(report["e164"], "+14155552671")
        self.assertEqual(report["region_code"], "US")
        self.assertIn("no owner lookup", report["mode"])


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
