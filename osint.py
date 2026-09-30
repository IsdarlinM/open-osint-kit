#!/usr/bin/env python3
"""Passive, public-source OSINT helpers for authorized domain research."""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections.abc import Callable
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, urlopen

import phonenumbers


__version__ = "1.3.0"
USER_AGENT = f"OpenOSINTKit/{__version__} (passive public-source research)"
GITHUB_RELEASE_API = "https://api.github.com/repos/IsdarlinM/open-osint-kit/releases/latest"
GITHUB_ARCHIVE_URL = "https://github.com/IsdarlinM/open-osint-kit/archive/refs/tags/{tag}.zip"
DNS_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CAA")
PHONE_NUMBER_TYPES = {
    phonenumbers.PhoneNumberType.FIXED_LINE: "fixed_line",
    phonenumbers.PhoneNumberType.MOBILE: "mobile",
    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_line_or_mobile",
    phonenumbers.PhoneNumberType.TOLL_FREE: "toll_free",
    phonenumbers.PhoneNumberType.PREMIUM_RATE: "premium_rate",
    phonenumbers.PhoneNumberType.SHARED_COST: "shared_cost",
    phonenumbers.PhoneNumberType.VOIP: "voip",
    phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "personal_number",
    phonenumbers.PhoneNumberType.PAGER: "pager",
    phonenumbers.PhoneNumberType.UAN: "uan",
    phonenumbers.PhoneNumberType.VOICEMAIL: "voicemail",
    phonenumbers.PhoneNumberType.UNKNOWN: "unknown",
}


def fetch_json(url: str, timeout: int) -> object:
    request = Request(url, headers={"Accept": "application/json", "User-Agent": USER_AGENT})
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def valid_domain(value: str) -> str:
    try:
        domain = value.strip().rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise argparse.ArgumentTypeError("invalid IDN domain format") from error
    labels = domain.split(".")
    label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    if len(labels) < 2 or len(domain) > 253 or any(not label_pattern.fullmatch(label) for label in labels):
        raise argparse.ArgumentTypeError("enter a valid domain, such as example.org")
    return domain


def valid_public_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("enter a valid IPv4 or IPv6 address") from error
    if not address.is_global:
        raise argparse.ArgumentTypeError("only public IP addresses are supported")
    return str(address)


def safe_lookup(callback) -> dict:
    try:
        return {"status": "ok", "data": callback()}
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, TypeError, AttributeError) as error:
        return {"status": "error", "error": str(error)}


def lookup_rdap(domain: str, timeout: int) -> dict:
    data = fetch_json(f"https://rdap.org/domain/{domain}", timeout)
    return {
        "handle": data.get("handle"),
        "ldhName": data.get("ldhName"),
        "status": data.get("status", []),
        "nameservers": [item.get("ldhName") for item in data.get("nameservers", [])],
        "events": [
            {"action": item.get("eventAction"), "date": item.get("eventDate")}
            for item in data.get("events", [])
        ],
    }


def lookup_certificates(domain: str, timeout: int) -> dict:
    url = "https://crt.sh/?" + urlencode({"q": f"%.{domain}", "output": "json"})
    records = fetch_json(url, timeout)
    certificates = []
    seen = set()
    for record in records:
        key = record.get("id")
        if key in seen:
            continue
        seen.add(key)
        certificates.append({
            "id": key,
            "names": record.get("name_value", "").splitlines(),
            "issuer": record.get("issuer_name"),
            "not_before": record.get("not_before"),
            "not_after": record.get("not_after"),
        })
        if len(certificates) == 100:
            break
    return {"count_returned": len(certificates), "records": certificates}


def lookup_dns(domain: str, record_type: str, timeout: int) -> dict:
    query = urlencode({"name": domain, "type": record_type})
    url = f"https://cloudflare-dns.com/dns-query?{query}"
    data = fetch_json(url, timeout)
    return {
        "status_code": data.get("Status"),
        "answers": [answer.get("data") for answer in data.get("Answer", [])],
    }


def lookup_ip_rdap(address: str, timeout: int) -> dict:
    data = fetch_json(f"https://rdap.org/ip/{address}", timeout)
    return {
        "name": data.get("name"),
        "handle": data.get("handle"),
        "start_address": data.get("startAddress"),
        "end_address": data.get("endAddress"),
        "country": data.get("country"),
        "type": data.get("type"),
    }


def build_report(domain: str, timeout: int) -> dict:
    return {
        "target": domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "passive public-source lookups",
        "sources": {
            "rdap": safe_lookup(lambda: lookup_rdap(domain, timeout)),
            "certificate_transparency": safe_lookup(lambda: lookup_certificates(domain, timeout)),
            "dns": {
                record_type: safe_lookup(
                    lambda record_type=record_type: lookup_dns(domain, record_type, timeout),
                )
                for record_type in DNS_TYPES
            },
        },
    }


def build_ip_report(address: str, timeout: int) -> dict:
    reverse_name = ipaddress.ip_address(address).reverse_pointer
    return {
        "target": address,
        "target_type": "ip",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "passive public-source lookups",
        "sources": {
            "rdap": safe_lookup(lambda: lookup_ip_rdap(address, timeout)),
            "reverse_dns": safe_lookup(lambda: lookup_dns(reverse_name, "PTR", timeout)),
        },
    }


def classify_indicator(value: str) -> tuple[str, str]:
    if re.fullmatch(r"(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})", value):
        return "hash", value.lower()
    try:
        address = ipaddress.ip_address(value)
        if not address.is_global:
            raise argparse.ArgumentTypeError("private or reserved IP indicators are not allowed")
        return "ip", str(address)
    except ValueError:
        pass

    try:
        parsed = urlsplit(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("invalid URL format") from error
    if parsed.scheme.lower() in {"http", "https"} and parsed.hostname:
        if parsed.username or parsed.password:
            raise argparse.ArgumentTypeError("remove URL credentials before using this indicator")
        if parsed.query:
            raise argparse.ArgumentTypeError(
                "URL query parameters are not allowed; remove potential tokens or secrets first"
            )
        try:
            url_address = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            pass
        else:
            if not url_address.is_global:
                raise argparse.ArgumentTypeError("URLs containing private or reserved IP addresses are not allowed")
        return "url", value
    try:
        return "domain", valid_domain(value)
    except argparse.ArgumentTypeError as error:
        raise argparse.ArgumentTypeError(
            "indicator must be a domain, IP address, HTTP(S) URL, or MD5/SHA1/SHA256 hash"
        ) from error


def build_ioc_report(value: str) -> dict:
    indicator_type, indicator = classify_indicator(value)
    encoded = quote(indicator, safe="")
    vt_type = {"ip": "ip-address", "domain": "domain", "url": "url", "hash": "file"}[indicator_type]
    vt_indicator = (
        base64.urlsafe_b64encode(indicator.encode("utf-8")).decode("ascii").rstrip("=")
        if indicator_type == "url"
        else encoded
    )
    otx_type = (
        "IPv6" if indicator_type == "ip" and ":" in indicator
        else {"ip": "IPv4", "domain": "domain", "url": "url", "hash": "file"}[indicator_type]
    )
    lookups = [
        {"source": "VirusTotal", "url": f"https://www.virustotal.com/gui/{vt_type}/{vt_indicator}"},
        {"source": "AlienVault OTX", "url": f"https://otx.alienvault.com/indicator/{otx_type}/{encoded}"},
    ]
    if indicator_type in {"domain", "url"}:
        lookups.append({"source": "URLhaus", "url": "https://urlhaus.abuse.ch/browse.php?" + urlencode({"search": indicator})})
    if indicator_type == "ip":
        lookups.append({"source": "AbuseIPDB", "url": f"https://www.abuseipdb.com/check/{encoded}"})
    if indicator_type == "hash":
        hash_type = {32: "md5", 40: "sha1", 64: "sha256"}[len(indicator)]
        lookups.append({"source": "CIRCL Hashlookup", "url": f"https://hashlookup.circl.lu/lookup/{hash_type}/{encoded}"})
    return {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "mode": "manual links; no indicator is sent automatically",
        "lookups": lookups,
    }


def build_search_report(target: str, kind: str) -> dict:
    term = f'"{target.strip()}"'
    if kind == "username":
        queries = [
            ("Reddit", f'site:reddit.com {term}'),
            ("GitHub", f'site:github.com {term}'),
            ("GitLab", f'site:gitlab.com {term}'),
            ("HackerOne", f'site:hackerone.com/{target.strip()}'),
            ("Bugcrowd", f'site:bugcrowd.com/{target.strip()}'),
            ("TryHackMe", f'site:tryhackme.com/p/{target.strip()}'),
            ("Hack The Box", f'site:app.hackthebox.com/profile/{target.strip()}'),
            ("LinkedIn", f'site:linkedin.com/in {term}'),
            ("Wellfound", f'site:wellfound.com/u/{target.strip()}'),
            ("Indeed", f'site:indeed.com {term}'),
            ("DuckDuckGo", term),
            ("Google", term),
            ("Bing", term),
        ]
    elif kind in {"organization", "company"}:
        queries = [
            ("DuckDuckGo", term),
            ("Google", term),
            ("Bing", term),
            ("GitHub", f'site:github.com {term}'),
            ("Reddit", f'site:reddit.com {term}'),
            ("LinkedIn", f'site:linkedin.com/company {term}'),
            ("OpenCorporates", f'site:opencorporates.com {term}'),
            ("Crunchbase", f'site:crunchbase.com/organization {term}'),
        ]
    else:
        queries = [
            ("DuckDuckGo", term),
            ("Google", term),
            ("Bing", term),
            ("GitHub", f'site:github.com {term}'),
            ("Reddit", f'site:reddit.com {term}'),
            ("LinkedIn", f'site:linkedin.com/in {term}'),
            ("Google News", f'{term}'),
            ("Google Scholar", f'site:scholar.google.com {term}'),
        ]
    return {
        "target": target,
        "target_type": kind,
        "mode": "manual search links; no search is performed and no identity is verified",
        "privacy_scope": "public sources only; no private contact details or sensitive personal records are collected",
        "searches": [
            {"source": source, "query": query, "url": "https://www.google.com/search?" + urlencode({"q": query}) if source not in {"DuckDuckGo", "Google", "Bing"} else _search_url(source, query)}
            for source, query in queries
        ],
    }


def valid_username(value: str) -> str:
    username = value.strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", username):
        raise argparse.ArgumentTypeError("enter a username containing 1-63 letters, digits, dots, underscores, or hyphens")
    return username


def probe_profile(
    service: str,
    category: str,
    profile_url: str,
    lookup: Callable[[], bool],
) -> dict | None:
    try:
        found = lookup()
    except HTTPError:
        return None
    except (URLError, TimeoutError, OSError, ValueError, TypeError, AttributeError):
        return None
    if not found:
        return None
    return {
        "service": service,
        "category": category,
        "status": "confirmed",
        "profile_url": profile_url,
    }


def build_profile_report(username: str, timeout: int) -> dict:
    encoded_username = quote(username, safe="")
    bluesky_handle = username if "." in username else f"{username}.bsky.social"
    profiles = [
        (
            "GitHub",
            "developer / cybersecurity",
            f"https://github.com/{encoded_username}",
            f"https://api.github.com/users/{encoded_username}",
            lambda data: isinstance(data, dict)
            and str(data.get("login", "")).casefold() == username.casefold(),
        ),
        (
            "GitLab",
            "developer / cybersecurity",
            f"https://gitlab.com/{encoded_username}",
            "https://gitlab.com/api/v4/users?" + urlencode({"username": username}),
            lambda data: isinstance(data, list)
            and any(
                isinstance(item, dict)
                and str(item.get("username", "")).casefold() == username.casefold()
                for item in data
            ),
        ),
        (
            "DEV Community",
            "developer community",
            f"https://dev.to/{encoded_username}",
            "https://dev.to/api/users/by_username?" + urlencode({"url": username}),
            lambda data: isinstance(data, dict)
            and str(data.get("username", "")).casefold() == username.casefold(),
        ),
        (
            "Hacker News",
            "technology forum",
            f"https://news.ycombinator.com/user?id={encoded_username}",
            f"https://hacker-news.firebaseio.com/v0/user/{encoded_username}.json",
            lambda data: isinstance(data, dict)
            and str(data.get("id", "")).casefold() == username.casefold(),
        ),
        (
            "Bluesky",
            "social network",
            f"https://bsky.app/profile/{quote(bluesky_handle, safe='')}",
            "https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?"
            + urlencode({"handle": bluesky_handle}),
            lambda data: isinstance(data, dict) and bool(data.get("did")),
        ),
        (
            "Reddit",
            "social network / forums / cybersecurity",
            f"https://www.reddit.com/user/{encoded_username}/",
            f"https://www.reddit.com/user/{encoded_username}/about.json",
            lambda data: isinstance(data, dict)
            and data.get("kind") == "t2"
            and isinstance(data.get("data"), dict)
            and str(data["data"].get("name", "")).casefold() == username.casefold(),
        ),
        (
            "Mastodon.social",
            "social network",
            f"https://mastodon.social/@{encoded_username}",
            "https://mastodon.social/api/v1/accounts/lookup?" + urlencode({"acct": username}),
            lambda data: isinstance(data, dict)
            and str(data.get("username", "")).casefold() == username.casefold(),
        ),
        (
            "Codeberg",
            "developer / cybersecurity",
            f"https://codeberg.org/{encoded_username}",
            f"https://codeberg.org/api/v1/users/{encoded_username}",
            lambda data: isinstance(data, dict)
            and str(data.get("login", data.get("username", ""))).casefold() == username.casefold(),
        ),
        (
            "Hugging Face",
            "developer / AI",
            f"https://huggingface.co/{encoded_username}",
            f"https://huggingface.co/api/users/{encoded_username}",
            lambda data: isinstance(data, dict)
            and str(data.get("user", data.get("username", ""))).casefold() == username.casefold(),
        ),
    ]

    results = {}
    with ThreadPoolExecutor(max_workers=len(profiles)) as executor:
        futures = {
            executor.submit(
                probe_profile,
                service,
                category,
                profile_url,
                lambda api_url=api_url, matches=matches: matches(fetch_json(api_url, timeout)),
            ): service
            for service, category, profile_url, api_url, matches in profiles
        }
        for future in as_completed(futures):
            results[futures[future]] = future.result()

    profile_results = [
        results[service]
        for service, _, _, _, _ in profiles
        if results.get(service) is not None
    ]
    category_priority = {
        "social network / forums / cybersecurity": 0,
        "social network": 1,
        "technology forum": 2,
        "developer community": 3,
        "developer / cybersecurity": 4,
        "developer / AI": 5,
    }
    profile_results.sort(key=lambda item: category_priority.get(item["category"], 99))
    return {
        "target": username,
        "target_type": "username",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "public profile existence checks; only exact confirmed matches are displayed",
        "results": profile_results,
        "summary": {"confirmed": len(profile_results)},
        "notice": "profiles without an exact match or with unavailable APIs are omitted; a username match does not prove shared ownership",
    }


def build_phone_report(value: str) -> dict:
    if not value.strip().startswith("+"):
        raise argparse.ArgumentTypeError("use international E.164 format, for example +14155552671")
    try:
        number = phonenumbers.parse(value, None)
    except phonenumbers.NumberParseException as error:
        raise argparse.ArgumentTypeError(f"invalid phone number: {error}") from error
    if not phonenumbers.is_possible_number(number) or not phonenumbers.is_valid_number(number):
        raise argparse.ArgumentTypeError("the number is not valid under the numbering plan")

    number_type = phonenumbers.number_type(number)
    return {
        "target_type": "phone_number",
        "e164": phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164),
        "international": phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "country_calling_code": number.country_code,
        "region_code": phonenumbers.region_code_for_number(number),
        "number_type": PHONE_NUMBER_TYPES.get(number_type, "unknown"),
        "mode": "local numbering-plan validation; no owner lookup or contact is made",
        "notice": "validity does not confirm that the number is assigned, active, or belongs to a person",
    }


def release_version(value: str) -> tuple[int, int, int] | None:
    match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def update_application() -> int:
    try:
        release = fetch_json(GITHUB_RELEASE_API, 15)
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as error:
        print(f"Could not check GitHub for updates: {error}", file=sys.stderr)
        return 1
    if not isinstance(release, dict) or not isinstance(release.get("tag_name"), str):
        print("GitHub returned invalid release information.", file=sys.stderr)
        return 1

    tag = release["tag_name"]
    latest_version = release_version(tag)
    current_version = release_version(f"v{__version__}")
    if latest_version is None or current_version is None:
        print(f"Unrecognized release version: {tag}", file=sys.stderr)
        return 1
    if latest_version <= current_version:
        print(f"You already have the latest stable version ({__version__}).")
        return 0

    archive_url = GITHUB_ARCHIVE_URL.format(tag=quote(tag, safe=""))
    command = [sys.executable, "-m", "pip", "install", "--upgrade", "--force-reinstall"]
    if sys.prefix == sys.base_prefix:
        command.append("--user")
    command.append(archive_url)
    print(f"Updating from {__version__} to {tag} via GitHub...")
    try:
        result = subprocess.run(command, check=False)
    except OSError as error:
        print(f"Could not start pip: {error}", file=sys.stderr)
        return 1
    if result.returncode == 0:
        print("Update complete. Restart the terminal if the old command is still loaded.")
    return result.returncode


def _search_url(source: str, query: str) -> str:
    query_string = urlencode({"q": query})
    if source == "DuckDuckGo":
        return f"https://duckduckgo.com/?{query_string}"
    if source == "Bing":
        return f"https://www.bing.com/search?{query_string}"
    return f"https://www.google.com/search?{query_string}"


def write_report(report: dict, output_path: str | None) -> int:
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    if not output_path:
        print(rendered)
        return 0
    try:
        with open(output_path, "w", encoding="utf-8") as output_file:
            output_file.write(rendered + "\n")
    except OSError as error:
        print(f"Could not write report: {error}", file=sys.stderr)
        return 1
    print(f"Report saved to {output_path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Cross-platform OSINT toolkit for authorized research using public sources."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--update", action="store_true", help="install the latest stable release from GitHub")
    subparsers = parser.add_subparsers(dest="command")
    domain_parser = subparsers.add_parser("domain", help="Look up RDAP, DNS, and TLS certificate transparency")
    domain_parser.add_argument("target", type=valid_domain, help="domain under authorized investigation")
    domain_parser.add_argument("-o", "--output", help="write the JSON report to this path")
    domain_parser.add_argument("--timeout", type=int, default=10, help="timeout per source, in seconds (1-60)")
    ip_parser = subparsers.add_parser("ip", help="Look up RDAP and reverse DNS for a public IP")
    ip_parser.add_argument("target", type=valid_public_ip, help="public IPv4 or IPv6 address")
    ip_parser.add_argument("-o", "--output", help="write the JSON report to this path")
    ip_parser.add_argument("--timeout", type=int, default=10, help="timeout per source, in seconds (1-60)")
    ioc_parser = subparsers.add_parser("ioc", help="Generate reputation links for an indicator")
    ioc_parser.add_argument("indicator", help="domain, IP address, HTTP(S) URL, or MD5/SHA1/SHA256 hash")
    ioc_parser.add_argument("-o", "--output", help="write the JSON report to this path")
    search_parser = subparsers.add_parser("search", help="Generate links for manual public-source searches")
    search_parser.add_argument("target", help="username, person, company, or organization name")
    search_parser.add_argument("--kind", choices=("username", "person", "organization", "company"), required=True)
    search_parser.add_argument("-o", "--output", help="write the JSON report to this path")
    profiles_parser = subparsers.add_parser("profiles", help="Check public profile presence for one username")
    profiles_parser.add_argument("username", type=valid_username, help="single username to check")
    profiles_parser.add_argument("--timeout", type=int, default=10, help="timeout per service, in seconds (1-30)")
    profiles_parser.add_argument("-o", "--output", help="write the JSON report to this path")
    phone_parser = subparsers.add_parser("phone", help="Validate an international phone number without identifying its owner")
    phone_parser.add_argument("number", help="international E.164 number, for example +14155552671")
    phone_parser.add_argument("-o", "--output", help="write the JSON report to this path")
    args = parser.parse_args()

    if args.update:
        return update_application()
    if args.command is None:
        parser.print_help()
        return 0
    if args.command in {"domain", "ip"} and not 1 <= args.timeout <= 60:
        parser.error("--timeout must be between 1 and 60 seconds")
    if args.command == "profiles" and not 1 <= args.timeout <= 30:
        parser.error("--timeout must be between 1 and 30 seconds")
    if args.command == "domain":
        report = build_report(args.target, args.timeout)
    elif args.command == "ip":
        report = build_ip_report(args.target, args.timeout)
    elif args.command == "ioc":
        try:
            report = build_ioc_report(args.indicator)
        except argparse.ArgumentTypeError as error:
            parser.error(str(error))
    elif args.command == "phone":
        try:
            report = build_phone_report(args.number)
        except argparse.ArgumentTypeError as error:
            parser.error(str(error))
    elif args.command == "profiles":
        report = build_profile_report(args.username, args.timeout)
    else:
        if not args.target.strip():
            parser.error("search target cannot be empty")
        report = build_search_report(args.target, args.kind)
    return write_report(report, args.output)


if __name__ == "__main__":
    raise SystemExit(main())