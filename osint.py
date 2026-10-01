#!/usr/bin/env python3
"""Passive, public-source OSINT helpers for authorized domain research."""

from __future__ import annotations

import argparse
import base64
import csv
import getpass
import hashlib
import io
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, urlopen

import keyring
import phonenumbers
from keyring.errors import KeyringError, PasswordDeleteError
from rich import box
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.theme import Theme
from rich_argparse import RichHelpFormatter

__version__ = "1.7.1"
USER_AGENT = f"OpenOSINTKit/{__version__} (passive public-source research)"
GITHUB_RELEASE_API = "https://api.github.com/repos/IsdarlinM/open-osint-kit/releases/latest"
GITHUB_MAIN_COMMIT_API = "https://api.github.com/repos/IsdarlinM/open-osint-kit/commits/main"
GITHUB_ARCHIVE_URL = "https://github.com/IsdarlinM/open-osint-kit/archive/refs/tags/{tag}.zip"
GITHUB_COMPARE_API = "https://api.github.com/repos/IsdarlinM/open-osint-kit/compare/{base}...main"
GITHUB_COMMIT_ARCHIVE_URL = "https://github.com/IsdarlinM/open-osint-kit/archive/{sha}.zip"
DNS_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CAA")
SHODAN_RESULTS_PER_PAGE = 100
SHODAN_MAX_RESULTS = 500
SHODAN_DEFAULT_CACHE_TTL = 300
REPORT_FORMATS = ("table", "json", "csv", "markdown")
MASTODON_INSTANCES = (
    "mastodon.social",
    "mastodon.online",
    "mstdn.social",
    "fosstodon.org",
    "infosec.exchange",
    "mastodon.world",
)
KEYRING_SERVICE = "open-osint-kit"
KEYRING_USERNAME = "shodan-api-key"
CLI_THEME = Theme({
    "success": "bold green",
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
})
CONSOLE = Console(theme=CLI_THEME, highlight=False)
ERROR_CONSOLE = Console(stderr=True, theme=CLI_THEME, highlight=False)
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


class ColorArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("formatter_class", RichHelpFormatter)
        super().__init__(*args, **kwargs)


def fetch_json(
    url: str, timeout: int, accept_header: str = "application/json"
) -> object:
    request = Request(url, headers={"Accept": accept_header, "User-Agent": USER_AGENT})
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


def valid_public_network(value: str) -> str:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as error:
        raise argparse.ArgumentTypeError("enter a valid IPv4 or IPv6 network in CIDR notation") from error
    minimum_prefix = 24 if network.version == 4 else 120
    if network.prefixlen < minimum_prefix:
        raise argparse.ArgumentTypeError(
            f"network is too large; use /{minimum_prefix} or a smaller range"
        )
    if not network.network_address.is_global or not network.broadcast_address.is_global:
        raise argparse.ArgumentTypeError("only globally routable public networks are supported")
    return str(network)


def valid_asn(value: str) -> str:
    match = re.fullmatch(r"(?:AS)?(\d{1,10})", value.strip(), re.IGNORECASE)
    if not match:
        raise argparse.ArgumentTypeError("enter an ASN such as AS15169 or 15169")
    number = int(match.group(1))
    if not 1 <= number <= 4294967295:
        raise argparse.ArgumentTypeError("ASN must be between 1 and 4294967295")
    return f"AS{number}"


def get_shodan_api_key() -> str | None:
    environment_key = os.environ.get("SHODAN_API_KEY", "").strip()
    if environment_key:
        return environment_key
    try:
        return keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
    except KeyringError:
        return None


def verify_shodan_api_key(api_key: str, timeout: int = 10) -> dict:
    url = "https://api.shodan.io/api-info?" + urlencode({"key": api_key})
    try:
        data = fetch_json(url, timeout)
    except HTTPError as error:
        return {
            "source": "Shodan",
            "status": "error",
            "error": _shodan_search_error(error),
        }
    except (URLError, TimeoutError, OSError, ValueError, TypeError, AttributeError) as error:
        return {
            "source": "Shodan",
            "status": "error",
            "error": f"Shodan request failed ({type(error).__name__}).",
        }
    if not isinstance(data, dict):
        return {"source": "Shodan", "status": "error", "error": "Invalid Shodan API-info response."}
    allowed_fields = ("plan", "query_credits", "scan_credits", "https")
    return {
        "source": "Shodan",
        "status": "ok",
        "account": {field: data[field] for field in allowed_fields if field in data},
    }


def configure_shodan(action: str) -> int:
    if action == "clear-cache":
        return clear_shodan_cache()

    if action == "test-shodan":
        api_key = get_shodan_api_key()
        if not api_key:
            ERROR_CONSOLE.print("[error]Shodan API key is not configured.[/error]")
            return 2
        report = verify_shodan_api_key(api_key)
        CONSOLE.print_json(data=report)
        return 0 if report["status"] == "ok" else 1

    if action == "set-shodan-key":
        if not sys.stdin.isatty():
            ERROR_CONSOLE.print("[error]Run this command in an interactive terminal to enter the key safely.[/error]")
            return 1
        CONSOLE.print("[info]Enter your Shodan API key (input hidden):[/info]")
        try:
            api_key = getpass.getpass("").strip()
        except (EOFError, KeyboardInterrupt):
            ERROR_CONSOLE.print("[warning]Key entry cancelled.[/warning]")
            return 1
        if not api_key:
            ERROR_CONSOLE.print("[error]The API key cannot be empty.[/error]")
            return 1
        try:
            keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, api_key)
        except KeyringError:
            ERROR_CONSOLE.print(
                "[error]Secure OS key storage is unavailable. Set SHODAN_API_KEY in your environment instead.[/error]"
            )
            return 1
        CONSOLE.print("[success]Shodan API key saved in the operating system keyring. The key was not displayed.[/success]")
        return 0

    if action == "remove-shodan-key":
        try:
            keyring.delete_password(KEYRING_SERVICE, KEYRING_USERNAME)
        except PasswordDeleteError:
            CONSOLE.print("[warning]No key was stored in the operating system keyring.[/warning]")
        except KeyringError:
            ERROR_CONSOLE.print("[error]Could not access the operating system keyring.[/error]")
            return 1
        else:
            CONSOLE.print("[success]Stored Shodan API key removed.[/success]")
        if os.environ.get("SHODAN_API_KEY"):
            CONSOLE.print("[warning]SHODAN_API_KEY is still set in this environment and takes precedence.[/warning]")
        return 0

    environment_key = os.environ.get("SHODAN_API_KEY", "").strip()
    if environment_key:
        CONSOLE.print("[success]Shodan API key is configured through SHODAN_API_KEY.[/success]")
        return 0
    try:
        stored_key = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
    except KeyringError:
        ERROR_CONSOLE.print(
            "[warning]The operating system keyring is unavailable. Set SHODAN_API_KEY to configure Shodan.[/warning]"
        )
        return 1
    if stored_key:
        CONSOLE.print("[success]Shodan API key is stored in the operating system keyring.[/success]")
    else:
        CONSOLE.print("[warning]Shodan API key is not configured.[/warning]")
    return 0


def build_shodan_report(
    address: str,
    api_key: str,
    timeout: int,
    cache_ttl: int = SHODAN_DEFAULT_CACHE_TTL,
    cache_dir: Path | None = None,
) -> dict:
    cache_query = f"host:{address}"
    cached = _read_shodan_cache(cache_query, api_key, 1, cache_ttl, cache_dir)
    if cached is not None:
        return cached
    url = f"https://api.shodan.io/shodan/host/{quote(address, safe='')}?{urlencode({'key': api_key})}"
    try:
        data = fetch_json(url, timeout)
    except HTTPError as error:
        if error.code == 404:
            report = {
                "target": address,
                "source": "Shodan",
                "status": "no_indexed_record",
                "mode": "passive indexed-data lookup; no scan performed",
            }
            if cache_ttl > 0:
                _write_shodan_cache(cache_query, api_key, 1, report, cache_dir)
            return {**report, "cache": {"status": "miss", "ttl_seconds": cache_ttl}}
        message = {
            401: "Shodan rejected the API key.",
            403: "Shodan denied the request or the key lacks access.",
            429: "Shodan rate limit reached.",
        }.get(error.code, f"Shodan request failed with HTTP {error.code}.")
        return {"target": address, "source": "Shodan", "status": "error", "error": message}
    except (URLError, TimeoutError, OSError, ValueError, TypeError, AttributeError) as error:
        return {
            "target": address,
            "source": "Shodan",
            "status": "error",
            "error": f"Shodan request failed ({type(error).__name__}).",
        }
    if not isinstance(data, dict):
        return {"target": address, "source": "Shodan", "status": "error", "error": "Invalid Shodan response."}

    allowed_fields = ("hostnames", "domains", "org", "isp", "asn", "country_code", "last_update")
    metadata = {field: data[field] for field in allowed_fields if field in data}
    report = {
        "target": address,
        "source": "Shodan",
        "status": "ok",
        "mode": "passive indexed-data lookup; no scan performed",
        "metadata": metadata,
    }
    if cache_ttl > 0:
        _write_shodan_cache(cache_query, api_key, 1, report, cache_dir)
    return {**report, "cache": {"status": "miss", "ttl_seconds": cache_ttl}}


def _shodan_search_error(error: HTTPError) -> str:
    return {
        401: "Shodan rejected the API key.",
        403: "Shodan denied the request or the key lacks access.",
        429: "Shodan rate limit reached.",
    }.get(error.code, f"Shodan request failed with HTTP {error.code}.")


def shodan_cache_directory() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return base / "open-osint-kit" / "shodan"


def _shodan_cache_path(
    query: str,
    api_key: str,
    limit: int,
    cache_dir: Path | None = None,
) -> Path:
    key_fingerprint = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
    cache_identifier = hashlib.sha256(
        f"{query}\0{limit}\0{key_fingerprint}".encode()
    ).hexdigest()
    return (cache_dir or shodan_cache_directory()) / f"{cache_identifier}.json"


def _read_shodan_cache(
    query: str,
    api_key: str,
    limit: int,
    cache_ttl: int,
    cache_dir: Path | None,
) -> dict | None:
    if cache_ttl <= 0:
        return None
    cache_path = _shodan_cache_path(query, api_key, limit, cache_dir)
    try:
        cached = json.loads(cache_path.read_text(encoding="utf-8"))
        age = time.time() - float(cached["saved_at"])
        report = cached["report"]
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None
    if age > cache_ttl or not isinstance(report, dict):
        try:
            cache_path.unlink(missing_ok=True)
        except OSError:
            pass
        return None
    return {**report, "cache": {"status": "hit", "ttl_seconds": cache_ttl}}


def _write_shodan_cache(
    query: str,
    api_key: str,
    limit: int,
    report: dict,
    cache_dir: Path | None,
) -> None:
    cache_path = _shodan_cache_path(query, api_key, limit, cache_dir)
    temporary_path = None
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=cache_path.parent,
            prefix=".shodan-",
            suffix=".tmp",
            delete=False,
        ) as cache_file:
            temporary_path = Path(cache_file.name)
            json.dump({"saved_at": time.time(), "report": report}, cache_file)
        if os.name != "nt":
            os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, cache_path)
    except OSError:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass


def clear_shodan_cache() -> int:
    try:
        shutil.rmtree(shodan_cache_directory())
    except FileNotFoundError:
        CONSOLE.print("[warning]No Shodan cache was found.[/warning]")
        return 0
    except OSError as error:
        ERROR_CONSOLE.print(f"[error]Could not clear the Shodan cache: {error}[/error]")
        return 1
    CONSOLE.print("[success]Shodan cache cleared.[/success]")
    return 0


def _shodan_host_summary(match: object) -> dict | None:
    if not isinstance(match, dict):
        return None
    try:
        address = ipaddress.ip_address(str(match.get("ip_str", "")))
    except ValueError:
        return None
    if not address.is_global:
        return None

    location = match.get("location")
    metadata = {
        "ip": str(address),
        "hostnames": match.get("hostnames", []),
        "domains": match.get("domains", []),
        "org": match.get("org"),
        "isp": match.get("isp"),
        "asn": match.get("asn"),
        "country_code": location.get("country_code") if isinstance(location, dict) else None,
        "last_seen": match.get("timestamp"),
    }
    return {field: value for field, value in metadata.items() if value not in (None, [])}


def build_shodan_search_report(
    target: str,
    query: str,
    search_type: str,
    api_key: str,
    timeout: int,
    limit: int,
    cache_ttl: int = SHODAN_DEFAULT_CACHE_TTL,
    cache_dir: Path | None = None,
) -> dict:
    if not 1 <= limit <= SHODAN_MAX_RESULTS:
        raise ValueError(f"limit must be between 1 and {SHODAN_MAX_RESULTS}")
    if not 0 <= cache_ttl <= 86400:
        raise ValueError("cache_ttl must be between 0 and 86400 seconds")
    cache_query = f"{search_type}:{query}"
    cached = _read_shodan_cache(cache_query, api_key, limit, cache_ttl, cache_dir)
    if cached is not None:
        return cached

    hosts = []
    total_matches = 0
    pages_fetched = 0
    warning = None
    pages_to_fetch = (limit + SHODAN_RESULTS_PER_PAGE - 1) // SHODAN_RESULTS_PER_PAGE
    for page in range(1, pages_to_fetch + 1):
        url = "https://api.shodan.io/shodan/host/search?" + urlencode({
            "key": api_key,
            "query": query,
            "page": page,
        })
        try:
            data = fetch_json(url, timeout)
        except HTTPError as error:
            if not hosts:
                return {
                    "target": target,
                    "target_type": search_type,
                    "source": "Shodan",
                    "status": "error",
                    "error": _shodan_search_error(error),
                }
            warning = _shodan_search_error(error)
            break
        except (URLError, TimeoutError, OSError, ValueError, TypeError, AttributeError) as error:
            if not hosts:
                return {
                    "target": target,
                    "target_type": search_type,
                    "source": "Shodan",
                    "status": "error",
                    "error": f"Shodan request failed ({type(error).__name__}).",
                }
            warning = f"Shodan request failed on page {page} ({type(error).__name__})."
            break
        if not isinstance(data, dict) or not isinstance(data.get("matches", []), list):
            if not hosts:
                return {
                    "target": target,
                    "target_type": search_type,
                    "source": "Shodan",
                    "status": "error",
                    "error": "Invalid Shodan response.",
                }
            warning = f"Invalid Shodan response on page {page}."
            break

        pages_fetched = page
        if isinstance(data.get("total"), int):
            total_matches = data["total"]
        matches = data.get("matches", [])
        for match in matches:
            summary = _shodan_host_summary(match)
            if summary is not None:
                hosts.append(summary)
                if len(hosts) >= limit:
                    break
        if len(hosts) >= limit or len(matches) < SHODAN_RESULTS_PER_PAGE:
            break

    report = {
        "target": target,
        "target_type": search_type,
        "source": "Shodan",
        "status": "partial" if warning else "ok",
        "mode": "passive indexed-data search; no scan performed",
        "total_matches": total_matches,
        "pages_fetched": pages_fetched,
        "returned_matches": len(hosts),
        "results": hosts[:limit],
    }
    if warning:
        report["warning"] = warning
    if report["status"] == "ok" and cache_ttl > 0:
        _write_shodan_cache(cache_query, api_key, limit, report, cache_dir)
    return {**report, "cache": {"status": "miss", "ttl_seconds": cache_ttl}}


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
    crt_url = "https://crt.sh/?" + urlencode({"q": f"%.{domain}", "output": "json"})
    provider = "crt.sh"
    try:
        records = fetch_json(crt_url, timeout)
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, TypeError):
        provider = "Cert Spotter"
        cert_spotter_url = "https://api.certspotter.com/v1/issuances?" + urlencode(
            [
                ("domain", domain),
                ("include_subdomains", "true"),
                ("expand", "dns_names"),
                ("expand", "issuer"),
            ]
        )
        records = fetch_json(cert_spotter_url, timeout)
    if not isinstance(records, list):
        raise TypeError("certificate transparency response is not a list")

    certificates = []
    seen = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        key = record.get("id")
        if key in seen:
            continue
        seen.add(key)
        if provider == "crt.sh":
            names = str(record.get("name_value", "")).splitlines()
            issuer = record.get("issuer_name")
        else:
            names = record.get("dns_names", [])
            issuer_data = record.get("issuer")
            issuer = issuer_data.get("name") if isinstance(issuer_data, dict) else None
        certificates.append(
            {
                "id": key,
                "names": names,
                "issuer": issuer,
                "not_before": record.get("not_before"),
                "not_after": record.get("not_after"),
            }
        )
        if len(certificates) == 100:
            break
    return {
        "provider": provider,
        "count_returned": len(certificates),
        "records": certificates,
    }


def lookup_dns(domain: str, record_type: str, timeout: int) -> dict:
    query = urlencode({"name": domain, "type": record_type})
    providers = (
        ("Cloudflare", f"https://cloudflare-dns.com/dns-query?{query}"),
        ("Google", f"https://dns.google/resolve?{query}"),
    )
    last_error = None
    for provider, url in providers:
        try:
            data = fetch_json(url, timeout)
            if not isinstance(data, dict):
                raise TypeError("DNS response is not an object")
            break
        except (
            HTTPError,
            URLError,
            TimeoutError,
            OSError,
            ValueError,
            TypeError,
        ) as error:
            last_error = error
    else:
        raise OSError(
            f"all DNS-over-HTTPS providers failed: {last_error}"
        ) from last_error

    return {
        "provider": provider,
        "status_code": data.get("Status"),
        "answers": [
            answer.get("data")
            for answer in data.get("Answer", [])
            if isinstance(answer, dict)
        ],
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
    target = valid_username(target) if kind == "username" else target.strip()
    term = f'"{target}"'
    if kind == "username":
        path_username = quote(target, safe="._-")
        queries = [
            ("Instagram", f"site:instagram.com/{path_username}"),
            ("TikTok", f"site:tiktok.com/@{path_username}"),
            ("X", f"site:x.com/{path_username} OR site:twitter.com/{path_username}"),
            ("Threads", f"site:threads.net/@{path_username}"),
            ("Bluesky", f"site:bsky.app/profile/{path_username}"),
            (
                "Mastodon",
                "(" + " OR ".join(
                    f"site:{instance}/@{path_username}"
                    for instance in MASTODON_INSTANCES
                ) + ")",
            ),
            ("Reddit", f"site:reddit.com/user/{path_username}"),
            ("YouTube", f"site:youtube.com/@{path_username}"),
            ("Twitch", f"site:twitch.tv/{path_username}"),
            ("Telegram", f"site:t.me/{path_username}"),
            ("Pinterest", f"site:pinterest.com/{path_username}"),
            ("Medium", f"site:medium.com/@{path_username}"),
            ("LinkedIn", f"site:linkedin.com/in {term}"),
            ("GitHub", f"site:github.com/{path_username}"),
            ("GitLab", f"site:gitlab.com/{path_username}"),
            ("Codeberg", f"site:codeberg.org/{path_username}"),
            ("Hugging Face", f"site:huggingface.co/{path_username}"),
            ("DEV Community", f"site:dev.to/{path_username}"),
            ("Stack Overflow", f"site:stackoverflow.com/users {term}"),
            ("Hacker News", f"site:news.ycombinator.com/user?id={path_username}"),
            ("HackerOne", f"site:hackerone.com/{path_username}"),
            ("Bugcrowd", f"site:bugcrowd.com/h/{path_username}"),
            ("YesWeHack", f"site:yeswehack.com/hunters/{path_username}"),
            ("Intigriti", f"site:app.intigriti.com/profile/{path_username}"),
            ("TryHackMe", f"site:tryhackme.com/p/{path_username}"),
            ("Hack The Box", f"site:app.hackthebox.com/profile/{path_username}"),
            ("Wellfound", f"site:wellfound.com/u/{path_username}"),
            ("Indeed", f"site:indeed.com {term}"),
            ("DuckDuckGo", term),
            ("Google", term),
            ("Bing", term),
        ]
    elif kind in {"organization", "company"}:
        queries = [
            ("DuckDuckGo", term),
            ("Google", term),
            ("Bing", term),
            ("GitHub", f"site:github.com {term}"),
            ("Reddit", f"site:reddit.com {term}"),
            ("LinkedIn", f"site:linkedin.com/company {term}"),
            ("OpenCorporates", f"site:opencorporates.com {term}"),
            ("Crunchbase", f"site:crunchbase.com/organization {term}"),
        ]
    else:
        queries = [
            ("DuckDuckGo", term),
            ("Google", term),
            ("Bing", term),
            ("GitHub", f"site:github.com {term}"),
            ("Reddit", f"site:reddit.com {term}"),
            ("LinkedIn", f"site:linkedin.com/in {term}"),
            ("Google News", f"{term}"),
            ("Google Scholar", f"site:scholar.google.com {term}"),
        ]
    return {
        "target": target,
        "target_type": kind,
        "mode": "manual search links; no search is performed and no identity is verified",
        "privacy_scope": "public sources only; no private contact details or sensitive personal records are collected",
        "searches": [
            {
                "source": source,
                "query": query,
                "url": "https://www.google.com/search?" + urlencode({"q": query})
                if source not in {"DuckDuckGo", "Google", "Bing"}
                else _search_url(source, query),
            }
            for source, query in queries
        ],
    }


def valid_username(value: str) -> str:
    username = value.strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", username):
        raise argparse.ArgumentTypeError("enter a username containing 1-63 letters, digits, dots, underscores, or hyphens")
    return username


def lookup_bug_bounty_profile(provider: str, username: str, timeout: int) -> bool:
    encoded_username = quote(username, safe="")
    if provider == "HackerOne":
        profile_url = f"https://hackerone.com/{encoded_username}?type=user"
        request = Request(
            profile_url,
            headers={"Accept": "text/html", "User-Agent": USER_AGENT},
        )
        try:
            with urlopen(request, timeout=timeout) as response:
                final_url = urlsplit(response.geturl())
                expected_path = f"/{encoded_username}".casefold()
                return (
                    response.status == 200
                    and response.headers.get_content_type() == "text/html"
                    and final_url.scheme == "https"
                    and final_url.hostname == "hackerone.com"
                    and final_url.path.rstrip("/").casefold() == expected_path
                )
        except HTTPError as error:
            if error.code == 404:
                return False
            raise
    elif provider == "Bugcrowd":
        api_url = f"https://bugcrowd.com/profile-service/v1/profiles/{encoded_username}"
        username_field = "username"
    elif provider == "YesWeHack":
        api_url = f"https://api.yeswehack.com/hunters/{encoded_username}"
        username_field = "slug"
    elif provider == "Intigriti":
        api_url = (
            f"https://app.intigriti.com/api/user/public/profile/{encoded_username}"
        )
        username_field = "userName"
    else:
        raise ValueError("unsupported bug bounty provider")

    try:
        data = fetch_json(api_url, timeout)
    except HTTPError as error:
        if error.code == 404:
            return False
        raise
    return (
        isinstance(data, dict)
        and str(data.get(username_field, "")).casefold() == username.casefold()
    )


def mastodon_webfinger_matches(data: object, username: str, instance: str) -> bool:
    if not isinstance(data, dict):
        return False
    expected_subject = f"acct:{username}@{instance}".casefold()
    if str(data.get("subject", "")).casefold() != expected_subject:
        return False
    links = data.get("links")
    if not isinstance(links, list):
        return False
    activity_types = {
        "application/activity+json",
        'application/ld+json; profile="https://www.w3.org/ns/activitystreams"',
    }
    return any(
        isinstance(link, dict)
        and link.get("rel") == "self"
        and str(link.get("type", "")).casefold() in activity_types
        and urlsplit(str(link.get("href", ""))).scheme == "https"
        and bool(urlsplit(str(link.get("href", ""))).hostname)
        for link in links
    )


def probe_profile(
    service: str,
    category: str,
    profile_url: str,
    lookup: Callable[[], bool],
) -> dict:
    status = "not_found"
    try:
        found = lookup()
    except HTTPError as error:
        status = "not_found" if error.code == 404 else "unavailable"
    except (URLError, TimeoutError, OSError, ValueError, TypeError, AttributeError):
        status = "unavailable"
    else:
        status = "confirmed" if found else "not_found"
    return {
        "service": service,
        "category": category,
        "status": status,
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
        (
            "HackerOne",
            "bug bounty",
            f"https://hackerone.com/{encoded_username}?type=user",
            None,
            lambda: lookup_bug_bounty_profile("HackerOne", username, timeout),
        ),
        (
            "Bugcrowd",
            "bug bounty",
            f"https://bugcrowd.com/h/{encoded_username}",
            None,
            lambda: lookup_bug_bounty_profile("Bugcrowd", username, timeout),
        ),
        (
            "YesWeHack",
            "bug bounty",
            f"https://yeswehack.com/hunters/{encoded_username}",
            None,
            lambda: lookup_bug_bounty_profile("YesWeHack", username, timeout),
        ),
        (
            "Intigriti",
            "bug bounty",
            f"https://app.intigriti.com/profile/{encoded_username}",
            None,
            lambda: lookup_bug_bounty_profile("Intigriti", username, timeout),
        ),
    ]
    for instance in MASTODON_INSTANCES:
        resource = f"acct:{username}@{instance}"
        webfinger_url = (
            f"https://{instance}/.well-known/webfinger?"
            + urlencode({"resource": resource})
        )
        service = "Mastodon.social" if instance == "mastodon.social" else f"Mastodon ({instance})"
        profiles.append((
            service,
            "social network / fediverse",
            f"https://{instance}/@{encoded_username}",
            webfinger_url,
            lambda data, instance=instance: mastodon_webfinger_matches(
                data, username, instance
            ),
        ))

    results = {}
    with ThreadPoolExecutor(max_workers=len(profiles)) as executor:
        futures = {}
        for service, category, profile_url, api_url, matches in profiles:
            if api_url is None:
                lookup = matches
            elif ".well-known/webfinger" in api_url:
                lookup = lambda api_url=api_url, matches=matches: matches(
                    fetch_json(
                        api_url,
                        timeout,
                        "application/jrd+json, application/json",
                    )
                )
            else:
                lookup = lambda api_url=api_url, matches=matches: matches(fetch_json(api_url, timeout))
            futures[executor.submit(probe_profile, service, category, profile_url, lookup)] = service
        for future in as_completed(futures):
            results[futures[future]] = future.result()

    profile_checks = [
        results[service]
        for service, _, _, _, _ in profiles
        if results.get(service) is not None
    ]
    profile_results = [item for item in profile_checks if item["status"] == "confirmed"]
    category_priority = {
        "social network / forums / cybersecurity": 0,
        "social network": 1,
        "social network / fediverse": 2,
        "technology forum": 2,
        "bug bounty": 3,
        "developer community": 4,
        "developer / cybersecurity": 5,
        "developer / AI": 6,
    }
    profile_results.sort(key=lambda item: category_priority.get(item["category"], 99))
    unavailable = sum(item["status"] == "unavailable" for item in profile_checks)
    not_found = sum(item["status"] == "not_found" for item in profile_checks)
    return {
        "target": username,
        "target_type": "username",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "exact public profile checks; availability is reported per source",
        "results": profile_results,
        "checks": profile_checks,
        "summary": {
            "checked": len(profile_checks),
            "confirmed": len(profile_results),
            "not_found": not_found,
            "unavailable": unavailable,
        },
        "notice": "results include exact confirmed username matches; checks distinguish missing profiles from unavailable services; a match does not prove shared ownership",
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


def installed_commit_sha() -> str | None:
    """Return the commit recorded by pip for a direct commit installation."""
    try:
        distribution = metadata.distribution("open-osint-kit")
        direct_url_text = distribution.read_text("direct_url.json")
    except (metadata.PackageNotFoundError, OSError):
        return None
    if not direct_url_text:
        return None
    try:
        direct_url = json.loads(direct_url_text)
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(direct_url, dict):
        return None

    vcs_info = direct_url.get("vcs_info")
    if isinstance(vcs_info, dict):
        commit_id = vcs_info.get("commit_id")
        if isinstance(commit_id, str) and re.fullmatch(r"[a-fA-F0-9]{40}", commit_id):
            return commit_id.lower()

    source_url = direct_url.get("url")
    if not isinstance(source_url, str):
        return None
    archive_match = re.search(r"/archive/([a-fA-F0-9]{40})\.zip(?:$|[?#])", source_url)
    return archive_match.group(1).lower() if archive_match else None


def update_application() -> int:
    try:
        release = fetch_json(GITHUB_RELEASE_API, 15)
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as error:
        ERROR_CONSOLE.print(f"[error]Could not check GitHub for updates: {error}[/error]")
        return 1
    if not isinstance(release, dict) or not isinstance(release.get("tag_name"), str):
        ERROR_CONSOLE.print("[error]GitHub returned invalid release information.[/error]")
        return 1

    tag = release["tag_name"]
    latest_version = release_version(tag)
    current_version = release_version(f"v{__version__}")
    if latest_version is None or current_version is None:
        ERROR_CONSOLE.print(f"[error]Unrecognized release version: {tag}[/error]")
        return 1
    if latest_version > current_version:
        archive_url = GITHUB_ARCHIVE_URL.format(tag=quote(tag, safe=""))
        update_reason = f"stable release {tag}"
    elif latest_version < current_version:
        CONSOLE.print(
            f"[success]Installed version {__version__} is newer than the latest stable release ({tag}).[/success]"
        )
        return 0
    else:
        installed_sha = installed_commit_sha()
        comparison_base = installed_sha or f"v{__version__}"
        compare_url = GITHUB_COMPARE_API.format(base=quote(comparison_base, safe=""))
        try:
            comparison = fetch_json(compare_url, 15)
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as error:
            ERROR_CONSOLE.print(f"[error]Could not check GitHub commit history: {error}[/error]")
            return 1
        if not isinstance(comparison, dict):
            ERROR_CONSOLE.print("[error]GitHub returned invalid commit comparison data.[/error]")
            return 1
        ahead_by = comparison.get("ahead_by", 0)
        if not isinstance(ahead_by, int):
            ERROR_CONSOLE.print("[error]GitHub returned invalid commit comparison data.[/error]")
            return 1
        if ahead_by <= 0:
            source_description = f"commit {installed_sha[:12]}" if installed_sha else f"release v{__version__}"
            CONSOLE.print(
                f"[success]Version {__version__} is current; main has no newer commits than installed "
                f"{source_description}.[/success]"
            )
            return 0
        try:
            latest_commit = fetch_json(GITHUB_MAIN_COMMIT_API, 15)
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as error:
            ERROR_CONSOLE.print(f"[error]Could not read the latest GitHub commit: {error}[/error]")
            return 1
        commit_sha = latest_commit.get("sha") if isinstance(latest_commit, dict) else None
        if not isinstance(commit_sha, str) or not re.fullmatch(r"[a-fA-F0-9]{40}", commit_sha):
            ERROR_CONSOLE.print("[error]GitHub returned an invalid latest commit SHA.[/error]")
            return 1
        archive_url = GITHUB_COMMIT_ARCHIVE_URL.format(sha=commit_sha)
        update_reason = f"new main commit {commit_sha[:12]} ({ahead_by} commit(s) after v{__version__})"

    command = [sys.executable, "-m", "pip", "install", "--upgrade", "--force-reinstall"]
    if sys.prefix == sys.base_prefix:
        command.append("--user")
    command.append(archive_url)
    CONSOLE.print(f"[info]Updating from {__version__} via GitHub: {update_reason}...[/info]")
    try:
        result = subprocess.run(command, check=False)
    except OSError as error:
        ERROR_CONSOLE.print(f"[error]Could not start pip: {error}[/error]")
        return 1
    if result.returncode == 0:
        CONSOLE.print("[success]Update complete. Restart the terminal if the old command is still loaded.[/success]")
    return result.returncode


def _search_url(source: str, query: str) -> str:
    query_string = urlencode({"q": query})
    if source == "DuckDuckGo":
        return f"https://duckduckgo.com/?{query_string}"
    if source == "Bing":
        return f"https://www.bing.com/search?{query_string}"
    return f"https://www.google.com/search?{query_string}"


def _report_rows(report: object) -> list[tuple[str, str]]:
    rows = []

    def visit(value: object, path: str) -> None:
        if isinstance(value, dict):
            if not value:
                rows.append((path, "{}"))
            for key, child in value.items():
                child_path = f"{path}.{key}" if path else str(key)
                visit(child, child_path)
        elif isinstance(value, list):
            if not value:
                rows.append((path, "[]"))
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]")
        elif isinstance(value, str):
            rows.append((path, value))
        else:
            rows.append((path, json.dumps(value, ensure_ascii=False)))

    visit(report, "")
    return rows


def _report_table_parts(report: object) -> tuple[list[tuple[str, object]], list[tuple[str, list[dict]]]]:
    fields = []
    record_tables = []

    def visit(value: object, path: str) -> None:
        if isinstance(value, dict):
            if not value:
                fields.append((path, "{}"))
            for key, child in value.items():
                child_path = f"{path}.{key}" if path else str(key)
                visit(child, child_path)
        elif isinstance(value, list):
            if value and all(isinstance(item, dict) for item in value):
                record_tables.append((path or "Results", value))
            elif not value:
                fields.append((path, "[]"))
            else:
                for index, child in enumerate(value):
                    visit(child, f"{path}[{index}]")
        else:
            fields.append((path, value))

    visit(report, "")
    return fields, record_tables


def _table_cell(value: object) -> str:
    if value is None:
        text = "—"
    elif isinstance(value, bool):
        text = "Yes" if value else "No"
    elif isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False, separators=(",", ": "))
    else:
        text = str(value)
    return escape(text)


def _render_report_table(console: Console, report: dict) -> None:
    fields, record_tables = _report_table_parts(report)

    if fields:
        table = Table(
            box=box.MINIMAL,
            expand=False,
            pad_edge=False,
            padding=(0, 1),
            header_style="bold",
        )
        table.add_column("Field", style="cyan", overflow="fold")
        table.add_column("Value", overflow="fold")
        for field, value in fields:
            table.add_row(_table_cell(field), _table_cell(value))
        console.print(table)

    for table_title, records in record_tables:
        columns = list(dict.fromkeys(key for record in records for key in record))
        console.print(f"\n[bold]{escape(table_title)}[/bold]")
        table = Table(
            box=box.MINIMAL,
            expand=False,
            pad_edge=False,
            padding=(0, 1),
            header_style="bold",
        )
        if not columns:
            table.add_column("Record")
            for _record in records:
                table.add_row("{}")
            console.print(table)
            continue
        for column in columns:
            table.add_column(escape(str(column)), overflow="fold")
        for record in records:
            table.add_row(*(_table_cell(record.get(column)) for column in columns))
        console.print(table)


def _render_table_text(report: dict) -> str:
    buffer = io.StringIO()
    file_console = Console(
        file=buffer,
        width=120,
        color_system=None,
        force_terminal=False,
        highlight=False,
    )
    _render_report_table(file_console, report)
    return buffer.getvalue()


def _render_csv(report: dict) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow(("field", "value"))
    writer.writerows(_report_rows(report))
    return buffer.getvalue()


def _markdown_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\r\n", "<br>").replace("\n", "<br>")


def _render_markdown(report: dict) -> str:
    title = report.get("target") or report.get("comparison") or "OSINT report"
    lines = [f"# {_markdown_cell(str(title))}", "", "| Field | Value |", "| --- | --- |"]
    lines.extend(
        f"| {_markdown_cell(field)} | {_markdown_cell(value)} |"
        for field, value in _report_rows(report)
    )
    return "\n".join(lines) + "\n"


def _resolve_report_format(output_format: str | None, output_path: str | None) -> str:
    if output_format:
        return output_format
    if not output_path:
        return "table"
    extension = Path(output_path).suffix.casefold()
    return {
        ".csv": "csv",
        ".md": "markdown",
        ".markdown": "markdown",
        ".txt": "table",
    }.get(extension, "json")


def add_report_output_options(command_parser: argparse.ArgumentParser) -> None:
    command_parser.add_argument("-o", "--output", help="write the report to this file")
    command_parser.add_argument(
        "--format",
        choices=REPORT_FORMATS,
        help="format: table, json, csv, or markdown (default: table in CLI; inferred for files)",
    )


def write_report(
    report: dict, output_path: str | None, output_format: str | None = None
) -> int:
    selected_format = _resolve_report_format(output_format, output_path)
    if selected_format == "table" and not output_path:
        _render_report_table(CONSOLE, report)
        return 0
    if selected_format == "json":
        rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    elif selected_format == "csv":
        rendered = _render_csv(report)
    elif selected_format == "markdown":
        rendered = _render_markdown(report)
    else:
        rendered = _render_table_text(report)

    if not output_path:
        if selected_format == "json":
            CONSOLE.print_json(data=report)
        else:
            sys.stdout.write(rendered)
        return 0
    try:
        with open(output_path, "w", encoding="utf-8", newline="") as output_file:
            output_file.write(rendered)
    except OSError as error:
        ERROR_CONSOLE.print(f"[error]Could not write report: {error}[/error]")
        return 1
    CONSOLE.print(f"[success]Report saved to[/success] [path]{output_path}[/path]")
    return 0


def _collect_report_changes(before: object, after: object, path: str = "") -> list[dict]:
    if isinstance(before, dict) and isinstance(after, dict):
        changes = []
        ignored_fields = {"generated_at", "cache", "cache_status"}
        for field in sorted(set(before) | set(after)):
            if field in ignored_fields:
                continue
            field_path = f"{path}.{field}" if path else field
            before_present = field in before
            after_present = field in after
            if not before_present or not after_present:
                changes.append({
                    "field": field_path,
                    "before_present": before_present,
                    "after_present": after_present,
                    "before": before.get(field),
                    "after": after.get(field),
                })
            else:
                changes.extend(_collect_report_changes(before[field], after[field], field_path))
        return changes
    if before != after:
        return [{"field": path, "before": before, "after": after}]
    return []


def build_report_diff(before: dict, after: dict) -> dict:
    changes = _collect_report_changes(before, after)
    return {
        "comparison": "OSINT report diff",
        "before_target": before.get("target"),
        "after_target": after.get("target"),
        "changed_fields": changes,
        "summary": {"changed_fields": len(changes)},
        "mode": "local comparison; no network requests performed",
    }


def load_report_file(path: str) -> dict:
    try:
        report = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as error:
        raise argparse.ArgumentTypeError(f"could not read report {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise argparse.ArgumentTypeError(f"report is not valid JSON: {path}") from error
    if not isinstance(report, dict):
        raise argparse.ArgumentTypeError(f"report must contain a JSON object: {path}")
    return report


def main() -> int:
    parser = ColorArgumentParser(
        description="Cross-platform OSINT toolkit for authorized research using public sources."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--update",
        action="store_true",
        help="install the latest release or a newer main commit from GitHub",
    )
    subparsers = parser.add_subparsers(dest="command", parser_class=ColorArgumentParser)
    domain_parser = subparsers.add_parser("domain", help="Look up RDAP, DNS, and TLS certificate transparency")
    domain_parser.add_argument("target", type=valid_domain, help="domain under authorized investigation")
    add_report_output_options(domain_parser)
    domain_parser.add_argument("--timeout", type=int, default=10, help="timeout per source, in seconds (1-60)")
    ip_parser = subparsers.add_parser("ip", help="Look up RDAP and reverse DNS for a public IP")
    ip_parser.add_argument("target", type=valid_public_ip, help="public IPv4 or IPv6 address")
    add_report_output_options(ip_parser)
    ip_parser.add_argument("--timeout", type=int, default=10, help="timeout per source, in seconds (1-60)")
    ioc_parser = subparsers.add_parser("ioc", help="Generate reputation links for an indicator")
    ioc_parser.add_argument("indicator", help="domain, IP address, HTTP(S) URL, or MD5/SHA1/SHA256 hash")
    add_report_output_options(ioc_parser)
    search_parser = subparsers.add_parser("search", help="Generate links for manual public-source searches")
    search_parser.add_argument("target", help="username, person, company, or organization name")
    search_parser.add_argument("--kind", choices=("username", "person", "organization", "company"), required=True)
    add_report_output_options(search_parser)
    profiles_parser = subparsers.add_parser("profiles", help="Check public profile presence for one username")
    profiles_parser.add_argument("username", type=valid_username, help="single username to check")
    profiles_parser.add_argument("--timeout", type=int, default=10, help="timeout per service, in seconds (1-30)")
    add_report_output_options(profiles_parser)
    phone_parser = subparsers.add_parser("phone", help="Validate an international phone number without identifying its owner")
    phone_parser.add_argument("number", help="international E.164 number, for example +14155552671")
    add_report_output_options(phone_parser)
    compare_parser = subparsers.add_parser("compare", help="Compare two saved JSON reports")
    compare_parser.add_argument("before", help="path to the older JSON report")
    compare_parser.add_argument("after", help="path to the newer JSON report")
    add_report_output_options(compare_parser)
    config_parser = subparsers.add_parser("config", help="Configure secure API credentials")
    config_actions = config_parser.add_subparsers(dest="config_action", required=True)
    config_actions.add_parser("set-shodan-key", help="save a Shodan API key in the OS keyring")
    config_actions.add_parser("remove-shodan-key", help="remove the stored Shodan API key")
    config_actions.add_parser("status", help="show whether a Shodan API key is configured")
    config_actions.add_parser("test-shodan", help="validate the Shodan API key and show safe account quotas")
    config_actions.add_parser("clear-cache", help="delete cached Shodan search results")
    shodan_parser = subparsers.add_parser("shodan", help="Look up passive Shodan metadata for one public IP")
    shodan_parser.add_argument("target", type=valid_public_ip, help="public IPv4 or IPv6 address")
    shodan_parser.add_argument("--timeout", type=int, default=10, help="request timeout, in seconds (1-30)")
    shodan_parser.add_argument("--cache-ttl", type=int, default=SHODAN_DEFAULT_CACHE_TTL, help="cache lifetime in seconds (0 disables cache; max 86400)")
    add_report_output_options(shodan_parser)
    range_parser = subparsers.add_parser("shodan-range", help="Search Shodan's indexed data for a public IPv4 or IPv6 CIDR range")
    range_parser.add_argument("network", type=valid_public_network, help="public CIDR; maximum 256 addresses (/24 IPv4 or /120 IPv6)")
    range_parser.add_argument("--limit", type=int, choices=(10, 25, 50, 100, 250, 500), default=100, help="maximum indexed results to include (default: 100; max: 500)")
    range_parser.add_argument("--timeout", type=int, default=10, help="request timeout, in seconds (1-30)")
    range_parser.add_argument("--cache-ttl", type=int, default=SHODAN_DEFAULT_CACHE_TTL, help="cache lifetime in seconds (0 disables cache; max 86400)")
    add_report_output_options(range_parser)
    asn_parser = subparsers.add_parser("asn", help="Search Shodan's indexed data for an autonomous system number")
    asn_parser.add_argument("number", type=valid_asn, help="ASN such as AS15169 or 15169")
    asn_parser.add_argument("--limit", type=int, choices=(10, 25, 50, 100, 250, 500), default=100, help="maximum indexed results to include (default: 100; max: 500)")
    asn_parser.add_argument("--timeout", type=int, default=10, help="request timeout, in seconds (1-30)")
    asn_parser.add_argument("--cache-ttl", type=int, default=SHODAN_DEFAULT_CACHE_TTL, help="cache lifetime in seconds (0 disables cache; max 86400)")
    add_report_output_options(asn_parser)
    args = parser.parse_args()

    if args.update:
        return update_application()
    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "config":
        return configure_shodan(args.config_action)
    if args.command == "compare":
        try:
            report = build_report_diff(load_report_file(args.before), load_report_file(args.after))
        except argparse.ArgumentTypeError as error:
            parser.error(str(error))
        return write_report(report, args.output, args.format)
    if args.command in {"domain", "ip"} and not 1 <= args.timeout <= 60:
        parser.error("--timeout must be between 1 and 60 seconds")
    if args.command in {"shodan", "shodan-range", "asn"} and not 1 <= args.timeout <= 30:
        parser.error("--timeout must be between 1 and 30 seconds")
    if args.command in {"shodan", "shodan-range", "asn"} and not 0 <= args.cache_ttl <= 86400:
        parser.error("--cache-ttl must be between 0 and 86400 seconds")
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
    elif args.command == "shodan":
        api_key = get_shodan_api_key()
        if not api_key:
            ERROR_CONSOLE.print("[error]Shodan API key is not configured. Run `osint-kit config set-shodan-key`.[/error]")
            return 2
        report = build_shodan_report(args.target, api_key, args.timeout, args.cache_ttl)
    elif args.command == "shodan-range":
        api_key = get_shodan_api_key()
        if not api_key:
            ERROR_CONSOLE.print("[error]Shodan API key is not configured. Run `osint-kit config set-shodan-key`.[/error]")
            return 2
        report = build_shodan_search_report(
            args.network,
            f"net:{args.network}",
            "ip_range",
            api_key,
            args.timeout,
            args.limit,
            args.cache_ttl,
        )
    elif args.command == "asn":
        api_key = get_shodan_api_key()
        if not api_key:
            ERROR_CONSOLE.print("[error]Shodan API key is not configured. Run `osint-kit config set-shodan-key`.[/error]")
            return 2
        report = build_shodan_search_report(
            args.number,
            f"asn:{args.number}",
            "asn",
            api_key,
            args.timeout,
            args.limit,
            args.cache_ttl,
        )
    else:
        if not args.target.strip():
            parser.error("search target cannot be empty")
        try:
            report = build_search_report(args.target, args.kind)
        except argparse.ArgumentTypeError as error:
            parser.error(str(error))
    return write_report(report, args.output, args.format)


if __name__ == "__main__":
    raise SystemExit(main())
