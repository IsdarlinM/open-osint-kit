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
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, urlopen

import phonenumbers


__version__ = "1.1.0"
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
        raise argparse.ArgumentTypeError("el dominio no tiene un formato IDN válido") from error
    labels = domain.split(".")
    label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    if len(labels) < 2 or len(domain) > 253 or any(not label_pattern.fullmatch(label) for label in labels):
        raise argparse.ArgumentTypeError("indica un dominio válido, por ejemplo example.org")
    return domain


def valid_public_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("indica una dirección IPv4 o IPv6 válida") from error
    if not address.is_global:
        raise argparse.ArgumentTypeError("solo se admiten direcciones IP públicas")
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
            raise argparse.ArgumentTypeError("no se permiten indicadores IP privados o reservados")
        return "ip", str(address)
    except ValueError:
        pass

    try:
        parsed = urlsplit(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("la URL no tiene un formato válido") from error
    if parsed.scheme.lower() in {"http", "https"} and parsed.hostname:
        if parsed.username or parsed.password:
            raise argparse.ArgumentTypeError("quita las credenciales de la URL antes de consultarla")
        if parsed.query:
            raise argparse.ArgumentTypeError(
                "la URL contiene parámetros; elimina posibles tokens o secretos antes de compartirla"
            )
        try:
            url_address = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            pass
        else:
            if not url_address.is_global:
                raise argparse.ArgumentTypeError("la URL contiene una IP privada o reservada")
        return "url", value
    try:
        return "domain", valid_domain(value)
    except argparse.ArgumentTypeError as error:
        raise argparse.ArgumentTypeError(
            "el indicador debe ser un dominio, una IP, una URL HTTP(S) o un hash MD5/SHA1/SHA256"
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
    queries = [
        ("DuckDuckGo", term),
        ("Google", term),
        ("Bing", term),
        ("GitHub", f'site:github.com {term}'),
        ("Reddit", f'site:reddit.com {term}'),
    ]
    if kind == "username":
        queries.extend([
            ("GitLab", f'site:gitlab.com {term}'),
            ("LinkedIn", f'site:linkedin.com/in {term}'),
        ])
    elif kind in {"organization", "company"}:
        queries.extend([
            ("LinkedIn", f'site:linkedin.com/company {term}'),
            ("OpenCorporates", f'site:opencorporates.com {term}'),
            ("Crunchbase", f'site:crunchbase.com/organization {term}'),
        ])
    else:
        queries.extend([
            ("LinkedIn", f'site:linkedin.com/in {term}'),
            ("Google News", f'{term}'),
            ("Google Scholar", f'site:scholar.google.com {term}'),
        ])
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


def build_phone_report(value: str) -> dict:
    if not value.strip().startswith("+"):
        raise argparse.ArgumentTypeError("usa formato internacional E.164, por ejemplo +14155552671")
    try:
        number = phonenumbers.parse(value, None)
    except phonenumbers.NumberParseException as error:
        raise argparse.ArgumentTypeError(f"número telefónico no válido: {error}") from error
    if not phonenumbers.is_possible_number(number) or not phonenumbers.is_valid_number(number):
        raise argparse.ArgumentTypeError("el número no es válido según el plan telefónico")

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
        print(f"No se pudo consultar GitHub: {error}", file=sys.stderr)
        return 1
    if not isinstance(release, dict) or not isinstance(release.get("tag_name"), str):
        print("GitHub devolvió información de release no válida.", file=sys.stderr)
        return 1

    tag = release["tag_name"]
    latest_version = release_version(tag)
    current_version = release_version(f"v{__version__}")
    if latest_version is None or current_version is None:
        print(f"Versión de release no reconocida: {tag}", file=sys.stderr)
        return 1
    if latest_version <= current_version:
        print(f"Ya tienes la última versión estable ({__version__}).")
        return 0

    archive_url = GITHUB_ARCHIVE_URL.format(tag=quote(tag, safe=""))
    command = [sys.executable, "-m", "pip", "install", "--upgrade", "--force-reinstall"]
    if sys.prefix == sys.base_prefix:
        command.append("--user")
    command.append(archive_url)
    print(f"Actualizando {__version__} a {tag} desde GitHub...")
    try:
        result = subprocess.run(command, check=False)
    except OSError as error:
        print(f"No se pudo iniciar pip: {error}", file=sys.stderr)
        return 1
    if result.returncode == 0:
        print("Actualización completada. Cierra y vuelve a abrir la terminal si el comando sigue cargado.")
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
        print(f"No se pudo escribir el informe: {error}", file=sys.stderr)
        return 1
    print(f"Informe guardado en {output_path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Kit OSINT multiplataforma para consultas autorizadas a fuentes públicas."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--update", action="store_true", help="instalar el último release estable desde GitHub")
    subparsers = parser.add_subparsers(dest="command")
    domain_parser = subparsers.add_parser("domain", help="Consultar RDAP, DNS y transparencia TLS")
    domain_parser.add_argument("target", type=valid_domain, help="dominio bajo investigación autorizada")
    domain_parser.add_argument("-o", "--output", help="guardar el informe JSON en esta ruta")
    domain_parser.add_argument("--timeout", type=int, default=10, help="timeout por fuente, en segundos (1-60)")
    ip_parser = subparsers.add_parser("ip", help="Consultar RDAP y DNS inverso para una IP pública")
    ip_parser.add_argument("target", type=valid_public_ip, help="dirección IPv4 o IPv6 pública")
    ip_parser.add_argument("-o", "--output", help="guardar el informe JSON en esta ruta")
    ip_parser.add_argument("--timeout", type=int, default=10, help="timeout por fuente, en segundos (1-60)")
    ioc_parser = subparsers.add_parser("ioc", help="Generar enlaces de reputación para un indicador")
    ioc_parser.add_argument("indicator", help="dominio, IP, URL HTTP(S), o hash MD5/SHA1/SHA256")
    ioc_parser.add_argument("-o", "--output", help="guardar el informe JSON en esta ruta")
    search_parser = subparsers.add_parser("search", help="Generar enlaces para búsquedas manuales")
    search_parser.add_argument("target", help="nombre de usuario u organización")
    search_parser.add_argument("--kind", choices=("username", "person", "organization", "company"), required=True)
    search_parser.add_argument("-o", "--output", help="guardar el informe JSON en esta ruta")
    phone_parser = subparsers.add_parser("phone", help="Validar un teléfono internacional sin buscar a su titular")
    phone_parser.add_argument("number", help="número internacional E.164, por ejemplo +14155552671")
    phone_parser.add_argument("-o", "--output", help="guardar el informe JSON en esta ruta")
    args = parser.parse_args()

    if args.update:
        return update_application()
    if args.command is None:
        parser.print_help()
        return 0
    if args.command in {"domain", "ip"} and not 1 <= args.timeout <= 60:
        parser.error("--timeout debe estar entre 1 y 60 segundos")
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
    else:
        if not args.target.strip():
            parser.error("el objetivo de búsqueda no puede estar vacío")
        report = build_search_report(args.target, args.kind)
    return write_report(report, args.output)


if __name__ == "__main__":
    raise SystemExit(main())