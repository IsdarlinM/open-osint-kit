# Open OSINT Kit 1.3.0

![Open OSINT Kit: open-source intelligence](assets/banner.svg)

Cross-platform Python CLI for authorized research into domains, infrastructure, and public indicators. Phone-number analysis uses the `phonenumbers` library.

## Features

`domain` gathers RDAP, DNS (A, AAAA, MX, NS, TXT, and CAA) over DNS-over-HTTPS, and Certificate Transparency records. Each source fails independently.

`ip` checks RDAP and reverse DNS for a public address. Private, local, and reserved IP addresses are rejected.

`ioc` classifies domains, IP addresses, HTTP(S) URLs, and MD5/SHA1/SHA256 hashes, then generates links to public services such as VirusTotal, AlienVault OTX, URLhaus, AbuseIPDB, and CIRCL Hashlookup. Indicators are not submitted automatically.

`search` generates manual search links for usernames, people, companies, and organizations. It does not scrape profiles, collect search results, or verify identities.

`profiles` checks one username against public APIs for GitHub, GitLab, DEV Community, Hacker News, Bluesky, Reddit, Mastodon.social, Codeberg, and Hugging Face. It displays only exact confirmed matches with their category and public profile URL; missing accounts and unavailable APIs are omitted. For Bluesky, a username without a domain is checked as `<username>.bsky.social`. Mastodon checks the `mastodon.social` instance only.

`phone` validates an international E.164 number and reports its formatting, numbering-plan region, and line type. It does not query carriers, identify owners, or verify that a line is active.

`--update` checks this repository's latest stable release and, when a newer version is available, installs the source archive for that release tag with `pip`.

For sites without a reliable public profile API, `search --kind username` also creates manual search links for HackerOne, Bugcrowd, TryHackMe, Hack The Box, LinkedIn, Wellfound, and Indeed, prioritized before general search engines. These are search links, not confirmed profile results.

## Installation

Requires Python 3.9 or later and `pip`. The first installation needs an internet connection to resolve dependencies and the build backend. Installation is per-user and does not require administrator privileges.

On Windows, run from the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
osint-kit --help
```

On Linux, run from the repository root:

```bash
bash ./install.sh
osint-kit --help
```

The installers add the command directory to the user's PATH. On Linux, the application runs in an isolated virtual environment under `~/.local/share/open-osint-kit` and uses the base Python interpreter, even when the installer is launched from another virtual environment. Open a new terminal after installation to apply the updated PATH to other sessions.

## Uninstallation

On Windows, run from PowerShell and the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\uninstall.ps1
```

On Linux, run from the repository root:

```bash
bash ./uninstall.sh
```

The uninstaller removes the per-user package on Windows or the kit's virtual environment and launcher on Linux. It does not uninstall `phonenumbers` on Windows because other applications may use it. It removes a PATH entry only when a recent installer recorded that it added the entry. Installations older than 1.1.1 may leave a shared PATH entry; in that case, it is preserved to avoid affecting other tools. Remove it manually only after confirming that no other application uses it.

## Usage

```text
osint-kit --update
osint-kit --version
osint-kit domain example.org
osint-kit domain example.org --output domain-report.json
osint-kit ip 8.8.8.8 --output ip-report.json
osint-kit ioc example.org
osint-kit ioc 44d88612fea8a8f36de82e1278abb02f
osint-kit search ExampleOrg --kind organization
osint-kit search example_user --kind username --output search.json
osint-kit search "Jane Example" --kind person
osint-kit search "Example Inc" --kind company
osint-kit profiles example_user --timeout 5 --output profiles.json
osint-kit search example_user --kind username
osint-kit phone +14155552671
```

`domain`, `ip`, `profiles`, and `--update` require an internet connection. `ioc` and `search` only generate links; `phone` analyzes numbering-plan metadata locally. The `domain` and `ip` timeouts apply per source, so a full run may take longer than the configured timeout. `profiles` queries each supported API once, concurrently, and may omit services that rate-limit or cannot be reached.

## Responsible Use

Use the kit only for legitimate, authorized research. It does not scan ports, authenticate, or exploit systems. `search` provides links that the user chooses whether to open and is limited to public/professional sources; `profiles` sends the supplied username to the listed APIs and only displays exact matches, without retaining profile details. A match does not prove that accounts belong to the same person. `phone` does not identify the owner. Do not use the tool to locate people or collect home addresses, private data, family details, or sensitive information. URLs with query strings are rejected to reduce the risk of exposing tokens or secrets. Public data may be incomplete, outdated, or subject to terms of use; verify findings before relying on them.
