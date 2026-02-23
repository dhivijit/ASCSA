"""
OSV Scanner — Dependency vulnerability checking via the OSV.dev API.

Parses requirements.txt (PyPI) and package.json (npm) to extract
dependency lists, then queries the OSV REST API for known
vulnerabilities in each package+version.
"""
import requests
import re
import json

# HTTP timeout for OSV API requests (seconds)
_OSV_TIMEOUT = 30


def scan_dep_vulns(content, filename):
    """Scan dependencies for vulnerabilities from content and filename.

    Args:
        content: The content of the requirements.txt or package.json file.
        filename: The filename to determine which parser to use.

    Returns:
        List of vulnerability dictionaries, empty list if none found.
    """

    def parse_requirements_txt(content):
        packages = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            match = re.match(r'^([a-zA-Z0-9_\-\.]+)[=<>!~]+([a-zA-Z0-9_\-\.]+)', line)
            if match:
                name, version = match.groups()
                packages.append({
                    "package": {"name": name, "ecosystem": "PyPI"},
                    "version": version
                })
        return packages

    def parse_package_json(content):
        packages = []
        data = json.loads(content)
        for dep_type in ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']:
            deps = data.get(dep_type, {})
            for name, version in deps.items():
                clean_version = re.sub(r'^[\^~><=]*', '', version)
                packages.append({
                    "package": {"name": name, "ecosystem": "npm"},
                    "version": clean_version
                })
        return packages

    def get_vulns_for_package(pkg):
        url = "https://api.osv.dev/v1/query"
        try:
            resp = requests.post(url, json=pkg, timeout=_OSV_TIMEOUT)
        except requests.exceptions.Timeout:
            print(f"Timeout querying OSV for {pkg['package']['name']}")
            return []
        except requests.exceptions.RequestException as e:
            print(f"Error querying OSV for {pkg['package']['name']}: {e}")
            return []

        if resp.status_code != 200:
            print(f"Error querying OSV for {pkg['package']['name']}: HTTP {resp.status_code}")
            return []

        data = resp.json()
        vulns = []
        for vuln in data.get("vulns", []):
            fixed_versions = []
            for aff in vuln.get("affected", []):
                for rng in aff.get("ranges", []):
                    for event in rng.get("events", []):
                        if "fixed" in event:
                            fixed_versions.append(event["fixed"])
            vulns.append({
                "package_name": pkg["package"]["name"],
                "ecosystem": pkg["package"]["ecosystem"],
                "version": pkg["version"],
                "id": vuln.get("id"),
                "summary": vuln.get("summary"),
                "details": vuln.get("details"),
                "aliases": vuln.get("aliases"),
                "published": vuln.get("published"),
                "fixed": fixed_versions
            })
        return vulns

    # Parse packages based on file extension
    if filename.endswith(".txt"):
        packages = parse_requirements_txt(content)
    elif filename.endswith(".json"):
        packages = parse_package_json(content)
    else:
        raise ValueError(f"Unsupported file type. Only .txt and .json are supported. Got {filename}")

    # Scan each package for vulnerabilities
    all_vulns = []
    for pkg in packages:
        vulns = get_vulns_for_package(pkg)
        if vulns:
            all_vulns.extend(vulns)

    if all_vulns:
        print(f"Found {len(all_vulns)} vulnerabilities in {filename}.")
    else:
        print(f"No vulnerabilities found in {filename}.")
    return all_vulns