"""
OSV Scanner — Dependency vulnerability checking via the OSV.dev API.

Parses requirements.txt / pyproject.toml (PyPI) and package.json /
package-lock.json (npm) to extract dependency lists, then queries the
OSV REST API for known vulnerabilities in each package+version.

The list of dependency files to scan is configured in
``config/thresholds.yaml`` under ``hcrs.dependency_files``.
To support a new format add a parser function and register it in
``_PARSERS``.
"""
import os
import requests
import re
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

# HTTP timeout for OSV API requests (seconds)
_OSV_TIMEOUT = 30


# ---------------------------------------------------------------------------
# Parsers — one per dependency-file format
# ---------------------------------------------------------------------------

def _parse_requirements_txt(content):
    """Parse pip requirements.txt into OSV query packages."""
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


def _parse_package_json(content):
    """Parse npm package.json into OSV query packages."""
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


def _parse_package_lock_json(content):
    """Parse npm package-lock.json (v1 / v2 / v3) into OSV query packages."""
    data = json.loads(content)
    packages = []

    # v2 / v3: top-level "packages" dict
    pkgs = data.get("packages", {})
    for path, info in pkgs.items():
        if not path:  # root entry ("") — skip
            continue
        # Extract scoped or unscoped package name from the node_modules path
        if "/node_modules/" in path:
            name = path.split("/node_modules/")[-1]
        elif path.startswith("node_modules/"):
            name = path[len("node_modules/"):]
        else:
            continue
        version = info.get("version")
        if name and version:
            packages.append({
                "package": {"name": name, "ecosystem": "npm"},
                "version": version
            })

    # v1 fallback: top-level "dependencies" with version objects
    if not packages:
        deps = data.get("dependencies", {})
        for name, info in deps.items():
            if isinstance(info, dict):
                version = info.get("version")
                if version:
                    packages.append({
                        "package": {"name": name, "ecosystem": "npm"},
                        "version": version
                    })

    return packages


def _parse_pyproject_toml(content):
    """Parse PEP 621 pyproject.toml into OSV query packages."""
    try:
        import tomllib
    except ModuleNotFoundError:
        try:
            import tomli as tomllib   # type: ignore[no-redef]
        except ModuleNotFoundError:
            print("Warning: tomllib/tomli not available — skipping pyproject.toml")
            return []

    data = tomllib.loads(content)
    packages = []
    for dep_str in data.get('project', {}).get('dependencies', []):
        match = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*[=<>!~]+\s*([a-zA-Z0-9_\-\.]+)', dep_str)
        if match:
            name, version = match.groups()
            packages.append({
                "package": {"name": name, "ecosystem": "PyPI"},
                "version": version
            })
    for group_deps in data.get('project', {}).get('optional-dependencies', {}).values():
        for dep_str in group_deps:
            match = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*[=<>!~]+\s*([a-zA-Z0-9_\-\.]+)', dep_str)
            if match:
                name, version = match.groups()
                packages.append({
                    "package": {"name": name, "ecosystem": "PyPI"},
                    "version": version
                })
    return packages


# Map dependency filenames to their parsers.
# To support a new format, add the filename and parser here and
# include it in hcrs.dependency_files in config/thresholds.yaml.
_PARSERS = {
    'requirements.txt': _parse_requirements_txt,
    'package.json': _parse_package_json,
    'package-lock.json': _parse_package_lock_json,
    'pyproject.toml': _parse_pyproject_toml,
}


# ---------------------------------------------------------------------------
# OSV API helpers
# ---------------------------------------------------------------------------

def _get_vulns_for_package(pkg):
    """Query the OSV REST API for vulnerabilities in a single package."""
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


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_dep_vulns(content, filename):
    """Scan dependencies for vulnerabilities from content and filename.

    Args:
        content: The content of the dependency file.
        filename: The filename (basename) used to select the right parser.

    Returns:
        List of vulnerability dictionaries, empty list if none found.
    """
    basename = os.path.basename(filename)
    parser = _PARSERS.get(basename)

    if parser is None:
        # Extension-based fallback for non-standard names
        if filename.endswith(".txt"):
            parser = _PARSERS['requirements.txt']
        elif filename.endswith(".json"):
            parser = _PARSERS['package.json']
        else:
            raise ValueError(
                f"Unsupported dependency file: {filename}. "
                f"Supported: {', '.join(sorted(_PARSERS))}"
            )

    packages = parser(content)

    # Query OSV for all packages in parallel
    all_vulns = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(_get_vulns_for_package, pkg): pkg for pkg in packages}
        for future in as_completed(futures):
            vulns = future.result()
            if vulns:
                all_vulns.extend(vulns)

    if all_vulns:
        print(f"Found {len(all_vulns)} vulnerabilities in {filename}.")
    else:
        print(f"No vulnerabilities found in {filename}.")
    return all_vulns