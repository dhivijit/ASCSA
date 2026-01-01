import requests
import re
import json

# subject to modification to pass the directory to let it directly access the dependency files

def scan_dep_vulns(content, filename):
    """
    Scan dependencies for vulnerabilities from content and filename.

    Args:
        content (str): The content of the requirements.txt or package.json file
        filename (str): The filename to determine which parser to use

    Returns:
        list: List of vulnerability dictionaries, empty list if no vulnerabilities found
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
        resp = requests.post(url, json=pkg)
        if resp.status_code != 200:
            print(f"Error querying OSV for {pkg}: {resp.status_code}")
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
        raise ValueError(f"Unsupported file type. Only .txt (requirements.txt) and .json (package.json) are supported. Got {filename}")

    # Scan each package for vulnerabilities
    all_vulns = []
    for pkg in packages:
        vulns = get_vulns_for_package(pkg)
        if vulns:
            all_vulns.extend(vulns)

    print(f"Found {len(all_vulns)} vulnerabilities in {filename}. Details: {all_vulns[:5]}...")  # Show first 5 for brevity
    if not all_vulns:
        print(f"No vulnerabilities found in {filename}.")
    else:
        print(f"Found {len(all_vulns)} vulnerabilities in {filename}.")
    return all_vulns