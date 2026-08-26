#!/usr/bin/env python3
"""Portable security auditor for Python projects.

Checks every installed distribution in the current environment against the
OSV.dev advisory database (the same data GitHub Dependabot and pip-audit use)
and prints any known vulnerabilities with their fixed versions.

Design goals:
  - Runs in ANY repo / virtualenv with only the standard library (no pip install).
  - Prefers pip-audit when it is available (the battle-tested PyPA tool);
    falls back to a direct OSV.dev query otherwise.

Usage:
    # In the project's environment (so it sees the installed versions):
    uv run python security_audit.py            # this repo (uv)
    python security_audit.py                    # any activated venv

    # Options:
    python security_audit.py --json             # machine-readable output
    python security_audit.py --no-pip-audit     # force the stdlib OSV path
    python security_audit.py --ignore GHSA-xxxx # skip specific advisory IDs

Exit code is 0 when clean, 1 when any vulnerability is found (handy for CI).
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from importlib import metadata

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
TIMEOUT = 30


def installed_packages() -> list[tuple[str, str]]:
    """Return (name, version) for every distribution in this environment."""
    seen: dict[str, str] = {}
    for dist in metadata.distributions():
        name = (dist.metadata.get("Name") or "").strip()
        version = (dist.version or "").strip()
        if name and version:
            seen[name.lower()] = version  # dedupe case-insensitively
    return sorted(seen.items())


def _post_json(url: str, payload: dict) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode())


def _get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode())


def osv_fixed_versions(vuln: dict) -> list[str]:
    """Extract the 'fixed' versions from an OSV advisory's affected ranges."""
    fixes: list[str] = []
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    fixes.append(event["fixed"])
    return sorted(set(fixes))


def scan_with_osv(packages: list[tuple[str, str]], ignore: set[str]) -> list[dict]:
    """Query OSV.dev for the given (name, version) pairs. Stdlib only."""
    queries = [
        {"package": {"ecosystem": "PyPI", "name": name}, "version": version}
        for name, version in packages
    ]
    try:
        batch = _post_json(OSV_BATCH_URL, {"queries": queries})
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"ERROR: could not reach OSV.dev ({exc}). Check network access.", file=sys.stderr)
        sys.exit(2)

    findings: list[dict] = []
    for (name, version), result in zip(packages, batch.get("results", [])):
        for stub in result.get("vulns", []):
            vid = stub.get("id", "")
            if vid in ignore:
                continue
            # querybatch returns only ids; fetch details for summary + fix versions.
            try:
                vuln = _get_json(OSV_VULN_URL + vid)
            except (urllib.error.URLError, TimeoutError):
                vuln = {}
            findings.append(
                {
                    "package": name,
                    "version": version,
                    "id": vid,
                    "aliases": vuln.get("aliases", []),
                    "summary": (vuln.get("summary") or vuln.get("details", "")[:120]).strip(),
                    "fixed_versions": osv_fixed_versions(vuln),
                }
            )
    return findings


def run_pip_audit() -> int | None:
    """Run pip-audit if reachable; return its exit code, or None if unavailable."""
    if shutil.which("uv"):
        cmd = ["uv", "run", "--with", "pip-audit", "pip-audit", "--format", "columns"]
    elif shutil.which("pip-audit"):
        cmd = ["pip-audit", "--format", "columns"]
    else:
        return None
    print(f"Running: {' '.join(cmd)}\n")
    return subprocess.run(cmd).returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", action="store_true", help="emit findings as JSON")
    parser.add_argument("--no-pip-audit", action="store_true", help="skip pip-audit, use the OSV path")
    parser.add_argument("--ignore", action="append", default=[], metavar="ID", help="advisory IDs to skip")
    args = parser.parse_args()

    # Prefer pip-audit (unless disabled or JSON output requested for the OSV path).
    if not args.no_pip_audit and not args.json:
        code = run_pip_audit()
        if code is not None:
            return code
        print("pip-audit not available; falling back to the built-in OSV scanner.\n")

    packages = installed_packages()
    findings = scan_with_osv(packages, ignore=set(args.ignore))

    if args.json:
        print(json.dumps(findings, indent=2))
        return 1 if findings else 0

    print(f"Scanned {len(packages)} installed packages against OSV.dev.\n")
    if not findings:
        print("No known vulnerabilities found.")
        return 0

    print(f"Found {len(findings)} known vulnerability(ies):\n")
    for f in findings:
        fixes = ", ".join(f["fixed_versions"]) or "no fix published"
        aliases = f" ({', '.join(f['aliases'])})" if f["aliases"] else ""
        print(f"  {f['package']} {f['version']}")
        print(f"    {f['id']}{aliases}")
        if f["summary"]:
            print(f"    {f['summary']}")
        print(f"    Fixed in: {fixes}\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
