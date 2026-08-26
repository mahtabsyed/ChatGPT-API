#!/usr/bin/env python3
"""Portable security auditor for Python projects (audits PINNED versions).

Checks the project's dependencies against the OSV.dev advisory database (the same
data GitHub Dependabot and pip-audit use) and prints any known vulnerabilities
with their fixed versions.

In a uv workspace the preferred path exports the fully-resolved, PINNED set from
`uv.lock` and audits exactly those versions, so the result reflects what actually
ships and is not polluted by tooling packages that an ephemeral `uv run --with`
environment would drag in (for example `pip` itself, which is not a project
dependency). When no lockfile export is available it falls back to auditing the
active environment, and the stdlib OSV path scans the installed distributions.

Design goals:
  - Runs in ANY repo / virtualenv with only the standard library (no pip install).
  - Prefers pip-audit when it is available (the battle-tested PyPA tool);
    falls back to a direct OSV.dev query otherwise.

Usage:
    # In the project's environment (so it can resolve the lockfile):
    uv run python security_audit_pinned.py      # this repo (uv, pinned set)
    python security_audit_pinned.py             # any activated venv

    # Options:
    python security_audit_pinned.py --json             # machine-readable output
    python security_audit_pinned.py --installed        # audit the live env, not uv.lock
    python security_audit_pinned.py --ignore GHSA-xxxx # skip specific advisory IDs

Exit code is 0 when clean, 1 when any vulnerability is found (handy for CI).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
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

    # OSV lists the same vulnerability once per advisory namespace (PYSEC, GHSA,
    # ...); collapse them into one finding, then honour --ignore against any of the
    # merged identifiers so ignoring a CVE also ignores its GHSA/PYSEC twins.
    merged = merge_advisories(findings)
    return [f for f in merged if not ({f["id"], *f["aliases"]} & ignore)]


def merge_advisories(findings: list[dict]) -> list[dict]:
    """Collapse OSV records that describe the same underlying vulnerability.

    OSV returns one record per advisory namespace, each cross-referencing the
    others via `aliases`. Records for the same package that share any identifier
    are merged into a single finding with every namespace id preserved. The
    display id prefers a CVE, then a GHSA, then whatever remains.
    """
    def rank(identifier: str) -> int:
        if identifier.startswith("CVE-"):
            return 0
        if identifier.startswith("GHSA-"):
            return 1
        return 2

    groups: list[dict] = []
    for f in findings:
        ids = {f["id"], *f["aliases"]}
        key = (f["package"], f["version"])
        target = next((g for g in groups if g["key"] == key and g["ids"] & ids), None)
        if target is None:
            groups.append(
                {
                    "key": key,
                    "ids": set(ids),
                    "package": f["package"],
                    "version": f["version"],
                    "summary": f["summary"],
                    "fixed_versions": list(f["fixed_versions"]),
                }
            )
            continue
        target["ids"] |= ids
        if not target["summary"] and f["summary"]:
            target["summary"] = f["summary"]
        for fx in f["fixed_versions"]:
            if fx not in target["fixed_versions"]:
                target["fixed_versions"].append(fx)

    merged: list[dict] = []
    for g in groups:
        ordered = sorted(g["ids"], key=lambda i: (rank(i), i))
        merged.append(
            {
                "package": g["package"],
                "version": g["version"],
                "id": ordered[0],
                "aliases": ordered[1:],
                "summary": g["summary"],
                "fixed_versions": sorted(set(g["fixed_versions"])),
            }
        )
    return merged


def export_pinned_requirements(path: str) -> bool:
    """Export the fully-resolved, PINNED dependency set from uv.lock to `path`.

    Uses `--all-packages` so every workspace member's locked closure is emitted
    (portable across single- and multi-package repos) and `--no-emit-project` so
    the local first-party packages themselves are excluded. `--frozen` guarantees
    the existing lockfile is used verbatim (no resolution, no network). Returns
    True when a non-empty requirements file was written.
    """
    cmd = [
        "uv", "export", "--frozen", "--no-hashes",
        "--all-packages", "--no-emit-project",
        "--format", "requirements-txt", "-o", path,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return False
    try:
        return any("==" in line for line in open(path, encoding="utf-8"))
    except OSError:
        return False


def pinned_packages() -> list[tuple[str, str]] | None:
    """Return (name, version) for the PINNED closure in uv.lock, or None.

    None means this is not a resolvable uv project (no `uv` on PATH, or the export
    produced nothing), so the caller should fall back to the installed environment.
    We audit the exported lockfile rather than shelling out to `pip-audit -r`
    because pip-audit spins up a throwaway venv per requirements file (running
    ensurepip), which is slow and fails outright on some interpreters. Parsing the
    pinned versions and querying OSV directly is deterministic and stdlib-only.
    """
    if not shutil.which("uv"):
        return None
    # Deterministic temp path so re-runs overwrite rather than pile up.
    req = os.path.join(tempfile.gettempdir(), "security_audit_pinned_reqs.txt")
    if not export_pinned_requirements(req):
        return None
    seen: dict[str, str] = {}
    try:
        with open(req, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "==" not in line:
                    continue
                # Drop environment markers: "name==1.2.3 ; python_version >= '3.12'".
                spec = line.split(";", 1)[0].strip()
                name, _, version = spec.partition("==")
                name = name.split("[", 1)[0].strip()  # drop extras, e.g. name[crypto]
                version = version.strip()
                if name and version:
                    seen[name.lower()] = version
    except OSError:
        return None
    return sorted(seen.items())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", action="store_true", help="emit findings as JSON")
    parser.add_argument("--installed", action="store_true",
                        help="audit the live environment instead of the pinned uv.lock set")
    parser.add_argument("--ignore", action="append", default=[], metavar="ID", help="advisory IDs to skip")
    args = parser.parse_args()

    # Default: audit the PINNED set from uv.lock (what actually ships). Fall back to
    # the installed environment when this is not a uv project or --installed is set.
    packages = None if args.installed else pinned_packages()
    if packages is not None:
        source = f"{len(packages)} PINNED packages from uv.lock"
    else:
        packages = installed_packages()
        source = f"{len(packages)} installed packages"

    findings = scan_with_osv(packages, ignore=set(args.ignore))

    if args.json:
        print(json.dumps(findings, indent=2))
        return 1 if findings else 0

    print(f"Scanned {source} against OSV.dev.\n")
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
