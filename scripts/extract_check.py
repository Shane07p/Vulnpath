"""Run symbol extraction against one real advisory and report what survived.

The number that matters is the gap between extracted and verified. Extraction alone
cannot be trusted and is not meant to be; this prints both columns so the verifier's
catch rate is visible rather than assumed.

    uv run python scripts/extract_check.py CVE-2020-14343 --package pyyaml

Reads GEMINI_API_KEY from the environment, or from a .env file beside this repo. The key
is never printed, and neither is any part of it.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import httpx

from vulnpath.environment import EnvironmentError_, find_site_packages
from vulnpath.extract import SymbolExtractor
from vulnpath.models import normalise
from vulnpath.osv import OSV_API, OsvVulnerability, to_advisory
from vulnpath.patches import PatchFetcher
from vulnpath.verify import verify_symbols

ROOT = Path(__file__).resolve().parent.parent


def load_dotenv(path: Path) -> None:
    """Put ``KEY=value`` lines into the environment, without overwriting what is set.

    A deliberately small reader rather than a dependency: this handles the one shape a
    key is written in, and an already-exported variable still wins so a shell override
    behaves the way anyone would expect.
    """
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, _, value = stripped.partition("=")
        name = name.strip()
        value = value.strip().strip("'\"")
        if name and name not in os.environ:
            os.environ[name] = value


def fetch_advisory(advisory_id: str) -> OsvVulnerability | None:
    """The real record from OSV, so the prompt sees prose nobody wrote for a test."""
    try:
        response = httpx.get(f"{OSV_API}/v1/vulns/{advisory_id}", timeout=20.0)
        response.raise_for_status()
        payload = response.json()
    except httpx.HTTPError as exc:
        print(f"could not fetch {advisory_id}: {exc}")
        return None
    if not isinstance(payload, dict):
        return None
    return OsvVulnerability.model_validate(payload)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("advisory", nargs="?", default="CVE-2020-14343")
    parser.add_argument("--package", default="pyyaml")
    parser.add_argument(
        "--import-names",
        default="",
        help="Comma-separated import names. Defaults to the package name.",
    )
    parser.add_argument(
        "--no-diff",
        action="store_true",
        help="Prose only, ignoring the fix diff. For A/B against the diff-assisted run.",
    )
    parser.add_argument(
        "--python",
        default=None,
        help="Environment to verify against. Defaults to this repo's own.",
    )
    args = parser.parse_args()

    load_dotenv(ROOT / ".env")

    package = normalise(args.package)
    names = frozenset(
        part.strip() for part in (args.import_names or package).split(",") if part.strip()
    )

    extractor = SymbolExtractor(offline=False)
    if not extractor.is_available:
        print("GEMINI_API_KEY is not set, in the environment or in .env.")
        return 2

    vuln = fetch_advisory(args.advisory)
    if vuln is None:
        return 2
    advisory = to_advisory(vuln, package)

    print(f"advisory   {advisory.display_id}")
    print(f"package    {package}  (import names: {', '.join(sorted(names))})")
    print(f"summary    {advisory.summary[:100]}")
    print()

    diff = ""
    if not args.no_diff:
        diff = PatchFetcher().diff_for(advisory.fix_commits)
        print(f"fix commits {len(advisory.fix_commits)}  diff chars {len(diff)}")

    extracted = extractor.symbols_for(advisory, package, names, diff)
    if extracted is None:
        print("extraction FAILED after one retry — no answer obtained.")
        return 1

    print(f"extracted  {list(extracted) or '(advisory names nothing specific)'}")

    try:
        site_packages = find_site_packages(ROOT, Path(args.python) if args.python else None)
    except EnvironmentError_ as exc:
        print(f"verified   (skipped: {exc})")
        return 0

    result = verify_symbols(extracted, site_packages)
    print(f"verified   {list(result.verified)}")
    print(f"dropped    {list(result.dropped)}")

    if result.dropped:
        print()
        print("Dropped symbols are either hallucinations or real symbols of a package")
        print("that is not installed here. Check which before reading this as accuracy.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
