# Vulnpath

Reachability-aware dependency triage for Python.

Every scanner tells you which packages have CVEs. Vulnpath is being built to tell you
which ones your code actually reaches, and what shape of fix each one needs.

> **Status: early.** Phase 1 of 8. Advisory matching works and is verified against
> `pip-audit`. Reachability analysis — the reason this project exists — is not built yet.
> Everything below distinguishes what runs today from what does not.

## The problem

Dependency scanners produce the same output: *"you depend on package X, and X has
CVE-YYYY-NNNNN."* That is mostly noise, for two independent reasons.

**Most findings are not real.** You may have the vulnerable package but never call the
vulnerable function. A Go library maintainer publicly asked people to turn Dependabot
off in early 2026, arguing false positives "reduce security by causing alert fatigue."

**Even real findings are often unactionable.** "Just upgrade" fails when the vulnerable
package is three levels deep and a parent's constraint forbids the fixed version. What
you need is the specific command — an override, a lockfile refresh, or a backported
version on your current release line.

Vulnpath is aimed at both halves: a call graph to answer *does my code reach this*, and
rules over the dependency DAG to answer *what fixes it*.

## What works today

```bash
uv run vulnpath scan .            # resolve uv.lock, query OSV, list findings
uv run vulnpath scan . --format json
uv run vulnpath guide             # every command and option, with build status
```

- Parses `uv.lock` — the lockfile, never the manifest. `pyproject.toml` says what was
  asked for; `uv.lock` says what was actually resolved and installed.
- Dependency graph with depth, so direct and transitive are distinguished.
- OSV.dev lookup, cached on disk outside the repo.
- Advisory deduplication: OSV returns one record per source database, so a single CVE
  arrives as both a GHSA and a PYSEC entry.
- Severity threshold filtering, JSON output, offline mode.

Not built yet: reachability analysis, fix-shape classification, SARIF output,
`--only-reachable`, `--fail-on reachable`. `vulnpath guide` marks each one.

## Verified against pip-audit

Phase 1's bar was parity with an established scanner. Against the checked-in fixture
project, comparing on the same advisory source:

| | Advisory records | Distinct CVEs | Packages |
|---|---|---|---|
| `pip-audit` | 38 | 19 | 5 |
| `vulnpath` | 19 | 19 | 5 |

**Identical CVE set. Zero missed.** The record count differs because OSV returns a
separate record per source database; vulnpath merges them, which is why 38 becomes 19
without losing anything.

Reproduce it:

```bash
cd tests/fixtures/sample_project
uv export --format requirements-txt --no-hashes -o reqs.txt
uvx pip-audit -r reqs.txt --no-deps --vulnerability-service osv -f json
uv run vulnpath scan tests/fixtures/sample_project --format json
```

## Design commitments

**`UNKNOWN` never means safe.** When reachability lands there will be three verdicts, not
two: `REACHABLE`, `NOT_REACHABLE`, and `UNKNOWN`. Dynamic dispatch anywhere on a partial
path produces `UNKNOWN`. A false "you're safe" is the one failure mode that makes a
security tool worse than useless, and no amount of noise reduction is worth it.

The same rule already applies to severity: many advisories publish none, and those
findings are **never** hidden by `--min-severity`. Missing data is not evidence of low
risk.

**Every LLM-extracted symbol will be verified against installed source** via `ast` before
being reported. Unverified symbols are dropped, not shown. That check is the reason the
LLM stage is safe to have at all.

**`--offline` must work with no API key**, degrading to weaker analysis and saying so.

## Development

```bash
uv run pytest          # tests
uv run ruff check      # lint
uv run mypy            # types, strict
```

Fixtures are real resolver output — actual `uv.lock` files produced by `uv lock`, never
hand-written. A test that passes against a mock lockfile proves nothing about this tool.

## Why Python

It analyses Python. Building a correct call graph needs import resolution, scope
resolution, and re-export following — all of which Python's own `ast` and `importlib`
already implement correctly. Writing it in Go would mean reimplementing Python's import
semantics for no gain.

## Licence

Not yet chosen.
