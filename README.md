# Vulnpath

Reachability-aware dependency triage for Python.

Every scanner tells you which packages have CVEs. Vulnpath is being built to tell you
which ones your code actually reaches, and what shape of fix each one needs.

> **Status: early.** Advisory matching and fix-shape classification work, and both are
> verified against real packages with known CVEs. Reachability analysis — the reason
> this project exists — is not built yet. Everything below distinguishes what runs
> today from what does not.

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
- **Fix-shape classification** — see below.
- Severity threshold filtering, JSON output, offline mode.

Not built yet: reachability analysis, SARIF output, `--only-reachable`,
`--fail-on reachable`. `vulnpath guide` marks each one.

## What kind of fix does it need?

"Just upgrade" is often wrong, so each finding is classified by the change that would
actually close it, with the command:

| Shape | Meaning |
|---|---|
| `LOCKFILE_REFRESH` | Nothing forbids the fix. Your lockfile is stale. |
| `DIRECT_BUMP` | Your own declared constraint forbids it. The manifest has to change. |
| `OVERRIDE` | A parent's constraint forbids it. Names the parent, and the release of it that lifts the constraint if one exists. |
| `BACKPORT_EXISTS` | The advisory names only a newer major line, but a patched release exists on yours. |
| `NO_FIX` | No released version fixes this. |
| `UNKNOWN` | Classification could not be completed. Never reported as `NO_FIX`. |

Two decisions worth knowing about:

**The target is the lowest fix on your own major line**, not the newest fix. A user on
`urllib3 1.26.5` is pointed at `1.26.17`, not `2.0.6` — the backport closes the advisory
without a major upgrade and is far less likely to collide with a parent's constraint.

**A blocking parent outranks your own pin.** A package can be both a direct dependency
and a dependency of something else. If both constraints forbid the fix, editing your own
pin achieves nothing, because the resolver still has to satisfy the parent. Real output
from the fixture:

```
urllib3 1.26.5  ·  direct  ·  8 advisories
 HIGH   CVE-2025-66418   2.6.0   urllib3 allows an unbounded number of links...
        OVERRIDE  requests <1.27,>=1.21.1 forbids 2.6.0, but a newer release lifts that.
          blocked by requests <1.27,>=1.21.1 — requests 2.34.2 lifts it
          $ uv add "requests>=2.34.2"
```

## Verified against pip-audit

Before its own analysis means anything, this has to find everything an established
scanner finds. Against the checked-in fixture project, on the same advisory source:

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

CI runs that comparison on every push and weekly, and fails only on a miss — a CVE
`pip-audit` found that vulnpath did not.

## Checked against real packages

Beyond the fixture, run against packages carrying well-known advisories —
`requests 2.19.1`, `jinja2 2.10`, `urllib3 1.23`, `certifi 2022.9.24`,
`gitpython 3.1.29`. Every advisory OSV publishes for those versions was reported, and
the fix targets match the published fixed versions:

| CVE | Package | Shape | Target |
|---|---|---|---|
| CVE-2018-18074 | requests | `DIRECT_BUMP` | 2.20.0 |
| CVE-2023-32681 | requests | `DIRECT_BUMP` | 2.31.0 |
| CVE-2019-10906 | jinja2 | `DIRECT_BUMP` | 2.10.1 |
| CVE-2022-24439 | gitpython | `DIRECT_BUMP` | 3.1.30 |
| CVE-2019-11324 | urllib3 | `OVERRIDE` | 1.24.2 |
| CVE-2020-26137 | urllib3 | `OVERRIDE` | 1.25.9 |

Both urllib3 findings are `OVERRIDE` rather than a bump because `requests 2.19.1` pins
`urllib3<1.24`, so no direct upgrade can reach the fix.

This exercise found a real bug. A scan cached 25 advisories for `gitpython 3.1.29` while
OSV returned 28 minutes later; three had just been published. Cached advisory lists now
expire after a day, because *which* advisories affect a version changes even though the
advisories themselves do not.

One honest gap: OSV publishes nothing for `py 1.11.0`, so CVE-2022-42969 is not
reported. That is a data-source limitation rather than a matching failure, and it is the
kind of thing an evaluation corpus has to record rather than hide.

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
