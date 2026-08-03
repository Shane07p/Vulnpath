"""Classify a finding by the kind of fix it needs.

Pure rules, no I/O. Every fact the decision needs is fetched upstream and handed in
as a ``FixContext``, which is what makes each shape testable without a network.

Predicates run in a fixed order and the first match wins. The ordering is not
arbitrary — see the note on ``classify``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from vulnpath.models import Advisory, AffectedRange, BlockingParent, Fix, FixShape, Package
from vulnpath.versions import (
    SpecifierSet,
    Version,
    parse_specifier,
    parse_version,
    satisfies,
    select_target,
)

YOUR_PROJECT = "your project"
"""Stands in for the root in the blocker map, so root and parent blockers compare alike."""


@dataclass(frozen=True)
class FixContext:
    """Everything classification needs, already fetched."""

    package: Package
    advisory: Advisory

    declared: str | None = None
    """The root project's own constraint, absent for packages it does not name."""

    parents: dict[str, str] = field(default_factory=dict)
    """Parent package name to its constraint on this package."""

    released: tuple[str, ...] | None = None
    """Every version on PyPI. ``None`` means the lookup failed, which is not the same
    as a package having no releases."""

    parent_upgrades: dict[str, str] = field(default_factory=dict)
    """Parent name to its newest release whose constraint permits the fix."""


def _unknown(reason: str) -> Fix:
    return Fix(shape=FixShape.UNKNOWN, reason=reason)


def _blockers(
    target: Version, declared: SpecifierSet | None, parents: dict[str, SpecifierSet]
) -> dict[str, SpecifierSet]:
    """Every constraint that forbids the target, keyed by who imposes it."""
    blocking: dict[str, SpecifierSet] = {}
    if declared is not None and not satisfies(target, declared):
        blocking[YOUR_PROJECT] = declared
    for name, specifier in parents.items():
        if not satisfies(target, specifier):
            blocking[name] = specifier
    return blocking


def is_affected(version: Version, ranges: tuple[AffectedRange, ...]) -> bool:
    """Whether an advisory's ranges cover this version.

    A range runs from ``introduced`` up to ``fixed`` (exclusive) or ``last_affected``
    (inclusive). An unparseable bound makes the range match, because a bound we cannot
    read is not a bound we can rule ourselves outside of.
    """
    for affected in ranges:
        introduced = parse_version(affected.introduced) if affected.introduced else None
        if affected.introduced and introduced is None:
            return True
        if introduced is not None and version < introduced:
            continue

        if affected.fixed:
            fixed = parse_version(affected.fixed)
            if fixed is None or version < fixed:
                return True
        elif affected.last_affected:
            last = parse_version(affected.last_affected)
            if last is None or version <= last:
                return True
        else:
            return True
    return False


def _unaffected_on_installed_line(
    installed: Version,
    released: tuple[str, ...],
    fixed: list[Version],
    ranges: tuple[AffectedRange, ...],
) -> Version | None:
    """The lowest release above the installed one, on its line, proven unaffected.

    Only meaningful when the advisory names no fix on that line — the case where it
    listed only a newer major and a patched release on the user's own line exists
    anyway.

    Proof is required. Offering a version merely because it is newer would recommend
    an upgrade with no evidence it fixes anything, which is worse than saying nothing.
    Without affected ranges there is no proof available, so nothing is offered.
    """
    if not ranges or any(v.major == installed.major for v in fixed):
        return None

    candidates = sorted(
        v
        for raw in released
        if (v := parse_version(raw)) is not None and v > installed and v.major == installed.major
    )
    for candidate in candidates:
        if not is_affected(candidate, ranges):
            return candidate
    return None


def classify(context: FixContext) -> Fix:
    """Which shape of fix this finding needs.

    Order matters in two places.

    A parent blocker outranks the root's own constraint. A package can be both a direct
    dependency and a dependency of something else — urllib3 typically is. If both
    constraints forbid the target, editing your own pin changes nothing, because the
    resolver must still satisfy the parent. Classifying on depth alone emits a command
    that does not work.

    ``BACKPORT_EXISTS`` is tested early because target selection already prefers the
    installed major line, so the ordinary backport resolves to a bump or a relock
    before reaching it. What is left is the case worth naming: the advisory listed only
    the newest fix and PyPI shows an unaffected release on the user's own line.
    """
    installed = parse_version(context.package.version)
    if installed is None:
        return _unknown(f"Installed version {context.package.version!r} is not a valid version.")

    if context.released is None:
        return _unknown("Could not reach PyPI to check released versions.")

    declared: SpecifierSet | None = None
    if context.declared is not None:
        declared = parse_specifier(context.declared)
        if declared is None:
            return _unknown(f"Could not parse your constraint {context.declared!r}.")

    parents: dict[str, SpecifierSet] = {}
    for name, raw in context.parents.items():
        specifier = parse_specifier(raw)
        if specifier is None:
            # An unread constraint is not a permissive one.
            return _unknown(f"Could not parse {name}'s constraint {raw!r}.")
        parents[name] = specifier

    fixed = [v for raw in context.advisory.fixed_versions if (v := parse_version(raw)) is not None]
    target = select_target(installed, fixed)
    backport = _unaffected_on_installed_line(
        installed, context.released, fixed, context.advisory.affected_ranges
    )

    if backport is not None and (target is None or backport < target):
        named = f"only {target}, a major upgrade" if target else "no fix on your line"
        return Fix(
            shape=FixShape.BACKPORT_EXISTS,
            target_version=str(backport),
            command=f'uv add "{context.package.name}>={backport}"',
            reason=(
                f"The advisory names {named}, but {backport} is released on your "
                f"{installed.major}.x line and falls outside the affected range."
            ),
        )

    if target is None:
        return Fix(
            shape=FixShape.NO_FIX,
            reason=(
                "No released version fixes this. Mitigate at the call site and watch for "
                "an upstream release."
            ),
        )

    blocking = _blockers(target, declared, parents)

    if not blocking:
        return Fix(
            shape=FixShape.LOCKFILE_REFRESH,
            target_version=str(target),
            command=f"uv lock --upgrade-package {context.package.name}",
            reason=f"Nothing forbids {target}. Your lockfile is simply out of date.",
        )

    parent_blockers = {name: spec for name, spec in blocking.items() if name != YOUR_PROJECT}

    if not parent_blockers:
        return Fix(
            shape=FixShape.DIRECT_BUMP,
            target_version=str(target),
            command=f'uv add "{context.package.name}>={target}"',
            reason=f"Your constraint {declared} forbids {target}.",
        )

    blocked_by = tuple(
        BlockingParent(
            name=name,
            constraint=str(specifier),
            upgrade_to=context.parent_upgrades.get(name),
        )
        for name, specifier in sorted(parent_blockers.items())
    )

    upgradable = [parent for parent in blocked_by if parent.upgrade_to]
    first = blocked_by[0]

    if len(upgradable) == len(blocked_by):
        command = " && ".join(f'uv add "{p.name}>={p.upgrade_to}"' for p in upgradable)
        reason = (
            f"{first.name} {first.constraint} forbids {target}, but a newer release of it "
            f"lifts that. Upgrading the parent is safer than an override."
        )
    else:
        command = f'[tool.uv]\noverride-dependencies = ["{context.package.name}>={target}"]'
        reason = (
            f"{first.name} {first.constraint} forbids {target} and no release of it lifts "
            f"that. An override pins a version the parent never declared support for."
        )

    return Fix(
        shape=FixShape.OVERRIDE,
        target_version=str(target),
        command=command,
        reason=reason,
        blocking_parents=blocked_by,
    )
