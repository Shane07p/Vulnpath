"""Test session setup.

Imported by pytest before any test module, so this runs before ``vulnpath.console``
builds its Console objects.
"""

import os

# CI terminals are detected as colour-capable; a local Windows console under pytest
# usually is not. Rich then emits escape codes in one environment and not the other,
# which is how a suite passes locally and fails in CI. Force the harsher path
# everywhere so the two environments cannot disagree.
os.environ.setdefault("FORCE_COLOR", "1")
