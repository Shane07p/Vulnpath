"""Deliberately inside the fixture: exercised by the test-exclusion tests."""

from sample_app.core import Processor


def test_process() -> None:
    assert Processor().process(" x ") == "x"
