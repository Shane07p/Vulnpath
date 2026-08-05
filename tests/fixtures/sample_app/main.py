"""Entry point calling into the rest of the package."""

from sample_app.core import Processor
from sample_app.utils import read_settings


def run(text: str) -> str:
    processor = Processor()
    settings = read_settings(text)
    return processor.process(str(settings))
