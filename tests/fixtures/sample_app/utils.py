"""Dependency imports, plain and aliased."""

import yaml
from json import loads as parse_json


def read_settings(text: str) -> object:
    return yaml.load(text)


def read_json(text: str) -> object:
    return parse_json(text)
