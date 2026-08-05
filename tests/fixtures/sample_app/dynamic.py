"""A dispatch static analysis cannot follow."""

import importlib


def dispatch(module_name: str, attribute: str, payload: str) -> object:
    module = importlib.import_module(module_name)
    handler = getattr(module, attribute)
    return handler(payload)
