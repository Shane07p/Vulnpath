"""Calls that live in a decorator, a default value and a class base, not a body."""


def get_ttl() -> int:
    return 60


def cache(seconds: int) -> object:
    def wrap(fn: object) -> object:
        return fn

    return wrap


@cache(get_ttl())
def handler() -> None:
    pass


def compute_default() -> int:
    return 42


def process(x: int = compute_default()) -> int:
    return x


def make_base() -> type:
    return object


class Dynamic(make_base()):
    pass
