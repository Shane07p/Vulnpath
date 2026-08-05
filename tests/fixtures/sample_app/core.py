"""Classes and inheritance."""


class Base:
    def describe(self) -> str:
        return "base"


class Processor(Base):
    def process(self, raw: str) -> str:
        return self.normalise(raw)

    def normalise(self, raw: str) -> str:
        return raw.strip()
