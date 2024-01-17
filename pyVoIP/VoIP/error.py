__all__ = [
    "InvalidRangeError",
    "InvalidStateError",
    "NoPortsAvailableError",
]


class InvalidRangeError(Exception):
    pass


class InvalidStateError(Exception):
    pass


class NoPortsAvailableError(Exception):
    pass
