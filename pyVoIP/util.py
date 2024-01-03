from contextlib import contextmanager
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from socket import socket
    from threading import Lock


@contextmanager
def acquired_lock_and_unblocked_socket(lock: "Lock", socket: "socket"):
    """Alongside an acquired Lock, a corresponding socket will become
    non-blocking, and then blocking once the Lock is released.

    Lock will release and socket will become blocking even during exceptions"""
    try:
        with lock:
            socket.setblocking(False)
            yield
    finally:
        socket.setblocking(True)
