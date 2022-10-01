from enum import Enum
from typing import Optional, Tuple, Union
import socket
import ssl


class TransportMode(Enum):
    def __new__(
        cls,
        value: str,
        socket_type: socket.SocketKind,
        tls_mode: Optional[int],
    ):
        obj = object.__new__(cls)
        obj._value_ = value
        obj.socket_type = socket_type
        obj.tls_mode = tls_mode

        return obj

    @property
    def socket_type(self) -> socket.SocketKind:
        return self._socket_type

    @socket_type.setter
    def socket_type(self, value: socket.SocketKind) -> None:
        self._socket_type = value

    @property
    def tls_mode(self) -> Optional[int]:
        return self._tls_mode

    @tls_mode.setter
    def tls_mode(self, value: Optional[int]) -> None:
        self._tls_mode = value

    def __str__(self) -> str:
        return self._value_

    UDP = ("UDP", socket.SOCK_DGRAM, None)
    TCP = ("TCP", socket.SOCK_STREAM, None)
    TLS = ("TLS", socket.SOCK_STREAM, ssl.PROTOCOL_TLS)


class VoIPSocket:
    def __init__(self, mode: TransportMode):
        self.mode = mode
        self.s = socket.socket(socket.AF_INET, mode.socket_type)
        if mode.tls_mode:
            ctx = ssl.SSLContext(protocol=mode.tls_mode)
            ctx.load_default_certs()
            self.s = ctx.wrap_socket(self.s)

    def bind(self, addr: Tuple[str, int]) -> None:
        return self.s.bind(addr)

    def listen(self, backlog=0) -> None:
        return self.s.listen(backlog)

    def start(self, addr: Tuple[str, int]) -> None:
        """
        Convience function that starts the socket in the proper configuration
        for the socket mode.
        """
        self.bind(addr)
        if self.mode != TransportMode.UDP:
            self.listen()

    def close(self) -> None:
        self.s.shutdown(socket.SHUT_RDWR)
        return self.s.close()

    def sendto(self, bytes: bytes, addr: Tuple[str, int]) -> None:
        if self.mode == TransportMode.UDP:
            return self.s.sendto(bytes, addr)
        self.s.connect(addr)
        self.s.send(bytes)
        self.s.shutdown(socket.SHUT_RDWR)
