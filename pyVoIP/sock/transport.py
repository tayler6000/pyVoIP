from enum import Enum
from typing import Optional
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
