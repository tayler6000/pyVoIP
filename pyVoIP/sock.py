from enum import Enum
from typing import Dict, List, Optional, Tuple, Union
import socket
import warnings

try:
    import ssl

    SSL_SUPPORTED = True
except Exception:
    SSL_SUPPORTED = False
    warnings.warn(
        "SSL/TLS is not available, do you have OpenSSL installed?",
        RuntimeWarning,
    )


class TransportMode(Enum):
    def __new__(
        cls,
        value: str,
        socket_type: socket.SocketKind,
        tls_mode: Optional[int],
    ):
        global SSL_SUPPORTED
        obj = object.__new__(cls)
        if value == "TLS" and SSL_SUPPORTED is False:
            """
            This should cause an error if someone tries to use TLS without
            OpenSSL, but has a potential benifit of self correcting if OpenSSL
            somehow becomes available later, though I don't think that's possible.
            """
            import ssl

            SSL_SUPPORTED = True
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
    if SSL_SUPPORTED:
        TLS = ("TLS", socket.SOCK_STREAM, ssl.PROTOCOL_TLS)


class VoIPSocket:
    def __init__(
        self,
        mode: TransportMode,
        cert_file: Optional[str] = None,
        key_file: Optional[str] = None,
        key_password: Optional[Union] = None,
    ):
        self.mode = mode
        self.listening_for: Dict[str, List[str]] = {}
        self.s = socket.socket(socket.AF_INET, mode.socket_type)
        self.server_context = None
        if mode.tls_mode:
            self.server_context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_SERVER)
            if certfile:
                ctx.load_cert_chain(cert_file, key_file, key_password)
            ctx.load_default_certs()
            # self.s = ctx.wrap_socket(self.s)

    def bind(self, addr: Tuple[str, int]) -> None:
        return self.s.bind(addr)

    def _listen(self, backlog=0) -> None:
        return self.s.listen(backlog)

    def start(self, addr: Tuple[str, int]) -> None:
        """
        Convience function that starts the socket in the proper configuration
        for the socket mode.
        """
        self.bind(addr)
        if self.mode != TransportMode.UDP:
            self._listen()

    def close(self) -> None:
        self.s.shutdown(socket.SHUT_RDWR)
        return self.s.close()

    def sendto(self, bytes: bytes, addr: Tuple[str, int]) -> None:
        if self.mode == TransportMode.UDP:
            self.s.sendto(bytes, addr)
            return self
        self.s.connect(addr)
        self.s.send(bytes)
        self.s.shutdown(socket.SHUT_RDWR)
