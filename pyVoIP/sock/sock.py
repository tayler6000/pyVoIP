from enum import Enum
from typing import Dict, List, Optional, Tuple, Union
from pyVoIP.types import KEY_PASSWORD, SOCKETS
from pyVoIP.sock.transport import TransportMode
import socket
import warnings
import ssl


class VoIPSocket:
    def __init__(
        self,
        mode: TransportMode,
        cert_file: Optional[str] = None,
        key_file: Optional[str] = None,
        key_password: KEY_PASSWORD = None,
    ):
        self.mode = mode
        self.listening_for: Dict[str, List[str]] = {}
        self.s = socket.socket(socket.AF_INET, mode.socket_type)
        self.server_context = None
        if mode.tls_mode:
            self.server_context = ssl.SSLContext(
                protocol=ssl.PROTOCOL_TLS_SERVER
            )
            if cert_file:
                self.server_context.load_cert_chain(
                    cert_file, key_file, key_password
                )
            self.server_context.load_default_certs()
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

    def sendto(self, bytes: bytes, addr: Tuple[str, int]) -> SOCKETS:
        """
        Creates a new connection, sends the data, then returns the socket
        """
        s = socket.socket(socket.AF_INET, self.mode.socket_type)
        if self.mode == TransportMode.UDP:
            self.s.sendto(bytes, addr)
            return self
        self.s.connect(addr)
        self.s.send(bytes)
        self.s.shutdown(socket.SHUT_RDWR)
        return s
