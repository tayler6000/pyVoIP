from typing import Dict, List, Optional, Tuple
from pyVoIP.types import KEY_PASSWORD, SOCKETS
from pyVoIP.SIP import SIPMessage
from pyVoIP.sock.transport import TransportMode
import socket
import sqlite3
import threading
import ssl


class VoIPConnection:
    def __init__(
        self,
        voip_sock: "VoIPSocket",
        conn: Optional[SOCKETS],
        message: SIPMessage,
    ):
        self.voip_sock = voip_sock
        self.conn = conn
        self.mode = voip_sock.mode
        self.call_id = message.headers["Call-ID"]
        self.to_tag = message.headers["To"]["tag"]
        self.from_tag = message.headers["From"]["tag"]


class VoIPSocket(threading.Thread):
    def __init__(
        self,
        mode: TransportMode,
        cert_file: Optional[str] = None,
        key_file: Optional[str] = None,
        key_password: KEY_PASSWORD = None,
    ):
        """
        This is the main phone SIP socket.  It should receive all new dialogs.
        """
        super().__init__(name="VoIPSocket Thread")
        self.SD = False
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
            self.s = self.server_context.wrap_socket(self.s)

        self.buffer = sqlite3.connect(":memory:", check_same_thread=False)
        conn = self.buffer.cursor()
        conn.execute(
            "CREATE TABLE msgs(id INTEGER PRIMARY KEY AUTOINCREMENT, call_id TEXT, from TEXT, to TEXT, msg TEXT);"
        )
        conn.execute("CREATE INDEX msg_index ON msgs (call_id, from, to);")
        self.buffer.commit()
        conn.close()
        self.conns: List[VoIPConnection] = []

    def bind(self, addr: Tuple[str, int]) -> None:
        return self.s.bind(addr)

    def _listen(self, backlog=0) -> None:
        return self.s.listen(backlog)

    def run(self, addr: Tuple[str, int]) -> None:
        self.bind(addr)
        if self.mode != TransportMode.UDP:
            self._listen()
        while not self.SD:
            if self.mode == TransportMode.UDP:
                data = self.s.recv(8192)
                message = SIPMessage(data)
                call_id = message.headers["Call-ID"]
                to_tag = message.headers["To"]["tag"]
                from_tag = message.headers["From"]["tag"]
                raw_message = data.decode("utf8")
                self.conns.append(VoIPConnection(self, None, message))
            else:
                conn, addr = self.s.accept()
                data = conn.recv(8192)
                message = SIPMessage(data)
                call_id = message.headers["Call-ID"]
                to_tag = message.headers["To"]["tag"]
                from_tag = message.headers["From"]["tag"]
                raw_message = data.decode("utf8")
                self.conns.append(VoIPConnection(self, conn, message))

            conn = self.buffer.cursor()
            conn.execute(
                "INSERT INTO msgs (call_id, from, to, msg) VALUES (?, ?, ?, ?)",
                (call_id, from_tag, to_tag, raw_message),
            )
            self.buffer.commit()
            conn.close()

    def close(self) -> None:
        self.SD = True
        self.s.shutdown(socket.SHUT_RDWR)
        return self.s.close()

    def sendto(self, bytes: bytes, addr: Tuple[str, int]) -> VoIPConnection:
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
