from typing import TYPE_CHECKING, List, Optional, Tuple, Union
from pyVoIP.types import KEY_PASSWORD, SOCKETS
from pyVoIP.SIP.message.message import SIPMessage, SIPRequest
from pyVoIP.SIP.error import SIPParseError
from pyVoIP.networking.nat import NAT, AddressType
from pyVoIP.networking.transport import TransportMode
import json
import math
import pprint
import pyVoIP
import socket
import sqlite3
import ssl
import threading
import time


if TYPE_CHECKING:
    from pyVoIP.SIP.client import SIPClient


debug = pyVoIP.debug


class VoIPConnection:
    def __init__(
        self,
        voip_sock: "VoIPSocket",
        conn: Optional[SOCKETS],
        message: SIPMessage,
    ):
        """
        Mimics a TCP connection when using UDP, and wraps a socket when
        using TCP or TLS.
        """
        self.sock = voip_sock
        self.conn = conn
        self.mode = self.sock.mode
        self.message = message
        self.call_id = message.headers["Call-ID"]
        self.local_tag, self.remote_tag = self.sock.determine_tags(
            self.message
        )
        self._peak_buffer: Optional[bytes] = None
        if conn and type(message) is SIPRequest:
            if self.sock.mode.tls_mode:
                client_context = ssl.create_default_context()
                client_context.check_hostname = pyVoIP.TLS_CHECK_HOSTNAME
                client_context.verify_mode = pyVoIP.TLS_VERIFY_MODE
                self.conn = client_context.wrap_socket(
                    self.conn, server_hostname=message.destination["host"]
                )
            addr = (message.destination["host"], message.destination["port"])
            self.conn.connect(addr)

    def send(self, data: Union[bytes, str]) -> None:
        if type(data) is str:
            data = data.encode("utf8")
        try:
            msg = SIPMessage.from_bytes(data)
        except SIPParseError:
            return
        if not self.conn:  # If UDP
            if type(msg) is SIPRequest:
                addr = (msg.destination["host"], msg.destination["port"])
            else:
                addr = msg.headers["Via"][0]["address"]
            self.sock.s.sendto(data, addr)
        else:
            self.conn.send(data)
        debug(f"SENT:\n{msg.summary()}")

    def update_tags(self, local_tag: str, remote_tag: str) -> None:
        self.local_tag = local_tag
        self.remote_tag = remote_tag

    def peak(self) -> bytes:
        return self.recv(8192, timeout=60, peak=True)

    def recv(self, nbytes: int = 8192, timeout=0, peak=False) -> bytes:
        if self._peak_buffer:
            data = self._peak_buffer
            if not peak:
                self._peak_buffer = None
            return data
        if self.conn:
            return self._tcp_tls_recv(nbytes, timeout, peak)
        else:
            return self._udp_recv(nbytes, timeout, peak)

    def _tcp_tls_recv(self, nbytes: int, timeout=0, peak=False) -> bytes:
        timeout = time.monotonic() + timeout if timeout else math.inf
        # TODO: Timeout
        msg = None
        while not msg and not self.sock.SD:
            data = self.conn.recv(nbytes)
            try:
                msg = SIPMessage.from_bytes(data)
            except SIPParseError as e:
                br = self.sock.gen_bad_request(
                    connection=self, error=e, received=data
                )
                self.send(br)
        if time.monotonic() >= timeout:
            raise TimeoutError()
        if peak:
            self._peak_buffer = data
        debug(f"RECEIVED:\n{msg.summary()}")
        return data

    def _udp_recv(self, nbytes: int, timeout=0, peak=False) -> bytes:
        timeout = time.monotonic() + timeout if timeout else math.inf
        while time.monotonic() <= timeout and not self.sock.SD:
            # print("Trying to receive")
            # print(self.sock.get_database_dump())
            conn = self.sock.buffer.cursor()
            conn.row_factory = sqlite3.Row
            sql = (
                'SELECT * FROM "msgs" WHERE "call_id"=? AND '
                + '"local_tag" IS ? AND "remote_tag" IS ?'
            )
            bindings = (
                self.call_id,
                self.local_tag,
                self.remote_tag,
            )
            result = conn.execute(sql, bindings)
            row = result.fetchone()
            if not row:
                conn.close()
                continue
            if peak:
                # If peaking, return before deleting from the database
                conn.close()
                return row["msg"].encode("utf8")
            try:
                conn.execute('DELETE FROM "msgs" WHERE "id" = ?', (row["id"],))
            except sqlite3.OperationalError:
                pass
            conn.close()
            return row["msg"].encode("utf8")
        if time.monotonic() >= timeout:
            raise TimeoutError()

    def close(self):
        self.sock.deregister_connection(self)
        if self.conn:
            self.conn.close()


class VoIPSocket(threading.Thread):
    def __init__(
        self,
        mode: TransportMode,
        bind_ip: str,
        bind_port: int,
        sip: "SIPClient",
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
        self.s = socket.socket(socket.AF_INET, mode.socket_type)
        self.bind_ip: str = bind_ip
        self.bind_port: int = bind_port
        self.sip = sip
        self.nat: NAT = sip.nat
        self.server_context: Optional[ssl.SSLContext] = None
        if mode.tls_mode:
            self.server_context = ssl.SSLContext(
                protocol=ssl.PROTOCOL_TLS_SERVER
            )
            self.server_context.load_default_certs()
            if cert_file:
                self.server_context.load_cert_chain(
                    cert_file, key_file, key_password
                )
            self.s = self.server_context.wrap_socket(self.s, server_side=True)

        self.buffer = sqlite3.connect(
            pyVoIP.SIP_STATE_DB_LOCATION,
            isolation_level=None,
            check_same_thread=False,
        )
        """
        RFC 3261 Section 12, Paragraph 2 states:
        "A dialog is identified at each UA with a dialog ID, which consists
        of a Call-ID value, a local tag and remote tag."

        This in memory database is designed to check if a VoIPConnection
        already exists for a dialog. The dialog is detected from the incoming
        message over UDP. If a VoIPConnection does not exist for the dialog,
        we will create one. This database also stores messages in the msgs
        table. This table stores new SIPMessages received by VoIPSocket
        over UDP for VoIPConnections to receive pull them.
        """
        conn = self.buffer.cursor()
        conn.execute(
            """CREATE TABLE "msgs" (
                "id" INTEGER PRIMARY KEY AUTOINCREMENT,
                "call_id" TEXT,
                "local_tag" TEXT,
                "remote_tag" TEXT,
                "msg" TEXT
            );"""
        )
        conn.execute(
            """CREATE INDEX "msg_index" ON msgs """
            + """("call_id", "local_tag", "remote_tag");"""
        )
        conn.execute(
            """CREATE INDEX "msg_index_2" ON msgs """
            + """("call_id", "remote_tag", "local_tag");"""
        )
        conn.execute(
            """CREATE TABLE "listening" (
                "call_id" TEXT NOT NULL,
                "local_tag" TEXT,
                "remote_tag" TEXT,
                "connection" INTEGER NOT NULL UNIQUE,
                PRIMARY KEY("call_id", "local_tag", "remote_tag")
            );"""
        )
        conn.close()
        self.conns_lock = threading.Lock()
        self.conns: List[VoIPConnection] = []

    def gen_bad_request(
        self, connection=None, message=None, error=None, received=None
    ) -> bytes:
        body = f"<error><message>{error}</message>"
        body += f"<received>{received}</received></error>"
        bad_request = "SIP/2.0 400 Malformed Request\r\n"
        bad_request += (
            f"Via: SIP/2.0/{self.mode} {self.bind_ip}:{self.bind_port}\r\n"
        )
        bad_request += "Content-Type: application/xml\r\n"
        bad_request += f"Content-Length: {len(body)}\r\n\r\n"
        bad_request += body
        return bad_request.encode("utf8")

    def __connection_exists(self, message: SIPMessage) -> bool:
        return bool(self.__get_connection(message))

    def __get_connection(
        self, message: SIPMessage
    ) -> Optional[VoIPConnection]:
        local_tag, remote_tag = self.determine_tags(message)
        call_id = message.headers["Call-ID"]
        conn = self.buffer.cursor()
        sql = 'SELECT "connection" FROM "listening" WHERE "call_id" IS ?'
        sql += ' AND "local_tag" IS ? AND "remote_tag" IS ?'
        result = conn.execute(sql, (call_id, local_tag, remote_tag))
        rows = result.fetchall()
        if rows:
            conn.close()
            return self.conns[rows[0][0]]
        debug("New Connection Started")
        # If we didn't find one lets look for something that doesn't have
        # one of the tags
        sql = 'SELECT "connection" FROM "listening" WHERE "call_id" = ?'
        sql += ' AND ("local_tag" IS NULL OR "local_tag" = ?)'
        sql += ' AND ("remote_tag" IS NULL OR "remote_tag" = ?)'
        result = conn.execute(sql, (call_id, local_tag, remote_tag))
        rows = result.fetchall()
        if rows:
            if local_tag and remote_tag:
                sql = 'UPDATE "listening" SET "remote_tag" = ?, '
                sql += '"local_tag" = ? WHERE "connection" = ?'
                conn.execute(sql, (remote_tag, local_tag, rows[0][0]))
                self.conns[rows[0][0]].update_tags(local_tag, remote_tag)
            conn.close()
            return self.conns[rows[0][0]]
        conn.close()
        return None

    def __register_connection(self, connection: VoIPConnection) -> int:
        self.conns_lock.acquire()
        self.conns.append(connection)
        conn_id = len(self.conns) - 1
        try:
            conn = self.buffer.cursor()
            conn.execute(
                """INSERT INTO "listening"
                    ("call_id", "local_tag", "remote_tag", "connection")
                    VALUES
                    (?, ?, ?, ?)""",
                (
                    connection.call_id,
                    connection.local_tag,
                    connection.remote_tag,
                    conn_id,
                ),
            )
        except sqlite3.IntegrityError as e:
            e.add_note(
                "Error is from registering connection for message: "
                + f"{connection.message.summary()}"
            )
            e.add_note("Internal Database Dump:\n" + self.get_database_dump())
            e.add_note(
                f"({connection.call_id=}, {connection.local_tag=}, "
                + f"{connection.remote_tag=}, {conn_id=})"
            )
            raise
        except sqlite3.OperationalError:
            pass
        finally:
            conn.close()
            self.conns_lock.release()
            return conn_id

    def deregister_connection(self, connection: VoIPConnection) -> None:
        if self.mode is not TransportMode.UDP:
            return
        self.conns_lock.acquire()
        debug(f"Deregistering {connection}")
        debug(f"{self.conns=}")
        debug(self.get_database_dump())
        try:
            conn = self.buffer.cursor()
            sql = 'SELECT "connection" FROM "listening" WHERE "call_id" = ?'
            sql += ' AND ("local_tag" IS NULL OR "local_tag" = ?)'
            sql += ' AND ("remote_tag" IS NULL OR "remote_tag" = ?)'
            result = conn.execute(
                sql,
                (
                    connection.call_id,
                    connection.local_tag,
                    connection.remote_tag,
                ),
            )
            row = result.fetchone()
            conn_id = row[0]
            """
            Need to set to None to not change the indexes of any other conn
            """
            self.conns[conn_id] = None
            conn.execute(
                'DELETE FROM "listening" WHERE "connection" = ?', (conn_id,)
            )
        except sqlite3.OperationalError:
            pass
        finally:
            conn.close()
            self.conns_lock.release()

    def get_database_dump(self, pretty=False) -> str:
        conn = self.buffer.cursor()
        ret = ""
        try:
            result = conn.execute('SELECT * FROM "listening";')
            result1 = result.fetchall()
            result = conn.execute('SELECT * FROM "msgs";')
            result2 = result.fetchall()
        finally:
            conn.close()
        if pretty:
            ret += "listening: " + pprint.pformat(result1) + "\n\n"
            ret += "msgs: " + pprint.pformat(result2) + "\n\n"
        else:
            ret += "listening: " + json.dumps(result1) + "\n\n"
            ret += "msgs: " + json.dumps(result2) + "\n\n"
        return ret

    def determine_tags(self, message: SIPMessage) -> Tuple[str, str]:
        """
        Return local_tag, remote_tag
        """

        to_header = message.headers["To"]
        from_header = message.headers["From"]
        to_host = to_header["host"]
        to_tag = to_header["tag"] if to_header["tag"] else None
        from_tag = from_header["tag"] if from_header["tag"] else None

        if self.nat.check_host(to_host) is AddressType.LOCAL:
            return to_tag, from_tag
        return from_tag, to_tag

    def bind(self, addr: Tuple[str, int]) -> None:
        self.s.bind(addr)
        self.bind_ip = addr[0]
        self.bind_port = addr[1]
        return None

    def _listen(self, backlog=0) -> None:
        return self.s.listen(backlog)

    def _tcp_tls_run(self) -> None:
        self._listen()
        while not self.SD:
            try:
                conn, addr = self.s.accept()
            except OSError:
                continue
            debug(f"Received new {self.mode} connection from {addr}.")
            data = conn.recv(8192)
            try:
                message = SIPMessage.from_bytes(data)
            except SIPParseError:
                continue
            debug("\n\nReceived SIP Message:")
            debug(message.summary())
            self._handle_incoming_message(conn, message)

    def _udp_run(self) -> None:
        while not self.SD:
            try:
                data = self.s.recv(8192)
            except OSError:
                continue
            try:
                message = SIPMessage.from_bytes(data)
            except SIPParseError:
                continue
            debug("\n\nReceived UDP Message:")
            debug(message.summary())
            self._handle_incoming_message(None, message)

    def _handle_incoming_message(
        self, conn: Optional[SOCKETS], message: SIPMessage
    ):
        conn_id = None
        if not self.__connection_exists(message):
            conn_id = self.__register_connection(
                VoIPConnection(self, conn, message)
            )

        call_id = message.headers["Call-ID"]
        local_tag, remote_tag = self.determine_tags(message)
        raw_message = message.raw.decode("utf8")
        conn = self.buffer.cursor()
        conn.execute(
            "INSERT INTO msgs (call_id, local_tag, remote_tag, msg) "
            + "VALUES (?, ?, ?, ?)",
            (call_id, local_tag, remote_tag, raw_message),
        )
        conn.close()
        if conn_id:
            self.sip.handle_new_connection(self.conns[conn_id])

    def start(self) -> None:
        self.bind((self.bind_ip, self.bind_port))
        super().start()

    def run(self) -> None:
        if self.mode == TransportMode.UDP:
            self._udp_run()
        else:
            self._tcp_tls_run()

    def close(self) -> None:
        self.SD = True
        if hasattr(self, "s"):
            if self.s:
                try:
                    self.s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self.s.close()
        return

    def send(self, data: bytes) -> VoIPConnection:
        """
        Creates a new connection, sends the data, then returns the socket
        """
        if self.mode == TransportMode.UDP:
            conn = VoIPConnection(self, None, SIPMessage.from_bytes(data))
            self.__register_connection(conn)
            conn.send(data)
            return conn
        s = socket.socket(socket.AF_INET, self.mode.socket_type)
        conn = VoIPConnection(self, s, SIPMessage.from_bytes(data))
        conn.send(data)
        return conn
