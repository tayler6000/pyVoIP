from base64 import b16encode, b64encode
from threading import Timer, Lock
from typing import Callable, Dict, List, Optional, Tuple, TYPE_CHECKING
from pyVoIP.credentials import CredentialsManager
from pyVoIP.SIP.message import (
    SIPMessage,
    SIPStatus,
    SIPMessageType,
)
from pyVoIP.SIP.error import (
    SIPParseError,
    InvalidAccountInfoError,
)
from pyVoIP.sock.transport import TransportMode
from pyVoIP.helpers import Counter
import pyVoIP
import hashlib
import socket
import random
import time
import uuid
import select
import ssl


if TYPE_CHECKING:
    from pyVoIP import RTP


debug = pyVoIP.debug


class SIPClient:
    def __init__(
        self,
        server: str,
        port: int,
        user: str,
        credentials_manager: CredentialsManager,
        bind_ip="0.0.0.0",
        bind_port=5060,
        call_callback: Optional[Callable[[SIPMessage], Optional[str]]] = None,
        transport_mode: TransportMode = TransportMode.UDP,
    ):
        self.NSD = False
        self.server = server
        self.port = port
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.user = user
        self.credentials_manager = credentials_manager
        self.transport_mode = transport_mode

        self.call_callback = call_callback

        self.tags: List[str] = []
        self.tagLibrary = {"register": self.gen_tag()}

        self.default_expires = 120
        self.register_timeout = 30

        self.inviteCounter = Counter()
        self.registerCounter = Counter()
        self.subscribeCounter = Counter()
        self.byeCounter = Counter()
        self.callID = Counter()
        self.sessID = Counter()

        self.urnUUID = self.gen_urn_uuid()
        self.nc: Dict[str, Counter] = {}

        self.registerThread: Optional[Timer] = None
        self.recvLock = Lock()

    def recv(self) -> None:
        while self.NSD:
            self.recvLock.acquire()
            self.s.setblocking(False)
            try:
                raw = self.s.recv(8192)
                if raw != b"\x00\x00\x00\x00":
                    try:
                        message = SIPMessage(raw)
                        debug(message.summary())
                        self.parse_message(message)
                    except Exception as ex:
                        debug(f"Error on header parsing: {ex}")
            except BlockingIOError:
                self.s.setblocking(True)
                self.recvLock.release()
                time.sleep(0.01)
                continue
            except SIPParseError as e:
                if "SIP Version" in str(e):
                    request = self.gen_sip_version_not_supported(message)
                    self.out.sendto(
                        request.encode("utf8"), (self.server, self.port)
                    )
                else:
                    debug(f"SIPParseError in SIP.recv: {type(e)}, {e}")
            except Exception as e:
                debug(f"SIP.recv error: {type(e)}, {e}\n\n{str(raw, 'utf8')}")
                if pyVoIP.DEBUG:
                    self.s.setblocking(True)
                    self.recvLock.release()
                    raise
            self.s.setblocking(True)
            self.recvLock.release()

    def parse_message(self, message: SIPMessage) -> None:
        if message.type != SIPMessageType.MESSAGE:
            if message.status == SIPStatus.OK:
                if self.call_callback is not None:
                    self.call_callback(message)
            elif message.status == SIPStatus.NOT_FOUND:
                if self.call_callback is not None:
                    self.call_callback(message)
            elif message.status == SIPStatus.SERVICE_UNAVAILABLE:
                if self.call_callback is not None:
                    self.call_callback(message)
            elif (
                message.status == SIPStatus.TRYING
                or message.status == SIPStatus.RINGING
            ):
                pass
            else:
                debug(
                    "TODO: Add 500 Error on Receiving SIP Response:\r\n"
                    + message.summary(),
                    "TODO: Add 500 Error on Receiving SIP Response",
                )
            self.s.setblocking(True)
            return
        elif message.method == "INVITE":
            if self.call_callback is None:
                request = self.gen_busy(message)
                self.out.sendto(
                    request.encode("utf8"), message.headers["Via"]["address"]
                )
            else:
                self.call_callback(message)
        elif message.method == "BYE":
            # TODO: If callCallback is None, the call doesn't exist, 481
            if self.call_callback:
                self.call_callback(message)
            response = self.gen_ok(message)
            try:
                # BYE comes from client cause server only acts as mediator
                (_sender_adress, _sender_port) = message.headers["Via"][0][
                    "address"
                ]
                self.out.sendto(
                    response.encode("utf8"),
                    (_sender_adress, int(_sender_port)),
                )
            except Exception:
                debug("BYE Answer failed falling back to server as target")
                self.out.sendto(
                    response.encode("utf8"), message.headers["Via"]["address"]
                )
        elif message.method == "ACK":
            return
        elif message.method == "CANCEL":
            # TODO: If callCallback is None, the call doesn't exist, 481
            self.call_callback(message)  # type: ignore
            response = self.gen_ok(message)
            self.out.sendto(
                response.encode("utf8"), message.headers["Via"]["address"]
            )
        elif message.method == "OPTIONS":
            if self.call_callback:
                response = str(self.call_callback(message))
            else:
                response = self._gen_options_response(message)
            self.out.sendto(
                response.encode("utf8"), message.headers["Via"]["address"]
            )
        else:
            debug("TODO: Add 400 Error on non processable request")

    def start(self) -> None:
        if self.NSD:
            raise RuntimeError("Attempted to start already started SIPClient")
        self.NSD = True
        self.s = socket.socket(socket.AF_INET, self.transport_mode.socket_type)
        """
        self.out = socket.socket(
            socket.AF_INET, self.transport_mode.socket_type
        )
        """

        if self.transport_mode.tls_mode:
            ctx = ssl.SSLContext(protocol=self.transport_mode.tls_mode)
            self.s = ctx.wrap_socket(self.s)
            # self.out = ctx.wrap_socket(self.out)
        self.s.bind((self.bind_ip, self.bind_port))
        self.out = self.s
        self.register()
        t = Timer(1, self.recv)
        t.name = "SIP Receive"
        t.start()

    def stop(self) -> None:
        self.NSD = False
        if self.registerThread:
            # Only run if registerThread exists
            self.registerThread.cancel()
            self.deregister()
        self._close_sockets()

    def _close_sockets(self) -> None:
        if hasattr(self, "s"):
            if self.s:
                self.s.close()
        if hasattr(self, "out"):
            if self.out:
                self.out.close()

    def gen_call_id(self) -> str:
        hash = hashlib.sha256(str(self.callID.next()).encode("utf8"))
        hhash = hash.hexdigest()
        return f"{hhash[0:32]}@{self.bind_ip}:{self.bind_port}"

    def gen_last_call_id(self) -> str:
        hash = hashlib.sha256(str(self.callID.current() - 1).encode("utf8"))
        hhash = hash.hexdigest()
        return f"{hhash[0:32]}@{self.bind_ip}:{self.bind_port}"

    def gen_tag(self) -> str:
        # Keep as True instead of NSD so it can generate a tag on deregister.
        while True:
            rand = str(random.randint(1, 4294967296)).encode("utf8")
            tag = hashlib.md5(rand).hexdigest()[0:8]
            if tag not in self.tags:
                self.tags.append(tag)
                return tag
        return ""

    def gen_to_for_response(self, request: SIPMessage) -> str:
        _to = request.headers["To"]
        return f'"{_to["display-name"]}" ' if _to["display-name"] else ""

    def gen_from_for_response(self, request: SIPMessage) -> str:
        _from = request.headers["From"]
        return f'"{_from["display-name"]}" ' if _from["display-name"] else ""

    def gen_allow(self) -> str:
        return f'Allow: {(", ".join(pyVoIP.SIPCompatibleMethods))}\r\n' \
               f'Max-Forwards: 70\r\n' \
               f'Allow-Events: org.3gpp.nwinitdereg\r\n' \
               f'User-Agent: pyVoIP {pyVoIP.__version__}\r\n'

    def gen_sip_version_not_supported(self, request: SIPMessage) -> str:
        # TODO: Add Supported
        response = f'SIP/2.0 505 SIP Version Not Supported\r\n' \
                   f'{self._gen_response_via_header(request)}' \
                   f'From: {request.headers["From"]["raw"]}\r\n' \
                   f'To: {self.gen_to_for_response(request)}' \
                   f'<{request.headers["To"]["uri"]}>;tag={self.gen_tag()}\r\n' \
                   f'Call-ID: {request.headers["Call-ID"]}\r\n' \
                   f'CSeq: {request.headers["CSeq"]["check"]} ' \
                   f'{request.headers["CSeq"]["method"]}\r\n' \
                   f'Contact: {request.headers["Contact"]["raw"]}\r\n' \
                   f'f"User-Agent: pyVoIP {pyVoIP.__version__}\r\n' \
                   f'Warning: 399 GS "Unable to accept call"\r\n' \
                   f'Allow: {(", ".join(pyVoIP.SIPCompatibleMethods))}\r\n' \
                   f'Content-Length: 0\r\n\r\n'

        return response

    def _hash_md5(self, data: bytes) -> str:
        """
        MD5 Hash function.
        """
        return hashlib.md5(data).hexdigest()

    def _hash_sha256(self, data: bytes) -> str:
        """
        SHA-256 Hash function.
        """
        sha256 = hashlib.new("sha256")
        sha256.update(data)
        return sha256.hexdigest()

    def _hash_sha512_256(self, data: bytes) -> str:
        """
        SHA-512-256 Hash function.
        """
        sha512 = hashlib.new("sha512")
        sha512.update(data)
        return sha512.hexdigest()[:64]

    def gen_digest(
        self, request: SIPMessage, body: str = ""
    ) -> Dict[str, str]:
        server = request.headers["From"]["host"]
        realm = request.authentication["realm"]
        user = request.headers["From"]["user"]
        credentials = self.credentials_manager.get(server, realm, user)
        username = credentials["username"]
        password = credentials["password"]
        nonce = request.authentication["nonce"]
        method = request.headers["CSeq"]["method"]
        uri = f"sip:{self.server};transport={self.transport_mode}"
        algo = request.authentication.get("algorithm", "md5").lower()
        if algo in ["sha512-256", "sha512-256-sess"]:
            hash_func = self._hash_sha512_256
        elif algo in ["sha256", "sha256-sess"]:
            hash_func = self._hash_sha256
        else:
            hash_func = self._hash_md5
        # Get new method values
        qop = request.authentication.get("qop", None).pop(0)
        opaque = request.authentication.get("opaque", None)
        userhash = request.authentication.get("userhash", False)

        if qop:
            # Use new hash method
            cnonce = uuid.uuid4().hex
            if nonce not in self.nc:
                self.nc[nonce] = Counter()
            nc = str(
                b16encode(self.nc[nonce].next().to_bytes(4, "big")), "utf8"
            )
            HA1 = f"{username}:{realm}:{password}"
            HA1 = hash_func(HA1.encode("utf8"))
            if "-sess" in algo:
                HA1 += f":{nonce}:{cnonce}"
            HA2 = f"{method}:{uri}"
            if "auth-int" in qop:
                HAB = hash_func(body.encode("utf8"))
                HA2 += f":{HAB}"
            HA2 = hash_func(HA2.encode("utf8"))
            HA3 = f"{HA1}:{nonce}:{nc}:{cnonce}:{qop}:{HA2}"
            if userhash:
                username = hash_func(f"{username}:{realm}")
            response = {
                "realm": realm,
                "nonce": nonce,
                "algorithm": algo,
                "digest": hash_func(HA3.encode("utf8")),
                "uri": uri,
                "username": username,
                "opaque": opaque,
                "qop": qop,
                "cnonce": cnonce,
                "nc": nc,
                "userhash": userhash,
            }
        else:
            # Use old hash method
            HA1 = f"{username}:{realm}:{password}"
            HA1 = hash_func(HA1.encode("utf8"))
            HA2 = f"{method}:{uri}"
            HA2 = hash_func(HA2.encode("utf8"))
            HA3 = f"{HA1}:{nonce}:{HA2}"
            response = {
                "realm": realm,
                "nonce": nonce,
                "algorithm": algo,
                "digest": hash_func(HA3.encode("utf8")),
                "username": username,
                "opaque": opaque,
            }

        return response

    def gen_authorization(self, request: SIPMessage, body: str = "") -> str:
        if request.authentication["method"].lower() == "digest":
            digest = self.gen_digest(request)
            response = (
                f'Authorization: Digest username="{digest["username"]}",'
                + f'realm="{digest["realm"]}",nonce="{digest["nonce"]}",'
                + f'uri="{digest["uri"]}",response="{digest["digest"]}",'
                + f'algorithm={digest["algorithm"]}'
            )
            if "qop" in digest:
                response += (
                    f',qop={digest["qop"]},'
                    + f'cnonce="{digest["cnonce"]}",nc={digest["nc"]},'
                    + f'userhash={str(digest["userhash"]).lower()}'
                )
            if "opaque" in digest:
                if digest["opaque"]:
                    response += f',opaque="{digest["opaque"]}"'
            response += "\r\n"
        elif request.authentication["method"].lower() == "basic":
            if not pyVoIP.ALLOW_BASIC_AUTH:
                raise RuntimeError(
                    "Basic authentication is not allowed. "
                    + "Please use pyVoIP.ALLOW_BASIC_AUTH = True to allow it, "
                    + "but this is not recommended."
                )
            server = request.headers["From"]["host"]
            realm = request.authentication.get("realm", None)
            credentials = self.credentials_manager.get(
                server, realm, self.user
            )
            username = credentials["username"]
            password = credentials["password"]
            userid_pass = f"{username}:{password}".encode("utf8")
            encoded = str(b64encode(userid_pass), "utf8")
            response = f"Authorization: Basic {encoded}\r\n"
        return response

    def gen_branch(self, length=32) -> str:
        """
        Generate unique branch id according to
        https://datatracker.ietf.org/doc/html/rfc3261#section-8.1.1.7
        """
        branchid = uuid.uuid4().hex[: length - 7]
        return f"z9hG4bK{branchid}"

    def gen_urn_uuid(self) -> str:
        """
        Generate client instance specific urn:uuid
        """
        return str(uuid.uuid4()).upper()

    def gen_first_request(self, deregister=False) -> str:
        reg_request = f"REGISTER sip:{self.server} SIP/2.0\r\n"
        reg_request += (
            "Via: SIP/2.0/"
            + str(self.transport_mode)
            + f" {self.bind_ip}:{self.bind_port};"
            + f"branch={self.gen_branch()};rport\r\n"
        )
        reg_request += (
            f'From: "{self.user}" '
            + f"<sip:{self.user}@{self.server}>;tag="
            + f'{self.tagLibrary["register"]}\r\n'
        )
        reg_request += (
            f'To: "{self.user}" ' + f"<sip:{self.user}@{self.server}>\r\n"
        )
        reg_request += f"Call-ID: {self.gen_call_id()}\r\n" \
                       f"CSeq: {self.registerCounter.next()} REGISTER\r\n"
        reg_request += (
            "Contact: "
            + f"<sip:{self.user}@{self.bind_ip}:{self.bind_port};"
            + "transport="
            + str(self.transport_mode)
            + ">;+sip.instance="
            + f'"<urn:uuid:{self.urnUUID}>"\r\n'
        )
        reg_request += f'{self.gen_allow()}'
        # Supported: 100rel, replaces, from-change, gruu
        reg_request += (
            "Expires: "
            + f"{self.default_expires if not deregister else 0}\r\n"
        )
        reg_request += "Content-Length: 0" \
                       "\r\n\r\n"

        return reg_request

    def gen_subscribe(self, response: SIPMessage) -> str:
        sub_request = f"SUBSCRIBE sip:{self.user}@{self.server} SIP/2.0\r\n"
        sub_request += (
            "Via: SIP/2.0/"
            + str(self.transport_mode)
            + f" {self.bind_ip}:{self.bind_port};"
            + f"branch={self.gen_branch()};rport\r\n"
        )
        sub_request += (
            f'From: "{self.user}" '
            + f"<sip:{self.user}@{self.server}>;tag="
            + f"{self.gen_tag()}\r\n"
        )
        sub_request += f'To: <sip:{self.user}@{self.server}>\r\n' \
                       f'Call-ID: {response.headers["Call-ID"]}\r\n' \
                       f'CSeq: {self.subscribeCounter.next()} SUBSCRIBE\r\n'
        # TODO: check if transport is needed
        sub_request += (
            "Contact: "
            + f"<sip:{self.user}@{self.bind_ip}:{self.bind_port};"
            + "transport="
            + str(self.transport_mode)
            + ">;+sip.instance="
            + f'"<urn:uuid:{self.urnUUID}>"\r\n'
        )
        sub_request += f'Max-Forwards: 70\r\n' \
                       f'User-Agent: pyVoIP {pyVoIP.__version__}\r\n' \
                       f'Expires: {self.default_expires * 2}\r\n' \
                       f'Event: message-summary\r\n' \
                       f'Accept: application/simple-message-summary' \
                       f'Content-Length: 0' \
                       f'\r\n\r\n'

        return sub_request

    def gen_register(self, request: SIPMessage, deregister=False) -> str:
        reg_request = f"REGISTER sip:{self.server} SIP/2.0\r\n"
        reg_request += (
            "Via: SIP/2.0/"
            + str(self.transport_mode)
            + f" {self.bind_ip}:{self.bind_port};branch="
            + f"{self.gen_branch()};rport\r\n"
        )
        reg_request += (
            f'From: "{self.user}" '
            + f"<sip:{self.user}@{self.server}>;tag="
            + f'{self.tagLibrary["register"]}\r\n'
        )
        reg_request += (
            f'To: "{self.user}" ' + f"<sip:{self.user}@{self.server}>\r\n"
        )
        call_id = request.headers.get("Call-ID", self.gen_call_id())
        reg_request += f'Call-ID: {call_id}\r\n' \
                       f'CSeq: {self.registerCounter.next()} REGISTER\r\n'
        reg_request += (
            "Contact: "
            + f"<sip:{self.user}@{self.bind_ip}:{self.bind_port};"
            + "transport="
            + str(self.transport_mode)
            + ">;+sip.instance="
            + f'"<urn:uuid:{self.urnUUID}>"\r\n'
        )
        reg_request += f'{self.gen_allow()}'
        reg_request += (
            "Expires: "
            + f"{self.default_expires if not deregister else 0}\r\n"
        )
        reg_request += f'{self.gen_authorization(request)}' \
                       f'Content-Length: 0' \
                       f'\r\n\r\n'

        return reg_request

    def gen_busy(self, request: SIPMessage) -> str:
        response = "SIP/2.0 486 Busy Here\r\n"
        response += self._gen_response_via_header(request)
        response += f"From: {request.headers['From']['raw']}\r\n"
        response += (
            f'To: {self.gen_to_for_response(request)}'
            f'<{request.headers["To"]["uri"]}>;tag=' + f"{self.gen_tag()}\r\n"
        )
        response += f"Call-ID: {request.headers['Call-ID']}\r\n"
        response += (
            f"CSeq: {request.headers['CSeq']['check']} "
            + f"{request.headers['CSeq']['method']}\r\n"
        )
        response += f"Contact: {request.headers['Contact']['raw']}\r\n"
        # TODO: Add Supported
        response += f"User-Agent: pyVoIP {pyVoIP.__version__}\r\n"
        response += 'Warning: 399 GS "Unable to accept call"\r\n'
        response += f"Allow: {(', '.join(pyVoIP.SIPCompatibleMethods))}\r\n"
        response += "Content-Length: 0\r\n\r\n"

        return response

    def gen_ok(self, request: SIPMessage) -> str:
        ok_response = f'SIP/2.0 200 OK\r\n' \
                      f'{self._gen_response_via_header(request)}' \
                      f'From: {request.headers["From"]["raw"]}\r\n' \
                      f'To: {self.gen_to_for_response(request)}' \
                      f'<{request.headers["To"]["uri"]}>;tag={self.gen_tag()}\r\n' \
                      f'Call-ID: {request.headers["Call-ID"]}\r\n'
        ok_response += (
            f"CSeq: {request.headers['CSeq']['check']} "
            + f"{request.headers['CSeq']['method']}\r\n"
        )
        ok_response += f"User-Agent: pyVoIP {pyVoIP.__version__}\r\n" \
                       f"Allow: {(', '.join(pyVoIP.SIPCompatibleMethods))}\r\n" \
                       f"Content-Length: 0\r\n\r\n"

        return ok_response

    def gen_ringing(self, request: SIPMessage) -> str:
        tag = self.gen_tag()
        reg_request = f'SIP/2.0 180 Ringing\r\n' \
                      f'{self._gen_response_via_header(request)}' \
                      f'From: {request.headers["From"]["raw"]}\r\n' \
                      f'To: {self.gen_to_for_response(request)}' \
                      f'<{request.headers["To"]["uri"]}>;tag={tag}\r\n' \
                      f'Call-ID: {request.headers["Call-ID"]}\r\n'
        reg_request += (
            f"CSeq: {request.headers['CSeq']['check']} "
            f"{request.headers['CSeq']['method']}\r\n"
        )
        # TODO: Add Supported
        reg_request += f"Contact: {request.headers['Contact']['raw']}\r\n" \
                       f"User-Agent: pyVoIP {pyVoIP.__version__}\r\n" \
                       f"Allow: {(', '.join(pyVoIP.SIPCompatibleMethods))}\r\n" \
                       f"Content-Length: 0\r\n\r\n"

        self.tagLibrary[request.headers["Call-ID"]] = tag

        return reg_request

    def gen_answer(
        self,
        request: SIPMessage,
        sess_id: str,
        ms: Dict[int, Dict[int, "RTP.PayloadType"]],
        sendtype: "RTP.TransmitType",
    ) -> str:
        # Generate body first for content length
        body = "v=0\r\n"
        # TODO: Check IPv4/IPv6
        body += (
            f"o=pyVoIP {sess_id} {int(sess_id)+2} IN IP4 {self.bind_ip}\r\n"
        )
        body += f"s=pyVoIP {pyVoIP.__version__}\r\n"
        # TODO: Check IPv4/IPv6
        body += f"c=IN IP4 {self.bind_ip}\r\n"
        body += "t=0 0\r\n"
        for x in ms:
            # TODO: Check AVP mode from request
            body += f"m=audio {x} RTP/AVP"
            for m in ms[x]:
                body += f" {m}"
        body += "\r\n"  # m=audio <port> RTP/AVP <codecs>\r\n
        for x in ms:
            for m in ms[x]:
                body += f"a=rtpmap:{m} {ms[x][m]}/{ms[x][m].rate}\r\n"
                if str(ms[x][m]) == "telephone-event":
                    body += f"a=fmtp:{m} 0-15\r\n"
        body += "a=ptime:20\r\n"
        body += "a=maxptime:150\r\n"
        body += f"a={sendtype}\r\n"

        tag = self.tagLibrary[request.headers["Call-ID"]]

        reg_request = f'SIP/2.0 200 OK\r\n' \
                      f'{self._gen_response_via_header(request)}' \
                      f'From: {request.headers["From"]["raw"]}\r\n' \
                      f'To: {self.gen_to_for_response(request)}' \
                      f'<{request.headers["To"]["uri"]}>;tag={tag}\r\n' \
                      f'Call-ID: {request.headers["Call-ID"]}\r\n'
        reg_request += (
            f"CSeq: {request.headers['CSeq']['check']} "
            f"{request.headers['CSeq']['method']}\r\n"
        )
        reg_request += f'Contact: <sip:{self.user}@{self.bind_ip}:{self.bind_port}>\r\n' \
                       f'{self.gen_allow()}' \
                       f'Content-Length: {len(body)}\r\n\r\n' \
                       f'{body}'

        return reg_request

    def gen_invite(
        self,
        number: str,
        sess_id: str,
        ms: Dict[int, Dict[int, "RTP.PayloadType"]],
        sendtype: "RTP.TransmitType",
        branch: str,
        call_id: str,
    ) -> str:
        # Generate body first for content length
        body = "v=0\r\n"
        # TODO: Check IPv4/IPv6
        body += (
            f"o=pyVoIP {sess_id} {int(sess_id)+2} IN IP4 {self.bind_ip}\r\n"
        )
        body += f"s=pyVoIP {pyVoIP.__version__}\r\n"
        body += f"c=IN IP4 {self.bind_ip}\r\n"  # TODO: Check IPv4/IPv6
        body += "t=0 0\r\n"
        for x in ms:
            # TODO: Check AVP mode from request
            body += f"m=audio {x} RTP/AVP"
            for m in ms[x]:
                body += f" {m}"
        body += "\r\n"  # m=audio <port> RTP/AVP <codecs>\r\n
        for x in ms:
            for m in ms[x]:
                body += f"a=rtpmap:{m} {ms[x][m]}/{ms[x][m].rate}\r\n"
                if str(ms[x][m]) == "telephone-event":
                    body += f"a=fmtp:{m} 0-15\r\n"
        body += "a=ptime:20\r\n"
        body += "a=maxptime:150\r\n"
        body += f"a={sendtype}\r\n"

        tag = self.gen_tag()
        self.tagLibrary[call_id] = tag

        inv_request = f"INVITE sip:{number}@{self.server} SIP/2.0\r\n"
        inv_request += (
            "Via: SIP/2.0/"
            + str(self.transport_mode)
            + f" {self.bind_ip}:{self.bind_port};branch="
            + f"{branch}\r\n"
        )
        inv_request += "Max-Forwards: 70\r\n"
        inv_request += (
            "Contact: "
            + f"<sip:{self.user}@{self.bind_ip}:{self.bind_port}>\r\n"
        )
        inv_request += f"To: <sip:{number}@{self.server}>\r\n" \
                       f"From: <sip:{self.user}@{self.bind_ip}>;tag={tag}\r\n" \
                       f"Call-ID: {call_id}\r\n" \
                       f"CSeq: {self.inviteCounter.next()} INVITE\r\n" \
                       f"{self.gen_allow()}" \
                       f"Content-Length: {len(body)}\r\n\r\n" \
                       f"{body}"

        return inv_request

    def gen_bye(self, request: SIPMessage) -> str:
        tag = self.tagLibrary[request.headers["Call-ID"]]
        c = request.headers["Contact"]["uri"]
        from_h = f'{self.gen_from_for_response(request)}<{request.headers["From"]["uri"]}>'
        to_h = f'{self.gen_to_for_response(request)}<{request.headers["To"]["uri"]}>'
        cseq = int(request.headers["CSeq"]["check"]) + 1

        bye_request = f'BYE {c} SIP/2.0\r\n' \
                      f'{self._gen_response_via_header(request)}'
        if request.headers["From"]["tag"] == tag:
            bye_request += f'From: {from_h};tag={tag}\r\n' \
                           f'To: {request.headers["To"]["raw"]}\r\n'
        else:
            bye_request += f'To: {request.headers["From"]["raw"]}\r\n' \
                           f'From: {to_h};tag={tag}\r\n'
        bye_request += f'Call-ID: {request.headers["Call-ID"]}\r\n' \
                       f'CSeq: {cseq} BYE\r\n' \
                       f'Contact: <sip:{self.user}@{self.bind_ip}:{self.bind_port}>\r\n' \
                       f'User-Agent: pyVoIP {pyVoIP.__version__}\r\n' \
                       f'Allow: {(", ".join(pyVoIP.SIPCompatibleMethods))}\r\n' \
                       f'Content-Length: 0\r\n\r\n'

        return bye_request

    def gen_ack(self, request: SIPMessage) -> str:
        tag = self.tagLibrary[request.headers["Call-ID"]]
        uri = request.headers["To"]["uri"]
        ack_message = f'ACK {uri} SIP/2.0\r\n' \
                      f'{self._gen_response_via_header(request)}' \
                      f'Max-Forwards: 70\r\n' \
                      f'To: {self.gen_to_for_response(request)}' \
                      f'<{request.headers["To"]["uri"]}>;tag={request.headers["To"]["tag"]}\r\n' \
                      f'From: {self.gen_from_for_response(request)}' \
                      f'<{request.headers["From"]["uri"]}>;tag={tag}\r\n' \
                      f'Call-ID: {request.headers["Call-ID"]}\r\n' \
                      f'CSeq: {request.headers["CSeq"]["check"]} ACK\r\n' \
                      f'User-Agent: pyVoIP {pyVoIP.__version__}\r\n' \
                      f'Content-Length: 0\r\n\r\n'

        return ack_message

    def _gen_options_response(self, request: SIPMessage) -> str:
        return self.gen_busy(request)

    def _gen_response_via_header(self, request: SIPMessage) -> str:
        via = ""
        for h_via in request.headers["Via"]:
            v_line = (
                "Via: SIP/2.0/"
                + str(self.transport_mode)
                + " "
                + f'{h_via["address"][0]}:{h_via["address"][1]}'
            )
            if "branch" in h_via.keys():
                v_line += f';branch={h_via["branch"]}'
            if "rport" in h_via.keys():
                if h_via["rport"] is not None:
                    v_line += f';rport={h_via["rport"]}'
                else:
                    v_line += ";rport"
            if "received" in h_via.keys():
                v_line += f';received={h_via["received"]}'
            v_line += "\r\n"
            via += v_line
        return via

    def invite(
        self,
        number: str,
        ms: Dict[int, Dict[int, "RTP.PayloadType"]],
        sendtype: "RTP.TransmitType",
    ) -> Tuple[SIPMessage, str, int]:
        branch = "z9hG4bK" + self.gen_call_id()[0:25]
        call_id = self.gen_call_id()
        sess_id = self.sessID.next()
        invite = self.gen_invite(
            number, str(sess_id), ms, sendtype, branch, call_id
        )
        self.recvLock.acquire()
        self.out.sendto(invite.encode("utf8"), (self.server, self.port))
        debug("Invited")
        response = SIPMessage(self.s.recv(8192))

        while (
            response.status != SIPStatus(401)
            and response.status != SIPStatus(100)
            and response.status != SIPStatus(180)
        ) or response.headers["Call-ID"] != call_id:
            if not self.NSD:
                break
            self.parse_message(response)
            response = SIPMessage(self.s.recv(8192))

        if response.status == SIPStatus(100) or response.status == SIPStatus(
            180
        ):
            self.recvLock.release()
            return SIPMessage(invite.encode("utf8")), call_id, sess_id
        debug(f"Received Response: {response.summary()}")
        ack = self.gen_ack(response)
        self.out.sendto(ack.encode("utf8"), (self.server, self.port))
        debug("Acknowledged")
        auth = self.gen_authorization(response)

        invite = self.gen_invite(
            number, str(sess_id), ms, sendtype, branch, call_id
        )
        invite = invite.replace(
            "\r\nContent-Length", f"\r\n{auth}Content-Length"
        )

        self.out.sendto(invite.encode("utf8"), (self.server, self.port))

        self.recvLock.release()

        return SIPMessage(invite.encode("utf8")), call_id, sess_id

    def bye(self, request: SIPMessage) -> None:
        message = self.gen_bye(request)
        # TODO: Handle bye to server vs. bye to connected client
        self.recvLock.acquire()
        self.out.sendto(
            message.encode("utf8"),
            (
                request.headers["Contact"]["host"],
                request.headers["Contact"]["port"],
            ),
        )
        response = SIPMessage(self.s.recv(8192))
        if response.status == SIPStatus(401):
            #  Requires password
            auth = self.gen_authorization(response)
            message = message.replace(
                "\r\nContent-Length", f"\r\n{auth}Content-Length"
            )
            # TODO: Handle bye to server vs. bye to connected client
            self.out.sendto(
                message.encode("utf8"),
                (
                    request.headers["Contact"]["host"],
                    request.headers["Contact"]["port"],
                ),
            )
        else:
            debug("Received not a 401 on bye:")
            debug(response.summary())
        self.recvLock.release()

    def deregister(self) -> bool:
        self.recvLock.acquire()
        first_request = self.gen_first_request(deregister=True)
        self.out.sendto(first_request.encode("utf8"), (self.server, self.port))

        self.out.setblocking(False)

        ready = select.select([self.out], [], [], self.register_timeout)
        if ready[0]:
            resp = self.s.recv(8192)
        else:
            raise TimeoutError("Deregistering on SIP Server timed out")

        response = SIPMessage(resp)
        response = self.trying_timeout_check(response)

        if response.status == SIPStatus(401):
            # Unauthorized, likely due to being password protected.
            reg_request = self.gen_register(response, deregister=True)
            self.out.sendto(
                reg_request.encode("utf8"), (self.server, self.port)
            )
            ready = select.select([self.s], [], [], self.register_timeout)
            if ready[0]:
                resp = self.s.recv(8192)
                response = SIPMessage(resp)
                if response.status == SIPStatus(401):
                    # At this point, it's reasonable to assume that
                    # this is caused by invalid credentials.
                    debug("Unauthorized")
                    raise InvalidAccountInfoError(
                        "Invalid Username or "
                        + "Password for SIP server "
                        + f"{self.server}:"
                        + f"{self.bind_port}"
                    )
                elif response.status == SIPStatus(400):
                    # Bad Request
                    # TODO: implement
                    # TODO: check if broken connection can be brought back
                    # with new urn:uuid or reply with expire 0
                    self._handle_bad_request()
            else:
                raise TimeoutError("Deregistering on SIP Server timed out")

        if response.status == SIPStatus(500):
            self.recvLock.release()
            time.sleep(5)
            return self.deregister()

        if response.status == SIPStatus.OK:
            self.recvLock.release()
            return True
        self.recvLock.release()
        return False

    def register(self) -> bool:
        self.recvLock.acquire()
        first_request = self.gen_first_request()
        self.out.sendto(first_request.encode("utf8"), (self.server, self.port))

        self.out.setblocking(False)

        ready = select.select([self.out], [], [], self.register_timeout)
        if ready[0]:
            resp = self.s.recv(8192)
        else:
            raise TimeoutError("Registering on SIP Server timed out")

        response = SIPMessage(resp)
        response = self.trying_timeout_check(response)
        first_response = response

        if response.status == SIPStatus(400):
            # Bad Request
            # TODO: implement
            # TODO: check if broken connection can be brought back
            # with new urn:uuid or reply with expire 0
            self._handle_bad_request()

        if response.status == SIPStatus(401):
            # Unauthorized, likely due to being password protected.
            reg_request = self.gen_register(response)
            self.out.sendto(
                reg_request.encode("utf8"), (self.server, self.port)
            )
            ready = select.select([self.s], [], [], self.register_timeout)
            if ready[0]:
                resp = self.s.recv(8192)
                response = SIPMessage(resp)
                response = self.trying_timeout_check(response)
                if response.status == SIPStatus(401):
                    # At this point, it's reasonable to assume that
                    # this is caused by invalid credentials.
                    debug("=" * 50)
                    debug("Unauthorized, SIP Message Log:\n")
                    debug("SENT")
                    debug(first_request)
                    debug("\nRECEIVED")
                    debug(first_response.summary())
                    debug("\nSENT (DO NOT SHARE THIS PACKET)")
                    debug(reg_request)
                    debug("\nRECEIVED")
                    debug(response.summary())
                    debug("=" * 50)
                    raise InvalidAccountInfoError(
                        "Invalid Username or "
                        + "Password for SIP server "
                        + f"{self.server}:"
                        + f"{self.bind_port}"
                    )
                elif response.status == SIPStatus(400):
                    # Bad Request
                    # TODO: implement
                    # TODO: check if broken connection can be brought back
                    # with new urn:uuid or reply with expire 0
                    self._handle_bad_request()
            else:
                raise TimeoutError("Registering on SIP Server timed out")

        if response.status == SIPStatus(407):
            # Proxy Authentication Required
            # TODO: implement
            debug("Proxy auth required")

        # TODO: This must be done more reliable
        if response.status not in [
            SIPStatus(400),
            SIPStatus(401),
            SIPStatus(407),
        ]:
            # Unauthorized
            if response.status == SIPStatus(500):
                self.recvLock.release()
                time.sleep(5)
                return self.register()
            else:
                # TODO: determine if needed here
                self.parse_message(response)

        debug(response.summary())
        debug(response.raw)

        self.recvLock.release()
        if response.status == SIPStatus.OK:
            if self.NSD:
                # self.subscribe(response)
                self.registerThread = Timer(
                    self.default_expires - 5, self.register
                )
                self.registerThread.name = (
                    "SIP Register CSeq: " + f"{self.registerCounter.x}"
                )
                self.registerThread.start()
            return True
        else:
            raise InvalidAccountInfoError(
                "Invalid Username or Password for "
                + f"SIP server {self.server}:"
                + f"{self.bind_port}"
            )

    def _handle_bad_request(self) -> None:
        # Bad Request
        # TODO: implement
        # TODO: check if broken connection can be brought back
        # with new urn:uuid or reply with expire 0
        debug("Bad Request")

    def subscribe(self, lastresponse: SIPMessage) -> None:
        # TODO: check if needed and maybe implement fully
        self.recvLock.acquire()

        subRequest = self.gen_subscribe(lastresponse)
        self.out.sendto(subRequest.encode("utf8"), (self.server, self.port))

        response = SIPMessage(self.s.recv(8192))

        debug(f'Got response to subscribe: {str(response.heading, "utf8")}')

        self.recvLock.release()

    def trying_timeout_check(self, response: SIPMessage) -> SIPMessage:
        """
        Some servers need time to process the response.
        When this happens, the first response you get from the server is
        SIPStatus.TRYING. This while loop tries checks every second for an
        updated response. It times out after 30 seconds.
        """
        start_time = time.monotonic()
        while response.status == SIPStatus.TRYING:
            if (time.monotonic() - start_time) >= self.register_timeout:
                raise TimeoutError(
                    f"Waited {self.register_timeout} seconds but server is "
                    + "still TRYING"
                )

            ready = select.select([self.s], [], [], self.register_timeout)
            if ready[0]:
                resp = self.s.recv(8192)
            response = SIPMessage(resp)
        return response
