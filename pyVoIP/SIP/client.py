from threading import Timer, Lock
from typing import Callable, Dict, List, Optional, Tuple, TYPE_CHECKING
from pyVoIP.SIP.message import (
    SIPMessage,
    SIPStatus,
    SIPMessageType,
)
from pyVoIP.SIP.error import (
    SIPParseError,
    InvalidAccountInfoError,
)
from pyVoIP.sock import TransportMode
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
        username: str,
        password: str,
        bind_ip="0.0.0.0",
        bind_port=5060,
        call_callback: Optional[Callable[[SIPMessage], None]] = None,
        transport_mode: TransportMode = TransportMode.UDP,
    ):
        self.NSD = False
        self.server = server
        self.port = port
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.username = username
        self.password = password
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
                    request.encode("utf8"), (self.server, self.port)
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
                    response.encode("utf8"), (self.server, self.port)
                )
        elif message.method == "ACK":
            return
        elif message.method == "CANCEL":
            # TODO: If callCallback is None, the call doesn't exist, 481
            self.call_callback(message)  # type: ignore
            response = self.gen_ok(message)
            self.out.sendto(response.encode("utf8"), (self.server, self.port))
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

    def gen_sip_version_not_supported(self, request: SIPMessage) -> str:
        # TODO: Add Supported
        response = "SIP/2.0 505 SIP Version Not Supported\r\n"
        response += self._gen_response_via_header(request)
        response += (
            f"From: {request.headers['From']['raw']};tag="
            + f"{request.headers['From']['tag']}\r\n"
        )
        response += (
            f"To: {request.headers['To']['raw']};tag="
            + f"{self.gen_tag()}\r\n"
        )
        response += f"Call-ID: {request.headers['Call-ID']}\r\n"
        response += (
            f"CSeq: {request.headers['CSeq']['check']} "
            + f"{request.headers['CSeq']['method']}\r\n"
        )
        response += f"Contact: {request.headers['Contact']}\r\n"
        response += f"User-Agent: pyVoIP {pyVoIP.__version__}\r\n"
        response += 'Warning: 399 GS "Unable to accept call"\r\n'
        response += f"Allow: {(', '.join(pyVoIP.SIPCompatibleMethods))}\r\n"
        response += "Content-Length: 0\r\n\r\n"

        return response

    def gen_authorization(self, request: SIPMessage) -> bytes:
        realm = request.authentication["realm"]
        HA1 = self.username + ":" + realm + ":" + self.password
        HA1 = hashlib.md5(HA1.encode("utf8")).hexdigest()
        HA2 = (
            ""
            + request.headers["CSeq"]["method"]
            + ":sip:"
            + self.server
            + ";transport=UDP"
        )
        HA2 = hashlib.md5(HA2.encode("utf8")).hexdigest()
        nonce = request.authentication["nonce"]
        response = (HA1 + ":" + nonce + ":" + HA2).encode("utf8")
        response = hashlib.md5(response).hexdigest().encode("utf8")

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
        regRequest = f"REGISTER sip:{self.server} SIP/2.0\r\n"
        regRequest += (
            f"Via: SIP/2.0/UDP {self.bind_ip}:{self.bind_port};"
            + f"branch={self.gen_branch()};rport\r\n"
        )
        regRequest += (
            f'From: "{self.username}" '
            + f"<sip:{self.username}@{self.server}>;tag="
            + f'{self.tagLibrary["register"]}\r\n'
        )
        regRequest += (
            f'To: "{self.username}" '
            + f"<sip:{self.username}@{self.server}>\r\n"
        )
        regRequest += f"Call-ID: {self.gen_call_id()}\r\n"
        regRequest += f"CSeq: {self.registerCounter.next()} REGISTER\r\n"
        regRequest += (
            "Contact: "
            + f"<sip:{self.username}@{self.bind_ip}:{self.bind_port};"
            + "transport=UDP>;+sip.instance="
            + f'"<urn:uuid:{self.urnUUID}>"\r\n'
        )
        regRequest += f'Allow: {(", ".join(pyVoIP.SIPCompatibleMethods))}\r\n'
        regRequest += "Max-Forwards: 70\r\n"
        regRequest += "Allow-Events: org.3gpp.nwinitdereg\r\n"
        regRequest += f"User-Agent: pyVoIP {pyVoIP.__version__}\r\n"
        # Supported: 100rel, replaces, from-change, gruu
        regRequest += (
            "Expires: "
            + f"{self.default_expires if not deregister else 0}\r\n"
        )
        regRequest += "Content-Length: 0"
        regRequest += "\r\n\r\n"

        return regRequest

    def gen_subscribe(self, response: SIPMessage) -> str:
        subRequest = f"SUBSCRIBE sip:{self.username}@{self.server} SIP/2.0\r\n"
        subRequest += (
            f"Via: SIP/2.0/UDP {self.bind_ip}:{self.bind_port};"
            + f"branch={self.gen_branch()};rport\r\n"
        )
        subRequest += (
            f'From: "{self.username}" '
            + f"<sip:{self.username}@{self.server}>;tag="
            + f"{self.gen_tag()}\r\n"
        )
        subRequest += f"To: <sip:{self.username}@{self.server}>\r\n"
        subRequest += f'Call-ID: {response.headers["Call-ID"]}\r\n'
        subRequest += f"CSeq: {self.subscribeCounter.next()} SUBSCRIBE\r\n"
        # TODO: check if transport is needed
        subRequest += (
            "Contact: "
            + f"<sip:{self.username}@{self.bind_ip}:{self.bind_port};"
            + "transport=UDP>;+sip.instance="
            + f'"<urn:uuid:{self.urnUUID}>"\r\n'
        )
        subRequest += "Max-Forwards: 70\r\n"
        subRequest += f"User-Agent: pyVoIP {pyVoIP.__version__}\r\n"
        subRequest += f"Expires: {self.default_expires * 2}\r\n"
        subRequest += "Event: message-summary\r\n"
        subRequest += "Accept: application/simple-message-summary"
        subRequest += "Content-Length: 0"
        subRequest += "\r\n\r\n"

        return subRequest

    def gen_register(self, request: SIPMessage, deregister=False) -> str:
        response = str(self.gen_authorization(request), "utf8")
        nonce = request.authentication["nonce"]
        realm = request.authentication["realm"]

        regRequest = f"REGISTER sip:{self.server} SIP/2.0\r\n"
        regRequest += (
            f"Via: SIP/2.0/UDP {self.bind_ip}:{self.bind_port};branch="
            + f"{self.gen_branch()};rport\r\n"
        )
        regRequest += (
            f'From: "{self.username}" '
            + f"<sip:{self.username}@{self.server}>;tag="
            + f'{self.tagLibrary["register"]}\r\n'
        )
        regRequest += (
            f'To: "{self.username}" '
            + f"<sip:{self.username}@{self.server}>\r\n"
        )
        regRequest += f"Call-ID: {self.gen_call_id()}\r\n"
        regRequest += f"CSeq: {self.registerCounter.next()} REGISTER\r\n"
        regRequest += (
            "Contact: "
            + f"<sip:{self.username}@{self.bind_ip}:{self.bind_port};"
            + "transport=UDP>;+sip.instance="
            + f'"<urn:uuid:{self.urnUUID}>"\r\n'
        )
        regRequest += f'Allow: {(", ".join(pyVoIP.SIPCompatibleMethods))}\r\n'
        regRequest += "Max-Forwards: 70\r\n"
        regRequest += "Allow-Events: org.3gpp.nwinitdereg\r\n"
        regRequest += f"User-Agent: pyVoIP {pyVoIP.__version__}\r\n"
        regRequest += (
            "Expires: "
            + f"{self.default_expires if not deregister else 0}\r\n"
        )
        regRequest += (
            f'Authorization: Digest username="{self.username}",'
            + f'realm="{realm}",nonce="{nonce}",'
            + f'uri="sip:{self.server};transport=UDP",'
            + f'response="{response}",algorithm=MD5\r\n'
        )
        regRequest += "Content-Length: 0"
        regRequest += "\r\n\r\n"

        return regRequest

    def gen_busy(self, request: SIPMessage) -> str:
        response = "SIP/2.0 486 Busy Here\r\n"
        response += self._gen_response_via_header(request)
        response += (
            f"From: {request.headers['From']['raw']};tag="
            + f"{request.headers['From']['tag']}\r\n"
        )
        response += (
            f"To: {request.headers['To']['raw']};tag="
            + f"{self.gen_tag()}\r\n"
        )
        response += f"Call-ID: {request.headers['Call-ID']}\r\n"
        response += (
            f"CSeq: {request.headers['CSeq']['check']} "
            + f"{request.headers['CSeq']['method']}\r\n"
        )
        response += f"Contact: {request.headers['Contact']}\r\n"
        # TODO: Add Supported
        response += f"User-Agent: pyVoIP {pyVoIP.__version__}\r\n"
        response += 'Warning: 399 GS "Unable to accept call"\r\n'
        response += f"Allow: {(', '.join(pyVoIP.SIPCompatibleMethods))}\r\n"
        response += "Content-Length: 0\r\n\r\n"

        return response

    def gen_ok(self, request: SIPMessage) -> str:
        okResponse = "SIP/2.0 200 OK\r\n"
        okResponse += self._gen_response_via_header(request)
        okResponse += (
            f"From: {request.headers['From']['raw']};tag="
            + f"{request.headers['From']['tag']}\r\n"
        )
        okResponse += (
            f"To: {request.headers['To']['raw']};tag="
            + f"{self.gen_tag()}\r\n"
        )
        okResponse += f"Call-ID: {request.headers['Call-ID']}\r\n"
        okResponse += (
            f"CSeq: {request.headers['CSeq']['check']} "
            + f"{request.headers['CSeq']['method']}\r\n"
        )
        okResponse += f"User-Agent: pyVoIP {pyVoIP.__version__}\r\n"
        okResponse += f"Allow: {(', '.join(pyVoIP.SIPCompatibleMethods))}\r\n"
        okResponse += "Content-Length: 0\r\n\r\n"

        return okResponse

    def gen_ringing(self, request: SIPMessage) -> str:
        tag = self.gen_tag()
        regRequest = "SIP/2.0 180 Ringing\r\n"
        regRequest += self._gen_response_via_header(request)
        regRequest += (
            f"From: {request.headers['From']['raw']};tag="
            + f"{request.headers['From']['tag']}\r\n"
        )
        regRequest += f"To: {request.headers['To']['raw']};tag={tag}\r\n"
        regRequest += f"Call-ID: {request.headers['Call-ID']}\r\n"
        regRequest += (
            f"CSeq: {request.headers['CSeq']['check']} "
            + f"{request.headers['CSeq']['method']}\r\n"
        )
        regRequest += f"Contact: {request.headers['Contact']}\r\n"
        # TODO: Add Supported
        regRequest += f"User-Agent: pyVoIP {pyVoIP.__version__}\r\n"
        regRequest += f"Allow: {(', '.join(pyVoIP.SIPCompatibleMethods))}\r\n"
        regRequest += "Content-Length: 0\r\n\r\n"

        self.tagLibrary[request.headers["Call-ID"]] = tag

        return regRequest

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

        regRequest = "SIP/2.0 200 OK\r\n"
        regRequest += self._gen_response_via_header(request)
        regRequest += (
            f"From: {request.headers['From']['raw']};tag="
            + f"{request.headers['From']['tag']}\r\n"
        )
        regRequest += f"To: {request.headers['To']['raw']};tag={tag}\r\n"
        regRequest += f"Call-ID: {request.headers['Call-ID']}\r\n"
        regRequest += (
            f"CSeq: {request.headers['CSeq']['check']} "
            + f"{request.headers['CSeq']['method']}\r\n"
        )
        regRequest += (
            "Contact: "
            + f"<sip:{self.username}@{self.bind_ip}:{self.bind_port}>\r\n"
        )
        # TODO: Add Supported
        regRequest += f"User-Agent: pyVoIP {pyVoIP.__version__}\r\n"
        regRequest += f"Allow: {(', '.join(pyVoIP.SIPCompatibleMethods))}\r\n"
        regRequest += "Content-Type: application/sdp\r\n"
        regRequest += f"Content-Length: {len(body)}\r\n\r\n"
        regRequest += body

        return regRequest

    def gen_invite(
        self,
        number: str,
        sess_id: str,
        ms: Dict[int, Dict[str, "RTP.PayloadType"]],
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

        invRequest = f"INVITE sip:{number}@{self.server} SIP/2.0\r\n"
        invRequest += (
            f"Via: SIP/2.0/UDP {self.bind_ip}:{self.bind_port};branch="
            + f"{branch}\r\n"
        )
        invRequest += "Max-Forwards: 70\r\n"
        invRequest += (
            "Contact: "
            + f"<sip:{self.username}@{self.bind_ip}:{self.bind_port}>\r\n"
        )
        invRequest += f"To: <sip:{number}@{self.server}>\r\n"
        invRequest += (
            f"From: <sip:{self.username}@{self.bind_ip}>;tag={tag}\r\n"
        )
        invRequest += f"Call-ID: {call_id}\r\n"
        invRequest += f"CSeq: {self.inviteCounter.next()} INVITE\r\n"
        invRequest += f"Allow: {(', '.join(pyVoIP.SIPCompatibleMethods))}\r\n"
        invRequest += "Content-Type: application/sdp\r\n"
        invRequest += f"User-Agent: pyVoIP {pyVoIP.__version__}\r\n"
        invRequest += f"Content-Length: {len(body)}\r\n\r\n"
        invRequest += body

        return invRequest

    def gen_bye(self, request: SIPMessage) -> str:
        tag = self.tagLibrary[request.headers["Call-ID"]]
        c = request.headers["Contact"].strip("<").strip(">")
        byeRequest = f"BYE {c} SIP/2.0\r\n"
        byeRequest += self._gen_response_via_header(request)
        fromH = request.headers["From"]["raw"]
        toH = request.headers["To"]["raw"]
        if request.headers["From"]["tag"] == tag:
            byeRequest += f"From: {fromH};tag={tag}\r\n"
            if request.headers["To"]["tag"] != "":
                to = toH + ";tag=" + request.headers["To"]["tag"]
            else:
                to = toH
            byeRequest += f"To: {to}\r\n"
        else:
            byeRequest += (
                f"To: {fromH};tag=" + f"{request.headers['From']['tag']}\r\n"
            )
            byeRequest += f"From: {toH};tag={tag}\r\n"
        byeRequest += f"Call-ID: {request.headers['Call-ID']}\r\n"
        cseq = int(request.headers["CSeq"]["check"]) + 1
        byeRequest += f"CSeq: {cseq} BYE\r\n"
        byeRequest += (
            "Contact: "
            + f"<sip:{self.username}@{self.bind_ip}:{self.bind_port}>\r\n"
        )
        byeRequest += f"User-Agent: pyVoIP {pyVoIP.__version__}\r\n"
        byeRequest += f"Allow: {(', '.join(pyVoIP.SIPCompatibleMethods))}\r\n"
        byeRequest += "Content-Length: 0\r\n\r\n"

        return byeRequest

    def gen_ack(self, request: SIPMessage) -> str:
        tag = self.tagLibrary[request.headers["Call-ID"]]
        t = request.headers["To"]["raw"].strip("<").strip(">")
        ackMessage = f"ACK {t} SIP/2.0\r\n"
        ackMessage += self._gen_response_via_header(request)
        ackMessage += "Max-Forwards: 70\r\n"
        ackMessage += (
            f"To: {request.headers['To']['raw']};tag="
            + f"{self.gen_tag()}\r\n"
        )
        ackMessage += f"From: {request.headers['From']['raw']};tag={tag}\r\n"
        ackMessage += f"Call-ID: {request.headers['Call-ID']}\r\n"
        ackMessage += f"CSeq: {request.headers['CSeq']['check']} ACK\r\n"
        ackMessage += f"User-Agent: pyVoIP {pyVoIP.__version__}\r\n"
        ackMessage += "Content-Length: 0\r\n\r\n"

        return ackMessage

    def _gen_response_via_header(self, request: SIPMessage) -> str:
        via = ""
        for h_via in request.headers["Via"]:
            v_line = (
                "Via: SIP/2.0/UDP "
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
        ms: Dict[int, Dict[str, "RTP.PayloadType"]],
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
            return SIPMessage(invite.encode("utf8")), call_id, sess_id
        debug(f"Received Response: {response.summary()}")
        ack = self.gen_ack(response)
        self.out.sendto(ack.encode("utf8"), (self.server, self.port))
        debug("Acknowledged")
        authhash = self.gen_authorization(response)
        nonce = response.authentication["nonce"]
        realm = response.authentication["realm"]
        auth = (
            f'Authorization: Digest username="{self.username}",realm='
            + f'"{realm}",nonce="{nonce}",uri="sip:{self.server};'
            + f'transport=UDP",response="{str(authhash, "utf8")}",'
            + "algorithm=MD5\r\n"
        )

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
        self.out.sendto(message.encode("utf8"), (self.server, self.port))

    def deregister(self) -> bool:
        self.recvLock.acquire()
        firstRequest = self.gen_first_request(deregister=True)
        self.out.sendto(firstRequest.encode("utf8"), (self.server, self.port))

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
            regRequest = self.gen_register(response, deregister=True)
            self.out.sendto(
                regRequest.encode("utf8"), (self.server, self.port)
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
        firstRequest = self.gen_first_request()
        self.out.sendto(firstRequest.encode("utf8"), (self.server, self.port))

        self.out.setblocking(False)

        ready = select.select([self.out], [], [], self.register_timeout)
        if ready[0]:
            resp = self.s.recv(8192)
        else:
            raise TimeoutError("Registering on SIP Server timed out")

        response = SIPMessage(resp)
        response = self.trying_timeout_check(response)

        if response.status == SIPStatus(400):
            # Bad Request
            # TODO: implement
            # TODO: check if broken connection can be brought back
            # with new urn:uuid or reply with expire 0
            self._handle_bad_request()

        if response.status == SIPStatus(401):
            # Unauthorized, likely due to being password protected.
            regRequest = self.gen_register(response)
            self.out.sendto(
                regRequest.encode("utf8"), (self.server, self.port)
            )
            ready = select.select([self.s], [], [], self.register_timeout)
            if ready[0]:
                resp = self.s.recv(8192)
                response = SIPMessage(resp)
                response = self.trying_timeout_check(response)
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
