from base64 import b16encode, b64encode
from threading import Timer
from typing import Callable, Dict, List, Optional, Tuple, TYPE_CHECKING
from pyVoIP.credentials import CredentialsManager
from pyVoIP.helpers import Counter
from pyVoIP.networking.nat import NAT, AddressType
from pyVoIP.networking.sock import VoIPSocket
from pyVoIP.networking.transport import TransportMode
from pyVoIP.SIP.error import (
    SIPParseError,
    InvalidAccountInfoError,
    RetryRequiredError,
)
from pyVoIP.SIP.message.message import (
    SIPMessage,
    SIPMethod,
    SIPResponse,
    SIPRequest,
)
from pyVoIP.SIP.message.response_codes import ResponseCode
from pyVoIP.types import KEY_PASSWORD
from pyVoIP.VoIP.status import PhoneStatus
import pyVoIP
import hashlib
import random
import time
import uuid


if TYPE_CHECKING:
    from pyVoIP import RTP
    from pyVoIP.networking.sock import VoIPConnection
    from pyVoIP.VoIP.phone import VoIPPhone


debug = pyVoIP.debug


UNAUTORIZED_RESPONSE_CODES = [
    ResponseCode.UNAUTHORIZED,
    ResponseCode.PROXY_AUTHENTICATION_REQUIRED,
]
INVITE_OK_RESPONSE_CODES = [
    ResponseCode.TRYING,
    ResponseCode.RINGING,
    ResponseCode.OK,
]


class SIPClient:
    def __init__(
        self,
        server: str,
        port: int,
        user: str,
        credentials_manager: CredentialsManager,
        phone: "VoIPPhone",
        bind_ip="0.0.0.0",
        bind_network="0.0.0.0/0",
        hostname: Optional[str] = None,
        remote_hostname: Optional[str] = None,
        bind_port=5060,
        call_callback: Optional[
            Callable[["VoIPConnection", SIPMessage], Optional[str]]
        ] = None,
        fatal_callback: Optional[Callable[..., None]] = None,
        transport_mode: TransportMode = TransportMode.UDP,
        cert_file: Optional[str] = None,
        key_file: Optional[str] = None,
        key_password: KEY_PASSWORD = None,
    ):
        self.NSD = False
        self.server = server
        self.port = port
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.nat = NAT(bind_ip, bind_network, hostname, remote_hostname)
        self.user = user
        self.credentials_manager = credentials_manager
        self.phone = phone
        self.transport_mode = transport_mode
        self.cert_file = cert_file
        self.key_file = key_file
        self.key_password = key_password

        self.call_callback = call_callback
        self.fatal_callback = fatal_callback

        self.tags: List[str] = []
        self.tagLibrary = {"register": self.gen_tag()}

        self.default_expires = 120
        self.register_timeout = 30

        self.inviteCounter = Counter()
        self.registerCounter = Counter()
        self.subscribeCounter = Counter()
        self.byeCounter = Counter()
        self.messageCounter = Counter()
        self.referCounter = Counter()
        self.callID = Counter()
        self.sessID = Counter()

        self.urnUUID = self.gen_urn_uuid()
        self.nc: Dict[str, Counter] = {}

        self.registerThread: Optional[Timer] = None
        self.register_failures = 0

    def recv(self) -> None:
        while self.NSD:
            try:
                raw = self.s.recv(8192)
                if raw != b"\x00\x00\x00\x00":
                    try:
                        message = SIPMessage.from_bytes(raw)
                        debug(message.summary())
                        self.parse_message(message)
                    except Exception as ex:
                        debug(f"Error on header parsing: {ex}")
            except BlockingIOError:
                time.sleep(0.01)
                continue
            except SIPParseError as e:
                if "SIP Version" in str(e):
                    request = self.gen_sip_version_not_supported(message)
                    self.sendto(request)
                else:
                    debug(f"SIPParseError in SIP.recv: {type(e)}, {e}")
            except Exception as e:
                try:
                    debug(
                        f"SIP.recv error: {type(e)}, {e}\n\n{str(raw, 'utf8')}"
                    )
                except UnboundLocalError:
                    debug("SIP.recv error: Unable to recv")
                finally:
                    if pyVoIP.DEBUG:
                        raise

    def handle_new_connection(self, conn: "VoIPConnection") -> None:
        message = SIPMessage.from_bytes(conn.peak())
        if type(message) is SIPRequest:
            if message.method == SIPMethod.INVITE:
                self._handle_invite(conn)

    def _handle_invite(self, conn: "VoIPConnection") -> None:
        message = SIPMessage.from_bytes(conn.peak())
        if self.call_callback is None:
            request = self.gen_busy(message)
            conn.send(request)
        else:
            self.call_callback(conn, message)

    def parse_message(self, message: SIPMessage) -> None:
        if type(message) is SIPResponse:
            if message.status in (
                ResponseCode.OK,
                ResponseCode.NOT_FOUND,
                ResponseCode.SERVICE_UNAVAILABLE,
                ResponseCode.PROXY_AUTHENTICATION_REQUIRED,
                ResponseCode.RINGING,
                ResponseCode.BUSY_HERE,
                ResponseCode.SESSION_PROGRESS,
                ResponseCode.REQUEST_TERMINATED,
            ):
                if self.call_callback is not None:
                    self.call_callback(message)
            elif message.status == ResponseCode.TRYING:
                pass
            else:
                debug(
                    "TODO: Add 500 Error on Receiving SIP Response:\r\n"
                    + message.summary(),
                    "TODO: Add 500 Error on Receiving SIP Response",
                )
            return
        elif type(message) is SIPRequest:
            if message.method == "BYE":
                # TODO: If callCallback is None, the call doesn't exist, 481
                if self.call_callback:
                    self.call_callback(message)
                response = self.gen_ok(message)
                try:
                    # BYE comes from client cause server only acts as mediator
                    (_sender_adress, _sender_port) = message.headers["Via"][0][
                        "address"
                    ]
                    self.sendto(
                        response,
                        (_sender_adress, int(_sender_port)),
                    )
                except Exception:
                    debug("BYE Answer failed falling back to server as target")
                    self.sendto(response, message.headers["Via"]["address"])
            elif message.method == "ACK":
                return
            elif message.method == "CANCEL":
                # TODO: If callCallback is None, the call doesn't exist, 481
                self.call_callback(message)  # type: ignore
                response = self.gen_ok(message)
                self.sendto(response, message.headers["Via"]["address"])
            elif message.method == "OPTIONS":
                if self.call_callback:
                    response = str(self.call_callback(message))
                else:
                    response = self._gen_options_response(message)
                self.sendto(response, message.headers["Via"]["address"])
            else:
                debug("TODO: Add 400 Error on non processable request")

    def start(self) -> None:
        if self.NSD:
            raise RuntimeError("Attempted to start already started SIPClient")

        self.NSD = True
        self.s = VoIPSocket(
            self.transport_mode,
            self.bind_ip,
            self.bind_port,
            self,
            self.cert_file,
            self.key_file,
            self.key_password,
        )
        """
        self.out = socket.socket(
            socket.AF_INET, self.transport_mode.socket_type
        )
        """

        self.s.start()
        # TODO: Check if we need to register with a server or proxy.
        self.register()
        """
        t = Timer(1, self.recv)
        t.name = "SIP Receive"
        t.start()
        """

    def stop(self) -> None:
        self.NSD = False
        if self.registerThread:
            # Only run if registerThread exists
            self.registerThread.cancel()
            self.deregister()
        if hasattr(self, "s"):
            if self.s:
                self.s.close()

    def sendto(self, request: str, address=None) -> "VoIPConnection":
        if address is None:
            address = (self.server, self.port)
        return self.s.send(request.encode("utf8"))

    def send(self, request: str) -> "VoIPConnection":
        return self.s.send(request.encode("utf8"))

    def __gen_from_to_via_request(
        self,
        request: SIPMessage,
        hdr: str,
        tag: Optional[str] = None,
        dsthdr: Optional[str] = None,
    ) -> str:
        if dsthdr is None:
            dsthdr = hdr
        h = request.headers[hdr]
        dn = h["display-name"]
        uri = h["uri"]

        if dn:
            ret = f'{dsthdr}: "{dn}"'
        else:
            ret = f"{dsthdr}:"

        if tag:
            return f"{ret} <{uri}>;tag={tag}\r\n"
        return f"{ret} <{uri}>\r\n"

    def __gen_from_to(
        self,
        header_type: str,
        user: str,
        host: str,
        method="sip",
        display_name: Optional[str] = None,
        password: Optional[str] = None,
        port=5060,
        uri_params: Optional[str] = None,
        header_parms: Optional[str] = None,
    ) -> str:
        header_type = header_type.capitalize()

        assert header_type in ["To", "From"], "header_type must be To or From"
        assert (
            display_name is None or '"' not in display_name
        ), f'{display_name=} cannot contain a `"`'

        uri = self.__gen_uri(method, user, host, password, port, uri_params)
        display_name = f'"{display_name}" ' if display_name else ""
        header_parms = f"{header_parms}" if header_parms else ""
        return f"{header_type}: {display_name}<{uri}>{header_parms}\r\n"

    def __gen_uri(
        self,
        method: str,
        user: str,
        host: str,
        password: Optional[str] = None,
        port=5060,
        params: Optional[str] = None,
    ) -> str:
        method = method.lower()

        assert method in ["sip", "sips"], "method must be sip or sips"
        assert (
            type(host) is str and len(host) > 0
        ), "Host must be a non-empty string"

        password = f":{password}" if password else ""
        port_str = f":{port}" if port != 5060 else ""
        params = params if params else ""
        if type(user) is str and len(user) > 0:
            return f"{method}:{user}{password}@{host}{port_str}{params}"
        return f"{method}:{host}{port_str}{params}"

    def __gen_via(self, to: str, branch: str) -> str:
        # SIP/2.0/ should still be the prefix even if using TLS per RFC 3261
        # 8.1.1.7, as shown in RFC 5630 6.1
        return (
            "Via: "
            + f"SIP/2.0/{str(self.transport_mode)}"
            + f" {self.nat.get_host(to)}:{self.bind_port};branch={branch}\r\n"
        )

    def __gen_contact(
        self,
        method: str,
        user: str,
        host: str,
        password: Optional[str] = None,
        port=5060,
        uriparams: Optional[str] = None,
        params: List[str] = [],
    ) -> str:
        uri = self.__gen_uri(method, user, host, password, port, uriparams)
        uri = f"<{uri}>"
        if params:
            uri += ";" + (";".join(params))
        return f"Contact: {uri}\r\n"

    def __gen_user_agent(self) -> str:
        return f"User-Agent: pyVoIP {pyVoIP.__version__}\r\n"

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
        response += f"From: {request.headers['From']['raw']}\r\n"
        response += self.__gen_from_to_via_request(
            request, "To", self.gen_tag()
        )
        response += f"Call-ID: {request.headers['Call-ID']}\r\n"
        response += (
            f"CSeq: {request.headers['CSeq']['check']} "
            + f"{request.headers['CSeq']['method']}\r\n"
        )
        response += f"Contact: {request.headers['Contact']['raw']}\r\n"
        response += self.__gen_user_agent()
        response += 'Warning: 399 GS "Unable to accept call"\r\n'
        response += f"Allow: {(', '.join(pyVoIP.SIPCompatibleMethods))}\r\n"
        response += "Content-Length: 0\r\n\r\n"

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
        uri = f"sip:{self.server};transport={self.transport_mode}"  # TODO: Fix TLS
        algo = request.authentication.get("algorithm", "md5").lower()
        if algo in ["sha512-256", "sha512-256-sess"]:
            hash_func = self._hash_sha512_256
        elif algo in ["sha256", "sha256-sess"]:
            hash_func = self._hash_sha256
        else:
            hash_func = self._hash_md5
        # Get new method values
        qop = request.authentication.get("qop", [None]).pop(0)
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
                "uri": uri,
                "username": username,
                "opaque": opaque,
            }

        return response

    def gen_authorization(self, request: SIPMessage, body: str = "") -> str:
        header = "Authorization"
        if request.authentication["header"].lower() == "proxy-authenticate":
            header = "Proxy-Authorization"

        if request.authentication["method"].lower() == "digest":
            digest = self.gen_digest(request)
            response = (
                f'{header}: Digest username="{digest["username"]}",'
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
            response = f"{header}: Basic {encoded}\r\n"
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
        regRequest = f"REGISTER sip:{self.server}:{self.port} SIP/2.0\r\n"
        regRequest += self.__gen_via(self.server, self.gen_branch())
        tag = self.tagLibrary["register"]
        method = "sips" if self.transport_mode is TransportMode.TLS else "sip"
        regRequest += self.__gen_from_to(
            "From",
            self.user,
            self.server,
            method=method,
            port=self.port,
            header_parms=f";tag={tag}",
        )
        regRequest += self.__gen_from_to(
            "To", self.user, self.server, method=method, port=self.port
        )
        regRequest += f"Call-ID: {self.gen_call_id()}\r\n"
        regRequest += f"CSeq: {self.registerCounter.next()} REGISTER\r\n"
        trans_mode = str(self.transport_mode)
        regRequest += self.__gen_contact(
            method,
            self.user,
            self.nat.get_host(self.server),
            port=self.bind_port,
            uriparams=f";transport={trans_mode}",
            params=[f'+sip.instance="<urn:uuid:{self.urnUUID}>"'],
        )
        regRequest += f'Allow: {(", ".join(pyVoIP.SIPCompatibleMethods))}\r\n'
        regRequest += "Max-Forwards: 70\r\n"
        regRequest += "Allow-Events: org.3gpp.nwinitdereg\r\n"
        regRequest += self.__gen_user_agent()
        # Supported: 100rel, replaces, from-change, gruu
        regRequest += (
            "Expires: "
            + f"{self.default_expires if not deregister else 0}\r\n"
        )
        regRequest += "Content-Length: 0"
        regRequest += "\r\n\r\n"

        return regRequest

    def gen_subscribe(self, response: SIPMessage) -> str:
        subRequest = f"SUBSCRIBE sip:{self.user}@{self.server} SIP/2.0\r\n"
        subRequest += self.__gen_via(self.server, self.gen_branch())
        method = "sips" if self.transport_mode is TransportMode.TLS else "sip"
        subRequest += self.__gen_from_to(
            "From",
            self.user,
            self.nat.get_host(self.server),
            method=method,
            port=self.bind_port,
            header_parms=f";tag={self.gen_tag()}",
        )
        subRequest += self.__gen_from_to(
            "To",
            self.user,
            self.server,
            method=method,
            port=self.port,
        )
        subRequest += f'Call-ID: {response.headers["Call-ID"]}\r\n'
        subRequest += f"CSeq: {self.subscribeCounter.next()} SUBSCRIBE\r\n"
        # TODO: check if transport is needed
        method = "sips" if self.transport_mode is TransportMode.TLS else "sip"
        trans_mode = str(self.transport_mode)
        subRequest += self.__gen_contact(
            method,
            self.user,
            self.nat.get_host(self.server),
            port=self.bind_port,
            uriparams=f";transport={trans_mode}",
            params=[f'+sip.instance="<urn:uuid:{self.urnUUID}>"'],
        )
        subRequest += "Max-Forwards: 70\r\n"
        subRequest += self.__gen_user_agent()
        subRequest += f"Expires: {self.default_expires * 2}\r\n"
        subRequest += "Event: message-summary\r\n"
        subRequest += "Accept: application/simple-message-summary\r\n"
        subRequest += "Content-Length: 0\r\n"
        subRequest += "\r\n"

        return subRequest

    def gen_register(self, request: SIPMessage, deregister=False) -> str:
        regRequest = f"REGISTER sip:{self.server}:{self.port} SIP/2.0\r\n"
        regRequest += self.__gen_via(self.server, self.gen_branch())
        method = "sips" if self.transport_mode is TransportMode.TLS else "sip"
        regRequest += self.__gen_from_to(
            "From",
            self.user,
            self.server,
            method=method,
            port=self.port,
            header_parms=f";tag={self.tagLibrary['register']}",
        )
        regRequest += self.__gen_from_to(
            "To",
            self.user,
            self.server,
            method=method,
            port=self.port,
        )
        call_id = request.headers.get("Call-ID", self.gen_call_id())
        regRequest += f"Call-ID: {call_id}\r\n"
        regRequest += f"CSeq: {self.registerCounter.next()} REGISTER\r\n"
        method = "sips" if self.transport_mode is TransportMode.TLS else "sip"
        trans_mode = str(self.transport_mode)
        regRequest += self.__gen_contact(
            method,
            self.user,
            self.nat.get_host(self.server),
            port=self.bind_port,
            uriparams=f";transport={trans_mode}",
            params=[f'+sip.instance="<urn:uuid:{self.urnUUID}>"'],
        )
        regRequest += f'Allow: {(", ".join(pyVoIP.SIPCompatibleMethods))}\r\n'
        regRequest += "Max-Forwards: 70\r\n"
        regRequest += "Allow-Events: org.3gpp.nwinitdereg\r\n"
        regRequest += self.__gen_user_agent()
        regRequest += (
            "Expires: "
            + f"{self.default_expires if not deregister else 0}\r\n"
        )
        regRequest += self.gen_authorization(request)
        regRequest += "Content-Length: 0"
        regRequest += "\r\n\r\n"

        return regRequest

    def gen_busy(self, request: SIPMessage) -> str:
        response = "SIP/2.0 486 Busy Here\r\n"
        response += self._gen_response_via_header(request)
        response += f"From: {request.headers['From']['raw']}\r\n"
        response += self.__gen_from_to_via_request(
            request, "To", self.gen_tag()
        )
        response += f"Call-ID: {request.headers['Call-ID']}\r\n"
        response += (
            f"CSeq: {request.headers['CSeq']['check']} "
            + f"{request.headers['CSeq']['method']}\r\n"
        )
        response += f"Contact: {request.headers['Contact']['raw']}\r\n"
        # TODO: Add Supported
        response += self.__gen_user_agent()
        response += 'Warning: 399 GS "Unable to accept call"\r\n'
        response += f"Allow: {(', '.join(pyVoIP.SIPCompatibleMethods))}\r\n"
        response += "Content-Length: 0\r\n\r\n"

        return response

    def gen_ok(self, request: SIPMessage) -> str:
        okResponse = "SIP/2.0 200 OK\r\n"
        okResponse += self._gen_response_via_header(request)
        okResponse += f"From: {request.headers['From']['raw']}\r\n"
        okResponse += self.__gen_from_to_via_request(
            request, "To", self.gen_tag()
        )
        okResponse += f"Call-ID: {request.headers['Call-ID']}\r\n"
        okResponse += (
            f"CSeq: {request.headers['CSeq']['check']} "
            + f"{request.headers['CSeq']['method']}\r\n"
        )
        okResponse += self.__gen_user_agent()
        okResponse += f"Allow: {(', '.join(pyVoIP.SIPCompatibleMethods))}\r\n"
        okResponse += "Content-Length: 0\r\n\r\n"

        return okResponse

    def gen_ringing(self, request: SIPMessage) -> str:
        tag = self.gen_tag()
        regRequest = "SIP/2.0 180 Ringing\r\n"
        regRequest += self._gen_response_via_header(request)
        regRequest += f"From: {request.headers['From']['raw']}\r\n"
        regRequest += self.__gen_from_to_via_request(request, "To", tag)
        regRequest += f"Call-ID: {request.headers['Call-ID']}\r\n"
        regRequest += (
            f"CSeq: {request.headers['CSeq']['check']} "
            + f"{request.headers['CSeq']['method']}\r\n"
        )
        regRequest += f"Contact: {request.headers['Contact']['raw']}\r\n"
        # TODO: Add Supported
        regRequest += self.__gen_user_agent()
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
            f"o=pyVoIP {sess_id} {int(sess_id) + 2} IN IP4 {self.bind_ip}\r\n"
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
        regRequest += f"From: {request.headers['From']['raw']}\r\n"
        regRequest += self.__gen_from_to_via_request(request, "To", tag)
        regRequest += f"Call-ID: {request.headers['Call-ID']}\r\n"
        regRequest += (
            f"CSeq: {request.headers['CSeq']['check']} "
            + f"{request.headers['CSeq']['method']}\r\n"
        )
        method = "sips" if self.transport_mode is TransportMode.TLS else "sip"
        regRequest += self.__gen_contact(
            method,
            self.user,
            self.nat.get_host(self.server),
            port=self.bind_port,
        )
        # TODO: Add Supported
        regRequest += self.__gen_user_agent()
        regRequest += f"Allow: {(', '.join(pyVoIP.SIPCompatibleMethods))}\r\n"
        regRequest += "Content-Type: application/sdp\r\n"
        regRequest += f"Content-Length: {len(body)}\r\n\r\n"
        regRequest += body

        return regRequest

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
        body += (
            f"o=pyVoIP {sess_id} {int(sess_id) + 2} IN IP"
            + f"{self.nat.bind_ip.version} {self.bind_ip}\r\n"
        )
        body += f"s=pyVoIP {pyVoIP.__version__}\r\n"
        body += f"c=IN IP{self.nat.bind_ip.version} {self.bind_ip}\r\n"
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

        uri_method = (
            "sips" if self.transport_mode == TransportMode.TLS else "sip"
        )
        to_uri = self.__gen_uri(
            uri_method, number, self.server, port=self.port
        )
        invRequest = f"INVITE {to_uri} SIP/2.0\r\n"
        invRequest += self.__gen_via(self.server, branch)
        invRequest += "Max-Forwards: 70\r\n"
        method = "sips" if self.transport_mode is TransportMode.TLS else "sip"
        invRequest += self.__gen_contact(
            method,
            self.user,
            self.nat.get_host(self.server),
            port=self.bind_port,
        )
        invRequest += self.__gen_from_to(
            "To", number, self.server, port=self.port
        )
        invRequest += self.__gen_from_to(
            "From",
            self.user,
            self.nat.get_host(self.server),
            port=self.bind_port,
            header_parms=f";tag={tag}",
        )
        invRequest += f"Call-ID: {call_id}\r\n"
        invRequest += f"CSeq: {self.inviteCounter.next()} INVITE\r\n"
        invRequest += f"Allow: {(', '.join(pyVoIP.SIPCompatibleMethods))}\r\n"
        invRequest += "Content-Type: application/sdp\r\n"
        invRequest += self.__gen_user_agent()
        invRequest += f"Content-Length: {len(body)}\r\n\r\n"
        invRequest += body

        return invRequest

    def gen_refer(
        self,
        request: SIPMessage,
        user: Optional[str] = None,
        uri: Optional[str] = None,
        blind=True,
        new_dialog=True,
    ) -> str:
        if new_dialog:
            return self.__gen_refer_new_dialog(request, user, uri, blind)
        return self.__gen_refer_same_dialog(request, user, uri, blind)

    def __gen_refer_new_dialog(
        self,
        request: SIPMessage,
        user: Optional[str] = None,
        uri: Optional[str] = None,
        blind=True,
    ) -> str:
        if user is None and uri is None:
            raise RuntimeError("Must specify a user or a URI to transfer to")
        call_id = self.gen_call_id()
        self.tagLibrary[call_id] = self.gen_tag()
        tag = self.tagLibrary[call_id]

        c = request.headers["Contact"]["uri"]
        refer = f"REFER {c} SIP/2.0\r\n"
        refer += self._gen_response_via_header(request)
        refer += "Max-Forwards: 70\r\n"

        method = "sips" if self.transport_mode is TransportMode.TLS else "sip"
        refer += self.__gen_from_to(
            "From",
            self.user,
            self.nat.get_host(self.bind_ip),
            method,
            header_parms=f";tag={tag}",
        )

        # Determine if To or From is local to decide who the refer is to
        to_local = (
            self.nat.check_host(request.headers["To"]["host"])
            == AddressType.LOCAL
        )

        if to_local:
            to_user = request.headers["From"]["user"]
            to_host = request.headers["From"]["host"]
            method = request.headers["From"]["uri-type"]
            to_display_name = request.headers["From"]["display-name"]
            to_password = request.headers["From"]["password"]
            to_port = request.headers["From"]["port"]
            remote_tag = request.headers["From"]["tag"]
        else:
            to_user = request.headers["To"]["user"]
            to_host = request.headers["To"]["host"]
            method = request.headers["To"]["uri-type"]
            to_display_name = request.headers["To"]["display-name"]
            to_password = request.headers["To"]["password"]
            to_port = request.headers["To"]["port"]
            remote_tag = request.headers["To"]["tag"]

        refer += self.__gen_from_to(
            "To",
            to_user,
            to_host,
            method,
            to_display_name,
            to_password,
            to_port,
        )

        refer += f"Call-ID: {call_id}\r\n"
        refer += f"CSeq: {self.referCounter.next()} REFER\r\n"
        refer += f"Allow: {(', '.join(pyVoIP.SIPCompatibleMethods))}\r\n"
        if user:
            method = (
                "sips" if self.transport_mode is TransportMode.TLS else "sip"
            )
            uri = self.__gen_uri(
                method,
                user,
                self.nat.get_host(self.server),
                port=self.bind_port,
            )
        refer += f"Refer-To: {uri}\r\n"
        sess_call_id = request.headers["Call-ID"]
        local_tag = self.tagLibrary[sess_call_id]
        refer += (
            f"Target-Dialog: {sess_call_id};local-tag={local_tag}"
            + f";remote-tag={remote_tag}\r\n"
        )
        refer += self.__gen_contact(
            method,
            self.user,
            self.nat.get_host(self.server),
            port=self.bind_port,
        )
        if blind:
            refer += "Refer-Sub: false\r\n"
        refer += "Supported: norefersub\r\n"
        refer += self.__gen_user_agent()
        refer += "Content-Length: 0\r\n\r\n"
        return refer

    def __gen_refer_same_dialog(
        self,
        request: SIPMessage,
        user: Optional[str] = None,
        uri: Optional[str] = None,
        blind=True,
    ) -> str:
        tag = self.tagLibrary[request.headers["Call-ID"]]
        c = request.headers["Contact"]["uri"]
        refer = f"REFER {c} SIP/2.0\r\n"
        refer += self._gen_response_via_header(request)
        refer += "Max-Forwards: 70\r\n"
        _from = request.headers["From"]
        to = request.headers["To"]
        if request.headers["From"]["tag"] == tag:
            refer += self.__gen_from_to_via_request(request, "From", tag)
            refer += f"To: {to['raw']}\r\n"
        else:
            refer += f"To: {_from['raw']}\r\n"
            refer += self.__gen_from_to_via_request(
                request, "To", tag, dsthdr="From"
            )
        refer += f"Call-ID: {request.headers['Call-ID']}\r\n"
        refer += f"CSeq: {self.referCounter.next()} REFER\r\n"
        refer += f"Allow: {(', '.join(pyVoIP.SIPCompatibleMethods))}\r\n"
        method = "sips" if self.transport_mode is TransportMode.TLS else "sip"
        if user:
            uri = self.__gen_uri(
                method,
                user,
                self.nat.get_host(self.server),
                port=self.bind_port,
            )
        refer += f"Refer-To: {uri}\r\n"
        refer += self.__gen_contact(
            method,
            self.user,
            self.nat.get_host(self.server),
            port=self.bind_port,
        )
        if blind:
            refer += "Refer-Sub: false\r\n"
        refer += "Supported: norefersub\r\n"
        refer += self.__gen_user_agent()
        refer += "Content-Length: 0\r\n\r\n"
        return refer

    def _gen_bye_cancel(self, request: SIPMessage, cmd: str) -> str:
        tag = self.tagLibrary[request.headers["Call-ID"]]
        c = request.headers["Contact"]["uri"]
        byeRequest = f"{cmd} {c} SIP/2.0\r\n"
        byeRequest += self._gen_response_via_header(request)
        _from = request.headers["From"]
        to = request.headers["To"]
        if request.headers["From"]["tag"] == tag:
            byeRequest += self.__gen_from_to_via_request(request, "From", tag)
            byeRequest += f"To: {to['raw']}\r\n"
        else:
            byeRequest += f"To: {_from['raw']}\r\n"
            byeRequest += self.__gen_from_to_via_request(
                request, "To", tag, dsthdr="From"
            )
        byeRequest += f"Call-ID: {request.headers['Call-ID']}\r\n"
        cseq = request.headers["CSeq"]["check"]
        byeRequest += f"CSeq: {cseq} {cmd}\r\n"
        byeRequest += "Max-Forwards: 70\r\n"
        method = "sips" if self.transport_mode is TransportMode.TLS else "sip"
        byeRequest += self.__gen_contact(
            method,
            self.user,
            self.nat.get_host(self.server),
            port=self.bind_port,
        )
        byeRequest += self.__gen_user_agent()
        byeRequest += f"Allow: {(', '.join(pyVoIP.SIPCompatibleMethods))}\r\n"
        byeRequest += "Content-Length: 0\r\n\r\n"

        return byeRequest

    def gen_bye(self, request: SIPMessage) -> str:
        return self._gen_bye_cancel(request, "BYE")

    def gen_cancel(self, request: SIPMessage) -> str:
        return self._gen_bye_cancel(request, "CANCEL")

    def gen_ack(self, request: SIPMessage) -> str:
        tag = self.tagLibrary[request.headers["Call-ID"]]
        uri = request.headers["To"]["uri"]
        ackMessage = f"ACK {uri} SIP/2.0\r\n"
        ackMessage += self._gen_response_via_header(request)
        ackMessage += "Max-Forwards: 70\r\n"
        to = request.headers["To"]
        display_name = f'"{to["display-name"]}" ' if to["display-name"] else ""
        ackMessage += f'To: {display_name}<{to["uri"]}>;tag={to["tag"]}\r\n'
        _from = request.headers["From"]
        display_name = (
            f'"{_from["display-name"]}" ' if _from["display-name"] else ""
        )
        ackMessage += f'From: {display_name}<{_from["uri"]}>;tag={tag}\r\n'
        ackMessage += f"Call-ID: {request.headers['Call-ID']}\r\n"
        ackMessage += f"CSeq: {request.headers['CSeq']['check']} ACK\r\n"
        ackMessage += self.__gen_user_agent()
        ackMessage += "Content-Length: 0\r\n\r\n"

        return ackMessage

    def _gen_options_response(self, request: SIPMessage) -> str:
        return self.gen_busy(request)

    def _gen_response_via_header(self, request: SIPMessage) -> str:
        via = ""
        for h_via in request.headers["Via"]:
            v_line = (
                f"Via: {h_via['type']} "
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
    ) -> Tuple[SIPMessage, str, int, "VoIPConnection"]:
        branch = "z9hG4bK" + self.gen_call_id()[0:25]
        call_id = self.gen_call_id()
        sess_id = self.sessID.next()
        invite = self.gen_invite(
            number, str(sess_id), ms, sendtype, branch, call_id
        )
        conn = self.sendto(invite)
        debug("Invited")
        response = SIPMessage.from_bytes(conn.recv(8192))

        while (
            type(response) is SIPResponse
            and (
                response.status
                not in UNAUTORIZED_RESPONSE_CODES + INVITE_OK_RESPONSE_CODES
            )
            or response.headers["Call-ID"] != call_id
        ):
            if not self.NSD:
                break
            debug(f"Received Response: {response.summary()}")
            self.parse_message(response)
            response = SIPMessage.from_bytes(conn.recv(8192))

        debug(f"Received Response: {response.summary()}")

        if (
            type(response) is SIPResponse
            and response.status in INVITE_OK_RESPONSE_CODES
        ):
            debug("Invite Accepted")
            if response.status is ResponseCode.OK:
                return response, call_id, sess_id, conn
            return SIPMessage.from_string(invite), call_id, sess_id, conn
        debug("Invite Requires Authorization")
        ack = self.gen_ack(response)
        conn.send(ack)
        debug("Acknowledged")
        conn.close()  # End of Dialog
        auth = self.gen_authorization(response)

        invite = self.gen_invite(
            number, str(sess_id), ms, sendtype, branch, call_id
        )
        invite = invite.replace(
            "\r\nContent-Length", f"\r\n{auth}Content-Length"
        )

        conn = self.sendto(invite)

        return SIPMessage.from_string(invite), call_id, sess_id, conn

    def gen_message(
        self, number: str, body: str, ctype: str, branch: str, call_id: str
    ) -> str:
        msg = f"MESSAGE sip:{number}@{self.server} SIP/2.0\r\n"
        msg += self.__gen_via(self.server, branch)
        msg += "Max-Forwards: 70\r\n"
        method = "sips" if self.transport_mode is TransportMode.TLS else "sip"
        msg += self.__gen_from_to(
            "From",
            self.user,
            self.nat.get_host(self.server),
            method=method,
            port=self.bind_port,
            header_parms=f";tag={self.gen_tag()}",
        )
        msg += self.__gen_from_to(
            "To",
            number,
            self.server,
            method=method,
            port=self.port,
        )
        msg += f"Call-ID: {call_id}\r\n"
        msg += f"CSeq: {self.messageCounter.next()} MESSAGE\r\n"
        msg += f"Allow: {(', '.join(pyVoIP.SIPCompatibleMethods))}\r\n"
        msg += f"Content-Type: {ctype}\r\n"
        msg += f"Content-Length: {len(body)}\r\n\r\n"
        msg += body
        return msg

    def message(
        self, number: str, body: str, ctype: str = "text/plain"
    ) -> SIPMessage:
        branch = "z0hG4bK" + self.gen_call_id()[0:25]
        call_id = self.gen_call_id()
        msg = self.gen_message(number, body, ctype, branch, call_id)
        conn = self.sendto(msg)
        debug("Message")
        auth = False
        while True:
            response = SIPMessage.from_bytes(conn.recv(8192))
            debug(f"Received Response: {response.summary()}")
            self.parse_message(response)
            if type(response) is not SIPResponse:
                continue
            if response.status == ResponseCode(100):
                continue
            if response.status == ResponseCode(
                401
            ) or response.status == ResponseCode(407):
                if auth:
                    debug("Auth Failure")
                    break
                auth = True
                auth = self.gen_auth_header(response, number)
                msg = msg.replace(
                    "\r\nContent-Length", "\r\n{auth}Content-Length"
                )
                conn.send(msg)
                continue
            if response.status == ResponseCode.OK:
                break
            if self.NSD:
                break
        return response

    def bye(self, request: SIPMessage) -> None:
        message = self.gen_bye(request)
        # TODO: Handle bye to server vs. bye to connected client
        conn = self.sendto(
            message,
            (
                request.headers["Contact"]["host"],
                request.headers["Contact"]["port"],
            ),
        )
        response = SIPMessage.from_bytes(conn.recv(8192))
        if response.status == ResponseCode(
            401
        ) or response.status == ResponseCode(407):
            #  Requires password
            auth = self.gen_authorization(response)
            message = message.replace(
                "\r\nContent-Length", f"\r\n{auth}Content-Length"
            )
            # TODO: Handle bye to server vs. bye to connected client
            conn.send(message)
        else:
            debug("Received not a 401 on bye:")
            debug(response.summary())

    def cancel(self, request: SIPMessage) -> None:
        message = self.gen_cancel(request)
        self.sendto(message)

    def deregister(self) -> bool:
        try:
            deregistered = self.__deregister()
            if not deregistered:
                debug("DEREGISTERATION FAILED")
                return False
            else:
                self.phone._status = PhoneStatus.INACTIVE

            return deregistered
        except BaseException as e:
            debug(f"DEREGISTERATION ERROR: {e}")
            # TODO: a maximum tries check should be implemented otherwise a
            # RecursionError will throw
            if isinstance(e, RetryRequiredError):
                time.sleep(5)
                return self.deregister()
            if type(e) is OSError:
                raise
            return False

    def __deregister(self) -> bool:
        self.phone._status = PhoneStatus.DEREGISTERING
        first_request = self.gen_first_request(deregister=True)
        conn = self.send(first_request)

        response = self.__receive(conn)
        first_response = response
        conn.close()  # Regardless of the response, the dialog is over

        if response.status == ResponseCode(
            401
        ) or response.status == ResponseCode(407):
            # Unauthorized, likely due to being password protected.
            password_request = self.gen_register(response, deregister=True)
            conn = self.send(password_request)
            response = self.__receive(conn)
            conn.close()

        if response.status == ResponseCode(400):
            # Bad Request
            # TODO: implement
            # TODO: check if broken connection can be brought back
            # with new urn:uuid or reply with expire 0
            self._handle_bad_request()

        elif response.status == ResponseCode(500):
            # We raise so the calling function can sleep and try again
            raise RetryRequiredError(
                "Received a 500 error when deregistering."
            )

        elif response.status == ResponseCode.OK:
            return True

        elif response.status == ResponseCode(
            401
        ) or response.status == ResponseCode(407):
            # At this point, it's reasonable to assume that
            # this is caused by invalid credentials.
            debug("=" * 50)
            debug("Unauthorized deregister, SIP Message Log:\n")
            debug("SENT")
            debug(first_request)
            debug("\nRECEIVED")
            debug(first_response.summary())
            debug("\nSENT (DO NOT SHARE THIS PACKET)")
            debug(password_request)
            debug("\nRECEIVED")
            debug(response.summary())
            debug("=" * 50)
            raise InvalidAccountInfoError(
                f"Invalid Username or Password for SIP server {self.server}:"
                + f"{self.bind_port}"
            )

        raise Exception(
            f"Unable to deregister. Ended with {response.summary()}"
        )

    def register(self) -> bool:
        try:
            registered = self.__register()
            if not registered:
                debug("REGISTERATION FAILED")
                self.register_failures += 1
            else:
                self.phone._status = PhoneStatus.REGISTERED
                self.register_failures = 0

            if self.register_failures >= pyVoIP.REGISTER_FAILURE_THRESHOLD:
                debug("Too many registration failures, stopping.")
                self.stop()
                self.fatal_callback()
                return False
            self.__start_register_timer()

            return registered
        except BaseException as e:
            debug(f"REGISTERATION ERROR: {e}")
            self.register_failures += 1
            if self.register_failures >= pyVoIP.REGISTER_FAILURE_THRESHOLD:
                self.stop()
                self.fatal_callback()
                return False
            if isinstance(e, RetryRequiredError):
                time.sleep(5)
                return self.register()
            self.__start_register_timer(delay=0)

    def __start_register_timer(self, delay: Optional[int] = None):
        if delay is None:
            delay = self.default_expires - 5
        if self.NSD:
            debug("New register thread")
            self.registerThread = Timer(delay, self.register)
            self.registerThread.name = (
                "SIP Register CSeq: " + f"{self.registerCounter.x}"
            )
            self.registerThread.start()

    def __register(self) -> bool:
        self.phone._status = PhoneStatus.REGISTERING
        first_request = self.gen_first_request()
        conn = self.send(first_request)

        response = self.__receive(conn)
        first_response = response
        conn.close()  # Regardless of the response, the dialog is over

        if response.status == ResponseCode(
            401
        ) or response.status == ResponseCode(407):
            # Unauthorized, likely due to being password protected.
            password_request = self.gen_register(response)
            conn = self.send(password_request)
            response = self.__receive(conn)
            conn.close()

        if response.status == ResponseCode(400):
            # Bad Request
            # TODO: implement
            # TODO: check if broken connection can be brought back
            # with new urn:uuid or reply with expire 0
            self._handle_bad_request()

        elif response.status == ResponseCode(500):
            # We raise so the calling function can sleep and try again
            raise RetryRequiredError("Received a 500 error when registering.")

        elif response.status == ResponseCode.OK:
            return True

        elif response.status == ResponseCode(
            401
        ) or response.status == ResponseCode(407):
            # At this point, it's reasonable to assume that
            # this is caused by invalid credentials.
            debug("=" * 50)
            debug("Unauthorized, SIP Message Log:\n")
            debug("SENT")
            debug(first_request)
            debug("\nRECEIVED")
            debug(first_response.summary())
            debug("\nSENT (DO NOT SHARE THIS PACKET)")
            debug(password_request)
            debug("\nRECEIVED")
            debug(response.summary())
            debug("=" * 50)
            raise InvalidAccountInfoError(
                f"Invalid Username or Password for SIP server {self.server}:"
                + f"{self.bind_port}"
            )

        raise Exception(f"Unable to register. Ended with {response.summary()}")

    def _handle_bad_request(self) -> None:
        # Bad Request
        # TODO: implement
        # TODO: check if broken connection can be brought back
        # with new urn:uuid or reply with expire 0
        debug("Bad Request")

    def subscribe(self, lastresponse: SIPMessage) -> None:
        # TODO: check if needed and maybe implement fully

        subRequest = self.gen_subscribe(lastresponse)
        conn = self.sendto(subRequest)

        response = SIPMessage.from_bytes(conn.recv(8192))

        debug(f'Got response to subscribe: {str(response.start_line, "utf8")}')

    def __receive(self, conn: "VoIPConnection") -> SIPResponse:
        """
        Some servers need time to process the response.
        When this happens, the first response you get from the server is
        ResponseCode.TRYING. This while loop tries checks every second for an
        updated response. It times out after 30 seconds with no response.
        """
        try:
            response = SIPMessage.from_bytes(
                conn.recv(8128, self.register_timeout)
            )
            while (
                type(response) is SIPResponse
                and response.status == ResponseCode.TRYING
                and self.NSD
            ):
                response = SIPMessage.from_bytes(
                    conn.recv(8128, self.register_timeout)
                )
                time.sleep(1)
        except TimeoutError:
            raise TimeoutError(
                f"Waited {self.register_timeout} seconds but the server is "
                + "still TRYING or has not responded."
            )
        assert type(response) is SIPResponse
        return response
