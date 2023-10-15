from enum import Enum
from pyVoIP import SIP, RTP
from pyVoIP.credentials import CredentialsManager
from pyVoIP.sock.transport import TransportMode
from pyVoIP.types import KEY_PASSWORD
from pyVoIP.VoIP.call import CallState, VoIPCall
from pyVoIP.VoIP.error import (
    InvalidRangeError,
    InvalidStateError,
    NoPortsAvailableError,
)
from threading import Timer, Lock
from typing import Callable, Dict, List, Optional, Type
import pyVoIP
import random
import time


__all__ = [
    "PhoneStatus",
    "VoIPPhone",
]

debug = pyVoIP.debug


class PhoneStatus(Enum):
    INACTIVE = "INACTIVE"
    REGISTERING = "REGISTERING"
    REGISTERED = "REGISTERED"
    DEREGISTERING = "DEREGISTERING"
    FAILED = "FAILED"


class VoIPPhone:
    def __init__(
        self,
        server: str,
        port: int,
        user: str,
        credentials_manager: CredentialsManager,
        bind_ip="0.0.0.0",
        bind_network="0.0.0.0/0",
        hostname: Optional[str] = None,
        remote_hostname: Optional[str] = None,
        bind_port=5060,
        transport_mode=TransportMode.UDP,
        cert_file: Optional[str] = None,
        key_file: Optional[str] = None,
        key_password: KEY_PASSWORD = None,
        call_callback: Optional[Callable[["VoIPCall"], None]] = None,
        rtp_port_low=10000,
        rtp_port_high=20000,
        callClass: Type[VoIPCall] = None,
        sipClass: Type[SIP.SIPClient] = None,
    ):
        if rtp_port_low > rtp_port_high:
            raise InvalidRangeError(
                "'rtp_port_high' must be >= 'rtp_port_low'"
            )

        self.rtp_port_low = rtp_port_low
        self.rtp_port_high = rtp_port_high
        self.NSD = False

        self.callClass = callClass is not None and callClass or VoIPCall
        self.sipClass = sipClass is not None and sipClass or SIP.SIPClient

        self.portsLock = Lock()
        self.assignedPorts: List[int] = []
        self.session_ids: List[int] = []

        self.server = server
        self.port = port
        self.bind_ip = bind_ip
        self.user = user
        self.credentials_manager = credentials_manager
        self.call_callback = call_callback
        self._status = PhoneStatus.INACTIVE
        self.transport_mode = transport_mode

        # "recvonly", "sendrecv", "sendonly", "inactive"
        self.sendmode = "sendrecv"
        self.recvmode = "sendrecv"

        self.calls: Dict[str, VoIPCall] = {}
        self.threads: List[Timer] = []
        # Allows you to find call ID based off thread.
        self.threadLookup: Dict[Timer, str] = {}
        self.sip = self.sipClass(
            server,
            port,
            user,
            credentials_manager,
            bind_ip=self.bind_ip,
            bind_network=bind_network,
            hostname=hostname,
            remote_hostname=remote_hostname,
            bind_port=bind_port,
            call_callback=self.callback,
            transport_mode=self.transport_mode,
        )

    def callback(self, request: SIP.SIPMessage) -> Optional[str]:
        # debug("Callback: "+request.summary())
        if request.type == pyVoIP.SIP.SIPMessageType.REQUEST:
            # debug("This is a message")
            if request.method == "INVITE":
                self._callback_MSG_Invite(request)
            elif request.method == "BYE":
                self._callback_MSG_Bye(request)
            elif request.method == "OPTIONS":
                return self._callback_MSG_Options(request)
        else:
            if request.status == SIP.SIPStatus.OK:
                self._callback_RESP_OK(request)
            elif request.status == SIP.SIPStatus.NOT_FOUND:
                self._callback_RESP_NotFound(request)
            elif request.status == SIP.SIPStatus.SERVICE_UNAVAILABLE:
                self._callback_RESP_Unavailable(request)
            elif request.status == SIP.SIPStatus.RINGING:
                self._callback_RESP_Ringing(request)
            elif request.status == SIP.SIPStatus.SESSION_PROGRESS:
                self._callback_RESP_Progress(request)
            elif request.status == SIP.SIPStatus.BUSY_HERE:
                self._callback_RESP_Busy(request)
            elif request.status == SIP.SIPStatus.REQUEST_TERMINATED:
                self._callback_RESP_Terminated(request)
        return None  # mypy needs this for some reason.

    def get_status(self) -> PhoneStatus:
        return self._status

    def _callback_MSG_Invite(self, request: SIP.SIPMessage) -> None:
        call_id = request.headers["Call-ID"]
        if call_id in self.calls:
            debug("Re-negotiation detected!")
            # TODO: this seems "dangerous" if for some reason sip server
            # handles 2 and more bindings it will cause duplicate RTP-Clients
            # to spawn.

            # CallState.Ringing seems important here to prevent multiple
            # answering and RTP-Client spawning. Find out when renegotiation
            # is relevant.
            if self.calls[call_id].state != CallState.RINGING:
                self.calls[call_id].renegotiate(request)
            return  # Raise Error
        if self.callClass is None:
            message = self.sip.gen_busy(request)
            self.sip.sendto(message, request.headers["Via"][0]["address"])
        else:
            debug("New call!")
            sess_id = None
            while sess_id is None:
                proposed = random.randint(1, 100000)
                if proposed not in self.session_ids:
                    self.session_ids.append(proposed)
                    sess_id = proposed
            message = self.sip.gen_ringing(request)
            self.sip.sendto(message, request.headers["Via"][0]["address"])
            call = self._create_Call(request, sess_id)
            try:
                t = Timer(1, call.ringing, [request])
                t.name = f"Phone Call: {call_id}"
                t.start()
                self.threads.append(t)
                self.threadLookup[t] = call_id
            except Exception:
                message = self.sip.gen_busy(request)
                self.sip.sendto(
                    message,
                    request.headers["Via"][0]["address"],
                )
                raise

    def _callback_MSG_Bye(self, request: SIP.SIPMessage) -> None:
        debug("BYE recieved")
        call_id = request.headers["Call-ID"]
        if call_id not in self.calls:
            return
        self.calls[call_id].bye()

    def _callback_MSG_Options(self, request: SIP.SIPMessage) -> str:
        debug("Options recieved")
        response = self.sip.gen_busy(request)
        if self.callClass:
            response = response.replace("486 Busy Here", "200 OK")
            # TODO: Remove warning, implement RFC 3264
        return response

    def _callback_RESP_OK(self, request: SIP.SIPMessage) -> None:
        debug("OK received")
        call_id = request.headers["Call-ID"]
        if call_id not in self.calls:
            debug("Unknown/No call")
            return
        # TODO: Somehow never is reached. Find out if you have a network
        # issue here or your invite is wrong.
        if request.headers["CSeq"]["method"] == "CANCEL":
            debug("Canceled")
            return
        else:
            self.calls[call_id].answered(request)
            debug("Answered")
        ack = self.sip.gen_ack(request)
        self.sip.sendto(
            ack,
            (
                request.headers["Contact"]["host"],
                request.headers["Contact"]["port"],
            ),
        )

    def _callback_RESP_Ringing(self, request: SIP.SIPMessage) -> None:
        debug("Ringing received")
        call_id = request.headers["Call-ID"]
        if call_id not in self.calls:
            debug("Unknown/No call")
            return
        self.calls[call_id].ringing(request)

    def _callback_RESP_Progress(self, request: SIP.SIPMessage) -> None:
        debug("Session progress received")
        call_id = request.headers["Call-ID"]
        if call_id not in self.calls:
            debug("Unknown/No call")
            return
        self.calls[call_id].progress(request)

    def _callback_RESP_Busy(self, request: SIP.SIPMessage) -> None:
        debug("Busy received")
        call_id = request.headers["Call-ID"]
        if call_id not in self.calls:
            debug("Unknown/No call")
            return
        self.calls[call_id].busy(request)
        ack = self.sip.gen_ack(request)
        self.sip.sendto(ack)

    def _callback_RESP_Terminated(self, request: SIP.SIPMessage) -> None:
        debug("Request terminated received")
        call_id = request.headers["Call-ID"]
        if call_id not in self.calls:
            debug("Unknown/No call")
        else:
            self.calls[call_id].bye()
        ack = self.sip.gen_ack(request)
        self.sip.sendto(ack)

    def _callback_RESP_NotFound(self, request: SIP.SIPMessage) -> None:
        debug("Not Found recieved, invalid number called?")
        call_id = request.headers["Call-ID"]
        if call_id not in self.calls:
            debug("Unknown/No call")
            debug(
                "TODO: Add 481 here as server is probably waiting for "
                + "an ACK"
            )
        self.calls[call_id].not_found(request)
        debug("Terminating Call")
        ack = self.sip.gen_ack(request)
        self.sip.sendto(ack)

    def _callback_RESP_Unavailable(self, request: SIP.SIPMessage) -> None:
        debug("Service Unavailable recieved")
        call_id = request.headers["Call-ID"]
        if call_id not in self.calls:
            debug("Unknown call")
            debug(
                "TODO: Add 481 here as server is probably waiting for "
                + "an ACK"
            )
        self.calls[call_id].unavailable(request)
        debug("Terminating Call")
        ack = self.sip.gen_ack(request)
        self.sip.sendto(ack)

    def _create_Call(self, request: SIP.SIPMessage, sess_id: int) -> VoIPCall:
        """
        Create VoIP call object. Should be separated to enable better
        subclassing.
        """
        call_id = request.headers["Call-ID"]
        self.calls[call_id] = self.callClass(
            self,
            CallState.RINGING,
            request,
            sess_id,
            self.bind_ip,
            sendmode=self.recvmode,
        )
        return self.calls[call_id]

    def start(self) -> None:
        self._status = PhoneStatus.REGISTERING
        try:
            self.sip.start()
            self._status = PhoneStatus.REGISTERED
            self.NSD = True
        except Exception:
            self._status = PhoneStatus.FAILED
            self.sip.stop()
            self.NSD = False
            raise

    def stop(self) -> None:
        self._status = PhoneStatus.DEREGISTERING
        for x in self.calls.copy():
            try:
                self.calls[x].hangup()
            except InvalidStateError:
                pass
        self.sip.stop()
        self._status = PhoneStatus.INACTIVE

    def call(
        self,
        number: str,
        payload_types: Optional[List[RTP.PayloadType]] = None,
    ) -> VoIPCall:
        port = self.request_port()
        medias = {}
        if not payload_types:
            payload_types = [RTP.PayloadType.PCMU, RTP.PayloadType.EVENT]
        medias[port] = {}
        dynamic_int = 101
        for pt in payload_types:
            if pt not in pyVoIP.RTPCompatibleCodecs:
                raise RuntimeError(
                    "Unable to make call!\n\n"
                    + f"{pt} is not supported by pyVoIP {pyVoIP.__version__}"
                )
            try:
                medias[port][int(pt)] = pt
            except RTP.DynamicPayloadType:
                medias[port][dynamic_int] = pt
                dynamic_int += 1
        debug(f"Making call with {medias=}")
        request, call_id, sess_id, conn = self.sip.invite(
            number, medias, RTP.TransmitType.SENDRECV
        )
        self.calls[call_id] = self.callClass(
            self,
            CallState.DIALING,
            request,
            sess_id,
            self.bind_ip,
            ms=medias,
            sendmode=self.sendmode,
            conn=conn,
        )

        return self.calls[call_id]

    def message(
        self, number: str, body: str, ctype: str = "text/plain"
    ) -> bool:
        response = self.sip.message(number, body, ctype)
        return response and response.status == SIP.SIPStatus.OK

    def request_port(self, blocking=True) -> int:
        ports_available = [
            port
            for port in range(self.rtp_port_low, self.rtp_port_high + 1)
            if port not in self.assignedPorts
        ]
        if len(ports_available) == 0:
            # If no ports are available attempt to cleanup any missed calls.
            self.release_ports()
            ports_available = [
                port
                for port in range(self.rtp_port_low, self.rtp_port_high + 1)
                if (port not in self.assignedPorts)
            ]

        while self.NSD and blocking and len(ports_available) == 0:
            ports_available = [
                port
                for port in range(self.rtp_port_low, self.rtp_port_high + 1)
                if (port not in self.assignedPorts)
            ]
            time.sleep(0.5)
            self.release_ports()

            if len(ports_available) == 0:
                raise NoPortsAvailableError(
                    "No ports were available to be assigned"
                )

        selection = random.choice(ports_available)
        self.assignedPorts.append(selection)

        return selection

    def release_ports(self, call: Optional[VoIPCall] = None) -> None:
        self.portsLock.acquire()
        self._cleanup_dead_calls()
        try:
            if isinstance(call, VoIPCall):
                ports = list(call.assignedPorts.keys())
            else:
                dnr_ports = []
                for call_id in self.calls:
                    dnr_ports += list(self.calls[call_id].assignedPorts.keys())
                ports = []
                for port in self.assignedPorts:
                    if port not in dnr_ports:
                        ports.append(port)

            for port in ports:
                self.assignedPorts.remove(port)
        finally:
            self.portsLock.release()

    def _cleanup_dead_calls(self) -> None:
        to_delete = []
        for thread in self.threads:
            if not thread.is_alive():
                call_id = self.threadLookup[thread]
                try:
                    del self.calls[call_id]
                except KeyError:
                    debug("Unable to delete from calls dictionary!")
                    debug(f"call_id={call_id} calls={self.calls}")
                try:
                    del self.threadLookup[thread]
                except KeyError:
                    debug("Unable to delete from threadLookup dictionary!")
                    debug(f"thread={thread} threadLookup={self.threadLookup}")
                to_delete.append(thread)
        for thread in to_delete:
            self.threads.remove(thread)
