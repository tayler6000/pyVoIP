from pyVoIP import RTP
from pyVoIP.credentials import CredentialsManager
from pyVoIP.SIP.client import SIPClient
from pyVoIP.SIP.message.message import SIPMessage, SIPRequest, SIPResponse
from pyVoIP.SIP.message.response_codes import ResponseCode
from pyVoIP.networking.sock import VoIPConnection
from pyVoIP.networking.transport import TransportMode
from pyVoIP.types import KEY_PASSWORD
from pyVoIP.VoIP.call import CallState, VoIPCall
from pyVoIP.VoIP.error import (
    InvalidRangeError,
    InvalidStateError,
    NoPortsAvailableError,
)
from pyVoIP.VoIP.status import PhoneStatus
from threading import Timer, Lock
from typing import Dict, List, Optional, Type
from dataclasses import dataclass
import pyVoIP
import random
import time


__all__ = ["VoIPPhone", "VoIPPhoneParameter"]


debug = pyVoIP.debug


@dataclass
class VoIPPhoneParameter:
    server: str
    port: int
    user: str
    credentials_manager: Optional[CredentialsManager]
    bind_ip: Optional[str] = "0.0.0.0"
    bind_port: Optional[int] = 5060
    bind_network: Optional[str] = "0.0.0.0/0"
    hostname: Optional[str] = None
    remote_hostname: Optional[str] = None
    transport_mode: Optional[TransportMode] = TransportMode.UDP
    cert_file: Optional[str] = None
    key_file: Optional[str] = None
    key_password: Optional[KEY_PASSWORD] = None
    rtp_port_low: Optional[int] = 10000
    rtp_port_high: Optional[int] = 20000
    call_class: Type[VoIPCall] = None
    sip_class: Type[SIPClient] = None


class VoIPPhone:
    def __init__(self, voip_phone_parameter: VoIPPhoneParameter):
        self.voip_phone_parameter = voip_phone_parameter
        if (
            self.voip_phone_parameter.rtp_port_low
            > self.voip_phone_parameter.rtp_port_high
        ):
            raise InvalidRangeError(
                "`rtp_port_high` must be >= `rtp_port_low`"
            )
        self.call_class = (
            self.voip_phone_parameter.call_class is not None
            and self.voip_phone_parameter.call_class
            or VoIPCall
        )
        self.sip_class = (
            self.voip_phone_parameter.sip_class is not None
            and self.voip_phone_parameter.sip_class
            or SIPClient
        )
        # data defined in class
        self._status = PhoneStatus.INACTIVE
        self.NSD = False

        self.portsLock = Lock()
        self.assignedPorts: List[int] = []
        self.session_ids: List[int] = []

        self._status = PhoneStatus.INACTIVE

        # "recvonly", "sendrecv", "sendonly", "inactive"
        self.sendmode = "sendrecv"
        self.recvmode = "sendrecv"

        self.calls: Dict[str, VoIPCall] = {}
        self.threads: List[Timer] = []
        # Allows you to find call ID based off thread.
        self.threadLookup: Dict[Timer, str] = {}
        self.sip = self.sip_class(
            self.voip_phone_parameter.server,
            self.voip_phone_parameter.port,
            self.voip_phone_parameter.user,
            self.voip_phone_parameter.credentials_manager,
            phone=self,
            bind_ip=self.voip_phone_parameter.bind_ip,
            bind_network=self.voip_phone_parameter.bind_network,
            hostname=self.voip_phone_parameter.hostname,
            remote_hostname=self.voip_phone_parameter.remote_hostname,
            bind_port=self.voip_phone_parameter.bind_port,
            call_callback=self.callback,
            fatal_callback=self.fatal,
            transport_mode=self.voip_phone_parameter.transport_mode,
        )

    def callback(
        self, conn: VoIPConnection, request: SIPMessage
    ) -> Optional[str]:
        # debug("Callback: "+request.summary())
        if type(request) is SIPRequest:
            # debug("This is a message")
            if request.method == "INVITE":
                self._callback_MSG_Invite(conn, request)
            elif request.method == "BYE":
                self._callback_MSG_Bye(request)
            elif request.method == "OPTIONS":
                return self._callback_MSG_Options(request)
        elif type(request) is SIPResponse:
            if request.status == ResponseCode.OK:
                self._callback_RESP_OK(request)
            elif request.status == ResponseCode.NOT_FOUND:
                self._callback_RESP_NotFound(request)
            elif request.status == ResponseCode.SERVICE_UNAVAILABLE:
                self._callback_RESP_Unavailable(request)
            elif request.status == ResponseCode.RINGING:
                self._callback_RESP_Ringing(request)
            elif request.status == ResponseCode.SESSION_PROGRESS:
                self._callback_RESP_Progress(request)
            elif request.status == ResponseCode.BUSY_HERE:
                self._callback_RESP_Busy(request)
            elif request.status == ResponseCode.REQUEST_TERMINATED:
                self._callback_RESP_Terminated(request)
        return None

    def get_status(self) -> PhoneStatus:
        return self._status

    def _callback_MSG_Invite(
        self, conn: VoIPConnection, request: SIPMessage
    ) -> None:
        call_id = request.headers["Call-ID"]
        if self.call_class is None:
            message = self.sip.gen_busy(request)
            conn.send(message)
        else:
            debug("New call!")
            sess_id = None
            while sess_id is None:
                proposed = random.randint(1, 100000)
                if proposed not in self.session_ids:
                    self.session_ids.append(proposed)
                    sess_id = proposed
            message = self.sip.gen_ringing(request)
            conn.send(message)
            call = self._create_call(conn, request, sess_id)
            try:
                t = Timer(1, call.ringing, [request])
                t.name = f"Phone Call: {call_id}"
                t.start()
                self.threads.append(t)
                self.threadLookup[t] = call_id
            except Exception:
                message = self.sip.gen_busy(request)
                conn.send(
                    message,
                )
                raise

    def _callback_MSG_Bye(self, request: SIPMessage) -> None:
        debug("BYE recieved")
        call_id = request.headers["Call-ID"]
        if call_id not in self.calls:
            return
        self.calls[call_id].bye()

    def _callback_MSG_Options(self, request: SIPMessage) -> str:
        debug("Options recieved")
        response = self.sip.gen_busy(request)
        if self.call_class:
            response = response.replace("486 Busy Here", "200 OK")
            # TODO: Remove warning, implement RFC 3264
        return response

    def _callback_RESP_OK(self, request: SIPMessage) -> None:
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

    def _callback_RESP_Ringing(self, request: SIPMessage) -> None:
        debug("Ringing received")
        call_id = request.headers["Call-ID"]
        if call_id not in self.calls:
            debug("Unknown/No call")
            return
        self.calls[call_id].ringing(request)

    def _callback_RESP_Progress(self, request: SIPMessage) -> None:
        debug("Session progress received")
        call_id = request.headers["Call-ID"]
        if call_id not in self.calls:
            debug("Unknown/No call")
            return
        self.calls[call_id].progress(request)

    def _callback_RESP_Busy(self, request: SIPMessage) -> None:
        debug("Busy received")
        call_id = request.headers["Call-ID"]
        if call_id not in self.calls:
            debug("Unknown/No call")
            return
        self.calls[call_id].busy(request)
        ack = self.sip.gen_ack(request)
        self.sip.sendto(ack)

    def _callback_RESP_Terminated(self, request: SIPMessage) -> None:
        debug("Request terminated received")
        call_id = request.headers["Call-ID"]
        if call_id not in self.calls:
            debug("Unknown/No call")
        else:
            self.calls[call_id].bye()
        ack = self.sip.gen_ack(request)
        self.sip.sendto(ack)

    def _callback_RESP_NotFound(self, request: SIPMessage) -> None:
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

    def _callback_RESP_Unavailable(self, request: SIPMessage) -> None:
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

    def _create_call(
        self, conn: VoIPConnection, request: SIPMessage, sess_id: int
    ) -> VoIPCall:
        """
        Create VoIP call object. Should be separated to enable better
        subclassing.
        """
        call_id = request.headers["Call-ID"]
        self.calls[call_id] = self.call_class(
            self,
            CallState.RINGING,
            request,
            sess_id,
            self.voip_phone_parameter.bind_ip,
            conn=conn,
            sendmode=self.recvmode,
        )
        return self.calls[call_id]

    def start(self) -> None:
        self._status = PhoneStatus.REGISTERING
        try:
            self.sip.start()
            self.NSD = True
        except Exception:
            self._status = PhoneStatus.FAILED
            self.sip.stop()
            self.NSD = False
            raise

    def stop(self, failed=False) -> None:
        self._status = PhoneStatus.DEREGISTERING
        for x in self.calls.copy():
            try:
                self.calls[x].hangup()
            except InvalidStateError:
                pass
        self.sip.stop()
        self.NSD = False
        self._status = PhoneStatus.INACTIVE
        if failed:
            self._status = PhoneStatus.FAILED

    def fatal(self) -> None:
        self.stop(failed=True)

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
        self.calls[call_id] = self.call_class(
            self,
            CallState.DIALING,
            request,
            sess_id,
            self.voip_phone_parameter.bind_ip,
            ms=medias,
            sendmode=self.sendmode,
            conn=conn,
        )

        return self.calls[call_id]

    def message(
        self, number: str, body: str, ctype: str = "text/plain"
    ) -> bool:
        response = self.sip.message(number, body, ctype)
        return (
            type(response) is SIPResponse
            and response.status == ResponseCode.OK
        )

    def request_port(self, blocking=True) -> int:
        ports_available = [
            port
            for port in range(
                self.voip_phone_parameter.rtp_port_low,
                self.voip_phone_parameter.rtp_port_high + 1,
            )
            if port not in self.assignedPorts
        ]
        if len(ports_available) == 0:
            # If no ports are available attempt to cleanup any missed calls.
            self.release_ports()
            ports_available = [
                port
                for port in range(
                    self.voip_phone_parameter.rtp_port_low,
                    self.voip_phone_parameter.rtp_port_high + 1,
                )
                if (port not in self.assignedPorts)
            ]

        while self.NSD and blocking and len(ports_available) == 0:
            ports_available = [
                port
                for port in range(
                    self.voip_phone_parameter.rtp_port_low,
                    self.voip_phone_parameter.rtp_port_high + 1,
                )
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
        with self.portsLock:
            self._cleanup_dead_calls()

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
