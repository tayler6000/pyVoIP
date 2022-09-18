from enum import Enum
from pyVoIP import SIP, RTP
from threading import Timer, Lock
from typing import Any, Callable, Dict, List, Optional
import audioop
import io
import pyVoIP
import random
import time
import warnings


__all__ = [
    "CallState",
    "InvalidRangeError",
    "InvalidStateError",
    "NoPortsAvailableError",
    "VoIPCall",
    "VoIPPhone",
]

debug = pyVoIP.debug


class InvalidRangeError(Exception):
    pass


class InvalidStateError(Exception):
    pass


class NoPortsAvailableError(Exception):
    pass


class CallState(Enum):
    DIALING = "DIALING"
    RINGING = "RINGING"
    ANSWERED = "ANSWERED"
    ENDED = "ENDED"


class PhoneStatus(Enum):
    INACTIVE = "INACTIVE"
    REGISTERING = "REGISTERING"
    REGISTERED = "REGISTERED"
    DEREGISTERING = "DEREGISTERING"
    FAILED = "FAILED"


class VoIPCall:
    def __init__(
        self,
        phone: "VoIPPhone",
        callstate: CallState,
        request: SIP.SIPMessage,
        session_id: int,
        myIP: str,
        ms: Optional[Dict[int, RTP.PayloadType]] = None,
        sendmode="sendonly",
    ):
        self.state = callstate
        self.phone = phone
        self.sip = self.phone.sip
        self.request = request
        self.call_id = request.headers["Call-ID"]
        self.session_id = str(session_id)
        self.myIP = myIP
        self.rtpPortHigh = self.phone.rtpPortHigh
        self.rtpPortLow = self.phone.rtpPortLow
        self.sendmode = sendmode

        self.dtmfLock = Lock()
        self.dtmf = io.StringIO()

        self.RTPClients: List[RTP.RTPClient] = []

        self.connections = 0
        self.audioPorts = 0
        self.videoPorts = 0

        # Type checker being weird with this variable.
        # Appears to be because this variable is used differently depending
        # on whether we received or originated the call.
        # Will need to refactor the code later to properly type this.
        self.assignedPorts: Any = {}

        if callstate == CallState.RINGING:
            audio = []
            video = []
            for x in self.request.body["c"]:
                self.connections += x["address_count"]
            for x in self.request.body["m"]:
                if x["type"] == "audio":
                    self.audioPorts += x["port_count"]
                    audio.append(x)
                elif x["type"] == "video":
                    self.videoPorts += x["port_count"]
                    video.append(x)
                else:
                    warnings.warn(
                        f"Unknown media description: {x['type']}", stacklevel=2
                    )

            # Ports Adjusted is used in case of multiple m tags.
            if len(audio) > 0:
                audioPortsAdj = self.audioPorts / len(audio)
            else:
                audioPortsAdj = 0
            if len(video) > 0:
                videoPortsAdj = self.videoPorts / len(video)
            else:
                videoPortsAdj = 0

            if not (
                (audioPortsAdj == self.connections or self.audioPorts == 0)
                and (videoPortsAdj == self.connections or self.videoPorts == 0)
            ):
                # TODO: Throw error to PBX in this case
                warnings.warn("Unable to assign ports for RTP.", stacklevel=2)
                return

            for i in request.body["m"]:
                assoc = {}
                e = False
                for x in i["methods"]:
                    try:
                        p = RTP.PayloadType(int(x))
                        assoc[int(x)] = p
                    except ValueError:
                        try:
                            p = RTP.PayloadType(
                                i["attributes"][x]["rtpmap"]["name"]
                            )
                            assoc[int(x)] = p
                        except ValueError:
                            # Sometimes rtpmap raise a KeyError because fmtp
                            # is set instate
                            pt = i["attributes"][x]["rtpmap"]["name"]
                            warnings.warn(
                                f"RTP Payload type {pt} not found.",
                                stacklevel=20,
                            )
                            # Resets the warning filter so this warning will
                            # come up again if it happens.  However, this
                            # also resets all other warnings.
                            warnings.simplefilter("default")
                            p = RTP.PayloadType("UNKNOWN")
                            assoc[int(x)] = p
                        except KeyError:
                            # fix issue 42
                            # When rtpmap is not found, also set the found
                            # element to UNKNOWN
                            warnings.warn(
                                f"RTP KeyError {x} not found.", stacklevel=20
                            )
                            p = RTP.PayloadType("UNKNOWN")
                            assoc[int(x)] = p

                if e:
                    raise RTP.RTPParseError(
                        f"RTP Payload type {pt} not found."
                    )

                # Make sure codecs are compatible.
                codecs = {}
                for m in assoc:
                    if assoc[m] in pyVoIP.RTPCompatibleCodecs:
                        codecs[m] = assoc[m]
                # TODO: If no codecs are compatible then send error to PBX.

                port = self.phone.request_port()
                self.createRTPClients(
                    codecs, self.myIP, port, request, i["port"]
                )
        elif callstate == CallState.DIALING:
            if ms is None:
                raise RuntimeError(
                    "Media assignments are required when "
                    + "initiating a call"
                )
            self.ms = ms
            for m in self.ms:
                self.port = m
                self.assignedPorts[m] = self.ms[m]

    def createRTPClients(
        self,
        codecs: Dict[int, RTP.PayloadType],
        ip: str,
        port: int,
        request: SIP.SIPMessage,
        baseport: int,
    ) -> None:
        warnings.warn(
            "createRTPClients is deprecated due to PEP8 "
            + "compliance. Use create_rtp_clients instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.create_rtp_clients(codecs, ip, port, request, baseport)

    def create_rtp_clients(
        self,
        codecs: Dict[int, RTP.PayloadType],
        ip: str,
        port: int,
        request: SIP.SIPMessage,
        baseport: int,
    ) -> None:
        for ii in range(len(request.body["c"])):
            # TODO: Check IPv4/IPv6
            c = RTP.RTPClient(
                codecs,
                ip,
                port,
                request.body["c"][ii]["address"],
                baseport + ii,
                self.sendmode,
                dtmf=self.dtmfCallback,
            )
            self.RTPClients.append(c)

    def dtmfCallback(self, code: str) -> None:
        warnings.warn(
            "dtmfCallback is deprecated due to PEP8 compliance. "
            + "Use dtmf_callback instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.dtmf_callback(code)

    def __del__(self):
        if hasattr(self, "phone"):
            self.phone.release_ports(call=self)

    def dtmf_callback(self, code: str) -> None:
        self.dtmfLock.acquire()
        bufferloc = self.dtmf.tell()
        self.dtmf.seek(0, 2)
        self.dtmf.write(code)
        self.dtmf.seek(bufferloc, 0)
        self.dtmfLock.release()

    def getDTMF(self, length=1) -> str:
        warnings.warn(
            "getDTMF is deprecated due to PEP8 compliance. "
            + "Use get_dtmf instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.get_dtmf(length)

    def get_dtmf(self, length=1) -> str:
        self.dtmfLock.acquire()
        packet = self.dtmf.read(length)
        self.dtmfLock.release()
        return packet

    def genMs(self) -> Dict[int, Dict[int, RTP.PayloadType]]:
        warnings.warn(
            "genMs is deprecated due to PEP8 compliance. "
            + "Use gen_ms instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.gen_ms()

    def gen_ms(self) -> Dict[int, Dict[int, RTP.PayloadType]]:
        """
        Generate m SDP attribute for answering originally and
        for re-negotiations.
        """
        # TODO: this seems "dangerous" if for some reason sip server handles 2
        # and more bindings it will cause duplicate RTP-Clients to spawn.
        m = {}
        for x in self.RTPClients:
            x.start()
            m[x.inPort] = x.assoc

        return m

    def renegotiate(self, request: SIP.SIPMessage) -> None:
        m = self.genMs()
        message = self.sip.genAnswer(
            request, self.session_id, m, self.sendmode
        )
        self.sip.out.sendto(
            message.encode("utf8"), (self.phone.server, self.phone.port)
        )
        for i in request.body["m"]:
            for ii, client in zip(
                range(len(request.body["c"])), self.RTPClients
            ):
                client.outIP = request.body["c"][ii]["address"]
                client.outPort = i["port"] + ii  # TODO: Check IPv4/IPv6

    def answer(self) -> None:
        if self.state != CallState.RINGING:
            raise InvalidStateError("Call is not ringing")
        m = self.genMs()
        message = self.sip.genAnswer(
            self.request, self.session_id, m, self.sendmode
        )
        self.sip.out.sendto(
            message.encode("utf8"), (self.phone.server, self.phone.port)
        )
        self.state = CallState.ANSWERED

    def answered(self, request: SIP.SIPMessage) -> None:
        if self.state != CallState.DIALING:
            return

        for i in request.body["m"]:
            assoc = {}
            e = False
            for x in i["methods"]:
                try:
                    p = RTP.PayloadType(int(x))
                    assoc[int(x)] = p
                except ValueError:
                    try:
                        p = RTP.PayloadType(
                            i["attributes"][x]["rtpmap"]["name"]
                        )
                        assoc[int(x)] = p
                    except ValueError:
                        e = True

            if e:
                raise RTP.RTPParseError(f"RTP Payload type {p} not found.")

            self.createRTPClients(
                assoc, self.myIP, self.port, request, i["port"]
            )

        for x in self.RTPClients:
            x.start()
        self.request.headers["Contact"] = request.headers["Contact"]
        self.request.headers["To"]["tag"] = request.headers["To"]["tag"]
        self.state = CallState.ANSWERED

    def notFound(self, request: SIP.SIPMessage) -> None:
        warnings.warn(
            "notFound is deprecated due to PEP8 compliance. "
            + "Use not_found instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.not_found(request)

    def not_found(self, request: SIP.SIPMessage) -> None:
        if self.state != CallState.DIALING:
            debug(
                "TODO: 500 Error, received a not found response for a "
                + f"call not in the dailing state.  Call: {self.call_id}, "
                + f"Call State: {self.state}"
            )
            return

        for x in self.RTPClients:
            x.stop()
        self.state = CallState.ENDED
        del self.phone.calls[self.request.headers["Call-ID"]]
        debug("Call not found and terminated")
        warnings.warn(
            f"The number '{request.headers['To']['number']}' "
            + "was not found.  Did you call the wrong number?  "
            + "CallState set to CallState.ENDED.",
            stacklevel=20,
        )
        # Resets the warning filter so this warning will
        # come up again if it happens.  However, this
        # also resets all other warnings.
        warnings.simplefilter("default")

    def unavailable(self, request: SIP.SIPMessage) -> None:
        if self.state != CallState.DIALING:
            debug(
                "TODO: 500 Error, received an unavailable response for a "
                + f"call not in the dailing state.  Call: {self.call_id}, "
                + f"Call State: {self.state}"
            )
            return

        for x in self.RTPClients:
            x.stop()
        self.state = CallState.ENDED
        del self.phone.calls[self.request.headers["Call-ID"]]
        debug("Call unavailable and terminated")
        warnings.warn(
            f"The number '{request.headers['To']['number']}' "
            + "was unavailable.  CallState set to CallState.ENDED.",
            stacklevel=20,
        )
        # Resets the warning filter so this warning will
        # come up again if it happens.  However, this
        # also resets all other warnings.
        warnings.simplefilter("default")

    def deny(self) -> None:
        if self.state != CallState.RINGING:
            raise InvalidStateError("Call is not ringing")
        message = self.sip.genBusy(self.request)
        self.sip.out.sendto(
            message.encode("utf8"), (self.phone.server, self.phone.port)
        )
        for x in self.RTPClients:
            x.stop()
        self.state = CallState.ENDED
        del self.phone.calls[self.request.headers["Call-ID"]]

    def hangup(self) -> None:
        if self.state != CallState.ANSWERED:
            raise InvalidStateError("Call is not answered")
        for x in self.RTPClients:
            x.stop()
        self.sip.bye(self.request)
        self.state = CallState.ENDED
        if self.request.headers["Call-ID"] in self.phone.calls:
            del self.phone.calls[self.request.headers["Call-ID"]]

    def bye(self) -> None:
        if self.state == CallState.ANSWERED:
            for x in self.RTPClients:
                x.stop()
            self.state = CallState.ENDED
        if self.request.headers["Call-ID"] in self.phone.calls:
            del self.phone.calls[self.request.headers["Call-ID"]]

    def writeAudio(self, data: bytes) -> None:
        warnings.warn(
            "writeAudio is deprecated due to PEP8 compliance. "
            + "Use write_audio instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.write_audio(data)

    def write_audio(self, data: bytes) -> None:
        for x in self.RTPClients:
            x.write(data)

    def readAudio(self, length=160, blocking=True) -> bytes:
        warnings.warn(
            "readAudio is deprecated due to PEP8 compliance. "
            + "Use read_audio instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.read_audio(length, blocking)

    def read_audio(self, length=160, blocking=True) -> bytes:
        if len(self.RTPClients) == 1:
            return self.RTPClients[0].read(length, blocking)
        data = []
        for x in self.RTPClients:
            data.append(x.read(length))
        # Mix audio from different sources before returning
        nd = audioop.add(data.pop(0), data.pop(0), 1)
        for d in data:
            nd = audioop.add(nd, d, 1)
        return nd


class VoIPPhone:
    def __init__(
        self,
        server: str,
        port: int,
        username: str,
        password: str,
        myIP="0.0.0.0",
        callCallback: Optional[Callable[["VoIPCall"], None]] = None,
        sipPort=5060,
        rtpPortLow=10000,
        rtpPortHigh=20000,
    ):
        if rtpPortLow > rtpPortHigh:
            raise InvalidRangeError("'rtpPortHigh' must be >= 'rtpPortLow'")

        self.rtpPortLow = rtpPortLow
        self.rtpPortHigh = rtpPortHigh
        self.NSD = False

        self.portsLock = Lock()
        self.assignedPorts: List[int] = []
        self.session_ids: List[int] = []

        self.server = server
        self.port = port
        self.myIP = myIP
        self.username = username
        self.password = password
        self.callCallback = callCallback
        self._status = PhoneStatus.INACTIVE

        # "recvonly", "sendrecv", "sendonly", "inactive"
        self.sendmode = "sendrecv"
        self.recvmode = "sendrecv"

        self.calls: Dict[str, VoIPCall] = {}
        self.threads: List[Timer] = []
        # Allows you to find call ID based off thread.
        self.threadLookup: Dict[Timer, str] = {}
        self.sip = SIP.SIPClient(
            server,
            port,
            username,
            password,
            myIP=self.myIP,
            myPort=sipPort,
            callCallback=self.callback,
        )

    def callback(self, request: SIP.SIPMessage) -> None:
        # debug("Callback: "+request.summary())
        if request.type == pyVoIP.SIP.SIPMessageType.MESSAGE:
            # debug("This is a message")
            if request.method == "INVITE":
                self._callback_MSG_Invite(request)
            elif request.method == "BYE":
                self._callback_MSG_Bye(request)
        else:
            if request.status == SIP.SIPStatus.OK:
                self._callback_RESP_OK(request)
            elif request.status == SIP.SIPStatus.NOT_FOUND:
                self._callback_RESP_NotFound(request)
            elif request.status == SIP.SIPStatus.SERVICE_UNAVAILABLE:
                self._callback_RESP_Unavailable(request)

    def getStatus(self) -> PhoneStatus:
        warnings.warn(
            "getStatus is deprecated due to PEP8 compliance. "
            + "Use get_status instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.get_status()

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
        if self.callCallback is None:
            message = self.sip.genBusy(request)
            self.sip.out.sendto(
                message.encode("utf8"), (self.server, self.port)
            )
        else:
            debug("New call!")
            sess_id = None
            while sess_id is None:
                proposed = random.randint(1, 100000)
                if proposed not in self.session_ids:
                    self.session_ids.append(proposed)
                    sess_id = proposed
            message = self.sip.genRinging(request)
            self.sip.out.sendto(
                message.encode("utf8"), (self.server, self.port)
            )
            self._create_Call(request, sess_id)
            try:
                t = Timer(1, self.callCallback, [self.calls[call_id]])
                t.name = f"Phone Call: {call_id}"
                t.start()
                self.threads.append(t)
                self.threadLookup[t] = call_id
            except Exception:
                message = self.sip.genBusy(request)
                self.sip.out.sendto(
                    message.encode("utf8"), (self.server, self.port)
                )
                raise

    def _callback_MSG_Bye(self, request: SIP.SIPMessage) -> None:
        debug("BYE recieved")
        call_id = request.headers["Call-ID"]
        if call_id not in self.calls:
            return
        self.calls[call_id].bye()

    def _callback_RESP_OK(self, request: SIP.SIPMessage) -> None:
        debug("OK recieved")
        call_id = request.headers["Call-ID"]
        if call_id not in self.calls:
            debug("Unknown/No call")
            return
        # TODO: Somehow never is reached. Find out if you have a network
        # issue here or your invite is wrong.
        self.calls[call_id].answered(request)
        debug("Answered")
        ack = self.sip.genAck(request)
        self.sip.out.sendto(ack.encode("utf8"), (self.server, self.port))

    def _callback_RESP_NotFound(self, request: SIP.SIPMessage) -> None:
        debug("Not Found recieved, invalid number called?")
        call_id = request.headers["Call-ID"]
        if call_id not in self.calls:
            debug("Unknown/No call")
            debug(
                "TODO: Add 481 here as server is probably waiting for "
                + "an ACK"
            )
        self.calls[call_id].notFound(request)
        debug("Terminating Call")
        ack = self.sip.genAck(request)
        self.sip.out.sendto(ack.encode("utf8"), (self.server, self.port))

    def _callback_RESP_Unavailable(self, request: SIP.SIPMessage) -> None:
        debug("Service Unavailable recieved")
        call_id = request.headers["Call-ID"]
        if call_id not in self.calls:
            debug("Unkown call")
            debug(
                "TODO: Add 481 here as server is probably waiting for "
                + "an ACK"
            )
        self.calls[call_id].unavailable(request)
        debug("Terminating Call")
        ack = self.sip.genAck(request)
        self.sip.out.sendto(ack.encode("utf8"), (self.server, self.port))

    def _create_Call(self, request: SIP.SIPMessage, sess_id: int) -> None:
        """
        Create VoIP call object. Should be separated to enable better
        subclassing.
        """
        call_id = request.headers["Call-ID"]
        self.calls[call_id] = VoIPCall(
            self,
            CallState.RINGING,
            request,
            sess_id,
            self.myIP,
            sendmode=self.recvmode,
        )

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

    def call(self, number: str) -> VoIPCall:
        port = self.request_port()
        medias = {}
        medias[port] = {0: RTP.PayloadType.PCMU, 101: RTP.PayloadType.EVENT}
        request, call_id, sess_id = self.sip.invite(
            number, medias, RTP.TransmitType.SENDRECV
        )
        self.calls[call_id] = VoIPCall(
            self,
            CallState.DIALING,
            request,
            sess_id,
            self.myIP,
            ms=medias,
            sendmode=self.sendmode,
        )

        return self.calls[call_id]

    def request_port(self, blocking=True) -> int:
        ports_available = [
            port
            for port in range(self.rtpPortLow, self.rtpPortHigh + 1)
            if port not in self.assignedPorts
        ]
        if len(ports_available) == 0:
            # If no ports are available attempt to cleanup any missed calls.
            self.release_ports()
            ports_available = [
                port
                for port in range(self.rtpPortLow, self.rtpPortHigh + 1)
                if (port not in self.assignedPorts)
            ]

        while self.NSD and blocking and len(ports_available) == 0:
            ports_available = [
                port
                for port in range(self.rtpPortLow, self.rtpPortHigh + 1)
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
