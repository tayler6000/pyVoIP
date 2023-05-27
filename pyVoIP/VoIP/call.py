from enum import Enum
from pyVoIP import RTP, SIP
from pyVoIP.VoIP.error import InvalidStateError
from threading import Lock
from typing import Any, Dict, List, Optional, TYPE_CHECKING
import audioop
import io
import pyVoIP
import warnings


__all__ = [
    "CallState",
    "VoIPCall",
]


debug = pyVoIP.debug


if TYPE_CHECKING:
    from pyVoIP.VoIP.phone import VoIPPhone


class CallState(Enum):
    DIALING = "DIALING"
    RINGING = "RINGING"
    PROGRESS = "PROGRESS"
    ANSWERED = "ANSWERED"
    CANCELING = "CANCELING"
    ENDED = "ENDED"


class VoIPCall:
    def __init__(
        self,
        phone: "VoIPPhone",
        callstate: CallState,
        request: SIP.SIPMessage,
        session_id: int,
        bind_ip: str,
        ms: Optional[Dict[int, RTP.PayloadType]] = None,
        sendmode="sendonly",
    ):
        self.state = callstate
        self.phone = phone
        self.sip = self.phone.sip
        self.request = request
        self.call_id = request.headers["Call-ID"]
        self.session_id = str(session_id)
        self.bind_ip = bind_ip
        self.rtp_port_high = self.phone.rtp_port_high
        self.rtp_port_low = self.phone.rtp_port_low
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
                self.create_rtp_clients(
                    codecs, self.bind_ip, port, request, i["port"]
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
                dtmf=self.dtmf_callback,
            )
            self.RTPClients.append(c)

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

    def get_dtmf(self, length=1) -> str:
        self.dtmfLock.acquire()
        packet = self.dtmf.read(length)
        self.dtmfLock.release()
        return packet

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
            m[x.in_port] = x.assoc

        return m

    def renegotiate(self, request: SIP.SIPMessage) -> None:
        m = self.gen_ms()
        message = self.sip.gen_answer(
            request, self.session_id, m, self.sendmode
        )
        self.sip.sendto(message, self.request.headers["Via"][0]["address"])
        for i in request.body["m"]:
            for ii, client in zip(
                range(len(request.body["c"])), self.RTPClients
            ):
                client.out_ip = request.body["c"][ii]["address"]
                client.out_port = i["port"] + ii  # TODO: Check IPv4/IPv6

    def answer(self) -> None:
        if self.state != CallState.RINGING:
            raise InvalidStateError("Call is not ringing")
        m = self.gen_ms()
        message = self.sip.gen_answer(
            self.request, self.session_id, m, self.sendmode
        )
        self.sip.sendto(message, self.request.headers["Via"][0]["address"])
        self.state = CallState.ANSWERED

    def rtp_answered(self, request: SIP.SIPMessage) -> None:
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

            self.create_rtp_clients(
                assoc, self.bind_ip, self.port, request, i["port"]
            )

        for x in self.RTPClients:
            x.start()
        self.request.headers["Contact"] = request.headers["Contact"]
        self.request.headers["To"]["tag"] = request.headers["To"]["tag"]

    def answered(self, request: SIP.SIPMessage) -> None:
        if self.state == CallState.DIALING:
            self.rtp_answered(request)
        elif self.state != CallState.PROGRESS:
            return
        self.state = CallState.ANSWERED

    def progress(self, request: SIP.SIPMessage) -> None:
        if self.state != CallState.DIALING:
            return
        self.request = request
        self.rtp_answered(request)
        self.state = CallState.PROGRESS

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

    def ringing(self, request: SIP.SIPMessage) -> None:
        if self.state == CallState.RINGING:
            self.deny()
        else:
            self.request = request

    def busy(self, request: SIP.SIPMessage) -> None:
        self.bye()

    def deny(self) -> None:
        if self.state != CallState.RINGING:
            raise InvalidStateError("Call is not ringing")
        message = self.sip.gen_busy(self.request)
        self.sip.sendto(message, self.request.headers["Via"][0]["address"])
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

    def cancel(self) -> None:
        if (
            self.state != CallState.DIALING
            and self.state != CallState.PROGRESS
        ):
            raise InvalidStateError("Call is not dialing or in progress")
        for x in self.RTPClients:
            x.stop()
        self.sip.cancel(self.request)
        self.state = CallState.CANCELING

    def bye(self) -> None:
        if (
            self.state == CallState.ANSWERED
            or self.state == CallState.PROGRESS
            or self.state == CallState.CANCELING
        ):
            for x in self.RTPClients:
                x.stop()
            self.state = CallState.ENDED
        if self.request.headers["Call-ID"] in self.phone.calls:
            del self.phone.calls[self.request.headers["Call-ID"]]

    def write_audio(self, data: bytes) -> None:
        for x in self.RTPClients:
            x.write(data)

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
