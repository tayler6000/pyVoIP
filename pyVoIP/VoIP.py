from enum import Enum
from pyVoIP import SIP, RTP
from threading import Timer, Lock
from typing import Any, Callable, Dict, List, Optional
import io
import inspect
import audioop
import pyVoIP
import random
import warnings

__all__ = [
            'CallState', 'InvalidRangeError', 'InvalidStateError', 'VoIPCall',
            'VoIPPhone'
          ]


debug = pyVoIP.debug


class InvalidRangeError(Exception):
    pass


class InvalidStateError(Exception):
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

    def __init__(self, phone: "VoIPPhone", callstate: CallState,
                 request: SIP.SIPMessage, session_id: int,
                 ms: Optional[Dict[int, RTP.PayloadType]] = None,
                 sendmode="sendonly"):
        debug(f"{self.__class__.__name__}.{inspect.stack()[0][3]} {callstate}, {session_id}, {ms}, {sendmode}")

        self.state = callstate
        self.phone = phone
        self.sip = self.phone.sip
        self.request = request
        self.call_id = request.headers['Call-ID']
        self.session_id = str(session_id)
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
            for x in self.request.body['c']:
                debug(f"{self.__class__.__name__}.{inspect.stack()[0][3]} connections c x = {x}")
                if x['address_type'] == 'IP4':
                    self.connections += x['address_count']
            for x in self.request.body['m']:
                debug(f"{self.__class__.__name__}.{inspect.stack()[0][3]} connections m x = {x}")
                if x['type'] == "audio":
                    self.audioPorts += x['port_count']
                    audio.append(x)
                elif x['type'] == "video":
                    self.videoPorts += x['port_count']
                    video.append(x)
                else:
                    warnings.warn(f"Unknown media description: {x['type']}",
                                  stacklevel=2)

            # Ports Adjusted is used in case of multiple m tags.
            if len(audio) > 0:
                audioPortsAdj = self.audioPorts / len(audio)
            else:
                audioPortsAdj = 0
            if len(video) > 0:
                videoPortsAdj = self.videoPorts / len(video)
            else:
                videoPortsAdj = 0

            debug(f"{self.__class__.__name__}.{inspect.stack()[0][3]} ({audioPortsAdj} == {self.connections} "
                  f"or {self.audioPorts} == 0) and ({videoPortsAdj} == {self.connections} or {self.videoPorts} == 0)")
            if not ((audioPortsAdj == self.connections or
                    self.audioPorts == 0) and
                    (videoPortsAdj == self.connections or
                    self.videoPorts == 0)):
                # TODO: Throw error to PBX in this case
                warnings.warn("Unable to assign ports for RTP.", stacklevel=2)
                return

            for i in request.body['m']:
                assoc = {}
                e = False
                for x in i['methods']:
                    try:
                        p = RTP.PayloadType(int(x))
                        assoc[int(x)] = p
                    except ValueError:
                        try:
                            p = RTP.PayloadType(
                                i['attributes'][x]['rtpmap']['name'])
                            assoc[int(x)] = p
                        except ValueError:
                            # sometimes rtpmap raise a KeyError because fmtp is set instate
                            pt = i['attributes'][x]['rtpmap']['name']
                            warnings.warn(f"RTP Payload type {pt} not found.",
                                          stacklevel=20)
                            # Resets the warning filter so this warning will
                            # come up again if it happens.  However, this
                            # also resets all other warnings.
                            warnings.simplefilter("default")
                            p = RTP.PayloadType("UNKNOWN")
                            assoc[int(x)] = p
                        except KeyError:
                            # When rtpmap is not found, also set the found
                            # element to UNKNOWN
                            warnings.warn(f"RTP KeyError {x} not found.", stacklevel=20)
                            p = RTP.PayloadType("UNKNOWN")
                            assoc[int(x)] = p

                if e:
                    raise RTP.RTPParseError(f"RTP Payload type {pt} not " +
                                            "found.")

                # Make sure codecs are compatible.
                codecs = {}
                for m in assoc:
                    if assoc[m] in pyVoIP.RTPCompatibleCodecs:
                        codecs[m] = assoc[m]
                # TODO: If no codecs are compatible then send error to PBX.

                port = None
                while port is Non
                    proposed = random.randint(self.phone.rtpPortLow,
                                              self.phone.rtpPortHigh)
                    if proposed not in self.phone.assignedPorts:
                        self.phone.assignedPorts.append(proposed)
                        self.assignedPorts[proposed] = codecs
                        port = proposed
                self.create_rtp_clients(codecs, self.phone.myIP, port, request,
                                        i['port'])
        elif callstate == CallState.DIALING:
            if ms is None:
                raise RuntimeError("Media assignments are required when " +
                                   "initiating a call")
            self.ms = ms
            for m in self.ms:
                self.port = m
                self.assignedPorts[m] = self.ms[m]

    def create_rtp_clients(self, codecs: Dict[int, RTP.PayloadType], ip: str,
                         port: int, request: SIP.SIPMessage,
                         baseport: int) -> None:
        debug(f'{self.__class__.__name__}.{inspect.stack()[0][3]} start')
        for ii in range(len(request.body['c'])):
            if request.body['c'][ii]['address_type'] == 'IP4':
                # TODO: Check IPv4/IPv6
                c = RTP.RTPClient(codecs, ip, port,
                                  request.body['c'][ii]['address'], baseport + ii,
                                  self.sendmode, dtmf=self.dtmf_callback)
                self.RTPClients.append(c)

    def dtmf_callback(self, code: str) -> None:
        debug(f'{self.__class__.__name__}.{inspect.stack()[0][3]} start')
        self.dtmfLock.acquire()
        bufferloc = self.dtmf.tell()
        self.dtmf.seek(0, 2)
        self.dtmf.write(code)
        self.dtmf.seek(bufferloc, 0)
        self.dtmfLock.release()

    def get_dtmf(self, length=1) -> str:
        debug(f'{self.__class__.__name__}.{inspect.stack()[0][3]} start')
        self.dtmfLock.acquire()
        packet = self.dtmf.read(length)
        self.dtmfLock.release()
        return packet

    def gen_ms(self) -> Dict[int, Dict[int, RTP.PayloadType]]:
        """
        Generate m SDP attribute for answering originally and
        for re-negotiations.
        """
        debug(f'{self.__class__.__name__}.{inspect.stack()[0][3]} start')
        # TODO: this seems "dangerous" if for some reason sip server handles 2 and
        #  more bindings it will cause duplicate RTP-Clients to spawn
        # The problem is in create_rtp_clients. This methode can create two or more
        # RTP Clients for the same connection
        m = {}
        for x in self.RTPClients:
            x.start()
            m[x.inPort] = x.assoc

        return m

    def renegotiate(self, request: SIP.SIPMessage) -> None:
        debug(f'{self.__class__.__name__}.{inspect.stack()[0][3]} start')
        m = self.gen_ms()
        message = self.sip.gen_answer(request, self.session_id, m,
                                      self.sendmode)
        self.sip.send_message(message)
        for i in request.body['m']:
            for ii, client in zip(range(len(request.body['c'])),
                                  self.RTPClients):
                debug(f'{self.__class__.__name__}.{inspect.stack()[0][3]} client 1 outIP '
                      f'{client.outIP} outPort {client.outPort}')
                client.outIP = request.body['c'][ii]['address']
                # TODO: Check IPv4/IPv6
                client.outPort = i['port'] + ii
                debug(f'{self.__class__.__name__}.{inspect.stack()[0][3]} client 2 outIP '
                      f'{client.outIP} outPort {client.outPort}')

    def answer(self) -> None:
        debug(f'{self.__class__.__name__}.{inspect.stack()[0][3]} start')
        if self.state != CallState.RINGING:
            raise InvalidStateError("Call is not ringing")
        m = self.gen_ms()
        message = self.sip.gen_answer(self.request, self.session_id, m,
                                      self.sendmode)
        self.sip.send_message(message)
        self.state = CallState.ANSWERED

    def answered(self, request: SIP.SIPMessage) -> None:
        debug(f'{self.__class__.__name__}.{inspect.stack()[0][3]} start')
        if self.state != CallState.DIALING:
            return

        for i in request.body['m']:
            assoc = {}
            e = False
            for x in i['methods']:
                try:
                    p = RTP.PayloadType(int(x))
                    assoc[int(x)] = p
                except ValueError:
                    try:
                        p = RTP.PayloadType(
                                i['attributes'][x]['rtpmap']['name']
                            )
                        assoc[int(x)] = p
                    except ValueError:
                        e = True

            if e:
                raise RTP.RTPParseError(f"RTP Payload type {p} not found.")

            self.create_rtp_clients(assoc, self.sip.get_my_ip(),
                                    self.sip.get_my_port(), request,
                                    i['port'])

        for x in self.RTPClients:
            x.start()
        self.request.headers['Contact'] = request.headers['Contact']
        self.request.headers['To']['tag'] = request.headers['To']['tag']
        self.state = CallState.ANSWERED

    def not_found(self, request: SIP.SIPMessage) -> None:
        debug(f'{self.__class__.__name__}.{inspect.stack()[0][3]} start')
        if self.state != CallState.DIALING:
            debug("TODO: 500 Error, received a not found response for a " +
                  f"call not in the dailing state.  Call: {self.call_id}, " +
                  f"Call State: {self.state}")
            return

        for x in self.RTPClients:
            x.stop()
        self.state = CallState.ENDED
        del self.phone.calls[self.request.headers['Call-ID']]
        debug("Call not found and terminated")
        warnings.warn(f"The number '{request.headers['To']['number']}' " +
                      "was not found.  Did you call the wrong number?  " +
                      "CallState set to CallState.ENDED.", stacklevel=20)
        # Resets the warning filter so this warning will
        # come up again if it happens.  However, this
        # also resets all other warnings.
        warnings.simplefilter("default")

    def unavailable(self, request: SIP.SIPMessage) -> None:
        debug(f'{self.__class__.__name__}.{inspect.stack()[0][3]} start')
        if self.state != CallState.DIALING:
            debug("TODO: 500 Error, received an unavailable response for a " +
                  f"call not in the dailing state.  Call: {self.call_id}, " +
                  f"Call State: {self.state}")
            return

        for x in self.RTPClients:
            x.stop()
        self.state = CallState.ENDED
        del self.phone.calls[self.request.headers['Call-ID']]
        debug("Call unavailable and terminated")
        warnings.warn(f"The number '{request.headers['To']['number']}' " +
                      "was unavailable.  CallState set to CallState.ENDED.",
                      stacklevel=20)
        # Resets the warning filter so this warning will
        # come up again if it happens.  However, this
        # also resets all other warnings.
        warnings.simplefilter("default")

    def deny(self) -> None:
        debug(f'{self.__class__.__name__}.{inspect.stack()[0][3]} start')
        if self.state != CallState.RINGING:
            raise InvalidStateError("Call is not ringing")
        message = self.sip.gen_busy(self.request)
        self.sip.send_message(message)
        self.RTPClients = []
        self.state = CallState.ENDED

    def hangup(self) -> None:
        debug(f'{self.__class__.__name__}.{inspect.stack()[0][3]} start')
        if self.state != CallState.ANSWERED:
            raise InvalidStateError("Call is not answered")
        for x in self.RTPClients:
            x.stop()
        self.sip.bye(self.request)
        self.state = CallState.ENDED
        if self.request.headers['Call-ID'] in self.phone.calls:
            del self.phone.calls[self.request.headers['Call-ID']]

    def bye(self) -> None:
        debug(f'{self.__class__.__name__}.{inspect.stack()[0][3]} start')
        if self.state == CallState.ANSWERED:
            for x in self.RTPClients:
                x.stop()
            self.state = CallState.ENDED
        if self.request.headers['Call-ID'] in self.phone.calls:
            del self.phone.calls[self.request.headers['Call-ID']]
            
    def write_audio(self, data: bytes) -> None:
        debug(f'{self.__class__.__name__}.{inspect.stack()[0][3]} start')
        for x in self.RTPClients:
            x.write(data)

    def read_audio(self, length=160, blocking=True) -> bytes:
        debug(f'{self.__class__.__name__}.{inspect.stack()[0][3]} start')
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

    def __init__(self, server: str, port: int, username: str, password: str,
                 myIP="0.0.0.0", proxy=None,
                 callCallback: Optional[Callable[['VoIPCall'], None]] = None,
                 sipPort=5060, rtpPortLow=10000, rtpPortHigh=20000):
        if rtpPortLow > rtpPortHigh:
            raise InvalidRangeError("'rtpPortHigh' must be >= 'rtpPortLow'")

        self.rtpPortLow = rtpPortLow
        self.rtpPortHigh = rtpPortHigh

        self.assignedPorts: List[int] = []
        self.session_ids: List[int] = []

        self.server = server
        self.proxy = proxy
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
        self.sip = SIP.SIPClient(server, port, username, password,
                                 myIP=self.myIP, proxy=self.proxy,
                                 myPort=sipPort,
                                 callCallback=self.callback)

    def callback(self, request: SIP.SIPMessage) -> None:
        debug(f'{self.__class__.__name__}.{inspect.stack()[0][3]} start')
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

    def get_status(self) -> PhoneStatus:
        debug(f'{self.__class__.__name__}.{inspect.stack()[0][3]} start')
        return self._status

    def _callback_MSG_Invite(self, request: SIP.SIPMessage) -> None:
        debug(f'{self.__class__.__name__}.{inspect.stack()[0][3]} start')
        call_id = request.headers['Call-ID']
        if call_id in self.calls:
            debug(f'{self.__class__.__name__} Re-negotiation detected! call state {self.calls[call_id].state}')
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
            message = self.sip.gen_busy(request)
            self.sip.send_message(message)
        else:
            debug(f"{self.__class__.__name__}.{inspect.stack()[0][3]} New call!")
            sess_id = None
            while sess_id is None:
                proposed = random.randint(1, 100000)
                if proposed not in self.session_ids:
                    self.session_ids.append(proposed)
                    sess_id = proposed
            message = self.sip.gen_ringing(request)
            self.sip.send_message(message)
            self._create_Call(request, sess_id)
            try:
                t = Timer(1, self.callCallback, [self.calls[call_id]])
                t.name = f"Phone Call: {call_id}"
                t.start()
            except Exception:
                message = self.sip.gen_busy(request)
                self.sip.send_message(message)
                raise

    def _callback_MSG_Bye(self, request: SIP.SIPMessage) -> None:
        debug(f'{self.__class__.__name__}.{inspect.stack()[0][3]} start BYE recieved')
        call_id = request.headers['Call-ID']
        if call_id not in self.calls:
            return
        self.calls[call_id].bye()

    def _callback_RESP_OK(self, request: SIP.SIPMessage) -> None:
        debug(f'{self.__class__.__name__}.{inspect.stack()[0][3]} start')
        call_id = request.headers['Call-ID']
        if call_id not in self.calls:
            debug(f'{self.__class__.__name__}.{inspect.stack()[0][3]} Unknown/No call')
            return
        # TODO: Somehow never is reached. Find out if you have a network
        # issue here or your invite is wrong.
        self.calls[call_id].answered(request)
        debug("Answered")
        ack = self.sip.gen_ack(request)
        self.sip.send_message(ack)

    def _callback_RESP_NotFound(self, request: SIP.SIPMessage) -> None:
        debug(f'{self.__class__.__name__}.{inspect.stack()[0][3]} start '
              f'-- Not Found received, invalid number called?')
        call_id = request.headers['Call-ID']
        if call_id not in self.calls:
            debug(f'{self.__class__.__name__}.{inspect.stack()[0][3]} Unknown/No call\n'
                  f'TODO: Add 481 here as server is probably waiting for an ACK')
        self.calls[call_id].notFound(request)
        debug("Terminating Call")
        ack = self.sip.gen_ack(request)
        self.sip.send_message(ack)

    def _callback_RESP_Unavailable(self, request: SIP.SIPMessage) -> None:
        debug(f'{self.__class__.__name__}.{inspect.stack()[0][3]} start '
              f'-- Service Unavailable received')
        call_id = request.headers['Call-ID']
        if call_id not in self.calls:
            debug(f"{self.__class__.__name__}.{inspect.stack()[0][3]} Unknown call")
            debug(f"{self.__class__.__name__}.{inspect.stack()[0][3]} TODO: Add 481 here as server "
                  f"is probably waiting for an ACK")
        self.calls[call_id].unavailable(request)
        debug("Terminating Call")
        ack = self.sip.gen_ack(request)
        self.sip.send_message(ack)

    def _create_Call(self, request: SIP.SIPMessage, sess_id: int) -> None:
        '''
        Create VoIP call object. Should be separated to enable better
        subclassing.
        '''
        debug(f'{self.__class__.__name__}.{inspect.stack()[0][3]} start')
        call_id = request.headers['Call-ID']
        self.calls[call_id] = VoIPCall(self, CallState.RINGING, request, sess_id, sendmode=self.recvmode)

    def start(self) -> None:
        debug(f'{self.__class__.__name__}.{inspect.stack()[0][3]} called from start')
        self._status = PhoneStatus.REGISTERING
        try:
            self.sip.start()
            self._status = PhoneStatus.REGISTERED
        except Exception:
            self._status = PhoneStatus.FAILED
            self.sip.stop()
            raise

    def stop(self) -> None:
        debug(f'{self.__class__.__name__}.{inspect.stack()[0][3]} start')
        self._status = PhoneStatus.DEREGISTERING
        for x in self.calls.copy():
            try:
                self.calls[x].hangup()
            except InvalidStateError:
                pass
        self.sip.stop()
        self._status = PhoneStatus.INACTIVE

    def call(self, number: str) -> VoIPCall:
        debug(f'{self.__class__.__name__}.{inspect.stack()[0][3]} start')
        port = None
        while port is None:
            proposed = random.randint(self.rtpPortLow, self.rtpPortHigh)
            if proposed not in self.assignedPorts:
                self.assignedPorts.append(proposed)
                port = proposed
        medias = {}
        medias[port] = {
                        0: RTP.PayloadType.PCMU,
                        101: RTP.PayloadType.EVENT
                       }
        request, call_id, sess_id = self.sip.invite(number, medias,
                                                    pyVoIP.RTP.TransmitType.SENDRECV)
        self.calls[call_id] = VoIPCall(self, CallState.DIALING, request,
                                       sess_id, ms=medias, sendmode=self.sendmode)
        return self.calls[call_id]
