from enum import Enum
from threading import Timer
from typing import Callable, Dict, Optional, Union
import audioop
import io
import pyVoIP
import random
import socket
import threading
import time
import warnings


__all__ = [
    "add_bytes",
    "byte_to_bits",
    "DynamicPayloadType",
    "PayloadType",
    "RTPParseError",
    "RTPProtocol",
    "RTPPacketManager",
    "RTPClient",
    "TransmitType",
]


debug = pyVoIP.debug


def byte_to_bits(byte: bytes) -> str:
    nbyte = bin(ord(byte)).lstrip("-0b")
    nbyte = ("0" * (8 - len(nbyte))) + nbyte
    return nbyte


def add_bytes(byte_string: bytes) -> int:
    binary = ""
    for byte in byte_string:
        nbyte = bin(byte).lstrip("-0b")
        nbyte = ("0" * (8 - len(nbyte))) + nbyte
        binary += nbyte
    return int(binary, 2)


class DynamicPayloadType(Exception):
    pass


class RTPParseError(Exception):
    pass


class RTPProtocol(Enum):
    UDP = "udp"
    AVP = "RTP/AVP"
    SAVP = "RTP/SAVP"


class TransmitType(Enum):
    RECVONLY = "recvonly"
    SENDRECV = "sendrecv"
    SENDONLY = "sendonly"
    INACTIVE = "inactive"

    def __str__(self):
        return self.value


class PayloadType(Enum):
    def __new__(
        cls,
        value: Union[int, str],
        clock: int = 0,
        channel: int = 0,
        description: str = "",
    ):
        obj = object.__new__(cls)
        obj._value_ = value
        obj.rate = clock
        obj.channel = channel
        obj.description = description
        return obj

    @property
    def rate(self) -> int:
        return self._rate

    @rate.setter
    def rate(self, value: int) -> None:
        self._rate = value

    @property
    def channel(self) -> int:
        return self._channel

    @channel.setter
    def channel(self, value: int) -> None:
        self._channel = value

    @property
    def description(self) -> str:
        return self._description

    @description.setter
    def description(self, value: str) -> None:
        self._description = value

    def __int__(self) -> int:
        try:
            return int(self.value)
        except ValueError:
            pass
        raise DynamicPayloadType(
            self.description + " is a dynamically assigned payload"
        )

    def __str__(self) -> str:
        if isinstance(self.value, int):
            return self.description
        return str(self.value)

    # Audio
    PCMU = 0, 8000, 1, "PCMU"
    GSM = 3, 8000, 1, "GSM"
    G723 = 4, 8000, 1, "G723"
    DVI4_8000 = 5, 8000, 1, "DVI4"
    DVI4_16000 = 6, 16000, 1, "DVI4"
    LPC = 7, 8000, 1, "LPC"
    PCMA = 8, 8000, 1, "PCMA"
    G722 = 9, 8000, 1, "G722"
    L16_2 = 10, 44100, 2, "L16"
    L16 = 11, 44100, 1, "L16"
    QCELP = 12, 8000, 1, "QCELP"
    CN = 13, 8000, 1, "CN"
    # MPA channel varries, should be defined in the RTP packet.
    MPA = 14, 90000, 0, "MPA"
    G728 = 15, 8000, 1, "G728"
    DVI4_11025 = 16, 11025, 1, "DVI4"
    DVI4_22050 = 17, 22050, 1, "DVI4"
    G729 = 18, 8000, 1, "G729"

    # Video
    CELB = 25, 90000, 0, "CelB"
    JPEG = 26, 90000, 0, "JPEG"
    NV = 28, 90000, 0, "nv"
    H261 = 31, 90000, 0, "H261"
    MPV = 32, 90000, 0, "MPV"
    # MP2T is both audio and video per RFC 3551 July 2003 5.7
    MP2T = 33, 90000, 1, "MP2T"
    H263 = 34, 90000, 0, "H263"

    # Non-codec
    EVENT = "telephone-event", 8000, 0, "telephone-event"
    UNKNOWN = "UNKNOWN", 0, 0, "UNKNOWN CODEC"


class RTPPacketManager:
    def __init__(self):
        self.offset = 4294967296
        """
        The largest number storable in 4 bytes + 1. This will ensure the
        offset adjustment in self.write(offset, data) works.
        """
        self.buffer = io.BytesIO()
        self.bufferLock = threading.Lock()
        self.log = {}
        self.rebuilding = False

    def read(self, length: int = 160) -> bytes:
        # This acts functionally as a lock while the buffer is being rebuilt.
        while self.rebuilding:
            time.sleep(0.01)
        self.bufferLock.acquire()
        packet = self.buffer.read(length)
        if len(packet) < length:
            packet = packet + (b"\x80" * (length - len(packet)))
        self.bufferLock.release()
        return packet

    def rebuild(self, reset: bool, offset: int = 0, data: bytes = b"") -> None:
        self.rebuilding = True
        if reset:
            self.log = {}
            self.log[offset] = data
            self.buffer = io.BytesIO(data)
        else:
            bufferloc = self.buffer.tell()
            self.buffer = io.BytesIO()
            for pkt in self.log:
                self.write(pkt, self.log[pkt])
            self.buffer.seek(bufferloc, 0)
        self.rebuilding = False

    def write(self, offset: int, data: bytes) -> None:
        self.bufferLock.acquire()
        self.log[offset] = data
        bufferloc = self.buffer.tell()
        if offset < self.offset:
            """
            If the new timestamp is over 100,000 bytes before the
            earliest, erase the buffer.  This will stop memory errors.
            """
            reset = abs(offset - self.offset) >= 100000
            self.offset = offset
            self.bufferLock.release()
            """
            Rebuilds the buffer if something before the earliest
            timestamp comes in, this will stop overwritting.
            """
            self.rebuild(reset, offset, data)
            return
        offset = offset - self.offset
        self.buffer.seek(offset, 0)
        self.buffer.write(data)
        self.buffer.seek(bufferloc, 0)
        self.bufferLock.release()


class RTPMessage:
    def __init__(self, data: bytes, assoc: Dict[int, PayloadType]):
        self.RTPCompatibleVersions = pyVoIP.RTPCompatibleVersions
        self.assoc = assoc
        # Setting defaults to stop mypy from complaining
        self.version = 0
        self.padding = False
        self.extension = False
        self.CC = 0
        self.marker = False
        self.payload_type = PayloadType.UNKNOWN
        self.sequence = 0
        self.timestamp = 0
        self.SSRC = 0

        self.parse(data)

    def summary(self) -> str:
        data = ""
        data += f"Version: {self.version}\n"
        data += f"Padding: {self.padding}\n"
        data += f"Extension: {self.extension}\n"
        data += f"CC: {self.CC}\n"
        data += f"Marker: {self.marker}\n"
        data += (
            f"Payload Type: {self.payload_type} "
            + f"({self.payload_type.value})\n"
        )
        data += f"Sequence Number: {self.sequence}\n"
        data += f"Timestamp: {self.timestamp}\n"
        data += f"SSRC: {self.SSRC}\n"
        return data

    def parse(self, packet: bytes) -> None:
        byte = byte_to_bits(packet[0:1])
        self.version = int(byte[0:2], 2)
        if self.version not in self.RTPCompatibleVersions:
            raise RTPParseError(f"RTP Version {self.version} not compatible.")
        self.padding = bool(int(byte[2], 2))
        self.extension = bool(int(byte[3], 2))
        self.CC = int(byte[4:], 2)

        byte = byte_to_bits(packet[1:2])
        self.marker = bool(int(byte[0], 2))

        pt = int(byte[1:], 2)
        if pt in self.assoc:
            self.payload_type = self.assoc[pt]
        else:
            try:
                self.payload_type = PayloadType(pt)
                e = False
            except ValueError:
                e = True
            if e:
                raise RTPParseError(f"RTP Payload type {pt} not found.")

        self.sequence = add_bytes(packet[2:4])
        self.timestamp = add_bytes(packet[4:8])
        self.SSRC = add_bytes(packet[8:12])

        self.CSRC = []

        i = 12
        for x in range(self.CC):
            self.CSRC.append(packet[i : i + 4])
            i += 4

        if self.extension:
            pass

        self.payload = packet[i:]


class RTPClient:
    def __init__(
        self,
        assoc: Dict[int, PayloadType],
        inIP: str,
        inPort: int,
        outIP: str,
        outPort: int,
        sendrecv: TransmitType,
        dtmf: Optional[Callable[[str], None]] = None,
    ):
        self.NSD = True
        # Example: {0: PayloadType.PCMU, 101: PayloadType.EVENT}
        self.assoc = assoc
        debug("Selecting audio codec for transmission")
        for m in assoc:
            try:
                if int(assoc[m]) is not None:
                    debug(f"Selected {assoc[m]}")
                    """
                    Select the first available actual codec to encode with.
                    TODO: will need to change if video codecs
                    are ever implemented.
                    """
                    self.preference = assoc[m]
                    break
            except Exception:
                debug(f"{assoc[m]} cannot be selected as an audio codec")

        self.inIP = inIP
        self.inPort = inPort
        self.outIP = outIP
        self.outPort = outPort

        self.dtmf = dtmf

        self.pmout = RTPPacketManager()  # To Send
        self.pmin = RTPPacketManager()  # Received
        self.outOffset = random.randint(1, 5000)

        self.outSequence = random.randint(1, 100)
        self.outTimestamp = random.randint(1, 10000)
        self.outSSRC = random.randint(1000, 65530)

    def start(self) -> None:
        self.sin = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sout = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sin.bind((self.inIP, self.inPort))
        self.sin.setblocking(False)

        r = Timer(0, self.recv)
        r.name = "RTP Receiver"
        r.start()
        t = Timer(0, self.trans)
        t.name = "RTP Transmitter"
        t.start()

    def stop(self) -> None:
        self.NSD = False
        self.sin.close()
        self.sout.close()

    def read(self, length: int = 160, blocking: bool = True) -> bytes:
        if not blocking:
            return self.pmin.read(length)
        packet = self.pmin.read(length)
        while packet == (b"\x80" * length) and self.NSD:
            time.sleep(0.01)
            packet = self.pmin.read(length)
        return packet

    def write(self, data: bytes) -> None:
        self.pmout.write(self.outOffset, data)
        self.outOffset += len(data)

    def recv(self) -> None:
        while self.NSD:
            try:
                packet = self.sin.recv(8192)
                self.parsePacket(packet)
            except BlockingIOError:
                time.sleep(0.01)
            except RTPParseError as e:
                debug(str(e))
            except OSError:
                pass

    def trans(self) -> None:
        while self.NSD:
            last_sent = time.monotonic_ns()
            payload = self.pmout.read()
            payload = self.encodePacket(payload)
            packet = b"\x80"  # RFC 1889 V2 No Padding Extension or CC.
            packet += chr(int(self.preference)).encode("utf8")
            try:
                packet += self.outSequence.to_bytes(2, byteorder="big")
            except OverflowError:
                self.outSequence = 0
            try:
                packet += self.outTimestamp.to_bytes(4, byteorder="big")
            except OverflowError:
                self.outTimestamp = 0
            packet += self.outSSRC.to_bytes(4, byteorder="big")
            packet += payload

            # debug(payload)

            try:
                self.sout.sendto(packet, (self.outIP, self.outPort))
            except OSError:
                warnings.warn(
                    "RTP Packet failed to send!",
                    RuntimeWarning,
                    stacklevel=2,
                )

            self.outSequence += 1
            self.outTimestamp += len(payload)
            # Calculate how long it took to generate this packet.
            # Then how long we should wait to send the next, then devide by 2.
            delay = (1 / self.preference.rate) * 160
            sleep_time = max(
                0, delay - ((time.monotonic_ns() - last_sent) / 1000000000)
            )
            time.sleep(sleep_time / self.trans_delay_reduction)

    @property
    def trans_delay_reduction(self) -> float:
        reduction = pyVoIP.TRANSMIT_DELAY_REDUCTION + 1
        return reduction if reduction else 1.0

    def parsePacket(self, packet: bytes) -> None:
        warnings.warn(
            "parsePacket is deprecated due to PEP8 compliance. "
            + "Use parse_packet instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.parse_packet(packet)

    def parse_packet(self, packet: bytes) -> None:
        msg = RTPMessage(packet, self.assoc)
        if msg.payload_type == PayloadType.PCMU:
            self.parsePCMU(msg)
        elif msg.payload_type == PayloadType.PCMA:
            self.parsePCMA(msg)
        elif msg.payload_type == PayloadType.EVENT:
            self.parseTelephoneEvent(msg)
        else:
            raise RTPParseError(
                "Unsupported codec (parse): " + str(msg.payload_type)
            )

    def encodePacket(self, payload: bytes) -> bytes:
        warnings.warn(
            "encodePacket is deprecated due to PEP8 compliance. "
            + "Use encode_packet instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.encode_packet(payload)

    def encode_packet(self, payload: bytes) -> bytes:
        if self.preference == PayloadType.PCMU:
            return self.encodePCMU(payload)
        elif self.preference == PayloadType.PCMA:
            return self.encodePCMA(payload)
        else:
            raise RTPParseError(
                "Unsupported codec (encode): " + str(self.preference)
            )

    def parsePCMU(self, packet: RTPMessage) -> None:
        warnings.warn(
            "parsePCMU is deprecated due to PEP8 compliance. "
            + "Use parse_pcmu instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.parse_pcmu(packet)

    def parse_pcmu(self, packet: RTPMessage) -> None:
        data = audioop.ulaw2lin(packet.payload, 1)
        data = audioop.bias(data, 1, 128)
        self.pmin.write(packet.timestamp, data)

    def encodePCMU(self, packet: bytes) -> bytes:
        warnings.warn(
            "encodePCMU is deprecated due to PEP8 compliance. "
            + "Use encode_pcmu instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.encode_pcmu(packet)

    def encode_pcmu(self, packet: bytes) -> bytes:
        packet = audioop.bias(packet, 1, -128)
        packet = audioop.lin2ulaw(packet, 1)
        return packet

    def parsePCMA(self, packet: RTPMessage) -> None:
        warnings.warn(
            "parsePCMA is deprecated due to PEP8 compliance. "
            + "Use parse_pcma instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.parse_pcma(packet)

    def parse_pcma(self, packet: RTPMessage) -> None:
        data = audioop.alaw2lin(packet.payload, 1)
        data = audioop.bias(data, 1, 128)
        self.pmin.write(packet.timestamp, data)

    def encodePCMA(self, packet: bytes) -> bytes:
        warnings.warn(
            "encodePCMA is deprecated due to PEP8 compliance. "
            + "Use encode_pcma instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.encode_pcma(packet)

    def encode_pcma(self, packet: bytes) -> bytes:
        packet = audioop.bias(packet, 1, -128)
        packet = audioop.lin2alaw(packet, 1)
        return packet

    def parseTelephoneEvent(self, packet: RTPMessage) -> None:
        warnings.warn(
            "parseTelephoneEvent "
            + "is deprecated due to PEP8 compliance. "
            + "Use parse_telephone_event instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.parse_telephone_event(packet)

    def parse_telephone_event(self, packet: RTPMessage) -> None:
        key = [
            "0",
            "1",
            "2",
            "3",
            "4",
            "5",
            "6",
            "7",
            "8",
            "9",
            "*",
            "#",
            "A",
            "B",
            "C",
            "D",
        ]

        payload = packet.payload
        event = key[payload[0]]
        """
        Commented out the following due to F841 (Unused variable).
        Might use at some point though, so I'm saving the logic.

        byte = byte_to_bits(payload[1:2])
        end = (byte[0] == '1')
        volume = int(byte[2:], 2)
        """

        if packet.marker:
            if self.dtmf is not None:
                self.dtmf(event)
