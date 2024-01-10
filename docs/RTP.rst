RTP - Real-time Transport Protocol
###################################

The RTP module recives and transmits sound and phone-event data for a particular phone call.

Functions
*********

The RTP module has two functions that are used by various classes for packet parsing.

pyVoIP.RTP.\ **byte_to_bits**\ (byte: bytes) -> str
  This method converts a single byte into an eight character string of ones and zeros. The *byte* argument must be a single byte.
  
pyVoIP.RTP.\ **add_bytes**\ (bytes: bytes) -> int
  This method takes multiple bytes and adds them together into an integer.
  
Errors
*******

*exception* pyVoIP.RTP.\ **DynamicPayloadType**
  This may be thrown when you try to int cast a dynamic PayloadType. Most PayloadTypes have a number assigned in `RFC 3551 Section 6 <https://tools.ietf.org/html/rfc3551#section-6>`_. However, some are considered to be 'dynamic' meaning the PBX/VoIP server will pick an available number, and define it.
  
*exception* pyVoIP.RTP.\ **RTPParseError**
  This is thrown by :ref:`RTPMessage` when unable to parse a RTP message. It may also be thrown by `RTPClient` when it's unable to encode or decode the RTP packet payload.

Enums
*******

pyVoIP.RTP.\ **RTPProtocol**
  RTPProtocol is an Enum with three attributes. It defines the method that packets are to be sent with. Currently, only AVP is supported.
  
  RTPProtocol.\ **UDP**
    This means the audio should be sent with pure UDP. Returns ``'udp'`` when string casted.
    
  RTPProtocol.\ **AVP**
    This means the audio should be sent with RTP Audio/Video Protocol described in :RFC:`3551`. Returns ``'RTP/AVP'`` when string casted.
    
  RTPProtocol.\ **SAVP**
    This means the audio should be sent with RTP Secure Audio/Video Protocol described in :RFC:`3711`. Returns ``'RTP/SAVP'`` when string casted.
    
.. _transmittype:
    
pyVoIP.RTP.\ **TransmitType**
  TransmitType is an Enum with four attributes. It describes how the :ref:`RTPClient` should act.
  
  TransmitType.\ **RECVONLY**
    This means the RTPClient should only recive audio, not transmit it. Returns ``'recvonly'`` when string casted.
    
  TransmitType.\ **SENDRECV**
    This means the RTPClient should send and receive audio. Returns ``'sendrecv'`` when string casted.
    
  TransmitType.\ **SENDONLY**
    This means the RTPClient should only send audio, not receive it. Returns ``'sendonly'`` when string casted.
    
  TransmitType.\ **INACTIVE**
    This means the RTP client should not send or receive audio, and instead wait to be activated. Returns ``'inactive'`` when string casted.

.. _payload-type:

pyVoIP.RTP.\ **PayloadType**
  PayloadType is an Enum with multiple attributes. It described the list of attributes in `RFC 3551 Section 6 <https://tools.ietf.org/html/rfc3551#section-6>`_. Currently, only one dynamic event is assigned: telephone-event. Telephone-event is used for sending and recieving DTMF codes. There are a few conflicing names in the RFC as they're the same codec with varrying options so we will go over the conflicts here. PayloadType has the following attributes:
  
    type.\ **value**
      This is either the number assigned as PT in the `RFC 3551 Section 6 chart <https://datatracker.ietf.org/doc/html/rfc3551#section-6>`_, or it is the encoding name if it is dynamic. Int casting the PayloadType will return this number, or raise a DynamicPayloadType error if the protocol is dynamic.
      
    type.\ **rate**
      This will return the clock rate of the codec.
      
    type.\ **channel**
      This will return the number of channels the used in the codec, or for Non-codecs like telephone-event, it will return zero.
      
    type.\ **description**
      This will return the encoding name of the payload. String casting the PayloadType will return this value.
      
  PayloadType.\ **DVI4_8000**
    This variation of the DVI4 Codec has the attributes: value 5, rate 8000, channel 1, description "DVI4"
    
  PayloadType.\ **DVI4_16000**
    This variation of the DVI4 Codec has the attributes: value 6, rate 16000, channel 1, description "DVI4"
    
  PayloadType.\ **DVI4_11025**
    This variation of the DVI4 Codec has the attributes: value 16, rate 11025, channel 1, description "DVI4"
    
  PayloadType.\ **DVI4_22050**
    This variation of the DVI4 Codec has the attributes: value 17, rate 22050, channel 1, description "DVI4"
    
  PayloadType.\ **L16**
    This variation of the L16 Codec has the attributes: value 11, rate 44100, channel 1, description "L16"
    
  PayloadType.\ **L16_2**
    This variation of the L16 Codec has the attributes: value 11, rate 44100, channel 2, description "L16"
    
  PayloadType.\ **EVENT**
    This is the dynamic non-codec 'telephone-event'. Telephone-event is used for sending and receiving DTMF codes.
    
Classes
*********

.. _RTPPacketManager:

RTPPacketManager
================

The RTPPacketManager class utilizes an ``io.ByteIO`` that stores either received payloads, or raw audio data waiting to be transmitted.

pyVoIP.RTP.\ **RTPPacketManager**\ ()
  
  **read**\ (length=160) -> bytes
    Reads *length* bytes from the ByteIO. This will always return the length requested, and will append ``b'\x80'``'s onto the end of the available bytes to achieve this length.
    
  **rebuild**\ (reset: bool, offset=0, data=b'') -> None
    This rebuilds the ByteIO if packets are sent out of order. Setting the argument *reset* to ``True`` will wipe all data in the ByteIO and insert in the data in the argument *data* at the position in the argument *offset*.
    
  **write**\ (offset: int, data: bytes) -> None
    Writes the data in the argument *data* to the ByteIO at the position in the argument *offset*. RTP data comes with a timestamp that is passed as the offset in this case. This makes it so a hole left by delayed packets can be filled later. If a packet with a timestamp sooner than any other timestamp received, it will rebuild the ByteIO with the new data. If this new position is over 100,000 bytes before the earliest byte, the ByteIO is completely wiped and starts over. This is to prevent Overflow errors.

.. _RTPMessage:

RTPMessage
===========

The RTPMessage class is used to parse RTP packets and makes them easily processed by the :ref:`RTPClient`.

pyVoIP.RTP.\ **RTPMessage**\ (data: bytes, assoc: dict[int, :ref:`PayloadType<payload-type>`])
    
    The *data* argument is the received RTP packet in bytes.
    
    The *assoc* argument is a dictionary, using the payload number as a key and a :ref:`PayloadType<payload-type>` as the value. This way RTPMessage can determine what number a dynamic payload is. This association dictionary is generated by :ref:`VoIPCall`.
    
  RTPMessage has attributes that come from `RFC 3550 Section 5.1 <https://tools.ietf.org/html/rfc3550#section-5.1>`_. RTPMessage has the following attributes:
    
    RTPMessage.\ **version**
      This attribute is the RTP packet version, represented as an integer.
      
    RTPMessage.\ **padding**
      If this attribute is set to True the payload has padding.
      
    RTPMessage.\ **extension**
      If this attribute is set to True the packet has a header extension.
      
    RTPMessage.\ **CC**
      This attribute is the CSRC Count, represented as an integer.
    
    RTPMessage.\ **marker**
      This attribute is set to True if the marker bit is set.
      
    RTPMessage.\ **payload_type**
      This attribute is set to the :ref:`PayloadType<payload-type>` that corresponds to the payload codec.
      
    RTPMessage.\ **sequence**
      This attribute is set to the sequence number of the RTP packet, represented as an integer.
      
    RTPMessage.\ **timestamp**
      This attribute is set to the timestamp of the RTP packet, represented as an integer.
      
    RTPMessage.\ **SSRC**
      This attribute is set to the synchronization source of the RTP packet, represented as an integer.
      
    RTPMessage.\ **payload**
      This attribute is the payload data of the RTP packet, represented as bytes.
      
    RTPMessage.\ **raw**
      This attribute is the unparsed version of the *data* argument, in bytes.
  
  **summary**\ () -> str
    This method returns a string representation of the RTP packet excluding the payload.
    
  **parse**\ (data: bytes) -> None
    This method is called by the initialization of the class. It determines the RTP version, whether the packet has padding, has a header extension, and other information about the backet.

.. _RTPClient:

RTPClient
=========

The RTPClient is used to send and receive RTP packets and encode/decode the audio codecs.

*class* pyVoIP.RTP.\ **RTPClient**\ (assoc: dict[int, :ref:`PayloadType<payload-type>`], inIP: str, inPort: int, outIP: str, outPort: int, sendrecv: :ref:`TransmitType<transmittype>`, dtmf: Optional[Callable[[str], None] = None):
    
    The *assoc* argument is a dictionary, using the payload number as a key and a :ref:`PayloadType<payload-type>` as the value. This way, RTPMessage can determine what a number a dynamic payload is. This association dictionary is generated by :ref:`VoIPCall`.
    
    The *inIP* argument is used to receive incoming RTP message.
    
    The *inPort* argument is the port RTPClient will bind to, to receive incoming RTP packets.
    
    The *outIP* argument is used to transmit RTP packets.
    
    The *outPort* argument is used to transmit RTP packets.
    
    The *sendrecv* argument describes how the RTPClient should act. Please reference :ref:`TransmitType<transmittype>` for more details.
    
    The *dtmf* argument is set to the callback :ref:`VoIPCall`.dtmfCallback().
    
  **start**\ () -> None
    This method is called by :ref:`VoIPCall`.answer(). It starts the recv() and trans() threads. It is also what initiates the bound port. **This should not be called by the** :term:`user`.
    
  **stop**\ () -> None
    This method is called by :ref:`VoIPCall`.hangup() and :ref:`VoIPCall`.bye(). It stops the recv() and trans() threads. It will also close the bound port. **This should not be called by the** :term:`user`.
    
  **read**\ (length=160, blocking=True) -> bytes
    This method is called by :ref:`VoIPCall`.readAudio(). It reads linear/raw audio data from the received buffer. Returns *length* amount of bytes. Default length is 160 as that is the amount of bytes sent per PCMU/PCMA packet. When *blocking* is set to true, this function will not return until data is available. When *blocking* is set to false and data is not available, this function will return bytes(length).
    
  **write**\ (data: bytes) -> None
    This method is called by :ref:`VoIPCall`.writeAudio(). It queues the data written to be sent to the :term:`client`.
    
  **recv**\ () -> None
    This method is called by RTPClient.start() and is responsible for receiving and parsing through RTP packets. **This should not be called by the** :term:`user`.
    
  **trans**\ () -> None
    This method is called by RTPClient.start() and is responsible for transmitting RTP packets. **This should not be called by the** :term:`user`.
    
  **parse_packet**\ (packet: bytes) -> None
    This method is called by the recv() thread. It converts the argument *packet* into a :ref:`RTPMessage`, then sends it to the proper parse function depending on the :ref:`PayloadType<payload-type>`.
    
  **encode_packet**\ (payload: bytes) -> bytes
    This method is called by the trans() thread. It encoded the argument *payload* into the prefered codec. Currently, PCMU is the hardcoded prefered codec. The trans() thread will use the payload to create the RTP packet before transmitting.
    
  **parse_pcmu**\ (packet: :ref:`RTPMessage`) -> None
    This method is called by parse_packet(). It will decode the *packet*'s payload from PCMU to linear/raw audio and write it to the incoming :ref:`RTPPacketManager`.
    
  **encode_pcmu**\ (packet: bytes) -> bytes
    This method is called by encode_packet(). It will encode the *payload* into the PCMU audio codec.
    
  **parse_pcma**\ (packet: :ref:`RTPMessage`) -> None
    This method is called by parse_packet(). It will decode the *packet*'s payload from PCMA to linear/raw audio and write it to the incoming :ref:`RTPPacketManager`.
    
  **encode_pcma**\ (payload: bytes) -> bytes
    This method is called by encode_packet(). It will encode the *payload* into the PCMA audio codec.
    
  **parse_telephone_event**\ (packet: :ref:`RTPMessage`) -> None
    This method is called by parse_packet(). It will decode the *packet*'s payload from the telephone-event non-codec to the string representation of the event. It will then call :ref:`VoIPCall`.dtmf_callback().
    
