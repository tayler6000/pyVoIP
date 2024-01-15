SIP - Session Initiation Protocol
##################################

The SIP module receives, parses, and responds to incoming SIP requests/messages.  If appropriate, it then forwards them to the *callback* method of :ref:`VoIPPhone`.

Errors
*******

There are two errors under ``pyVoIP.SIP``.

.. _InvalidAccountInfoError:

*exception* SIP.\ **InvalidAccountInfoError**
  This is thrown when :ref:`SIPClient` gets a bad response when trying to register with the PBX/VoIP server.  This error also kills the SIP REGISTER thread, so you will need to call SIPClient.stop() then SIPClient.start().

.. _sip-parse-error:

*exception* SIP.\ **SIPParseError**
  This is thrown when :ref:`SIPMessage` is unable to parse a SIP message/request.

.. _Enums:

Enums
******

SIP.\ **SIPMessageType**
  SIPMessageType is an IntEnum with two attributes.  It's stored in ``SIPMessage.type`` to effectively parse the message.
  
  SIPMessageType.\ **MESSAGE**
    This SIPMessageType is used to signify the message was a SIP request.
    
  SIPMessageType.\ **RESPONSE**
    This SIPMessageType is used to signify the message was a SIP response.
    
SIP.\ **SIPStatus**
  SIPStatus is used for :ref:`SIPMessage`'s with SIPMessageType.RESPONSE.  They will not all be listed here, but a complete list can be found on `Wikipedia <https://en.wikipedia.org/wiki/List_of_SIP_response_codes>`_.  SIPStatus has the following attributes:
  
    status.\ **value**
      This is the integer value of the status.  For example, ``SIPStatus.OK.value`` is equal to ``int(200)``.
      
    status.\ **phrase**
      This is the string value of the status, usually written next to the number in a SIP response. For example, ``SIPStatus.TRYING.phrase`` is equal to ``'Trying'``.
      
    status.\ **description**
      This is the string value of the description of the status, it can be useful for debugging.  For example, ``SIPStatus.OK.description`` is equal to ``'Request successful'``  Not all responses have a description.
  
  Here are a few common SIPStatus' and their attributes in the order of value, phrase, description:
  
  SIPStatus.\ **TRYING**
    100, 'Trying', 'Extended search being performed, may take a significant time'
    
  SIPStatus.\ **RINGING**
    180, 'Ringing', 'Destination user agent received INVITE, and is alerting user of call'
  
  SIPStatus.\ **OK**
    200, 'OK', 'Request successful'
    
  SIPStatus.\ **BUSY_HERE**
    486, 'Busy Here', 'Callee is busy'

Classes
********

.. _SIPClient:

SIPClient
==========

The SIPClient class is used to communicate with the PBX/VoIP server.  It is responsible for registering with the server, and receiving phone calls.

*class* SIP.\ **SIPClient**\ (server: str, port: int, username: str, password: str, myIP="0.0.0.0", myPort=5060, callCallback: Optional[Callable[[SIPMessage], None]] = None, auth_username: str)
    The *server* argument is your PBX/VoIP server's IP.
    
    The *port* argument is your PBX/VoIP server's port.

    The *username* argument is your SIP account username on the PBX/VoIP server.

    The *password* argument is your SIP account password on the PBX/VoIP server.

    The *myIP* argument is used to bind a socket and receive incoming SIP requests and responses.

    The *myPort* argument is the port SIPClient will bind to, to receive incoming SIP requests and responses. The default for this protocol is port 5060, but any port can be used.

    The *callCallback* argument is the callback function for :ref:`VoIPPhone`.  VoIPPhone will process the SIP request, and perform the appropriate actions.

    The *auth_username* argument is the optional username for proxy-authentication, represented as a string.

  **recv**\ () -> None
    This method is called by SIPClient.start() and is responsible for receiving and parsing through SIP requests.  **This should not be called by the** :term:`user`.
    
  **parseMessage**\ (message: :ref:`SIPMessage`) -> None
    *Deprecated.* Please use ``parse_message`` instead.

  **parse_message**\ (message: :ref:`SIPMessage`) -> None
    This method is called by SIPClient.recv() and is responsible for parsing through SIP responses.  **This should not be called by the** :term:`user`.
    
  **start**\ () -> None
    This method is called by :ref:`VoIPPhone`.start().  It starts the REGISTER and recv() threads.  It is also what initiates the bound port.  **This should not be called by the** :term:`user`.
    
  **stop**\ () -> None
    This method is called by :ref:`VoIPPhone`.stop(). It stops the REGISTER and recv() threads.  It will also close the bound port.  **This should not be called by the** :term:`user`.
    
  **genCallID**\ () -> str
    *Deprecated.* **This should not be called by the** :term:`user`.

  **gen_call_id**\ () -> str
    This method is called by other 'gen' methods when a new Call-ID header is needed.  See `RFC 3261 Section 20.8 <https://tools.ietf.org/html/rfc3261#section-20.8>`_.  **This should not be called by the** :term:`user`.

  **lastCallID**\ () -> str
    *Deprecated.*  **This should not be called by the** :term:`user`.

  **last_call_id**\ () -> str
    This method is called by other 'gen' methods when the last Call-ID header is needed.  See `RFC 3261 Section 20.8 <https://tools.ietf.org/html/rfc3261#section-20.8>`_.  **This should not be called by the** :term:`user`.
    
  **genTag**\ () -> str
    *Deprecated.* **This should not be called by the** :term:`user`.

  **gen_tag**\ () -> str
    This method is called by other 'gen' methods when a new tag is needed. See `RFC 3261 Section 8.2.6.2 <https://tools.ietf.org/html/rfc3261#section-8.2.6.2>`_.  **This should not be called by the** :term:`user`.
    
  **genSIPVersionNotSupported**\ () -> str
    *Deprecated.* **This should not be called by the** :term:`user`.

  **gen_sip_version_not_supported**\ () -> str
    This method is called by the recv() thread when it has received a SIP message that is not SIP version 2.0.
    
  **genAuthorization**\ (request: :ref:`SIPMessage`) -> bytes
    *Deprecated.* **This should not be called by the** :term:`user`.

  **gen_authorization**\ (request: :ref:`SIPMessage`) -> bytes
    This calculates the authroization hash in response to the WWW-Authenticate header.  See `RFC 3261 Section 20.7 <https://tools.ietf.org/html/rfc3261#section-20.7>`_.  The *request* argument should be a 401 Unauthorized response.  **This should not be called by the** :term:`user`.
    
  **genRegister**\ (request: :ref:`SIPMessage`, deregister: bool = False) -> str
    *Deprecated.* **This should not be called by the** :term:`user`.

  **gen_register**\ (request: :ref:`SIPMessage`, deregister: bool = False) -> str
    This method generates a SIP REGISTER request. The *request* argument should be a 401 Unauthorized response.  If *deregister* is set to true, a SIP DE-REGISTER request is generated instead.  **This should not be called by the** :term:`user`.
    
  **genBusy**\ (request: :ref:`SIPMessage`) -> str
    *Deprecated.* **This should not be called by the** :term:`user`.

  **gen_busy**\ (request: :ref:`SIPMessage`) -> str
    This method generates a SIP 486 'Busy Here' response.  The *request* argument should be a SIP INVITE request.
    
  **genOk**\ (request: :ref:`SIPMessage`) -> str
    *Deprecated.* **This should not be called by the** :term:`user`.

  **gen_ok**\ (request: :ref:`SIPMessage`) -> str
    This method generates a SIP 200 'Ok' response.  The *request* argument should be a SIP BYE request.
    
  **genInvite**\ (number: str, sess_id: str, ms: dict[int, dict[str, RTP.\ :ref:`PayloadType<payload-type>`]], sendtype: RTP.\ :ref:`TransmitType`, branch: str, call_id: str) -> str
    *Deprecated.* **This should not be called by the** :term:`user`.

  **gen_invite**\ (number: str, sess_id: str, ms: dict[int, dict[str, RTP.\ :ref:`PayloadType<payload-type>`]], sendtype: RTP.\ :ref:`TransmitType`, branch: str, call_id: str) -> str
    This method generates a SIP INVITE request.  This is called by SIPClient.invite().

    The *number* argument must be the number being called as a string.

    The *sess_id* argument must be a unique number.

    The *ms* argument is a dictionary of the media types to be used.  Currently only PCMU and telephone-event is supported.

    The *sendtype* argument must be an instance of :ref:`TransmitType`.

    The *branch* argument must be a unique string starting with "z9hG4bK".  See `RFC 3261 Section 8.1.1.7 <https://tools.ietf.org/html/rfc3261#section-8.1.1.7>`_.

    The *call_id* argument must be a unique string.  See `RFC 3261 Section 8.1.1.4 <https://tools.ietf.org/html/rfc3261#section-8.1.1.4>`_.
    
  **genRinging**\ (request: :ref:`SIPMessage`) -> str
    *Deprecated.* **This should not be called by the** :term:`user`.

  **gen_ringing**\ (request: :ref:`SIPMessage`) -> str
    This method generates a SIP 180 'Ringing' response.  The *request* argument should be a SIP INVITE request.
    
  **genAnswer**\ (request: :ref:`SIPMessage`, sess_id: str, ms: list[dict[str, Any]], sendtype: RTP.\ :ref:`TransmitType`)
    *Deprecated.* **This should not be called by the** :term:`user`.

  **gen_answer**\ (request: :ref:`SIPMessage`, sess_id: str, ms: list[dict[str, Any]], sendtype: RTP.\ :ref:`TransmitType`)
    This method generates a SIP 200 'OK' response.  Which, when in reply to an INVITE request, tells the server the :term:`user` has answered.  **This should not be called by the** :term:`user`.
    
    The *request* argument should be a SIP INVITE request.
    
    The *sess_id* argument should be a string casted integer.  This will be used for the SDP o tag.  See `RFC 4566 Section 5.2 <https://tools.ietf.org/html/rfc4566#section-5.2>`_.  The *sess_id* argument will also server as the *<sess-version>* argument in the SDP o tag.
    
    The *ms* argument should be a list of parsed SDP m tags, found in the :ref:`SIPMessage`.body attribute.  This is used to generate the response SDP m tags.   See `RFC 4566 Section 5.14 <https://tools.ietf.org/html/rfc4566#section-5.14>`_.
    
    The *sendtype* argument should be a RTP.\ :ref:`TransmitType<transmittype>` enum.  This will be used to generate the SDP a tag.   See `RFC 4567 Section 6 <https://tools.ietf.org/html/rfc4567#section-6>`_.
    
  **genBye**\ (request: :ref:`SIPMessage`) -> str
    *Deprecated.* **This should not be called by the** :term:`user`.

  **gen_bye**\ (request: :ref:`SIPMessage`) -> str
    This method generates a SIP BYE request.  This is used to end a call. The *request* argument should be a SIP INVITE request.  **This should not be called by the** :term:`user`.
    
  **genAck**\ (request: :ref:`SIPMessage`) -> str
    *Deprecated.* **This should not be called by the** :term:`user`.

  **gen_ack**\ (request: :ref:`SIPMessage`) -> str
    This method generates a SIP ACK response.  The *request* argument should be a SIP 401 response.
    
  **invite**\ (number: str, ms: dict[int, dict[str, RTP.\ :ref:`PayloadType<payload-type>`]], sendtype: RTP.\ :ref:`TransmitType`)
    This method generates a SIP INVITE request.  This method is called by :ref:`VoIPPhone`.call().

    The *number* argument must be the number being called as a string.

    The *ms* argument is a dictionary of the media types to be used.  Currently only PCMU and telephone-event is supported.

    The *sendtype* argument must be an instance of :ref:`TransmitType`.
    
  **bye**\ (request: :ref:`SIPMessage`) -> None
    This method is called by :ref:`VoIPCall`.hangup().  It calls genBye(), and then transmits the generated request.  **This should not be called by the** :term:`user`.
    
  **deregister**\ () -> bool
    This method is called by SIPClient.stop() after the REGISTER thread is stopped.  It will generate and transmit a REGISTER request with an Expiration of zero.  Telling the PBX/VoIP server it is turning off.  **This should not be called by the** :term:`user`.
    
  **register**\ () -> bool
    This method is called by the REGISTER thread.  It will generate and transmit a REGISTER request telling the PBX/VoIP server that it will be online for at least 300 seconds.  The REGISTER thread will call this function every 295 seconds.  **This should not be called by the** :term:`user`.
    
.. _SIPMessage:

SIPMessage
==========

The SIPMessage class is used to parse SIP requests and responses and makes them easily processed by other classes.

*class* SIP.\ **SIPMessage**\ (data: bytes)
    The *data* argument is the SIP message in bytes.  It is then passed to SIPMessage.parse().
  
  SIPMessage has the following attributes:
  
    SIPMessage.\ **heading**
      This attribute is the first line of the SIP message as a string.  It contains the SIP Version, and the method/response code.
      
    SIPMessage.\ **type**
      This attribute will be a :ref:`SIPMessageType<enums>`.
      
    SIPMessage.\ **status**
      This attribute will be a :ref:`SIPStatus<enums>`.  It will be set to ``int(0)`` if the message is a request.
      
    SIPMessage.\ **method**
      This attribute will be a string representation of the method.  It will be set to None if the message is a response.
      
    SIPMessage.\ **headers**
      This attribute is a dictionary of all the headers in the request, and their parsed values.
      
    SIPMessage.\ **body**
      This attribute is a dictionary of all the SDP tags in the request, and their parsed values.
      
    SIPMessage.\ **authentication**
      This attribute is a dictionary of a parsed Authentication header.  There are two authentication headers: Authorization, and WWW-Authenticate.  See RFC 3261 Sections `20.7 <https://tools.ietf.org/html/rfc3261#section-20.7>`_ and `20.44 <https://tools.ietf.org/html/rfc3261#section-20.44>`_ respectively.
      
    SIPMessage.\ **raw**
      This attribute is an unparsed version of the *data* argument, in bytes.
      
  **summary**\ () -> str
    This method returns a string representation of the SIP request.
    
  **parse**\ (data: bytes) -> None
    This method is called by the initialization of the class.  It decides the SIPMessageType, and sends it to the corresponding parse function.  *Data* is the original *data* argument in the initialization of the class.  **This should not be called by the** :term:`user`.

  **parseSIPResponse**\ (data: bytes) -> None
    *Deprecated.* **This should not be called by the** :term:`user`.

  **parse_sip_response**\ (data: bytes) -> None
    This method is called by parse().  It sets the *header*, *version*, and *status* attributes and may raise a :ref:`SIPParseError<sip-parse-error>` if the SIP response is an unsupported SIP version.  It then calls parseHeader() for each header in the request. *Data* is the original *data* argument in the initialization of the class.  **This should not be called by the** :term:`user`.
    
  **parseSIPMessage**\ (data: bytes) -> None
    *Deprecated.* **This should not be called by the** :term:`user`.

  **parse_sip_message**\ (data: bytes) -> None
    This method is called by parse().  It sets the *header*, *version*, and *method* attributes and may raise a :ref:`SIPParseError<sip-parse-error>` if the SIP request is an unsupported SIP version.  It then calls parseHeader() and parseBody() for each header or tag in the request respectively. *Data* is the original *data* argument in the initialization of the class.  **This should not be called by the** :term:`user`.
    
  **parseHeader**\ (header: str, data: str) -> None
    *Deprecated.* **This should not be called by the** :term:`user`.

  **parse_header**\ (header: str, data: str) -> None
    This method is called by parseSIPResponse() and parseSIPMessage().  The *header* argument is the name of the header, i.e. 'Call-ID' or 'CSeq', represented as a string.  The *data* argument is the value of the header, i.e. 'Ogq-T7iBmNozoUu3GL9Lvg..' or '1 INVITE', represented as a string.  **This should not be called by the** :term:`user`.
    
  **parseBody**\ (header: str, data: str) -> None
    *Deprecated.* **This should not be called by the** :term:`user`.

  **parse_body**\ (header: str, data: str) -> None
    This method is called by parseSIPResponse() and parseSIPMessage().  The *header* argument is the name of the SDP tag, i.e. 'm' or 'a', represented as a string.  The *data* argument is the value of the header, i.e. 'audio 56704 RTP/AVP 0' or 'sendrecv', represented as a string.  **This should not be called by the** :term:`user`.
