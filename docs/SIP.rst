SIP - Session Initiation Protocol
##################################

The SIP module receives, parses, and responds to incoming SIP requests and responses. If appropriate, it then forwards them to the :ref:`VoIPPhone`.

Errors
*******

There are two errors under ``pyVoIP.SIP.error``.

.. _InvalidAccountInfoError:

*exception* pyVoIP.SIP.\ **InvalidAccountInfoError**
  This is thrown when :ref:`SIPClient` gets a bad response when trying to register with the PBX/VoIP server. This error also kills the SIP REGISTER thread, so you will need to call SIPClient.stop() then SIPClient.start().

.. _SIPParseError:

*exception* pyVoIP.SIP.\ **SIPParseError**
  This is thrown when :ref:`SIPMessage` is unable to parse a SIP message/request.

Enums
******

.. _SIPMessageType:

pyVoIP.SIP.message.\ **SIPMessageType**
  SIPMessageType is an IntEnum with two members. It's stored in ``SIPMessage.type`` to effectively parse the message.

  SIPMessageType.\ **REQUEST**
    This SIPMessageType is used to signify the message was a SIP request.
    
  SIPMessageType.\ **RESPONSE**
    This SIPMessageType is used to signify the message was a SIP response.
    
.. _SIPStatus:

pyVoIP.SIP.message.\ **SIPStatus**
  SIPStatus is used for :ref:`SIPMessage`'s with SIPMessageType.RESPONSE. They will not all be listed here, but a complete list can be found on `Wikipedia <https://en.wikipedia.org/wiki/List_of_SIP_response_codes>`_. SIPStatus has the following attributes:
    status.\ **value**
      This is the integer value of the status. For example, ``SIPStatus.OK.value`` is equal to ``int(200)``.
      
    status.\ **phrase**
      This is the string value of the status, usually written next to the number in a SIP response. For example, ``SIPStatus.TRYING.phrase`` is equal to ``"Trying"``.
      
    status.\ **description**
      This is the string value of the description of the status, it can be useful for debugging. For example, ``SIPStatus.OK.description`` is equal to ``"Request successful"``  Not all responses have a description.
  
Here are a few common SIPStatus members and their attributes in the order of value, phrase, description:
  SIPStatus.\ **TRYING**
    100, "Trying", "Extended search being performed, may take a significant time"
    
  SIPStatus.\ **RINGING**
    180, "Ringing", "Destination user agent received INVITE, and is alerting user of call"
  
  SIPStatus.\ **OK**
    200, "OK", "Request successful"
    
  SIPStatus.\ **BUSY_HERE**
    486, "Busy Here", "Callee is busy"

Classes
********

.. _SIPClient:

SIPClient
==========

The SIPClient class is used to communicate with the PBX/VoIP server. It is responsible for registering with the server, and receiving phone calls.

*class* pyVoIP.SIP.client.\ **SIPClient**\ (server: str, port: int, user: str, credentials_manager: :ref:`CredentialsManager`, bind_ip="0.0.0.0", bind_network="0.0.0.0/0", hostname: Optional[str] = None, remote_hostname: Optional[str] = None, bind_port=5060, call_callback: Optional[Callable[[:ref:`VoIPConnection`, :ref:`SIPMessage`], Optional[str]]] = None, fatal_callback: Optional[Callable[..., None]] = None, transport_mode: :ref:`TransportMode<TransportMode>` = TransportMode.UDP, cert_file: Optional[str] = None, key_file: Optional[str] = None, key_password: :ref:`KEY_PASSWORD<KEY_PASSWORD>` = None)
    The *server* argument is your PBX/VoIP server's IP.

    The *port* argument is your PBX/VoIP server's port.

    The *user* argument is the user element of the URI. This MAY not be the username which is used for authentication.

    The *credentials_manager* argument is a :ref:`CredentialsManager` instance that stores all usernames and passwords your phone may need.

    The *bind_ip* argument is used to bind SIP and RTP ports to receive incoming calls. Default is to bind to 0.0.0.0, however, this is not recommended.

    The *bind_network* argument is used to configure pyVoIP's NAT. pyVoIP uses this to know whether to use the *hostname* or *remote_hostname* when generating SIP requests to in-network and out-of-network devices respectively. Value must be a string with IPv4 CIDR notation.

    The *hostname* argument is used to generate SIP requests and responses with devices within pyVoIP's *bind_network*. If left as None, the *bind_ip* will be used instead.

    The *remote_hostname* argument is used to generate SIP requests and responses with devices outside of pyVoIP's *bind_network*. If left as None, pyVoIP will throw a :ref:`NATError<NATError>` if a request is sent outside of pyVoIP's *bind_network*.

    The *bind_port* argument is the port SIP will bind to to receive SIP requests. The default for this protocol is port 5060, but any port can be used.

    The *call_callback* argument is a function that tells the :ref:`VoIPPhone` instance it is receiving a call.

    The *fatal_callback* argument is a function that tells the :ref:`VoIPPhone` instance there was a fatal error, e.g., failed to register.

    The *transport_mode* argument determines whether pyVoIP will use UDP, TCP, or TLS. Value should be a :ref:`TransportMode<TransportMode>`.

    The *cert_file*, *key_file*, and *key_password* arguments are used to load certificates in pyVoIP's server context if using TLS for the transport mode. See Python's documentation on `load_cert_chain <https://docs.python.org/3/library/ssl.html?highlight=ssl#ssl.SSLContext.load_cert_chain>`_ for more details.

  **start**\ () -> None
    This method starts the SIPClient and registers with the PBX/VoIP server. It is called automatically when :ref:`VoIPPhone` starts.
    
  **stop**\ () -> None
    This method stops the SIPClient and deregisters with the PBX/VoIP server. It is called automatically when :ref:`VoIPPhone` stops.

  **send**\ (request: str) -> :ref:`VoIPConnection`
    This method starts a new SIP dialog and sends the request using the request to determine its destination.  Returns the VoIPConnection to continue the dialog.
    
  **invite**\ (number: str, ms: dict[int, dict[str, :ref:`PayloadType<payload-type>`]], sendtype: :ref:`TransmitType<TransmitType>`)
    This method generates a SIP INVITE request. This method is called by :ref:`VoIPPhone`.call().

    The *number* argument must be the number being called as a string.

    The *ms* argument is a dictionary of the media types to be used. Currently only PCMU and telephone-event is supported.

    The *sendtype* argument must be an instance of :ref:`TransmitType<TransmitType>`.
    
  **bye**\ (request: :ref:`SIPMessage`) -> None
    This method is called by :ref:`VoIPCall`.hangup(). It generates a BYE request, and then transmits the generated request. **This should not be called by the** :term:`user`.
    
  **deregister**\ () -> bool
    This method is called by SIPClient.stop() after the REGISTER thread is stopped. It will generate and transmit a REGISTER request with an Expiration of zero. Telling the PBX/VoIP server it is turning off. **This should not be called by the** :term:`user`.
    
  **register**\ () -> bool
    This method is called by the REGISTER thread. It will generate and transmit a REGISTER request telling the PBX/VoIP server that it will be online for at least 300 seconds. The REGISTER thread will call this function every 295 seconds. **This should not be called by the** :term:`user`.
    
.. _SIPMessage:

SIPMessage
==========

The SIPMessage class is used to parse SIP requests and responses and makes them easily processed by other classes.

*class* pyVoIP.SIP.message.\ **SIPMessage**\ (data: bytes)
    The *data* argument is the SIP message in bytes. It is then passed to SIPMessage.parse().
  
  SIPMessage has the following attributes:
  
    SIPMessage.\ **heading**
      This attribute is the first line of the SIP message as a string. It contains the SIP Version, and the method/response code.
      
    SIPMessage.\ **type**
      This attribute will be a :ref:`SIPMessageType<SIPMessageType>`.
      
    SIPMessage.\ **status**
      This attribute will be a :ref:`SIPStatus<SIPStatus>`. It will be set to ``int(0)`` if the message is a request.
      
    SIPMessage.\ **method**
      This attribute will be a string representation of the method. It will be set to None if the message is a response.
      
    SIPMessage.\ **headers**
      This attribute is a dictionary of all the headers in the request, and their parsed values.
      
    SIPMessage.\ **body**
      This attribute is a dictionary of the content of the body.
      
    SIPMessage.\ **authentication**
      This attribute is a dictionary of a parsed Authentication header. There are two authentication headers: Authorization, and WWW-Authenticate. See RFC 3261 Sections `20.7 <https://tools.ietf.org/html/rfc3261#section-20.7>`_ and `20.44 <https://tools.ietf.org/html/rfc3261#section-20.44>`_ respectively.
      
    SIPMessage.\ **raw**
      This attribute is an unparsed version of the *data* argument, in bytes.
      
  **summary**\ () -> str
    This method returns a string representation of the SIP request.
