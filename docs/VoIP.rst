VoIP - The Bridge Between SIP and RTP
#####################################

The VoIP module coordinates between the SIP and RTP modules in order to create an effective Voice over Internet Protocol system. The VoIP system is made for your convenience, and if you have a particularly intricate situation, you can override the SIP module on initialization to fit your use case.

Errors
********

There are three errors under ``pyVoIP.VoIP.error``.

.. _invalidstateerror:

*exception* pyVoIP.VoIP.error.\ **InvalidStateError**
  This is thrown by :ref:`VoIPCall` when you try to perform an action that cannot be performed during the current :ref:`CallState<callstate>`. For example denying a call that has already been answered, hanging up a call that hasn't been answered yet, or has already ended.
  
*exception* pyVoIP.VoIP.error.\ **InvalidRangeError**
  This is thrown by :ref:`VoIPPhone` when you define the RTP port ranges as rtp_port_low > rtp_port_high. However, this is not checked by :ref:`VoIPCall`, so if you are using your own class instead of VoIPPhone, make sure these ranges are correct.
  
*exception* pyVoIP.VoIP.error.\ **NoPortsAvailableError**
  This is thrown when a call is attempting to be initiated but no RTP ports are available.

Enums
***********

.. _callstate:

*enum* pyVoIP.VoIP.call.\ **CallState**
  CallState is an Enum with six attributes.

  CallState.\ **DIALING**
    This CallState is used to describe when a :term:`user` has originated a call to a :term:`client`, but it has yet to be answered.

    In this state, you can use ``VoIPCall.cancel()``.

  CallState.\ **RINGING**
    This CallState is used to describe when a :term:`client` is calling, but the call has yet to be answered.

    In this state, you can use ``VoIPCall.answer()`` or ``VoIPCall.deny()``.

  CallState.\ **PROGRESS**
    This CallState is used when a 183 Session Progress response is received on a call that is dialing.

    In this state, you can use ``VoIPCall.answer()``, ``VoIPCall.deny()``, or ``VoIPCall.cancel()``.

  CallState.\ **ANSWRED**
    This CallState is used to describe when a call has been answered and is active.

    In this state, you can use ``VoIPCall.hangup()``.

  CallState.\ **CANCELING**
    This CallState is used when a dialing call is canceled with ``VoIPCall.cancel()``.

  CallState.\ **ENDED**
    This CallState is used to describe when a call has been terminated.

.. _PhoneStatus:

*enum* pyVoIP.VoIP.status.\ **PhoneStatus**
  PhoneStatus is an Enum with five attributes.

  PhoneStatus.\ **INACTIVE**
    This PhoneStatus is used when ``VoIPPhone.start()`` has not been called, or after the phone has fully stopped after calling ``VoIPPhone.stop()``.

  PhoneStatus.\ **REGISTERING**
    This PhoneStatus is used when ``VoIPPhone.start()`` has been called, but has not finished starting, or when the phone is re-registering.

  PhoneStatus.\ **REGISTERED**
    This PhoneStatus is used when ``VoIPPhone`` has finished starting successfully, and is ready for use.

  PhoneStatus.\ **DEREGISTERING**
    This PhoneStatus is used when ``VoIPPhone.stop()`` has been called, but has not finished stopping.

  PhoneStatus.\ **FAILED**
    This PhoneStatus is used when ``VoIPPhone.start()`` has been called, but failed to start due to an error.

Classes
********

.. _VoIPCall:

VoIPCall
=========

The VoIPCall class is used to represent a single VoIP session, which may be to multiple :term:`clients<client>`.

*class* pyVoIP.VoIP.call.\ **VoIPCall**\ (phone: :ref:`VoIPPhone`, callstate: :ref:`CallState <CallState>`, request: :ref:`SIPMessage`, session_id: int, bind_ip: str, conn: :ref:`VoIPConnection`, ms: Optional[Dict[int, :ref:`PayloadType<payload-type>`]] = None, sendmode="sendonly")
      The *phone* argument is the initating instance of :ref:`VoIPPhone`.

      The *callstate* arguement is the initiating :ref:`CallState<callstate>`.

      The *request* argument is the :ref:`SIPMessage` representation of the SIP INVITE request from the VoIP server.

      The *session_id* argument is a unique code used to identify the session with `SDP <https://tools.ietf.org/html/rfc4566#section-5.2>`_ when answering the call.

      The *bind_ip* argument is the IP address that pyVoIP will bind its sockets to.

      The *ms* arguement is a dictionary with int as the key and a :ref:`PayloadType<payload-type>` as the value. This is only used when originating the call.


    **get_dtmf**\ (length=1) -> str
      This method can be called get the next pressed DTMF key. DTMF's are stored in an `StringIO <https://docs.python.org/3/library/io.html?highlight=stringio#io.StringIO>`_ which is a buffer. Calling this method when there a key has not been pressed returns an empty string. To return the entire contents of the buffer set length to a negative number or None. If the :term:`client` presses the numbers 1-9-5 you'll have the following output:
  
      .. code-block:: python
  
        self.get_dtmf()
        >>> '1'
        self.get_dtmf(length=2)
        >>> '95'
        self.get_dtmf()
        >>> ''


    **answer**\ () -> None
      Answers the call if the phone's state is CallState.RINGING.

    **transfer**\ (user: Optional[str] = None, uri: Optional[str] = None, blind=True) -> bool
      Sends a REFER request to transfer the call. If blind is true (default), the call will immediately end after received a 200 or 202 response. Otherwise, it will wait for the Transferee to report a successful transfer. Or, if the transfer is unsuccessful, the call will continue. This function returns true if the transfer is blind or successful, and returns false if it is unsuccessful.

      If using a URI to transfer, you must use a complete URI to include <> brackets as necessary.

    **ringing**\ (request: :ref:`SIPMessage`) -> None
      This function is what is called when receiving a new call. Custom VoIPCall classes should override this function to answer the call.
 
    **deny**\ () -> None
      Denies the call if the phone's state is CallState.RINGING.
 
    **hangup**\ () -> None
      Ends the call if the phone's state is CallState.ANSWRED.
 
    **cancel**\ () -> None
      Cancels a dialing call.
 
    **write_audio**\ (data: bytes) -> None
      Writes linear/raw audio data to the transmit buffer before being encoded and sent. The *data* argument MUST be bytes. **This audio must be linear/not encoded.** :ref:`RTPClient` **will encode it before transmitting.**
 
    **read_audio**\ (length=160, blocking=True) -> bytes
      Reads linear/raw audio data from the received buffer. Returns *length* amount of bytes. Default length is 160 as that is the amount of bytes sent per PCMU/PCMA packet. When *blocking* is set to true, this function will not return until data is available. When *blocking* is set to false and data is not available, this function will return ``b"\x80" * length``.
    
.. _VoIPPhoneParameter:

VoIPPhoneParameter
==================

*class* pyVoIP.VoIP.phone.\ **VoIPPhoneParameter**\ (server: str, port: int, user: str, credentials_manager: Optional[:ref:`CredentialsManager`],  bind_ip="0.0.0.0", bind_port=5060, bind_network="0.0.0.0/0", hostname: Optional[str] = None, remote_hostname: Optional[str] = None, transport_mode=\ :ref:`TransportMode<TransportMode>`.UDP, cert_file: Optional[str] = None, key_file: Optional[str] = None, key_password: :ref:`KEY_PASSWORD<KEY_PASSWORD>` = None, rtp_port_low=10000, rtp_port_high=20000, call_class: Type[VoIPCall] = None, sip_class: Type[SIP.SIPClient] = None)
    The *server* argument is your PBX/VoIP server's IP.

    The *port* argument is your PBX/VoIP server's port.

    The *user* argument is the user element of the URI. This MAY not be the username which is used for authentication.

    The *credentials_manager* argument is a :ref:`CredentialsManager` instance that stores all usernames and passwords your phone may need.

    The *bind_ip* argument is used to bind SIP and RTP ports to receive incoming calls. Default is to bind to 0.0.0.0, however, this is not recommended.

    The *bind_port* argument is the port SIP will bind to to receive SIP requests. The default for this protocol is port 5060, but any port can be used.

    The *bind_network* argument is used to configure pyVoIP's NAT. pyVoIP uses this to know whether to use the *hostname* or *remote_hostname* when generating SIP requests to in-network and out-of-network devices respectively. Value must be a string with IPv4 CIDR notation.

    The *hostname* argument is used to generate SIP requests and responses with devices within pyVoIP's *bind_network*. If left as None, the *bind_ip* will be used instead.

    The *remote_hostname* argument is used to generate SIP requests and responses with devices outside of pyVoIP's *bind_network*. If left as None, pyVoIP will throw a :ref:`NATError<NATError>` if a request is sent outside of pyVoIP's *bind_network*.

    The *transport_mode* argument determines whether pyVoIP will use UDP, TCP, or TLS. Value should be a :ref:`TransportMode<TransportMode>`.

    The *cert_file*, *key_file*, and *key_password* arguments are used to load certificates in pyVoIP's server context if using TLS for the transport mode. See Python's documentation on `load_cert_chain <https://docs.python.org/3/library/ssl.html?highlight=ssl#ssl.SSLContext.load_cert_chain>`_ for more details.

    The *rtp_port_low* and *rtp_port_high* arguments are used to generate random ports to use for audio transfer. Per RFC 4566 Sections `5.7 <https://tools.ietf.org/html/rfc4566#section-5.7>`_ and `5.14 <https://tools.ietf.org/html/rfc4566#section-5.14>`_, it can take multiple ports to fully communicate with other :term:`clients<client>`, as such a large range is recommended. If an invalid range is given, a :ref:`InvalidStateError<invalidstateerror>` will be thrown.

    The *call_class* argument allows to override the used :ref:`VoIPCall` class (must be a child class of :ref:`VoIPCall`).

    The *sip_class* argument allows to override the used :ref:`SIPClient` class (must be a child class of :ref:`SIPClient`).

.. _VoIPPhone:

VoIPPhone
=========

The VoIPPhone class is used to manage the :ref:`SIPClient` class and create :ref:`VoIPCall`'s when there is an incoming call or a :term:`user` makes a call. It then uses the VoIPCall class to handle the call's states.

*class* pyVoIP.VoIP.phone.\ **VoIPPhone**\ (voip_phone_parameter: :ref:`VoIPPhoneParameter`)
  **get_status**\ () -> :ref:`PhoneStatus <PhoneStatus>`
    This method returns the phone's current status.
    
  **start**\ () -> None
    This method starts the :ref:`SIPClient` class. On failure, this will automatically call stop().
    
  **stop**\ () -> None
    This method ends all ongoing calls, then stops the :ref:`SIPClient` class
  
  **call**\ (number: str, payload_types: Optional[List[:ref:`PayloadType<payload-type>`]] = None) -> :ref:`VoIPCall`
    Originates a call using the specified *payload_types*, or PCMU and telephone-event by default. The *number* argument must be a string. 

    Returns a :ref:`VoIPCall` class in CallState.DIALING.

  **message**\ (number: str, body: str, ctype = "text/plain") -> bool
    Sends a MESSAGE request to the *number* with the text of *body*, and the Content-Type header is set to the value of *ctype*.
  
