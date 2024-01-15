VoIP - The Bridge Between SIP and RTP
#####################################

The VoIP module coordinates between the SIP and RTP modules in order to create an effective Voice over Internet Protocol system.  The VoIP system is made for your convenience, and if you have a particularly intricate situation, you can use the SIP and RTP modules independently and create your own version of the VoIP module.  If you choose to use the VoIP module, this section will explain how.

Errors
********

There are two errors under ``pyVoIP.VoIP``.

.. _invalidstateerror:

*exception* VoIP.\ **InvalidStateError**
  This is thrown by :ref:`VoIPCall` when you try to perform an action that cannot be performed during the current :ref:`CallState<callstate>`.  For example denying a call that has already been answered, hanging up a call that hasn't been answered yet, or has already been ended.
  
*exception* VoIP.\ **InvalidRangeError**
  This is thrown by :ref:`VoIPPhone` when you define the rtpPort ranges as rtpPortLow > rtpPortHigh.  However, this is not checked by :ref:`VoIPCall`, so if you are using your own class instead of VoIPPhone, make sure these ranges are correct.
  
*exception* VoIP.\ **NoPortsAvailableError**
  This is thrown when a call is attempting to be initiated but no ports are available.

Enums
***********

.. _callstate:

VoIP.\ **CallState**
  CallState is an Enum with four attributes.
  
  CallState.\ **DIALING**
    This CallState is used to describe when a :term:`user` has originated a call to a :term:`client`, but it has yet to be answered.
  
  CallState.\ **RINGING**
    This CallState is used to describe when a :term:`client` is calling, but the call has yet to be answered.
    
    In this state, you can use ``VoIPCall.answer()`` or ``VoIPCall.deny()``.
  
  CallState.\ **ANSWRED**
    This CallState is used to describe when a call has been answered and is active.
    
    In this state, you can use ``VoIPCall.hangup()``.
    
  CallState.\ **ENDED**
    This CallState is used to describe when a call has been terminated.
    
    In this state, you can not use any functions.

.. _phonestatus

VoIP.\ **PhoneStatus**
  PhoneStatus is an Enum with five attributes.

  PhoneStatus.\ **INACTIVE**
    This PhoneStatus is used when ``VoIPPhone.start()`` has not been called, or after the phone has fully stopped after calling ``VoIPPhone.stop()``.

  PhoneStatus.\ **REGISTERING**
    This PhoneStatus is used when ``VoIPPhone.start()`` has been called, but has not finished starting.

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

The VoIPCall class is used to represent a single VoIP Session, which may be to multiple :term:`clients<client>`.

*class* VoIP.\ **VoIPCall**\ (phone: :ref:`VoIPPhone`, request: :ref:`SIPMessage`, session_id: int, myIP: str, rtpPortLow: int, rtpPortHigh: int)
      The *phone* argument is the initating instance of :ref:`VoIPPhone`.
     
      The *callstate* arguement is the initiating :ref:`CallState<callstate>`.
     
      The *request* argument is the :ref:`SIPMessage` representation of the SIP INVITE request from the VoIP server.
     
      The *session_id* argument is a unique code used to identify the session with `SDP <https://tools.ietf.org/html/rfc4566#section-5.2>`_ when answering the call.
     
      The *myIP* argument is the IP address it will pass to :ref:`RTPClient`'s to bind to.
     
      The *ms* arguement is a dictionary with int as the key and a :ref:`PayloadType<payload-type>` as the value.  This is only used when originating the call.
     
     
    **dtmfCallback**\ (code: str) -> None
      *Deprecated.* Please use ``dtmf_callback`` instead.

    **dtmf_callback**\ (code: str) -> None
      This method is called by :ref:`RTPClient`'s when a telephone-event DTMF message is received.  The *code* argument is a string.  It should be an Event in complinace with `RFC 4733 Section 3.2 <https://tools.ietf.org/html/rfc4733#section-3.2>`_.
       
    **getDTMF**\ (length=1) -> str
      *Deprecated.* Please use ``get_dtmf`` instead.

    **get_dtmf**\ (length=1) -> str
      This method can be called get the next pressed DTMF key.  DTMF's are stored in an ``io.StringIO`` and act as a stack.  Meaning if the :term:`client` presses the numbers 1-9-5 you'll have the following output:
       
      .. code-block:: python
       
        VoIPCall.get_dtmf()
        >>> '1'
        VoIPCall.get_dtmf(length=2)
        >>> '95'
        VoIPCall.get_dtmf()
        >>> ''
      
      As you can see, calling this method when there a key has not been pressed returns an empty string.
      
    **answer**\ () -> None
      Answers the call if the phone's state is CallState.RINGING.
      
    **answered**\ (request: :ref:`SIPMessage`) -> None
      This function is called by :ref:`SIPClient` when a call originated by the :term:`user` has been answered by the :term:`client`.
      
    **deny**\ () -> None
      Denies the call if the phone's state is CallState.RINGING.
      
    **hangup**\ () -> None
      Ends the call if the phone's state is CallState.ANSWRED.
    
    **bye**\ () -> None
      Ends the call but does not send a SIP BYE message to the SIP server.  This function is used to end the call on the server side when the client ended the call.  **THE** :term:`USER<user>` **SHOUND NOT CALL THIS FUNCTION OR THE** :term:`CLIENT<client>` **WILL BE LEFT ON THE LINE WITH NO RESPONSE. CALL HANGUP() INSTEAD.**
      
    **writeAudio**\ (data: bytes) -> None
      *Deprecated.* Please use ``write_audio`` instead.

    **write_audio**\ (data: bytes) -> None
      Writes linear/raw audio data to the transmit buffer before being encoded and sent.  The *data* argument MUST be bytes.  **This audio must be linear/not encoded,** :ref:`RTPClient` **will encode it before transmitting.**
      
    **readAudio**\ (length=160, blocking=True) -> bytes
      *Deprecated.* Please use ``read_audio`` instead.

    **read_audio**\ (length=160, blocking=True) -> bytes
      Reads linear/raw audio data from the received buffer.  Returns *length* amount of bytes.  Default length is 160 as that is the amount of bytes sent per PCMU/PCMA packet.  When *blocking* is set to true, this function will not return until data is available.  When *blocking* is set to false and data is not available, this function will return ``b"\x80" * length``.
    
.. _VoIPPhone:

VoIPPhone
=========

The VoIPPhone class is used to manage the :ref:`SIPClient` class and create :ref:`VoIPCall`'s when there is an incoming call.  It then passes the VoIPCall as the argument in the callback.

*class* VoIP.\ **VoIPPhone**\ (server: str, port: int, username: str, password: str, callCallback: Optional[Callable] = None, myIP: Optional[str] = None, sipPort=5060, rtpPortLow=10000, rtpPortHigh=20000, auth_username: str)
    The *server* argument is your PBX/VoIP server's IP, represented as a string.
    
    The *port* argument is your PBX/VoIP server's port, represented as an integer.
    
    The *username* argument is your SIP account username on the PBX/VoIP server, represented as a string.
    
    The *password* argument is your SIP account password on the PBX/VoIP server, represented as a string.
    
    The *callCallback* argument is your callback function that VoIPPhone will run when you receive a call.  The callback must take one argument, which will be a :ref:`VoIPCall`.  If left as None, the VoIPPhone will automatically respond to all incoming calls as Busy.
    
    The *myIP* argument is used to bind SIP and RTP ports to receive incoming calls.  If left as None, the VoIPPhone will bind to 0.0.0.0.
    
    The *sipPort* argument is the port SIP will bind to to receive SIP requests.  The default for this protocol is port 5060, but any port can be used.
    
    The *rtpPortLow* and *rtpPortHigh* arguments are used to generate random ports to use for audio transfer.  Per RFC 4566 Sections `5.7 <https://tools.ietf.org/html/rfc4566#section-5.7>`_ and `5.14 <https://tools.ietf.org/html/rfc4566#section-5.14>`_, it can take multiple ports to fully communicate with other :term:`clients<client>`, as such a large range is recommended.  If an invalid range is given, a :ref:`InvalidStateError<invalidstateerror>` will be thrown.

    The *auth_username* argument is the optional username for proxy-authentication, represented as a string.
    
  **callback**\ (request: :ref:`SIPMessage`) -> None
    This method is called by the :ref:`SIPClient` when an INVITE or BYE request is received.  This function then creates a :ref:`VoIPCall` or terminates it respectively.  When a VoIPCall is created, it will then pass it to the *callCallback* function as an argument.  If *callCallback* is set to None, this function replies as BUSY. **This function should not be called by the** :term:`user`.

  **getStatus**\ () -> PhoneStatus
    *Deprecated.* Please use ``get_status`` instead.

  **get_status**\ () -> PhoneStatus
    This method returns the :ref:`PhoneStatus<phonestatus>`.
    
  **request_port**\ (blocking=True) -> int
    This method is called when a new port is needed to use in a :ref:`VoIPCall`.  If blocking is set to True, this will wait until a port is available.  Otherwise, it will raise NoPortsAvailableError.
    
  **release_ports**\ (call: Optional[VoIPCall] = None) -> None
    This method is called when a call ends.  If call is provided, it will only release the ports used by that :ref:`VoIPCall`.  Otherwise, it will iterate through all active calls, and release all ports that are no longer in use.
    
  **start**\ () -> None
    This method starts the :ref:`SIPClient` class.  On failure, this will automatically call stop().
    
  **stop**\ () -> None
    This method ends all currently ongoing calls, then stops the :ref:`SIPClient` class
  
  **call**\ (number: str) -> :ref:`VoIPCall`
    Originates a call using PCMU and telephone-event. The *number* argument must be a string, and it returns a :ref:`VoIPCall` class in CallState.DIALING.  You should use a while loop to wait until the CallState is ANSWRED.
  
