VoIP - The Bridge Between SIP and RTP
#####################################

The VoIP module coordinates between the SIP and RTP modules in order to create an effective Voice over Internet Protocol system.  The VoIP system is made for your convenience, and if you have a particularly intricate situation, you can use the SIP and RTP modules independently and create your own version of the VoIP module.  If you choose to use the VoIP module, this section will explain how.

Errors
********

There are two errors under ``pyVoIP.VoIP``.

.. _invalidstateerror:

*exception* VoIP.\ **InvalidStateError**
  This is thrown when you try to run :ref:`VoIPCall` when you try to perform an action that cannot be performed during the current :ref:`CallState<callstate>`.  For example denying a call that has already been answered, hanging up a call that hasn't been answered yet, or has already been ended.
  
*exception* VoIP.\ **InvalidRangeError**
  This is thrown by :ref:`VoIPPhone` when you define the rtpPort ranges as rtpPortLow > rtpPortHigh.  However this is not checked by :ref:`VoIPCall`, so if you are using your own class instead of VoIPPhone, make sure these ranges are correct.

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

Classes
********

.. _VoIPCall:

VoIPCall
=========

The VoIPCall class is used to represent a single VoIP Session, which may be to multiple :term:`clients<client>`.

*class* VoIP.\ **VoIPCall**\ (phone, request, session_id, myIP, rtpPortLow, rtpPortHigh)
      The *phone* argument is the initating instance of :ref:`VoIPPhone`.
     
      The *request* argument is the :ref:`SIPMessage` representation of the SIP INVITE request from the VoIP server.
     
      The *session_id* argument is a unique code used to identify the session with `SDP <https://tools.ietf.org/html/rfc4566#section-5.2>`_ when answering the call.
     
      The *myIP* argument is the IP address it will pass to :ref:`RTPClient`'s to bind to.
     
      The *rtpPortLow* and *rtpPortHigh* arguments are used to generate random ports to use for audio transfer.  Per RFC 4566 Sections `5.7 <https://tools.ietf.org/html/rfc4566#section-5.7>`_ and `5.14 <https://tools.ietf.org/html/rfc4566#section-5.14>`_, it can take multiple ports to fully communicate with other :term:`clients<client>`, as such a large range is recommended.
     
    **dtmfCallback**\ (code)
      This method is called by :ref:`RTPClient`'s when a telephone-event DTMF message is received.  The *code* argument is a string.  It should be an Event in complinace with `RFC 4733 Section 3.2 <https://tools.ietf.org/html/rfc4733#section-3.2>`_.
       
    **getDTMF**\ (length=1)
      This method can be called get the next pressed DTMF key.  DTMF's are stored in an ``io.StringIO`` and act as a stack.  Meaning if the :term:`client` presses the numbers 1-9-5 you'll have the following output:
       
      .. code-block:: python
       
        VoIPCall.getDTMF()
        >>> '1'
        VoIPCall.getDTMF(length=2)
        >>> '95'
        VoIPCall.getDTMF()
        >>> ''
      
      As you can see, calling this method when there a key has not been pressed returns an empty string.
      
    **answer**\ ()
      Answers the call if the phone's state is CallState.RINGING.
      
    **answered**\ (request)
      This function is called by :ref:`SIPClient` when a call originated by the :term:`user` has been answered by the :term:`client`.
      
    **deny**\ ()
      Denies the call if the phone's state is CallState.RINGING.
      
    **hangup**\ ()
      Ends the call if the phone's state is CallState.ANSWRED.
    
    **bye**\ ()
      Ends the call but does not send a SIP BYE message to the SIP server.  This function is used to end the call on the server side when the client ended the call.  **THE** :term:`USER<user>` **SHOUND NOT CALL THIS FUNCTION OR THE** :term:`CLIENT<client>` **WILL BE LEFT ON THE LINE WITH NO RESPONSE. CALL HANGUP() INSTEAD.**
      
    **writeAudio**\ (data)
      Writes linear/raw audio data to the transmit buffer before being encoded and sent.  The *data* argument MUST be bytes.  **This audio must be linear/not encoded,** :ref:`RTPClient` **will encode it before transmitting.**
      
    **readAudio**\ (length=160, blocking=True)
      Reads linear/raw audio data from the received buffer.  Returns *length* amount of bytes.  Default length is 160 as that is the amount of bytes sent per PCMU/PCMA packet.  When *blocking* is set to true, this function will not return until data is available.  When *blocking* is set to false and data is not available, this function will return bytes(length).
    
.. _VoIPPhone:

VoIPPhone
=========

The VoIPPhone class is used to manage the :ref:`SIPClient` class and create :ref:`VoIPCall`'s when there is an incoming call.  It then passes the VoIPCall as the argument in the callback.

*class* VoIP.\ **VoIPPhone**\ (server, port, username, password, callCallback=None, myIP=None, sipPort=5060, rtpPortLow=10000, rtpPortHigh=20000)
    The *server* argument is your PBX/VoIP server's IP, represented as a string.
    
    The *port* argument is your PBX/VoIP server's port, represented as an integer.
    
    The *username* argument is your SIP account username on the PBX/VoIP server, represented as a string.
    
    The *password* argument is your SIP account password on the PBX/VoIP server, represented as a string.
    
    The *callCallback* argument is your callback function that VoIPPhone will run when you receive a call.  The callback must take one argument, which will be a :ref:`VoIPCall`.  If left as None, the VoIPPhone will automatically respond to all incoming calls as Busy.
    
    The *myIP* argument is used to bind SIP and RTP ports to receive incoming calls.  If left as None, the VoIPPhone will bind to 0.0.0.0.
    
    The *sipPort* argument is the port SIP will bind to to receive SIP requests.  The default for this protocol is port 5060, but any port can be used.
    
    The *rtpPortLow* and *rtpPortHigh* arguments are used to generate random ports to use for audio transfer.  Per RFC 4566 Sections `5.7 <https://tools.ietf.org/html/rfc4566#section-5.7>`_ and `5.14 <https://tools.ietf.org/html/rfc4566#section-5.14>`_, it can take multiple ports to fully communicate with other :term:`clients<client>`, as such a large range is recommended.  If an invalid range is given, a :ref:`InvalidStateError<invalidstateerror>` will be thrown.
    
  **callback**\ (request)
    This method is called by the :ref:`SIPClient` when an INVITE or BYE request is received.  This function then creates a :ref:`VoIPCall` or terminates it respectively.  When a VoIPCall is created, it will then pass it to the *callCallback* function as an argument.  If *callCallback* is set to None, this function replies as BUSY. **This function should not be called by the** :term:`user`.
    
  **start**\ ()
    This method starts the :ref:`SIPClient` class.
    
  **stop**\ ()
    This method ends all currently ongoing calls, then stops the :ref:`SIPClient` class
  
  **call**\ (number)
    Originates a call using PCMU and telephone-event. The *number* argument must be a string, and it returns a :ref:`VoIPCall` class in CallState.DIALING.  You should use a while loop to wait until the CallState is ANSWRED.
  
