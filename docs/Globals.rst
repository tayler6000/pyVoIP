Globals
#######

Global Variables
****************

There are a few global variables that may assist you if you're having problems with the library.

pyVoIP.\ **DEBUG** = False
    If set to true, pyVoIP will print debug messages that may be useful if you need to troubleshoot or open a GitHub issue.

pyVoIP.\ **TRANSMIT_DELAY_REDUCTION** = 0.0
    The higher this variable is, the more often RTP packets are sent.  This *should* only ever need to be 0.0.  However, when testing on Windows, there has sometimes been jittering, setting this to 0.75 fixed this in testing, but you may need to tinker with this number on a per-system basis.

pyVoIP.\ **ALLOW_BASIC_AUTH** = False
    Controls whether Basic authentication (:RFC:`7617`) is allowed for SIP authentication. Basic authentication is deprecated as it will send your password in plain-text, likely in the clear (unencrypted) as well. As such this is disabled be default.

pyVoIP.\ **ALLOW_MD5_AUTH** = True
    MD5 Digest authentication is deprecated per `RFC 8760 Section 3 <https://tools.ietf.org/html/rfc8760#section-3>`_ as it a weak hash. However, it is still used often so it is enabled by default.

pyVoIP.\ **REGISTER_FAILURE_THRESHOLD** = 3
    If registration fails this many times, VoIPPhone's status will be set to FAILED and the phone will stop.

pyVoIP.\ **ALLOW_TLS_FALLBACK** = False
    If this is set to True TLS will fall back to TCP if the TLS handshake fails. This is off by default, as it would be irresponsible to have a security feature disabled by default.

    This feature is currently not implemented.

pyVoIP.\ **TLS_CHECK_HOSTNAME** = True
    Is used to create SSLContexts. See Python's documentation on `check_hostname <https://docs.python.org/3/library/ssl.html#ssl.SSLContext.check_hostname>`_ for more details.

    You should use the :ref:`set_tls_security <set_tls_security>` function to change this variable.

pyVoIP.\ **TLS_VERIFY_MODE** = True
    Is used to create SSLContexts. See Python's documentation on `verify_mode <https://docs.python.org/3/library/ssl.html#ssl.SSLContext.verify_mode>`_ for more details.

    You should use the :ref:`set_tls_security <set_tls_security>` function to change this variable.

pyVoIP.\ **SIP_STATE_DB_LOCATION** = ":memory:"
    This variable allows you to save the SIP message state database to a file instead of storing it in memory which is the default.  This is useful for debugging, however pyVoIP does not delete the database afterwards which will cause an Exception upon restarting pyVoIP.  For this reason, we recommend you do not change this variable in production.

Global Functions
****************

.. _set_tls_security:

pyVoIP.\  **set_tls_security**\ (verify_mode: `VerifyMode <https://docs.python.org/3/library/ssl.html?highlight=ssl#ssl.VerifyMode>`_) -> None
    This method ensures that TLS_CHECK_HOSTNAME and TLS_VERIFY_MODE are set correctly depending on the TLS certificate verification settings you want to use.
