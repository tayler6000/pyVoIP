Types
#####

pyVoIP has several type aliases that it stores in ``pyVoIP.types``.

.. _URI_HEADER:

pyVoIP.types.\ **URI_HEADER** = Dict[str, Union[str, int]]
    This is for URI Headers (such as To, From, Contact, etc) dictionaries in a :ref:`SIPMessage`.

.. _SOCKETS:

pyVoIP.types.\ **SOCKETS** = Union[socket.socket, ssl.SSLSocket]
    This is in a few places in :ref:`VoIPSocket` and :ref:`VoIPConnection`.

.. _KEY_PASSWORD:

pyVoIP.types.\ **KEY_PASSWORD** = Union[bytes, bytearray, str, Callable[[], bytes], Callable[[], bytearray], Callable[[], str]]
    This is used for TLS settings. See Python's documentation on `load_cert_chain's password argument <https://docs.python.org/3/library/ssl.html?highlight=ssl#ssl.SSLContext.load_cert_chain>`_ for more details.

.. _CREDENTIALS_DICT:

pyVoIP.types.\ **CREDENTIALS_DICT** = Dict[Optional[str], Dict[Optional[str], Dict[Optional[str], Dict[str, str]]]]
    This is the format of the :ref:`CredentialsManager`'s internal dictionary.
