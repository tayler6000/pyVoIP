Networking
##########

VoIP uses a lot of complex networking in order to accomplish its tasks. The networking module handles all of these complex operations.

Errors
*******

.. _NATError:

*exception* pyVoIP.networking.nat.\ **NATError**
  This is thrown when :ref:`NAT<NAT>` is either unable to resolve a hostname or when a remote hostname has not been specified and an attempt was made to connect to a remote host.

Enums
******

.. _AddressType:

pyVoIP.networking.nat.\ **AddressType**
  Used for determining remote or local tags in SIP messages.

  AddressType.\ **REMOTE**
    
  AddressType.\ **LOCAL**

.. _TransportMode:

pyVoIP.networking.transport.\ **TransportMode**
  TransportMode is used by pyVoIP to determine what communication protocol to use. TransportMode has the following properties:

    TransportMode.\ **value**
      This is the string value of the TransportMode. For example, ``UDP`` or ``TLS``.
      
    TransportMode.\ **socket_type**
      This is the `SocketKind <https://docs.python.org/3/library/socket.html?highlight=socket#constants>`_ associated with the TransportMode.
      
    TransportMode.\ **tls_mode**
      This is either `PROTOCOL_TLS <https://docs.python.org/3/library/ssl.html?highlight=ssl#ssl.PROTOCOL_TLS>`_ when using TLS or None otherwise.
  
  Here is a list of current supported transport modes:

  TransportMode.\ **UDP**
    "UDP", `SOCK_DGRAM <https://docs.python.org/3/library/socket.html#socket.SOCK_DGRAM>`_, None
    
  TransportMode.\ **TCP**
    "TCP", `SOCK_STREAM <https://docs.python.org/3/library/socket.html#socket.SOCK_STREAM>`_, None
  
  TransportMode.\ **TLS**
    "TLS", `SOCK_STREAM <https://docs.python.org/3/library/socket.html#socket.SOCK_STREAM>`_, `PROTOCOL_TLS <https://docs.python.org/3/library/ssl.html?highlight=ssl#ssl.PROTOCOL_TLS>`_

Classes
********

.. _NAT:

NAT
===

The NAT class is used automatically understand and translate IPs and hostnames for LAN to WAN connections and vice versa.

*class* pyVoIP.networking.nat.\ **NAT**\ (bind_ip: str, network: str, hostname: Optional[str] = None, remote_hostname: Optional[str] = None)
    The *bind_ip* argument is the IP address that pyVoIP will bind its sockets to.

    The *network* argument is used to know whether to use the *hostname* or *remote_hostname* when generating SIP requests to in-network and out-of-network devices respectively. Value must be a string with IPv4 CIDR notation.

    The *hostname* argument is used to generate SIP requests and responses with devices within pyVoIP's *bind_network*. If left as None, the *bind_ip* will be used instead.

    The *remote_hostname* argument is used to generate SIP requests and responses with devices outside of pyVoIP's *bind_network*. If left as None, pyVoIP will throw a :ref:`NATError<NATError>` if a request is sent outside of pyVoIP's *bind_network*.

  **get_host**\ (host: str) -> str
    This method return the hostname another :term:`client` needs to connect to us.
    
  **check_host**\ (host: str) -> :ref:`AddressType<AddressType>`
    This method determine if a host is a remote computer or not.

.. _VoIPSocket:

VoIPSocket
==========

The VoIPSocket class is the phone's main SIP socket. It receives and processes all new dialogs, and all messages if using :ref:`TransportMode<TransportMode>`.UDP.

*class* pyVoIP.networking.sock.\ **VoIPSocket**\ (mode: :ref:`TransportMode<TransportMode>`, bind_ip: str, bind_port: int, sip: :ref:`SIPClient`, cert_file: Optional[str] = None, key_file: Optional[str] = None, key_password: :ref:`KEY_PASSWORD<KEY_PASSWORD>` = None)
    The *TransportMode* argument is used to determine what communication protocol to use.

    The *bind_ip* argument is the IP address that pyVoIP will bind its sockets to.

    The *bind_port* argument is the port SIP will bind to to receive SIP requests.

    The *sip* argument is a :ref:`SIPClient` instance reference.

    The *cert_file*, *key_file*, and *key_password* arguments are used to load certificates in pyVoIP's server context if using TLS for the transport mode. See Python's documentation on `load_cert_chain <https://docs.python.org/3/library/ssl.html?highlight=ssl#ssl.SSLContext.load_cert_chain>`_ for more details.

  **get_database_dump**\ (pretty=False) -> str
    If using UDP, all messages and dialog states are stored in an in-memory sqlite3 database. This function will return a string with all entries from the dialogs (listening) table and unread messages (msgs) table. If *pretty* is set to true, it will use Python's pprint module to make the test reader friendly for a print statement. If *pretty* is set to false, it will return JSON instead.

  **send**\ (data: bytes) -> :ref:`VoIPConnection`
    Creates a new connection / dialog, sends the data, then returns the socket.

.. _VoIPConnection:

VoIPConnection
==============

The VoIPConnecion class is a wrapper for Python's sockets. Since UDP, TCP, and TLS sockets all have different quarks in Python, this class consolidates everything into one interface. For UDP, VoIPConnection will pull messages from :ref:`VoIPSocket`'s database.

*class* pyVoIP.networking.sock.\ **VoIPConnection**\ (voip_sock: :ref:`VoIPSocket`, conn: Optional[:ref:`SOCKETS<SOCKETS>`, message: :ref:`SIPMessage`)
    The *voiop_socket* argument is a :ref:`VoIPSocket` instance reference.

    The *conn* argument is the underlying Python socket.

    The *message* argument is the :ref:`SIPMessage` used to initate the dialog.

  **send**\ (data: Union[bytes, str]) -> None
    Sends *data* to the :term:`client`. If *data* is a string, it will be UTF8 encoded first.

  **peak**\ () -> bytes
    Calls ``recv`` with *peak* set to true.

  **recv**\ (nbytes=8192, timeout=0, peak=False) -> bytes
    Receives the next *nbytes* from the socket. The *timeout* argument is in seconds, and if set to ``0`` it will not timeout. If the *peak* argument is set to True, it will receive the next *nbytes* from the socket and return them, however, the same data will be returned upon the next call of ``recv``.

  **close**\ () -> None
    Closes the socket.
