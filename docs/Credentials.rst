Credentials
###########

Since SIP requests can traverse multiple servers and can receive multiple challenges, the Credentials Manager was made to store multiple passwords and pyVoIP will use the appropriate password upon request.

Per `RFC 3261 Section 22.1 <https://www.rfc-editor.org/rfc/rfc3261.html#section-22.1>`_, SIP uses authentication similar to HTTP authentication (:RFC:`2617`), with the main difference being ``The realm string alone defines the protection domain.``. However, some services always use the same domain. For example, if you need to authenticate with two seperate Asterisk servers, the realm will almost certainly be ``asterisk`` for both, despite being otherwise unrelated servers. For that reason, the Credentials Manager also supports server filtering.

.. _CredentialsManager:

CredentialsManager
==================

*class* pyVoIP.credentials.\ **CredentialsManager**\ ()
  **add**\ (username: str, password: str, server: Optional[str] = None, realm: Optional[str] = None, user: Optional[str] = None) -> None
    This method registers a username and password combination with the Credentials Manager.

    The *username* argument is the username that will be used in the Authentication header and digest calculation.

    The *password* argument is the password that will be used in the Authentication header digest calculation.

    The *server* argument is used to determine the correct credentials when challenged for authentication. If *server* is left as ``None``, the credentials may be selected with any server.
    
    The *realm* argument is used to determine the correct credentials when challenged for authentication. If *realm* is left as ``None``, the credentials may be selected with any realm.
    
    The *user* argument is used to determine the correct credentials when challenged for authentication. If *user* is left as ``None``, the credentials may be selected with any user. The *user* argument is the user in the SIP URI, **not** the username used in authentication.
    
  **get**\ (server: str, realm: str, user: str) -> Dict[str, str]
    Looks for credentials that match the server, realm, and user in that order. If no matchng credentials are found, this will return anonymous credentials as a server MAY accept them per `RFC 3261 Section 22.1 <https://www.rfc-editor.org/rfc/rfc3261.html#section-22.1>`_.
