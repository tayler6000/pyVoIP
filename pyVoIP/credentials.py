from pyVoIP.types import CREDENTIALS_DICT
from typing import Dict, Optional


class CredentialsManager:
    def __init__(self):
        self.credentials: CREDENTIALS_DICT = {}

    def add(
        self,
        username: str,
        password: str,
        server: Optional[str] = None,
        realm: Optional[str] = None,
        user: Optional[str] = None,
    ) -> None:
        """
        Add a username and password for a server, realm, and/or user.

        If you want to set a default ommit the option.  For examle, if you want
        to use the same username and password for the realm asterisk regardless
        of the server or user you would do:

        add(username, password, realm="asterisk")
        """
        if server not in self.credentials:
            self.credentials[server] = {}
        if realm not in self.credentials[server]:
            self.credentials[server][realm] = {}
        self.credentials[server][realm][user] = {
            "username": username,
            "password": password,
        }

    def get(self, server: str, realm: str, user: str) -> Dict[str, str]:
        """
        Lookup a username and password for a server, realm, and/or user.
        """
        if server in self.credentials:
            if realm in self.credentials[server]:
                if user in self.credentials[server][realm]:
                    return self.credentials[server][realm][user]
                if None in self.credentials[server][realm]:
                    return self.credentials[server][realm][None]
            if None in self.credentials[server]:
                if user in self.credentials[server][None]:
                    return self.credentials[server][None][user]
                if None in self.credentials[server][None]:
                    return self.credentials[server][None][None]
        if None in self.credentials:
            if realm in self.credentials[None]:
                if user in self.credentials[None][realm]:
                    return self.credentials[None][realm][user]
                if None in self.credentials[None][realm]:
                    return self.credentials[None][realm][None]
            if None in self.credentials[None]:
                if user in self.credentials[None][None]:
                    return self.credentials[None][None][user]
                if None in self.credentials[None][None]:
                    return self.credentials[None][None][None]
        return {
            "username": "anonymous",
            "password": "",
        }  # Default per RFC 3261 Section 22.1
