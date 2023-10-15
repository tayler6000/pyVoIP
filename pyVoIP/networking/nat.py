from typing import Optional
import ipaddress
import socket


class NATError(Exception):
    pass


class NAT:
    def __init__(
        self,
        bind_ip: str,
        network: str,
        hostname: Optional[str] = None,
        remote_hostname: Optional[str] = None,
    ):
        self.bind_ip = ipaddress.ip_address(bind_ip)
        self.network = ipaddress.ip_network(network)
        self.hostname = bind_ip if hostname is None else hostname
        self.remote_hostname = remote_hostname

    def get_host(self, host: str):
        """Return the hostname another client needs to connect to us."""
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            try:
                ip = socket.gethostbyname(host)
            except socket.gaierror:
                raise NATError(f"Unable to resolve hostname {host}")

        if ip in self.network:
            return self.hostname
        else:
            if self.remote_hostname is not None:
                return self.remote_hostname
            raise NATError(
                "No remote hostname specified, "
                + "cannot provide a return path for remote hosts."
            )
