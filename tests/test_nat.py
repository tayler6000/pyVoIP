from pyVoIP.networking.nat import NAT, NATError
import pytest


@pytest.mark.parametrize(
    "nat_settings,test_against,expected",
    [
        # Test Remote Host
        (
            {
                "bind_ip": "10.0.0.4",
                "network": "10.0.0.0/24",
                "remote_hostname": "example.com",
            },
            "8.8.8.8",
            "example.com",
        ),
        (
            {
                "bind_ip": "10.0.0.4",
                "network": "10.0.0.0/24",
                "remote_hostname": "example.com",
            },
            "example.org",
            "example.com",
        ),
        (
            {
                "bind_ip": "10.0.0.4",
                "network": "10.0.0.0/24",
                "remote_hostname": "example.com",
            },
            "10.0.1.1",
            "example.com",
        ),
        (
            {
                "bind_ip": "10.0.0.4",
                "network": "10.0.0.0/16",
                "remote_hostname": "example.com",
            },
            "10.1.0.1",
            "example.com",
        ),
        # Test Remote Host with Bind 0.0.0.0
        (
            {
                "bind_ip": "0.0.0.0",
                "network": "10.0.0.0/24",
                "hostname": "10.0.0.4",
                "remote_hostname": "example.com",
            },
            "8.8.8.8",
            "example.com",
        ),
        (
            {
                "bind_ip": "0.0.0.0",
                "network": "10.0.0.0/24",
                "hostname": "10.0.0.4",
                "remote_hostname": "example.com",
            },
            "10.0.1.1",
            "example.com",
        ),
        (
            {
                "bind_ip": "0.0.0.0",
                "network": "10.0.0.0/16",
                "hostname": "10.0.0.4",
                "remote_hostname": "example.com",
            },
            "10.1.0.1",
            "example.com",
        ),
        # Test Local Host
        (
            {
                "bind_ip": "10.0.0.4",
                "network": "10.0.0.0/24",
            },
            "10.0.0.10",
            "10.0.0.4",
        ),
        (
            {
                "bind_ip": "10.0.0.4",
                "network": "10.0.0.0/16",
            },
            "10.0.1.1",
            "10.0.0.4",
        ),
        (
            {
                "bind_ip": "10.0.0.4",
                "network": "10.0.0.0/8",
            },
            "10.1.1.1",
            "10.0.0.4",
        ),
        # Test Local Host with Bind 0.0.0.0
        (
            {
                "bind_ip": "0.0.0.0",
                "network": "10.0.0.0/24",
                "hostname": "10.0.0.4",
            },
            "10.0.0.10",
            "10.0.0.4",
        ),
        (
            {
                "bind_ip": "0.0.0.0",
                "network": "10.0.0.0/16",
                "hostname": "10.0.0.4",
            },
            "10.0.1.1",
            "10.0.0.4",
        ),
        (
            {
                "bind_ip": "0.0.0.0",
                "network": "10.0.0.0/8",
                "hostname": "10.0.0.4",
            },
            "10.1.1.10",
            "10.0.0.4",
        ),
    ],
)
def test_nat(nat_settings, test_against, expected):
    nat = NAT(**nat_settings)
    assert nat.get_host(test_against) == expected


def test_nat_error():
    nat = NAT("192.168.0.5", "192.168.0.0/24")
    with pytest.raises(NATError):
        nat.get_host("google.com")
