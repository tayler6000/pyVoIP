from pyVoIP.credentials import CredentialsManager
from pyVoIP.VoIP.call import CallState
from pyVoIP.VoIP.phone import PhoneStatus, VoIPPhone
from pyVoIP.sock.transport import TransportMode
import pytest
import pyVoIP
import ssl
import sys
import time

TEST_CONDITION = (
    "--check-functionality" not in sys.argv and "--check-func" not in sys.argv
)
REASON = "Not checking functionality"
pyVoIP.set_tls_security(ssl.CERT_NONE)
SERVER_HOST = "127.0.0.1"
UDP_PORT = 5060
TCP_PORT = 5061
TLS_PORT = 5062


@pytest.fixture
def phone():
    cm = CredentialsManager()
    cm.add("pass", "Testing123!")
    phone = VoIPPhone(
        SERVER_HOST,
        UDP_PORT,
        "pass",
        cm,
        hostname="host.docker.internal",
        bind_port=5059,
    )
    phone.start()
    yield phone
    phone.stop()


@pytest.fixture
def nopass_phone():
    phone = VoIPPhone(
        SERVER_HOST,
        UDP_PORT,
        "nopass",
        CredentialsManager(),
        hostname="host.docker.internal",
        bind_port=5059,
    )
    phone.start()
    yield phone
    phone.stop()


@pytest.mark.udp
@pytest.mark.registration
@pytest.mark.skipif(TEST_CONDITION, reason=REASON)
def test_nopass():
    phone = VoIPPhone(
        SERVER_HOST,
        UDP_PORT,
        "nopass",
        CredentialsManager(),
        hostname="host.docker.internal",
        bind_port=5059,
    )
    assert phone.get_status() == PhoneStatus.INACTIVE
    phone.start()
    while phone.get_status() == PhoneStatus.REGISTERING:
        time.sleep(0.1)
    assert phone.get_status() == PhoneStatus.REGISTERED
    phone.stop()
    while phone.get_status() == PhoneStatus.DEREGISTERING:
        time.sleep(0.1)
    assert phone.get_status() == PhoneStatus.INACTIVE


@pytest.mark.udp
@pytest.mark.registration
@pytest.mark.skipif(TEST_CONDITION, reason=REASON)
def test_pass():
    cm = CredentialsManager()
    cm.add("pass", "Testing123!")
    phone = VoIPPhone(
        SERVER_HOST,
        UDP_PORT,
        "pass",
        cm,
        hostname="host.docker.internal",
        bind_port=5059,
    )
    assert phone.get_status() == PhoneStatus.INACTIVE
    phone.start()
    while phone.get_status() == PhoneStatus.REGISTERING:
        time.sleep(0.1)
    assert phone.get_status() == PhoneStatus.REGISTERED
    phone.stop()
    while phone.get_status() == PhoneStatus.DEREGISTERING:
        time.sleep(0.1)
    assert phone.get_status() == PhoneStatus.INACTIVE


@pytest.mark.tcp
@pytest.mark.registration
@pytest.mark.skipif(TEST_CONDITION, reason=REASON)
def test_tcp_nopass():
    phone = VoIPPhone(
        SERVER_HOST,
        TCP_PORT,
        "nopass",
        CredentialsManager(),
        hostname="host.docker.internal",
        bind_port=5059,
        transport_mode=TransportMode.TCP,
    )
    assert phone.get_status() == PhoneStatus.INACTIVE
    phone.start()
    while phone.get_status() == PhoneStatus.REGISTERING:
        time.sleep(0.1)
    assert phone.get_status() == PhoneStatus.REGISTERED
    phone.stop()
    while phone.get_status() == PhoneStatus.DEREGISTERING:
        time.sleep(0.1)
    assert phone.get_status() == PhoneStatus.INACTIVE


@pytest.mark.tcp
@pytest.mark.registration
@pytest.mark.skipif(TEST_CONDITION, reason=REASON)
def test_tcp_pass():
    cm = CredentialsManager()
    cm.add("pass", "Testing123!")
    phone = VoIPPhone(
        SERVER_HOST,
        TCP_PORT,
        "pass",
        cm,
        hostname="host.docker.internal",
        bind_port=5059,
        transport_mode=TransportMode.TCP,
    )
    assert phone.get_status() == PhoneStatus.INACTIVE
    phone.start()
    while phone.get_status() == PhoneStatus.REGISTERING:
        time.sleep(0.1)
    assert phone.get_status() == PhoneStatus.REGISTERED
    phone.stop()
    while phone.get_status() == PhoneStatus.DEREGISTERING:
        time.sleep(0.1)
    assert phone.get_status() == PhoneStatus.INACTIVE


@pytest.mark.tls
@pytest.mark.registration
@pytest.mark.skipif(TEST_CONDITION, reason=REASON)
def test_tls_nopass():
    phone = VoIPPhone(
        SERVER_HOST,
        TLS_PORT,
        "nopass",
        CredentialsManager(),
        hostname="host.docker.internal",
        bind_port=5059,
        transport_mode=TransportMode.TLS,
        cert_file="certs/cert.crt",
        key_file="certs/key.txt",
        key_password=None,
    )
    assert phone.get_status() == PhoneStatus.INACTIVE
    phone.start()
    while phone.get_status() == PhoneStatus.REGISTERING:
        time.sleep(0.1)
    assert phone.get_status() == PhoneStatus.REGISTERED
    phone.stop()
    while phone.get_status() == PhoneStatus.DEREGISTERING:
        time.sleep(0.1)
    assert phone.get_status() == PhoneStatus.INACTIVE


@pytest.mark.tls
@pytest.mark.registration
@pytest.mark.skipif(TEST_CONDITION, reason=REASON)
def test_tls_pass():
    cm = CredentialsManager()
    cm.add("pass", "Testing123!")
    phone = VoIPPhone(
        SERVER_HOST,
        TLS_PORT,
        "pass",
        cm,
        hostname="host.docker.internal",
        bind_port=5059,
        transport_mode=TransportMode.TLS,
        cert_file="certs/cert.crt",
        key_file="certs/key.txt",
        key_password=None,
    )
    assert phone.get_status() == PhoneStatus.INACTIVE
    phone.start()
    while phone.get_status() == PhoneStatus.REGISTERING:
        time.sleep(0.1)
    assert phone.get_status() == PhoneStatus.REGISTERED
    phone.stop()
    while phone.get_status() == PhoneStatus.DEREGISTERING:
        time.sleep(0.1)
    assert phone.get_status() == PhoneStatus.INACTIVE


@pytest.mark.skip
@pytest.mark.udp
@pytest.mark.calling
@pytest.mark.skipif(TEST_CONDITION, reason=REASON)
def test_make_call(phone):
    call = phone.call("answerme")
    while call.state == CallState.DIALING:
        time.sleep(0.1)
    assert call.state == CallState.ANSWERED
    call.hangup()
    assert call.state == CallState.ENDED


@pytest.mark.skip
@pytest.mark.udp
@pytest.mark.calling
@pytest.mark.skipif(TEST_CONDITION, reason=REASON)
def test_make_nopass_call(nopass_phone):
    call = nopass_phone.call("answerme")
    while call.state == CallState.DIALING:
        time.sleep(0.1)
    assert call.state == CallState.ANSWERED
    call.hangup()
    assert call.state == CallState.ENDED


@pytest.mark.skip
@pytest.mark.udp
@pytest.mark.calling
@pytest.mark.skipif(TEST_CONDITION, reason=REASON)
def test_remote_hangup(phone):
    call = phone.call("answerme")
    while call.state == CallState.DIALING:
        time.sleep(0.1)
    assert call.state == CallState.ANSWERED
    time.sleep(5)
    assert call.state == CallState.ENDED
