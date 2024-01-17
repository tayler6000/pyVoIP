from pyVoIP.credentials import CredentialsManager
from pyVoIP.VoIP.call import CallState
from pyVoIP.VoIP.phone import PhoneStatus, VoIPPhone, VoIPPhoneParameter
from pyVoIP.networking.transport import TransportMode
import json
import os
import pytest
import pyVoIP
import ssl
import subprocess
import sys
import time


IS_WINDOWS = True if os.name == "nt" else False
TEST_CONDITION = (
    "--check-functionality" not in sys.argv and "--check-func" not in sys.argv
)

if not TEST_CONDITION and not IS_WINDOWS:
    obj = json.loads(
        subprocess.check_output(["docker", "network", "inspect", "bridge"])
    )
    DOCKER_GATEWAY = obj[0]["IPAM"]["Config"][0]["Gateway"]
    CONTAINER_ID = list(obj[0]["Containers"].keys())[0]
    CONTAINER_IP = obj[0]["Containers"][CONTAINER_ID]["IPv4Address"].split(
        "/"
    )[0]

REASON = "Not checking functionality"
NT_REASON = "Test always fails on Windows"
pyVoIP.set_tls_security(ssl.CERT_NONE)
SERVER_HOST = "127.0.0.1" if IS_WINDOWS else CONTAINER_IP
BIND_IP = "0.0.0.0" if IS_WINDOWS else DOCKER_GATEWAY
UDP_PORT = 5060
TCP_PORT = 5061
TLS_PORT = 5062

CALL_TIMEOUT = 2  # 2 seconds to answer.


@pytest.fixture
def phone():
    cm = CredentialsManager()
    cm.add("pass", "Testing123!")
    voip_phone_parameter = VoIPPhoneParameter(
        server=SERVER_HOST,
        port=UDP_PORT,
        user="pass",
        credentials_manager=cm,
        hostname="host.docker.internal",
        bind_ip=BIND_IP,
        bind_port=5059,
    )
    phone = VoIPPhone(voip_phone_parameter)
    phone.start()
    yield phone
    phone.stop()


@pytest.fixture
def nopass_phone():
    voip_phone_parameter = VoIPPhoneParameter(
        server=SERVER_HOST,
        port=UDP_PORT,
        user="nopass",
        credentials_manager=CredentialsManager(),
        hostname="host.docker.internal",
        bind_ip=BIND_IP,
        bind_port=5059,
    )
    phone = VoIPPhone(voip_phone_parameter)
    phone.start()
    yield phone
    phone.stop()


@pytest.mark.udp
@pytest.mark.registration
@pytest.mark.skipif(TEST_CONDITION, reason=REASON)
def test_nopass():
    voip_phone_parameter = VoIPPhoneParameter(
        server=SERVER_HOST,
        port=UDP_PORT,
        user="nopass",
        credentials_manager=CredentialsManager(),
        hostname="host.docker.internal",
        bind_ip=BIND_IP,
        bind_port=5059,
    )
    phone = VoIPPhone(voip_phone_parameter)
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
    voip_phone_parameter = VoIPPhoneParameter(
        server=SERVER_HOST,
        port=UDP_PORT,
        user="pass",
        credentials_manager=cm,
        hostname="host.docker.internal",
        bind_ip=BIND_IP,
        bind_port=5059,
    )
    phone = VoIPPhone(voip_phone_parameter)
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
    voip_phone_parameter = VoIPPhoneParameter(
        server=SERVER_HOST,
        port=TCP_PORT,
        user="nopass",
        credentials_manager=CredentialsManager(),
        hostname="host.docker.internal",
        bind_ip=BIND_IP,
        bind_port=5059,
        transport_mode=TransportMode.TCP,
    )
    phone = VoIPPhone(voip_phone_parameter)
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
    voip_phone_parameter = VoIPPhoneParameter(
        server=SERVER_HOST,
        port=TCP_PORT,
        user="pass",
        credentials_manager=cm,
        hostname="host.docker.internal",
        bind_ip=BIND_IP,
        bind_port=5059,
        transport_mode=TransportMode.TCP,
    )
    phone = VoIPPhone(voip_phone_parameter)
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
    voip_phone_parameter = VoIPPhoneParameter(
        server=SERVER_HOST,
        port=TLS_PORT,
        user="nopass",
        credentials_manager=CredentialsManager(),
        bind_ip=BIND_IP,
        bind_port=5059,
        transport_mode=TransportMode.TLS,
        cert_file="certs/cert.crt",
        key_file="certs/key.txt",
        key_password=None,
    )
    phone = VoIPPhone(voip_phone_parameter)
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
    voip_phone_parameter = VoIPPhoneParameter(
        server=SERVER_HOST,
        port=TLS_PORT,
        user="pass",
        credentials_manager=cm,
        hostname="host.docker.internal",
        bind_ip=BIND_IP,
        bind_port=5059,
        transport_mode=TransportMode.TLS,
        cert_file="certs/cert.crt",
        key_file="certs/key.txt",
        key_password=None,
    )
    phone = VoIPPhone(voip_phone_parameter)
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
@pytest.mark.calling
@pytest.mark.skipif(TEST_CONDITION, reason=REASON)
@pytest.mark.skipif(IS_WINDOWS, reason=NT_REASON)
def test_make_call(phone):
    call = phone.call("answerme")
    start = time.time()
    while call.state == CallState.DIALING:
        time.sleep(0.1)
        if start + CALL_TIMEOUT < time.time():
            raise TimeoutError("Call was not answered before the timeout.")
    assert call.state == CallState.ANSWERED
    call.hangup()
    assert call.state == CallState.ENDED


@pytest.mark.udp
@pytest.mark.calling
@pytest.mark.skipif(TEST_CONDITION, reason=REASON)
@pytest.mark.skipif(IS_WINDOWS, reason=NT_REASON)
def test_make_nopass_call(nopass_phone):
    call = nopass_phone.call("answerme")
    start = time.time()
    while call.state == CallState.DIALING:
        time.sleep(0.1)
        if start + CALL_TIMEOUT < time.time():
            raise TimeoutError("Call was not answered before the timeout.")
    assert call.state == CallState.ANSWERED
    call.hangup()
    assert call.state == CallState.ENDED


@pytest.mark.skip
@pytest.mark.udp
@pytest.mark.calling
@pytest.mark.skipif(TEST_CONDITION, reason=REASON)
@pytest.mark.skipif(IS_WINDOWS, reason=NT_REASON)
def test_remote_hangup(phone):
    call = phone.call("answerme")
    start = time.time()
    while call.state == CallState.DIALING:
        time.sleep(0.1)
        if start + CALL_TIMEOUT < time.time():
            raise TimeoutError("Call was not answered before the timeout.")
    assert call.state == CallState.ANSWERED
    time.sleep(5)
    assert call.state == CallState.ENDED
