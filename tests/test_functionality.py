from pyVoIP.VoIP import VoIPPhone, PhoneStatus, CallState
import pytest
import sys
import time

TEST_CONDITION = (
    "--check-functionality" not in sys.argv and "--check-func" not in sys.argv
)
REASON = "Not checking functionality"


@pytest.fixture
def phone():
    phone = VoIPPhone(
        "127.0.0.1",
        5060,
        "pass",
        "Testing123!",
        myIP="127.0.0.1",
        sipPort=5059,
    )
    phone.start()
    yield phone
    phone.stop()


@pytest.fixture
def nopass_phone():
    phone = VoIPPhone(
        "127.0.0.1", 5060, "nopass", "", myIP="127.0.0.1", sipPort=5059
    )
    phone.start()
    yield phone
    phone.stop()


@pytest.mark.skipif(TEST_CONDITION, reason=REASON)
def test_nopass():
    phone = VoIPPhone(
        "127.0.0.1", 5060, "nopass", "", myIP="127.0.0.1", sipPort=5059
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


@pytest.mark.skipif(TEST_CONDITION, reason=REASON)
def test_pass():
    phone = VoIPPhone(
        "127.0.0.1",
        5060,
        "pass",
        "Testing123!",
        myIP="127.0.0.1",
        sipPort=5059,
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


@pytest.mark.skipif(TEST_CONDITION, reason=REASON)
def test_make_call(phone):
    call = phone.call("answerme")
    while call.state == CallState.DIALING:
        time.sleep(0.1)
    assert call.state == CallState.ANSWERED
    call.hangup()
    assert call.state == CallState.ENDED


@pytest.mark.skipif(TEST_CONDITION, reason=REASON)
def test_make_nopass_call(nopass_phone):
    call = nopass_phone.call("answerme")
    while call.state == CallState.DIALING:
        time.sleep(0.1)
    assert call.state == CallState.ANSWERED
    call.hangup()
    assert call.state == CallState.ENDED


@pytest.mark.skip
@pytest.mark.skipif(TEST_CONDITION, reason=REASON)
def test_remote_hangup(phone):
    call = phone.call("answerme")
    while call.state == CallState.DIALING:
        time.sleep(0.1)
    assert call.state == CallState.ANSWERED
    time.sleep(5)
    assert call.state == CallState.ENDED
