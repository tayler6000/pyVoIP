from pyVoIP.VoIP import VoIPPhone, PhoneStatus
import pytest
import sys
import time

TEST_CONDITION = ("--check-functionality" not in sys.argv and "--check-func" not in sys.argv)
REASON = "Not checking functionality"

@pytest.mark.skipif(TEST_CONDITION, reason=REASON)
def test_nopass():
    phone = VoIPPhone("127.0.0.1", 5060, "nopass", "", myIP="127.0.0.1", sipPort=5059)
    assert phone.get_status() == PhoneStatus.INACTIVE
    phone.start()
    while phone.get_status() == PhoneStatus.REGISTERING:
        time.sleep(.1)
    assert phone.get_status() == PhoneStatus.REGISTERED
    phone.stop()
    while phone.get_status() == PhoneStatus.DEREGISTERING:
        time.sleep(.1)
    assert phone.get_status() == PhoneStatus.INACTIVE

@pytest.mark.skipif(TEST_CONDITION, reason=REASON)
def test_pass():
    phone = VoIPPhone("127.0.0.1", 5060, "pass", "Testing123!", myIP="127.0.0.1", sipPort=5059)
    assert phone.get_status() == PhoneStatus.INACTIVE
    phone.start()
    while phone.get_status() == PhoneStatus.REGISTERING:
        time.sleep(.1)
    assert phone.get_status() == PhoneStatus.REGISTERED
    phone.stop()
    while phone.get_status() == PhoneStatus.DEREGISTERING:
        time.sleep(.1)
    assert phone.get_status() == PhoneStatus.INACTIVE
