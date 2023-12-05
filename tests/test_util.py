from pyVoIP.util import acquired_lock_and_unblocked_socket
from threading import Lock
from socket import socket
import pytest


def test_acquired_lock_and_unblocked_socket():
    l = Lock()
    s = socket()
    assert l.locked() is False
    assert s.getblocking() is True
    with acquired_lock_and_unblocked_socket(l, s):
        assert l.locked() is True
        assert s.getblocking() is False
    assert l.locked() is False
    assert s.getblocking() is True


def test_acquired_lock_and_unblocked_socket__with_exception():
    l = Lock()
    s = socket()
    assert l.locked() is False
    assert s.getblocking() is True
    with pytest.raises(Exception):
        with acquired_lock_and_unblocked_socket(l, s):
            assert l.locked() is True
            assert s.getblocking() is False
            raise Exception("Uh oh")
            assert False, "Should never execute"
    assert l.locked() is False
    assert s.getblocking() is True
