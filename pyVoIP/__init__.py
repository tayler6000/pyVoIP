import ssl

__all__ = ["SIP", "RTP", "VoIP"]

version_info = (2, 0, "0a5")

__version__ = ".".join([str(x) for x in version_info])

DEBUG = False

"""
The higher this variable is, the more often RTP packets are sent.
This should only ever need to be 0.0. However, when testing on Windows,
there has sometimes been jittering, setting this to 0.75 fixed this in testing.
"""
TRANSMIT_DELAY_REDUCTION = 0.0

"""
Basic authentication is deprecated as it will send your password in plain-text,
likely in the clear (unencrypted) as well. As such this is disabled be default.
"""
ALLOW_BASIC_AUTH = False

"""
MD5 Digest authentication is deprecated as it a weak hash. However, it is still
used often so it is enabled by default.
"""
ALLOW_MD5_AUTH = True

"""
If registration fails this many times, VoIPPhone's status will be set to FAILED
and the phone will stop.
"""
REGISTER_FAILURE_THRESHOLD = 3

# TODO: Implement
"""
If this is set to True TLS will fall back to TCP if the TLS handshake fails.
This is off by default, as it would be irresponsible to have a security feature
disabled by default.

This is currently not implemented.
"""
ALLOW_TLS_FALLBACK = False

"""
The default TLS settings do not allow you to connect to servers with
self-signed certificates. These options below allow you to change those
settings. Refer to the SSL library documentation below. These settings must be
changed in a specific order, so the function pyVoIP.set_tls_security was
created as a helper function.
"""
# https://docs.python.org/3/library/ssl.html#ssl.SSLContext.check_hostname
TLS_CHECK_HOSTNAME = True

# https://docs.python.org/3/library/ssl.html#ssl.SSLContext.verify_mode
TLS_VERIFY_MODE = ssl.CERT_REQUIRED

"""
DO NOT CHANGE IN PRODUCTION.

This variable allows you to save the SIP message state database to a file
instead of storing it in memory which is the default.  This is useful for
debugging, however pyVoIP does not delete the database afterwards which will
cause an Exception upon restarting pyVoIP.  For this reason, we recommend you
do not change this variable in production.
"""
SIP_STATE_DB_LOCATION = ":memory:"


def set_tls_security(verify_mode: ssl.VerifyMode) -> None:
    """
    Set the TLS defaults for connections.
    """
    global TLS_CHECK_HOSTNAME
    global TLS_VERIFY_MODE
    if verify_mode == ssl.CERT_NONE:
        TLS_CHECK_HOSTNAME = False
        TLS_VERIFY_MODE = verify_mode
    else:
        TLS_CHECK_HOSTNAME = True
        TLS_VERIFY_MODE = verify_mode


def debug(s, e=None):
    if DEBUG:
        print(s)
    elif e is not None:
        print(e)


# noqa because import will fail if debug is not defined
from pyVoIP.RTP import PayloadType  # noqa: E402
from pyVoIP.SIP.message.message import SIPMethod  # noqa: E402

SIPCompatibleVersions = ["SIP/2.0"]
SIPCompatibleMethods = list(map(lambda x: str(x), list(SIPMethod)))

RTPCompatibleVersions = [2]
RTPCompatibleCodecs = [PayloadType.PCMU, PayloadType.PCMA, PayloadType.EVENT]
