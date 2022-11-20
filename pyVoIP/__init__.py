__all__ = ["SIP", "RTP", "VoIP"]

version_info = (2, 0, 0)

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
If this is set to True TLS will fall back to TCP if the TLS handshake fails.
This is off by default, as it would be irresponsible to have a security feature
disabled by default.
"""
ALLOW_TLS_FALLBACK = False


def debug(s, e=None):
    if DEBUG:
        print(s)
    elif e is not None:
        print(e)


# noqa because import will fail if debug is not defined
from pyVoIP.RTP import PayloadType  # noqa: E402

SIPCompatibleMethods = ["INVITE", "ACK", "BYE", "CANCEL", "OPTIONS"]
SIPCompatibleVersions = ["SIP/2.0"]

RTPCompatibleVersions = [2]
RTPCompatibleCodecs = [PayloadType.PCMU, PayloadType.PCMA, PayloadType.EVENT]
