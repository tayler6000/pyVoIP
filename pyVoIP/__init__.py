__all__ = ["SIP", "RTP", "VoIP"]

version_info = (1, 6, 1)

__version__ = ".".join([str(x) for x in version_info])

DEBUG = False

"""
The higher this variable is, the more often RTP packets are sent.
This should only ever need to be 0.0. However, when testing on Windows,
there has sometimes been jittering, setting this to 0.75 fixed this in testing.
"""
TRANSMIT_DELAY_REDUCTION = 0.0


def debug(s, e=None):
    if DEBUG:
        print(s)
    elif e is not None:
        print(e)


# noqa because import will fail if debug is not defined
from pyVoIP.RTP import PayloadType  # noqa: E402

SIPCompatibleMethods = ["INVITE", "ACK", "BYE", "CANCEL"]
SIPCompatibleVersions = ["SIP/2.0"]

RTPCompatibleVersions = [2]
RTPCompatibleCodecs = [PayloadType.PCMU, PayloadType.PCMA, PayloadType.EVENT]
