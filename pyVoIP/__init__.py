__all__ = ['SIP', 'RTP', 'VoIP']

version_info = (1, 6, 0, 2)

__version__ = ".".join([str(x) for x in version_info])

DEBUG = True



def debug(s, e=None):
    if DEBUG:
        print(s)
    elif e is not None:
        print(e)


# noqa because import will fail if debug is not defined
from pyVoIP.RTP import PayloadType  # noqa: E402

SIPCompatibleMethods = ['INVITE', 'ACK', 'BYE', 'CANCEL', 'NOTIFY']

SIPCompatibleVersions = ['SIP/2.0']

RTPCompatibleVersions = [2]
RTPCompatibleCodecs = [PayloadType.PCMU, PayloadType.PCMA, PayloadType.EVENT]
