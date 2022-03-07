from pyVoIP.RTP import PayloadType

__all__ = ['SIP', 'RTP', 'VoIP']

version_info = (1, 6, 0)

__version__ = ".".join([str(x) for x in version_info])

DEBUG = False


def debug(s, e=None):
    if DEBUG:
        print(s)
    elif e is not None:
        print(e)


SIPCompatibleMethods = ['INVITE', 'ACK', 'BYE', 'CANCEL']
SIPCompatibleVersions = ['SIP/2.0']

RTPCompatibleVersions = [2]
RTPCompatibleCodecs = [PayloadType.PCMU, PayloadType.PCMA, PayloadType.EVENT]
