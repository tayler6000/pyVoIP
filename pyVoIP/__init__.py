
__all__ = ['SIP', 'RTP', 'VoIP']

version_info = (1, 5, 2)

__version__ = ".".join([str(x) for x in version_info])

DEBUG = False

def debug(s, e=None):
  if DEBUG:
    print(s)
  elif e is not None:
    print(e)

from pyVoIP.RTP import PayloadType

SIPCompatibleMethods = ['INVITE', 'ACK', 'BYE']
SIPCompatibleVersions = ['SIP/2.0']

RTPCompatibleVersions = [2]
RTPCompatibleCodecs = [PayloadType.PCMU, PayloadType.PCMA, PayloadType.EVENT]

