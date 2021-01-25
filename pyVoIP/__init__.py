__all__ = ['SIP', 'RTP', 'VoIP']

version_info = (1, 0, 0)

__version__ = ".".join([str(x) for x in version_info])

SIPCompatibleMethods = ['INVITE', 'ACK', 'BYE']
SIPCompatibleVersions = ['SIP/2.0']

RTPCompatibleVersions = [2]