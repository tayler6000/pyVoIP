__all__ = ['SIP', 'RTP', 'VoIP']

version_info = (0, 5, 2, '')

__version__ = ".".join([str(x) for x in version_info])

SIPCompatibleMethods = ['INVITE', 'ACK', 'BYE']
SIPCompatibleVersions = ['SIP/2.0']

RTPCompatibleVersions = [2]