from pyVoIP.SIP.message.message import SIPMessage, SIPResponse
import pytest


@pytest.mark.parametrize(
    "packet,expected",
    [
        (
            b"""SIP/2.0 401 Unauthorized\r\nVia: SIP/2.0/UDP 0.0.0.0:5060;branch=z9hG4bK03150189fc65493a9d4e3a582;rport=5060;received=192.168.178.110\r\nFrom: "tarantulla" <sip:tarantulla@192.168.178.1>;tag=9338abd3\r\nTo: "tarantulla" <sip:tarantulla@192.168.178.1>;tag=950C00889AC0DB3B\r\nCall-ID: 6b86b273ff34fce19d6b804eff5a3f57@0.0.0.0:5060\r\nCSeq: 1 REGISTER\r\nWWW-Authenticate: Digest realm="fritz.box", nonce="78B29326485EAE52"\r\nUser-Agent: FRITZ!OS\r\nContent-Length: 0\r\n\r\n""",
            {
                "header": "WWW-Authenticate",
                "method": "Digest",
                "realm": "fritz.box",
                "nonce": "78B29326485EAE52",
            },
        ),
        (
            b"""SIP/2.0 401 Unauthorized\r\nVia: SIP/2.0/UDP 0.0.0.0:5060;branch=z9hG4bK03150189fc65493a9d4e3a582;rport=5060;received=192.168.178.110\r\nFrom: "tarantulla" <sip:tarantulla@192.168.178.1>;tag=9338abd3\r\nTo: "tarantulla" <sip:tarantulla@192.168.178.1>;tag=950C00889AC0DB3B\r\nCall-ID: 6b86b273ff34fce19d6b804eff5a3f57@0.0.0.0:5060\r\nCSeq: 1 REGISTER\r\nWWW-Authenticate: Digest algorithm=MD5,realm="local",nonce="111111:222222aaaaaa333333bbbbbb444444"\r\nUser-Agent: FRITZ!OS\r\nContent-Length: 0\r\n\r\n""",
            {
                "header": "WWW-Authenticate",
                "method": "Digest",
                "algorithm": "MD5",
                "realm": "local",
                "nonce": "111111:222222aaaaaa333333bbbbbb444444",
            },
        ),
        (
            b"""SIP/2.0 401 Unauthorized\r\nVia: SIP/2.0/UDP 0.0.0.0:5060;branch=z9hG4bK03150189fc65493a9d4e3a582;rport=5060;received=192.168.178.110\r\nFrom: "tarantulla" <sip:tarantulla@192.168.178.1>;tag=9338abd3\r\nTo: "tarantulla" <sip:tarantulla@192.168.178.1>;tag=950C00889AC0DB3B\r\nCall-ID: 6b86b273ff34fce19d6b804eff5a3f57@0.0.0.0:5060\r\nCSeq: 1 REGISTER\r\nWWW-Authenticate: Digest algorithm=MD5, realm="asterisk",nonce="45f77cee"\r\nUser-Agent: FRITZ!OS\r\nContent-Length: 0\r\n\r\n""",
            {
                "header": "WWW-Authenticate",
                "method": "Digest",
                "algorithm": "MD5",
                "realm": "asterisk",
                "nonce": "45f77cee",
            },
        ),
        (
            b"""SIP/2.0 401 Unauthorized\r\nVia: SIP/2.0/UDP 192.168.0.76:5060;rport=5060;received=192.168.0.76;branch=z9hG4bK92b19bf363d84d2ea95d18cd3\r\nCall-ID: 6b86b273ff34fce19d6b804eff5a3f57@192.168.0.76:5060\r\nFrom: "5555" <sip:5555@192.168.0.100>;tag=fb11549a\r\nTo: "5555" <sip:5555@192.168.0.100>;tag=z9hG4bK92b19bf363d84d2ea95d18cd3\r\nCSeq: 1 REGISTER\r\nWWW-Authenticate: Digest realm="asterisk",nonce="1664256201/30ff48bd45c78b935077262030d584bd",opaque="5f0937be1ccec4cf",algorithm=md5,qop="auth"\r\nServer: Asterisk PBX 18.2.0\r\nContent-Length:  0\r\n\r\n""",
            {
                "header": "WWW-Authenticate",
                "method": "Digest",
                "algorithm": "md5",
                "realm": "asterisk",
                "nonce": "1664256201/30ff48bd45c78b935077262030d584bd",
                "opaque": "5f0937be1ccec4cf",
                "qop": ["auth"],
            },
        ),
        (
            b"""SIP/2.0 401 Unauthorized\r\nVia: SIP/2.0/UDP 192.168.0.76:5060;rport=5060;received=192.168.0.76;branch=z9hG4bK92b19bf363d84d2ea95d18cd3\r\nCall-ID: 6b86b273ff34fce19d6b804eff5a3f57@192.168.0.76:5060\r\nFrom: "5555" <sip:5555@192.168.0.100>;tag=fb11549a\r\nTo: "5555" <sip:5555@192.168.0.100>;tag=z9hG4bK92b19bf363d84d2ea95d18cd3\r\nCSeq: 1 REGISTER\r\nWWW-Authenticate: Digest realm="asterisk",nonce="1664256201/30ff48bd45c78b935077262030d584bd",opaque="5f0937be1ccec4cf",algorithm=md5,qop="auth, auth-int",userhash=true\r\nServer: Asterisk PBX 18.2.0\r\nContent-Length:  0\r\n\r\n""",
            {
                "header": "WWW-Authenticate",
                "method": "Digest",
                "algorithm": "md5",
                "realm": "asterisk",
                "nonce": "1664256201/30ff48bd45c78b935077262030d584bd",
                "opaque": "5f0937be1ccec4cf",
                "qop": ["auth", "auth-int"],
                "userhash": True,
            },
        ),
        # Some RFC examples, some are deprecated.
        (
            b"""SIP/2.0 401 Unauthorized\r\nVia: SIP/2.0/UDP 0.0.0.0:5060;branch=z9hG4bK03150189fc65493a9d4e3a582;rport=5060;received=192.168.178.110\r\nFrom: "tarantulla" <sip:tarantulla@192.168.178.1>;tag=9338abd3\r\nTo: "tarantulla" <sip:tarantulla@192.168.178.1>;tag=950C00889AC0DB3B\r\nCall-ID: 6b86b273ff34fce19d6b804eff5a3f57@0.0.0.0:5060\r\nCSeq: 1 REGISTER\r\nWWW-Authenticate: Basic realm="WallyWorld"\r\nUser-Agent: FRITZ!OS\r\nContent-Length: 0\r\n\r\n""",
            {
                "header": "WWW-Authenticate",
                "method": "Basic",
                "realm": "WallyWorld",
            },
        ),
        (
            b"""SIP/2.0 401 Unauthorized\r\nVia: SIP/2.0/UDP 0.0.0.0:5060;branch=z9hG4bK03150189fc65493a9d4e3a582;rport=5060;received=192.168.178.110\r\nFrom: "tarantulla" <sip:tarantulla@192.168.178.1>;tag=9338abd3\r\nTo: "tarantulla" <sip:tarantulla@192.168.178.1>;tag=950C00889AC0DB3B\r\nCall-ID: 6b86b273ff34fce19d6b804eff5a3f57@0.0.0.0:5060\r\nCSeq: 1 REGISTER\r\nWWW-Authenticate: Digest realm="http-auth@example.org",qop="auth, auth-int",algorithm=SHA-256,nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"\r\nUser-Agent: FRITZ!OS\r\nContent-Length: 0\r\n\r\n""",
            {
                "header": "WWW-Authenticate",
                "method": "Digest",
                "algorithm": "SHA-256",
                "realm": "http-auth@example.org",
                "nonce": "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
                "opaque": "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS",
                "qop": ["auth", "auth-int"],
            },
        ),
    ],
)
def test_sip_authentication(packet, expected):
    message = SIPMessage.from_bytes(packet)
    assert type(message) is SIPResponse
    assert message.authentication == expected


@pytest.mark.parametrize(
    "packet,expected",
    [
        (
            b"""SIP/2.0 401 Unauthorized\r\nVia: SIP/2.0/UDP 0.0.0.0:5060;branch=z9hG4bK03150189fc65493a9d4e3a582;rport=5060;received=192.168.178.110\r\nFrom: "tarantulla" <sip:tarantulla@192.168.178.1>;tag=9338abd3\r\nTo: "tarantulla" <sip:tarantulla@192.168.178.1>;tag=950C00889AC0DB3B\r\nCall-ID: 6b86b273ff34fce19d6b804eff5a3f57@0.0.0.0:5060\r\nCSeq: 1 REGISTER\r\nWWW-Authenticate: Digest realm="fritz.box", nonce="78B29326485EAE52"\r\nUser-Agent: FRITZ!OS\r\nContent-Length: 0\r\n\r\n""",
            {
                "raw": '"tarantulla" <sip:tarantulla@192.168.178.1>;tag=950C00889AC0DB3B',
                "tag": "950C00889AC0DB3B",
                "uri": "sip:tarantulla@192.168.178.1",
                "uri-type": "sip",
                "user": "tarantulla",
                "password": "",
                "display-name": "tarantulla",
                "host": "192.168.178.1",
                "port": 5060,
            },
        ),
        (
            b"""SIP/2.0 401 Unauthorized\r\nVia: SIP/2.0/UDP 192.168.0.76:5060;rport=5060;received=192.168.0.76;branch=z9hG4bK92b19bf363d84d2ea95d18cd3\r\nCall-ID: 6b86b273ff34fce19d6b804eff5a3f57@192.168.0.76:5060\r\nFrom: "5555" <sip:5555@192.168.0.100>;tag=fb11549a\r\nTo: "5555" <sip:5555@192.168.0.100>;tag=z9hG4bK92b19bf363d84d2ea95d18cd3\r\nCSeq: 1 REGISTER\r\nWWW-Authenticate: Digest realm="asterisk",nonce="1664256201/30ff48bd45c78b935077262030d584bd",opaque="5f0937be1ccec4cf",algorithm=md5,qop="auth"\r\nServer: Asterisk PBX 18.2.0\r\nContent-Length:  0\r\n\r\n""",
            {
                "raw": '"5555" <sip:5555@192.168.0.100>;tag=z9hG4bK92b19bf363d84d2ea95d18cd3',
                "tag": "z9hG4bK92b19bf363d84d2ea95d18cd3",
                "uri": "sip:5555@192.168.0.100",
                "uri-type": "sip",
                "user": "5555",
                "password": "",
                "display-name": "5555",
                "host": "192.168.0.100",
                "port": 5060,
            },
        ),
        (
            b"""SIP/2.0 401 Unauthorized\r\nVia: SIP/2.0/UDP 192.168.0.76:5060;rport=5060;received=192.168.0.76;branch=z9hG4bK92b19bf363d84d2ea95d18cd3\r\nCall-ID: 6b86b273ff34fce19d6b804eff5a3f57@192.168.0.76:5060\r\nFrom: "5555" <sip:5555@192.168.0.100>;tag=fb11549a\r\nTo: "5555" <sip:5555:secret_password@192.168.0.100:616>;tag=z9hG4bK92b19bf363d84d2ea95d18cd3\r\nCSeq: 1 REGISTER\r\nWWW-Authenticate: Digest realm="asterisk",nonce="1664256201/30ff48bd45c78b935077262030d584bd",opaque="5f0937be1ccec4cf",algorithm=md5,qop="auth"\r\nServer: Asterisk PBX 18.2.0\r\nContent-Length:  0\r\n\r\n""",
            {
                "raw": '"5555" <sip:5555:secret_password@192.168.0.100:616>;tag=z9hG4bK92b19bf363d84d2ea95d18cd3',
                "tag": "z9hG4bK92b19bf363d84d2ea95d18cd3",
                "uri": "sip:5555@192.168.0.100:616",
                "uri-type": "sip",
                "user": "5555",
                "password": "secret_password",
                "display-name": "5555",
                "host": "192.168.0.100",
                "port": 616,
            },
        ),
        (
            b"""SIP/2.0 401 Unauthorized\r\nVia: SIP/2.0/UDP 192.168.0.76:5060;rport=5060;received=192.168.0.76;branch=z9hG4bK92b19bf363d84d2ea95d18cd3\r\nCall-ID: 6b86b273ff34fce19d6b804eff5a3f57@192.168.0.76:5060\r\nFrom: "5555" <sip:5555@192.168.0.100>;tag=fb11549a\r\nTo: "5555" <sip:5555:secret_password@192.168.0.100>;tag=z9hG4bK92b19bf363d84d2ea95d18cd3\r\nCSeq: 1 REGISTER\r\nWWW-Authenticate: Digest realm="asterisk",nonce="1664256201/30ff48bd45c78b935077262030d584bd",opaque="5f0937be1ccec4cf",algorithm=md5,qop="auth"\r\nServer: Asterisk PBX 18.2.0\r\nContent-Length:  0\r\n\r\n""",
            {
                "raw": '"5555" <sip:5555:secret_password@192.168.0.100>;tag=z9hG4bK92b19bf363d84d2ea95d18cd3',
                "tag": "z9hG4bK92b19bf363d84d2ea95d18cd3",
                "uri": "sip:5555@192.168.0.100",
                "uri-type": "sip",
                "user": "5555",
                "password": "secret_password",
                "display-name": "5555",
                "host": "192.168.0.100",
                "port": 5060,
            },
        ),
        (
            b"""SIP/2.0 401 Unauthorized\r\nVia: SIP/2.0/UDP 192.168.0.76:5060;rport=5060;received=192.168.0.76;branch=z9hG4bK92b19bf363d84d2ea95d18cd3\r\nCall-ID: 6b86b273ff34fce19d6b804eff5a3f57@192.168.0.76:5060\r\nFrom: "5555" <sip:5555@192.168.0.100>;tag=fb11549a\r\nTo: "5555" <sip:5555@192.168.0.100:616>;tag=z9hG4bK92b19bf363d84d2ea95d18cd3\r\nCSeq: 1 REGISTER\r\nWWW-Authenticate: Digest realm="asterisk",nonce="1664256201/30ff48bd45c78b935077262030d584bd",opaque="5f0937be1ccec4cf",algorithm=md5,qop="auth"\r\nServer: Asterisk PBX 18.2.0\r\nContent-Length:  0\r\n\r\n""",
            {
                "raw": '"5555" <sip:5555@192.168.0.100:616>;tag=z9hG4bK92b19bf363d84d2ea95d18cd3',
                "tag": "z9hG4bK92b19bf363d84d2ea95d18cd3",
                "uri": "sip:5555@192.168.0.100:616",
                "uri-type": "sip",
                "user": "5555",
                "password": "",
                "display-name": "5555",
                "host": "192.168.0.100",
                "port": 616,
            },
        ),
        (
            b"""SIP/2.0 401 Unauthorized\r\nVia: SIP/2.0/UDP 192.168.0.76:5060;rport=5060;received=192.168.0.76;branch=z9hG4bK92b19bf363d84d2ea95d18cd3\r\nCall-ID: 6b86b273ff34fce19d6b804eff5a3f57@192.168.0.76:5060\r\nFrom: "5555" <sip:5555@192.168.0.100>;tag=fb11549a\r\nTo: <sip:192.168.0.106:5060>;tag=1925137351\r\nCSeq: 1 REGISTER\r\nWWW-Authenticate: Digest realm="asterisk",nonce="1664256201/30ff48bd45c78b935077262030d584bd",opaque="5f0937be1ccec4cf",algorithm=md5,qop="auth"\r\nServer: Asterisk PBX 18.2.0\r\nContent-Length:  0\r\n\r\n""",
            {
                "raw": "<sip:192.168.0.106:5060>;tag=1925137351",
                "tag": "1925137351",
                "uri": "sip:192.168.0.106:5060",
                "uri-type": "sip",
                "user": "",
                "password": "",
                "display-name": "",
                "host": "192.168.0.106",
                "port": 5060,
            },
        ),
        # Begin RFC Examples
        (
            b"""SIP/2.0 200 OK\r\nTo: The Operator <sip:operator@cs.columbia.edu>;tag=287447\r\n\r\n""",
            {
                "raw": "The Operator <sip:operator@cs.columbia.edu>;tag=287447",
                "tag": "287447",
                "uri": "sip:operator@cs.columbia.edu",
                "uri-type": "sip",
                "user": "operator",
                "password": "",
                "display-name": "The Operator",
                "host": "cs.columbia.edu",
                "port": 5060,
            },
        ),
        (
            b"""SIP/2.0 200 OK\r\nt: sip:+12125551212@server.phone2net.com\r\n\r\n""",
            {
                "raw": "sip:+12125551212@server.phone2net.com",
                "tag": "",
                "uri": "sip:+12125551212@server.phone2net.com",
                "uri-type": "sip",
                "user": "+12125551212",
                "password": "",
                "display-name": "",
                "host": "server.phone2net.com",
                "port": 5060,
            },
        ),
    ],
)
def test_sip_to_from(packet, expected):
    message = SIPMessage.from_bytes(packet)
    assert type(message) is SIPResponse
    assert type(message.headers["To"]) == dict
    assert message.headers["To"] == expected


@pytest.mark.parametrize(
    "packet,expected",
    [
        (
            b"""SIP/2.0 401 Unauthorized\r\nVia: SIP/2.0/UDP 0.0.0.0:5060;branch=z9hG4bK03150189fc65493a9d4e3a582;rport=5060;received=192.168.178.110\r\nFrom: "tarantulla" <sip:tarantulla@192.168.178.1>;tag=9338abd3\r\nTo: "tarantulla" <sip:tarantulla@192.168.178.1>;tag=950C00889AC0DB3B\r\nCall-ID: 6b86b273ff34fce19d6b804eff5a3f57@0.0.0.0:5060\r\nCSeq: 1 REGISTER\r\nWWW-Authenticate: Digest realm="fritz.box", nonce="78B29326485EAE52"\r\nUser-Agent: FRITZ!OS\r\nContent-Length: 0\r\n\r\n""",
            [
                {
                    "type": "SIP/2.0/UDP",
                    "address": ("0.0.0.0", 5060),
                    "branch": "z9hG4bK03150189fc65493a9d4e3a582",
                    "rport": 5060,
                    "received": "192.168.178.110",
                },
            ],
        ),
        (
            b"""SIP/2.0 401 Unauthorized\r\nVia: SIP/2.0/UDP 192.168.0.76:5060;rport=5060;received=192.168.0.76;branch=z9hG4bK92b19bf363d84d2ea95d18cd3\r\nCall-ID: 6b86b273ff34fce19d6b804eff5a3f57@192.168.0.76:5060\r\nFrom: "5555" <sip:5555@192.168.0.100>;tag=fb11549a\r\nTo: "5555" <sip:5555@192.168.0.100>;tag=z9hG4bK92b19bf363d84d2ea95d18cd3\r\nCSeq: 1 REGISTER\r\nWWW-Authenticate: Digest realm="asterisk",nonce="1664256201/30ff48bd45c78b935077262030d584bd",opaque="5f0937be1ccec4cf",algorithm=md5,qop="auth"\r\nServer: Asterisk PBX 18.2.0\r\nContent-Length:  0\r\n\r\n""",
            [
                {
                    "type": "SIP/2.0/UDP",
                    "address": ("192.168.0.76", 5060),
                    "branch": "z9hG4bK92b19bf363d84d2ea95d18cd3",
                    "rport": 5060,
                    "received": "192.168.0.76",
                },
            ],
        ),
        # Begin RFC Examples
        (
            b"""SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP server10.biloxi.com;branch=z9hG4bK4b43c2ff8.1;received=192.0.2.3\r\nVia: SIP/2.0/UDP bigbox3.site3.atlanta.com;branch=z9hG4bK77ef4c2312983.1;received=192.0.2.2\r\nVia: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8;received=192.0.2.1\r\nTo: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\nFrom: Alice <sip:alice@atlanta.com>;tag=1928301774\r\nCall-ID: a84b4c76e66710\r\nCSeq: 314159 INVITE\r\nContact: <sip:bob@192.0.2.4>\r\nContent-Type: application/sdp\r\nContent-Length: 131\r\n\r\n""",
            [
                {
                    "type": "SIP/2.0/UDP",
                    "address": ("server10.biloxi.com", 5060),
                    "branch": "z9hG4bK4b43c2ff8.1",
                    "received": "192.0.2.3",
                },
                {
                    "type": "SIP/2.0/UDP",
                    "address": ("bigbox3.site3.atlanta.com", 5060),
                    "branch": "z9hG4bK77ef4c2312983.1",
                    "received": "192.0.2.2",
                },
                {
                    "type": "SIP/2.0/UDP",
                    "address": ("pc33.atlanta.com", 5060),
                    "branch": "z9hG4bKnashds8",
                    "received": "192.0.2.1",
                },
            ],
        ),
        (
            b"""SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP bigbox3.site3.atlanta.com;branch=z9hG4bK77ef4c2312983.1;received=192.0.2.2\r\nVia: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8;received=192.0.2.1\r\nTo: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\nFrom: Alice <sip:alice@atlanta.com>;tag=1928301774\r\nCall-ID: a84b4c76e66710\r\nCSeq: 314159 INVITE\r\nContact: <sip:bob@192.0.2.4>\r\nContent-Type: application/sdp\r\nContent-Length: 131\r\n\r\n""",
            [
                {
                    "type": "SIP/2.0/UDP",
                    "address": ("bigbox3.site3.atlanta.com", 5060),
                    "branch": "z9hG4bK77ef4c2312983.1",
                    "received": "192.0.2.2",
                },
                {
                    "type": "SIP/2.0/UDP",
                    "address": ("pc33.atlanta.com", 5060),
                    "branch": "z9hG4bKnashds8",
                    "received": "192.0.2.1",
                },
            ],
        ),
        (
            b"""SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKnashds8;received=192.0.2.1\r\nTo: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\nFrom: Alice <sip:alice@atlanta.com>;tag=1928301774\r\nCall-ID: a84b4c76e66710\r\nCSeq: 314159 INVITE\r\nContact: <sip:bob@192.0.2.4>\r\nContent-Type: application/sdp\r\nContent-Length: 131\r\n\r\n""",
            [
                {
                    "type": "SIP/2.0/UDP",
                    "address": ("pc33.atlanta.com", 5060),
                    "branch": "z9hG4bKnashds8",
                    "received": "192.0.2.1",
                },
            ],
        ),
    ],
)
def test_multi_via(packet, expected):
    message = SIPMessage.from_bytes(packet)
    assert type(message) is SIPResponse
    assert message.headers["Via"] == expected
