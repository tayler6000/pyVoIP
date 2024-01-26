from typing import Any, Dict, List
from pyVoIP import regex
from pyVoIP.types import URI_HEADER
from pyVoIP.SIP.error import SIPParseError
import pyVoIP


# Compacts defined in RFC 3261 Section 7.3.3 and 20
COMPACT_KEY = {
    "i": "Call-ID",
    "m": "Contact",
    "e": "Content-Encoding",
    "l": "Content-Length",
    "c": "Content-Type",
    "f": "From",
    "s": "Subject",
    "k": "Supported",
    "t": "To",
    "v": "Via",
}


def parse_raw_headers(raw_headers: List[bytes]) -> Dict[str, Any]:
    headers: Dict[str, Any] = {"Via": []}
    # Only use first occurance of VIA header field;
    # got second VIA from Kamailio running in DOCKER
    # According to RFC 3261 these messages should be
    # discarded in a response
    for x in raw_headers:
        i = str(x, "utf8").split(": ")
        if i[0] == "Via":
            headers["Via"].append(i[1])
        if i[0] not in headers.keys():
            headers[i[0]] = i[1]

    parsed_headers: Dict[str, Any] = {}
    for key, val in headers.items():
        if key in COMPACT_KEY.keys():
            key = COMPACT_KEY[key]

        parsed_headers[key] = parse_header(key, val)
    return parsed_headers


def parse_raw_body(body: bytes, ctype: str) -> Dict[str, Any]:
    if len(body) > 0:
        if ctype == "application/sdp":
            parsed_body: Dict[str, Any] = {}
            body_raw = body.split(b"\r\n")
            for x in body_raw:
                i = str(x, "utf8").split("=")
                if i != [""]:
                    parse_sdp_tag(parsed_body, i[0], i[1])
            return parsed_body
        else:
            return {"content": body}
    return {"content": None}


def get_uri_header(data: str) -> URI_HEADER:
    info = data.split(";tag=")
    tag = ""
    if len(info) >= 2:
        tag = info[1]
    raw = data
    reg = regex.TO_FROM_MATCH
    direct = "@" not in data
    if direct:
        reg = regex.TO_FROM_DIRECT_MATCH
    match = reg.match(data)
    if match is None:
        raise SIPParseError(
            "Regex failed to match To/From.\n\n"
            + "Please open a GitHub Issue at "
            + "https://www.github.com/tayler6000/pyVoIP "
            + "and include the following:\n\n"
            + f"{data=} {type(match)=}"
        )
    matches = match.groupdict()
    if direct:
        matches["user"] = ""
        matches["password"] = ""
    uri = f'{matches["uri_type"]}:{matches["user"]}@{matches["host"]}'
    if direct:
        uri = f'{matches["uri_type"]}:{matches["host"]}'
    if matches["port"]:
        uri += matches["port"]
    uri_type = matches["uri_type"]
    user = matches["user"]
    password = matches["password"].strip(":") if matches["password"] else ""
    display_name = (
        matches["display_name"].strip().strip('"')
        if matches["display_name"]
        else ""
    )
    host = matches["host"]
    port = int(matches["port"].strip(":")) if matches["port"] else 5060

    return {
        "raw": raw,
        "tag": tag,
        "uri": uri,
        "uri-type": uri_type,
        "user": user,
        "password": password,
        "display-name": display_name,
        "host": host,
        "port": port,
    }


def parse_header(header: str, data: str) -> Any:
    if header == "Via":
        vias = []
        for d in data:
            info = regex.VIA_SPLIT.split(d)
            _type = info[0]  # SIP Method
            _address = info[1].split(":")  # Tuple: address, port
            _ip = _address[0]

            """
            If no port is provided in via header assume default port.
            Needs to be str. Check response build for better str creation
            """
            _port = int(info[1].split(":")[1]) if len(_address) > 1 else 5060
            _via = {"type": _type, "address": (_ip, _port)}

            """
            Sets branch, maddr, ttl, received, and rport if defined
            as per RFC 3261 20.7
            """
            for x in info[2:]:
                if "=" in x:
                    try:
                        _via[x.split("=")[0]] = int(x.split("=")[1])
                    except ValueError:
                        _via[x.split("=")[0]] = x.split("=")[1]
                else:
                    _via[x] = None
            vias.append(_via)
        return vias
    elif header in ["To", "From", "Contact", "Refer-To"]:
        return get_uri_header(data)
    elif header == "CSeq":
        return {
            "check": int(data.split(" ")[0]),
            "method": data.split(" ")[1],
        }
    elif header in ["Allow", "Supported", "Require"]:
        return data.split(", ")
    elif header == "Call-ID":
        return data
    elif header in (
        "WWW-Authenticate",
        "Authorization",
        "Proxy-Authenticate",
    ):
        method = data.split(" ")[0]
        data = data.replace(f"{method} ", "")
        auth_match = regex.AUTH_MATCH
        row_data = auth_match.findall(data)
        auth_data: Dict[str, Any] = {"header": header, "method": method}
        for var, data in row_data:
            if var == "userhash":
                auth_data[var] = (
                    False if data.strip('"').lower() == "false" else True
                )
                continue
            if var == "qop":
                authorized = data.strip('"').split(",")
                for i, value in enumerate(authorized):
                    authorized[i] = value.strip()
                auth_data[var] = authorized
                continue
            auth_data[var] = data.strip('"')
        return auth_data
    elif header == "Target-Dialog":
        # Target-Dialog (tdialog) is specified in RFC 4538
        params = data.split(";")
        td_data: Dict[str, Any] = {
            "callid": params.pop(0)
        }  # key is callid to be consitenent with RFC 4538 Section 7
        for x in params:
            y = x.split("=")
            td_data[y[0]] = y[1]
        return td_data
    elif header == "Refer-Sub":
        # Refer-Sub (norefersub) is specified in RFC 4488
        params = data.split(";")
        rs_data: Dict[str, Any] = {
            "value": True if params.pop(0) == "true" else False
        }  # BNF states extens are possible
        for x in params:
            y = x.split("=")
            rs_data[y[0]] = y[1]
        return rs_data
    else:
        try:
            return int(data)
        except ValueError:
            return data


def parse_sdp_tag(parsed_body: Dict[str, Any], field: str, data: str) -> Any:
    # Referenced RFC 4566 July 2006
    if field == "v":
        # SDP 5.1 Version
        parsed_body[field] = int(data)
    elif field == "o":
        # SDP 5.2 Origin
        # o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address> # noqa: E501
        d = data.split(" ")
        parsed_body[field] = {
            "username": d[0],
            "id": d[1],
            "version": d[2],
            "network_type": d[3],
            "address_type": d[4],
            "address": d[5],
        }
    elif field == "s":
        # SDP 5.3 Session Name
        # s=<session name>
        parsed_body[field] = data
    elif field == "i":
        # SDP 5.4 Session Information
        # i=<session-description>
        parsed_body[field] = data
    elif field == "u":
        # SDP 5.5 URI
        # u=<uri>
        parsed_body[field] = data
    elif field == "e" or field == "p":
        # SDP 5.6 Email Address and Phone Number of person
        # responsible for the conference
        # e=<email-address>
        # p=<phone-number>
        parsed_body[field] = data
    elif field == "c":
        # SDP 5.7 Connection Data
        # c=<nettype> <addrtype> <connection-address>
        if "c" not in parsed_body:
            parsed_body["c"] = []
        d = data.split(" ")
        # TTL Data and Multicast addresses may be specified.
        # For IPv4 its listed as addr/ttl/number of addresses.
        # c=IN IP4 224.2.1.1/127/3 means:
        # c=IN IP4 224.2.1.1/127
        # c=IN IP4 224.2.1.2/127
        # c=IN IP4 224.2.1.3/127
        # With the TTL being 127.
        # IPv6 does not support time to live so you will only see a '/'
        # for multicast addresses.
        if "/" in d[2]:
            if d[1] == "IP6":
                parsed_body[field].append(
                    {
                        "network_type": d[0],
                        "address_type": d[1],
                        "address": d[2].split("/")[0],
                        "ttl": None,
                        "address_count": int(d[2].split("/")[1]),
                    }
                )
            else:
                address_data = d[2].split("/")
                if len(address_data) == 2:
                    parsed_body[field].append(
                        {
                            "network_type": d[0],
                            "address_type": d[1],
                            "address": address_data[0],
                            "ttl": int(address_data[1]),
                            "address_count": 1,
                        }
                    )
                else:
                    parsed_body[field].append(
                        {
                            "network_type": d[0],
                            "address_type": d[1],
                            "address": address_data[0],
                            "ttl": int(address_data[1]),
                            "address_count": int(address_data[2]),
                        }
                    )
        else:
            parsed_body[field].append(
                {
                    "network_type": d[0],
                    "address_type": d[1],
                    "address": d[2],
                    "ttl": None,
                    "address_count": 1,
                }
            )
    elif field == "b":
        # SDP 5.8 Bandwidth
        # b=<bwtype>:<bandwidth>
        # A bwtype of CT means Conference Total between all medias
        # and all devices in the conference.
        # A bwtype of AS means Applicaton Specific total for this
        # media and this device.
        # The bandwidth is given in kilobits per second.
        # As this was written in 2006, this could be Kibibits.
        # TODO: Implement Bandwidth restrictions
        d = data.split(":")
        parsed_body[field] = {"type": d[0], "bandwidth": d[1]}
    elif field == "t":
        # SDP 5.9 Timing
        # t=<start-time> <stop-time>
        d = data.split(" ")
        parsed_body[field] = {"start": d[0], "stop": d[1]}
    elif field == "r":
        # SDP 5.10 Repeat Times
        # r=<repeat interval> <active duration> <offsets from start-time> # noqa: E501
        d = data.split(" ")
        parsed_body[field] = {
            "repeat": d[0],
            "duration": d[1],
            "offset1": d[2],
            "offset2": d[3],
        }
    elif field == "z":
        # SDP 5.11 Time Zones
        # z=<adjustment time> <offset> <adjustment time> <offset> ....
        # Used for change in timezones such as day light savings time.
        d = data.split()
        amount = len(d) / 2
        parsed_body[field] = {}
        for x in range(int(amount)):
            parsed_body[field]["adjustment-time" + str(x)] = d[x * 2]
            parsed_body[field]["offset" + str(x)] = d[x * 2 + 1]
    elif field == "k":
        # SDP 5.12 Encryption Keys
        # k=<method>
        # k=<method>:<encryption key>
        if ":" in data:
            d = data.split(":")
            parsed_body[field] = {"method": d[0], "key": d[1]}
        else:
            parsed_body[field] = {"method": data}
    elif field == "m":
        # SDP 5.14 Media Descriptions
        # m=<media> <port>/<number of ports> <proto> <fmt> ...
        # <port> should be even, and <port>+1 should be the RTCP port.
        # <number of ports> should coinside with number of
        # addresses in SDP 5.7 c=
        if "m" not in parsed_body:
            parsed_body["m"] = []
        d = data.split(" ")

        if "/" in d[1]:
            ports_raw = d[1].split("/")
            port = ports_raw[0]
            count = int(ports_raw[1])
        else:
            port = d[1]
            count = 1
        methods = d[3:]

        parsed_body["m"].append(
            {
                "type": d[0],
                "port": int(port),
                "port_count": count,
                "protocol": pyVoIP.RTP.RTPProtocol(d[2]),
                "methods": methods,
                "attributes": {},
            }
        )
        for x in parsed_body["m"][-1]["methods"]:
            parsed_body["m"][-1]["attributes"][x] = {}
    elif field == "a":
        # SDP 5.13 Attributes & 6.0 SDP Attributes
        # a=<attribute>
        # a=<attribute>:<value>

        if "a" not in parsed_body:
            parsed_body["a"] = {}

        if ":" in data:
            d = data.split(":")
            attribute = d[0]
            value = d[1]
        else:
            attribute = data
            value = None

        if value is not None:
            if attribute == "rtpmap":
                # a=rtpmap:<payload type> <encoding name>/<clock rate> [/<encoding parameters>] # noqa: E501
                v = regex.SDP_A_SPLIT.split(value)
                for t in parsed_body["m"]:
                    if v[0] in t["methods"]:
                        index = int(parsed_body["m"].index(t))
                        break
                if len(v) == 4:
                    encoding = v[3]
                else:
                    encoding = None

                parsed_body["m"][index]["attributes"][v[0]]["rtpmap"] = {
                    "id": v[0],
                    "name": v[1],
                    "frequency": v[2],
                    "encoding": encoding,
                }

            elif attribute == "fmtp":
                # a=fmtp:<format> <format specific parameters>
                d = value.split(" ")
                for t in parsed_body["m"]:
                    if d[0] in t["methods"]:
                        index = int(parsed_body["m"].index(t))
                        break

                parsed_body["m"][index]["attributes"][d[0]]["fmtp"] = {
                    "id": d[0],
                    "settings": d[1:],
                }
            else:
                parsed_body["a"][attribute] = value
        else:
            if (
                attribute == "recvonly"
                or attribute == "sendrecv"
                or attribute == "sendonly"
                or attribute == "inactive"
            ):
                parsed_body["a"]["transmit_type"] = pyVoIP.RTP.TransmitType(
                    attribute
                )  # noqa: E501
    else:
        parsed_body[field] = data
