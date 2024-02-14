"""
This file is for the compilation of every regex used in pyVoIP.
Regex, though extremely powerful, is not efficient. To help with this,
Python offers regex compilation so you only have to compile once, not on
each search. This module holds all the compiled regex so it can be compiled
once on startup, then used directly later by other modules.
"""

import re


Match = re.Match

AUTH_MATCH = re.compile(r'(\w+)=("[^"]+"|[^ \t,]+)')
VIA_SPLIT = re.compile(r" |;")
TO_FROM_MATCH = re.compile(
    r'(?P<display_name>"?[\w ]*"? )?<?(?P<uri_type>sips?):(?P<user>[\w+]+)(?P<password>:\w+)?@(?P<host>[\w.]+)(?P<port>:[0-9]+)?>?'
)
TO_FROM_DIRECT_MATCH = re.compile(
    r'(?P<display_name>"?[\w ]*"? )?<?(?P<uri_type>sips?):(?P<host>[\w.]+)(?P<port>:[0-9]+)?>?'
)
SDP_A_SPLIT = re.compile(" |/")
SIP_VERSION_MATCH = re.compile(r"(?:SIP|sip)/[0-9.]+")
