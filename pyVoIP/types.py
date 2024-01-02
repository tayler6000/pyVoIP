from typing import Callable, Dict, Optional, Union
import socket
import ssl


URI_HEADER = Dict[
    str, Union[str, int]
]  # URI headers such as To, From, Contact, etc


SOCKETS = Union[socket.socket, ssl.SSLSocket]


KEY_PASSWORD = Optional[
    Union[
        bytes,
        bytearray,
        str,
        Callable[[], bytes],
        Callable[[], bytearray],
        Callable[[], str],
    ]
]


CREDENTIALS_DICT = Dict[
    Optional[str],  # Server or None if default
    Dict[
        Optional[str],  # Realm or None if default
        Dict[
            Optional[str],  # To or None if default
            Dict[str, str],  # Actual credentials
        ],
    ],
]
