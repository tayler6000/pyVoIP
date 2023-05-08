def pytest_addoption(parser):
    parser.addoption(
        "--check-functionality",
        "--check-func",
        action="store_true",
        default=False,
        help="Actually connect to a server and run tests.",
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "tcp: mark test as uses TCP")
    config.addinivalue_line("markers", "tls: mark test as uses TLS")
    config.addinivalue_line("markers", "udp: mark test as uses UDP")
    config.addinivalue_line(
        "markers", "registration: mark test as attempts to register"
    )
    config.addinivalue_line(
        "markers", "calling: mark test as attempts to make calls"
    )
