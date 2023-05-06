
def pytest_addoption(parser):
    parser.addoption("--check-functionality", "--check-func", action="store_true", default=False, help="Actually connect to a server and run tests.")
