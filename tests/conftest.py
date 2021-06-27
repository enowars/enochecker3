import pytest

from enochecker3 import Enochecker


@pytest.fixture
def checker() -> Enochecker:
    return Enochecker("asd", 1234)


def pytest_addoption(parser):
    parser.addoption(
        "--with_mongodb", action="store_true", help="Run the tests with the mongodb"
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "mongodb: mark test as requiring MongoDB")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--with_mongodb"):
        return
    skip_mongodb = pytest.mark.skip(reason="need --with_mongodb option to run")
    for item in items:
        if "mongodb" in item.keywords:
            item.add_marker(skip_mongodb)
