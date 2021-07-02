import hashlib

import pytest

from enochecker3 import MumbleException
from enochecker3.utils import FlagSearcher, assert_equals, assert_in


def test_assert_in():
    with pytest.raises(MumbleException) as ex:
        assert_in("a", "b", "test_message")
    assert str(ex.value) == "test_message"

    with pytest.raises(MumbleException):
        assert_in("a", None)

    assert_in("a", "aa")

    with pytest.raises(MumbleException):
        assert_in("a", "b")


def test_assert_equals():
    with pytest.raises(MumbleException) as ex:
        assert_equals("a", "b", "test_message")
    assert str(ex.value) == "test_message"

    # no autobyteify
    with pytest.raises(MumbleException):
        assert_equals("a", b"a")
    with pytest.raises(MumbleException):
        assert_equals(b"a", "a")
    assert_equals("a", "a")
    assert_equals(b"a", b"a")


@pytest.mark.parametrize(
    "haystack", ["ENOabcdefgh=", "ENOstuvwxyz=asdasdENOabcdefgh=asdasd"]
)
def test_search_flag(haystack):
    flag_regex = r"ENO.{8}="
    flag_hash = hashlib.sha256(b"ENOabcdefgh=").hexdigest()

    searcher = FlagSearcher(flag_regex, flag_hash)

    assert searcher.search_flag(haystack) == b"ENOabcdefgh="


@pytest.mark.parametrize("haystack", ["ENOstuvwxyz="])
def test_search_flag_not_found(haystack):
    flag_regex = r"ENO.{8}="
    flag_hash = hashlib.sha256(b"ENOabcdefgh=").hexdigest()

    searcher = FlagSearcher(flag_regex, flag_hash)

    assert searcher.search_flag(haystack) == None
