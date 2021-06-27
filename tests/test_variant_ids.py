import pytest

from enochecker3 import Enochecker, InvalidVariantIdsException
from enochecker3.types import CheckerMethod


def test_missing_putflag(checker: Enochecker):
    @checker.getflag(0)
    def foo():
        pass

    with pytest.raises(InvalidVariantIdsException):
        checker._validate_variant_ids()


def test_missing_getflag(checker: Enochecker):
    @checker.putflag(0)
    def foo():
        pass

    with pytest.raises(InvalidVariantIdsException):
        checker._validate_variant_ids()


def test_missing_putnoise(checker: Enochecker):
    @checker.getnoise(0)
    def foo():
        pass

    with pytest.raises(InvalidVariantIdsException):
        checker._validate_variant_ids()


def test_missing_getnoise(checker: Enochecker):
    @checker.putnoise(0)
    def foo():
        pass

    with pytest.raises(InvalidVariantIdsException):
        checker._validate_variant_ids()


@pytest.mark.parametrize("method", [x.value for x in CheckerMethod])
def test_duplicate_variant_id(checker, method):
    dec = getattr(checker, method)

    @dec(0)
    def foo():
        pass

    with pytest.raises(InvalidVariantIdsException):

        @dec(0)
        def bar():
            pass


@pytest.mark.parametrize("method", [x.value for x in CheckerMethod])
def test_negative_variant_id(checker, method):
    dec = getattr(checker, method)

    with pytest.raises(InvalidVariantIdsException):

        @dec(-1)
        def foo():
            pass


@pytest.mark.parametrize("method", [x.value for x in CheckerMethod])
def test_missing_variant_id(checker, method):
    dec = getattr(checker, method)

    @dec(0)
    def foo():
        pass

    @dec(2)
    def bar():
        pass

    with pytest.raises(InvalidVariantIdsException):
        checker._validate_variant_ids()
