import hashlib
import re
from typing import Any, Optional, Union

from .types import MumbleException


def assert_in(o1: Any, o2: Any, message: Optional[str] = None) -> None:
    if not o2 or o1 not in o2:
        raise MumbleException(
            message or "assertion failed",
        )


def assert_equals(o1: Any, o2: Any, message: Optional[str] = None) -> None:
    if o1 != o2:
        raise MumbleException(message or "assertion failed")


class FlagSearcher:
    def __init__(self, flag_regex: str, flag_hash: str):
        self._flag_re: re.Pattern = re.compile(flag_regex.encode())
        self.flag_hash: str = flag_hash

    def search_flag(self, haystack: Union[str, bytes]) -> Optional[bytes]:
        if type(haystack) == str:
            haystack = haystack.encode()
        for flag in self._flag_re.findall(haystack):
            hash_ = hashlib.sha256(flag).hexdigest()
            if hash_ == self.flag_hash:
                return flag
        return None
