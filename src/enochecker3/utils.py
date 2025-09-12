import hashlib
import re
import traceback
from typing import Any, Optional, Union

from .types import MumbleException


def caller_loc() -> str:
    trace = traceback.StackSummary.extract(traceback.walk_stack(None))
    caller = list(trace)[2]
    return f"{caller.filename}:{caller.lineno}"


def assert_in(o1: Any, o2: Any, message: Optional[str] = None) -> None:
    if not o2 or o1 not in o2:
        raise MumbleException(
            message or "Checker assertion failed",
            log_message=f"Assertion (assert_in) failed! ({caller_loc()})"
            + f"\n  Needle: ({type(o1)}) {o1}\n  Haystack: ({type(o2)}) {o2}",
        )


def assert_equals(o1: Any, o2: Any, message: Optional[str] = None) -> None:
    if o1 != o2:
        raise MumbleException(
            message or "Checker assertion failed",
            log_message=f"Assertion (assert_equals) failed! ({caller_loc()})"
            + f"\n  Left: ({type(o1)}) {o1}\n  Right: ({type(o2)}) {o2}",
        )


class FlagSearcher:
    def __init__(self, flag_regex: str, flag_hash: str):
        self._flag_re: re.Pattern = re.compile(flag_regex.encode())
        self.flag_hash: str = flag_hash

    def search_flag(self, haystack: Union[str, bytes]) -> Optional[bytes]:
        if type(haystack) is str:
            haystack = haystack.encode()
        candidates = []
        for flag in self._flag_re.findall(haystack):
            if self.flag_hash != "":
                hash_ = hashlib.sha256(flag).hexdigest()
                if hash_ == self.flag_hash:
                    return flag
            candidates.append(flag)
        if self.flag_hash != "" or len(candidates) == 0:
            return None
        else:
            return b"\n".join(candidates)
