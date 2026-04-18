__all__ = [
    "BaseCheckerTaskMessage",
    "CheckerMethod",
    "CheckerTaskMessage",
    "CheckerInfoMessage",
    "CheckerResultMessage",
    "CheckerTaskResult",
    "EnoLogMessage",
]

from typing import Literal, Optional

from enochecker_core import (
    CheckerInfoMessage,
    CheckerMethod,
    CheckerResultMessage,
    CheckerTaskMessage,
    CheckerTaskResult,
    EnoLogMessage,
)

BaseCheckerTaskMessage = CheckerTaskMessage


class PutflagCheckerTaskMessage(CheckerTaskMessage):
    flag: str
    method: Literal[CheckerMethod.PUTFLAG] = CheckerMethod.PUTFLAG


class GetflagCheckerTaskMessage(CheckerTaskMessage):
    flag: str
    method: Literal[CheckerMethod.GETFLAG] = CheckerMethod.GETFLAG


class PutnoiseCheckerTaskMessage(CheckerTaskMessage):
    method: Literal[CheckerMethod.PUTNOISE] = CheckerMethod.PUTNOISE


class GetnoiseCheckerTaskMessage(CheckerTaskMessage):
    method: Literal[CheckerMethod.GETNOISE] = CheckerMethod.GETNOISE


class HavocCheckerTaskMessage(CheckerTaskMessage):
    method: Literal[CheckerMethod.HAVOC] = CheckerMethod.HAVOC


class ExploitCheckerTaskMessage(CheckerTaskMessage):
    flag_regex: str
    flag_hash: str
    attack_info: Optional[str]
    method: Literal[CheckerMethod.EXPLOIT] = CheckerMethod.EXPLOIT


class TestCheckerTaskMessage(CheckerTaskMessage):
    __test__ = False  # Tell pytest not to collect this as a test class
    method: Literal[CheckerMethod.TEST] = CheckerMethod.TEST


class BaseException(Exception):
    def __init__(self, message: Optional[str], log_message: Optional[str] = None):
        self.message: Optional[str] = message
        self.log_message: Optional[str] = log_message


class MumbleException(BaseException):
    pass


class OfflineException(BaseException):
    pass


class InternalErrorException(BaseException):
    def __init__(
        self,
        message: Optional[str],
        log_message: Optional[str] = None,
        inner: Optional[Exception] = None,
    ):
        super().__init__(message, log_message)
        self.inner: Optional[Exception] = inner
