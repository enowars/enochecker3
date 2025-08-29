__all__ = [
    "CheckerMethod",
    "CheckerTaskMessage",
    "CheckerInfoMessage",
    "CheckerResultMessage",
    "CheckerTaskResult",
    "EnoLogMessage",
]

from typing import ClassVar, Optional

from enochecker_core import (
    BaseModel,
    CheckerMethod,
    CheckerTaskResult,
    CheckerTaskMessage,
    CheckerInfoMessage,
    CheckerResultMessage,
    EnoLogMessage,
)


class BaseCheckerTaskMessage(BaseModel):
    task_id: int
    address: str
    team_id: int
    team_name: str
    current_round_id: int
    variant_id: int
    timeout: int
    round_length: int
    task_chain_id: str

    method: ClassVar[CheckerMethod]


class FlagCheckerTaskMessage(BaseCheckerTaskMessage):
    flag: str


class PutflagCheckerTaskMessage(FlagCheckerTaskMessage):
    method = CheckerMethod.PUTFLAG


class GetflagCheckerTaskMessage(FlagCheckerTaskMessage):
    related_round_id: int

    method = CheckerMethod.GETFLAG


class NoiseCheckerTaskMessage(BaseCheckerTaskMessage):
    pass


class PutnoiseCheckerTaskMessage(NoiseCheckerTaskMessage):
    method = CheckerMethod.PUTNOISE


class GetnoiseCheckerTaskMessage(NoiseCheckerTaskMessage):
    related_round_id: int

    method = CheckerMethod.GETNOISE


class HavocCheckerTaskMessage(BaseCheckerTaskMessage):
    method = CheckerMethod.HAVOC


class ExploitCheckerTaskMessage(BaseCheckerTaskMessage):
    flag_regex: str
    flag_hash: str
    attack_info: Optional[str]

    method = CheckerMethod.EXPLOIT


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
