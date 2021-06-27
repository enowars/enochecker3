import re
from enum import Enum
from typing import ClassVar, Optional

from pydantic import BaseModel as PydanticBaseModel

SNAKE_CASE_PATTERN = re.compile("(_[a-z])")


def _to_camel_case(x: str) -> str:
    return SNAKE_CASE_PATTERN.sub(lambda y: y.group(1)[1].upper(), x)


class BaseModel(PydanticBaseModel):
    class Config:
        use_enum_values = True
        alias_generator = _to_camel_case
        allow_population_by_field_name = True


class CheckerTaskResult(str, Enum):
    value: str
    OK = "OK"
    MUMBLE = "MUMBLE"
    OFFLINE = "OFFLINE"
    INTERNAL_ERROR = "INTERNAL_ERROR"

    def __str__(self) -> str:
        return self.value


class CheckerMethod(str, Enum):
    value: str
    PUTFLAG = "putflag"
    GETFLAG = "getflag"
    PUTNOISE = "putnoise"
    GETNOISE = "getnoise"
    HAVOC = "havoc"
    EXPLOIT = "exploit"

    def __str__(self) -> str:
        return self.value


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


class CheckerInfoMessage(BaseModel):
    service_name: str
    flag_variants: int
    noise_variants: int
    havoc_variants: int
    exploit_variants: int


class CheckerResultMessage(BaseModel):
    result: CheckerTaskResult
    message: Optional[str]
    attack_info: Optional[str] = None
    flag: Optional[str] = None


class CheckerTaskMessage(BaseModel):
    task_id: int
    method: CheckerMethod
    address: str
    team_id: int
    team_name: str
    current_round_id: int
    related_round_id: int
    flag: Optional[str]
    variant_id: int
    timeout: int
    round_length: int
    task_chain_id: str
    flag_regex: Optional[str] = None
    flag_hash: Optional[str] = None
    attack_info: Optional[str] = None


class BaseException(Exception):
    def __init__(self, message: Optional[str]):
        self.message: Optional[str] = message


class MumbleException(BaseException):
    pass


class OfflineException(BaseException):
    pass


class InternalErrorException(BaseException):
    pass


class EnoLogMessage(BaseModel):
    tool: str
    type: str
    severity: str
    severity_level: int
    timestamp: str
    message: str
    module: Optional[str]
    function: Optional[str]
    service_name: Optional[str]
    task_id: Optional[int]
    method: Optional[str]
    team_id: Optional[int]
    team_name: Optional[str]
    current_round_id: Optional[int]
    related_round_id: Optional[int]
    flag: Optional[str]
    variant_id: Optional[int]
    task_chain_id: Optional[str]
    flag_regex: Optional[str]
    flag_hash: Optional[str]
    attack_info: Optional[str]
