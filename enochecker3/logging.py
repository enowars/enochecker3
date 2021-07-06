import datetime
import logging
from typing import Optional

from .types import CheckerTaskMessage, EnoLogMessage

LOGGING_PREFIX = "##ENOLOGMESSAGE "


class ELKFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        if record.args is not None:
            record.msg = record.msg % record.args

        return LOGGING_PREFIX + self.create_message(record).json(by_alias=True)

    def to_level(self, levelname: str) -> int:
        if levelname == "CRITICAL":
            return 4
        if levelname == "ERROR":
            return 3
        if levelname == "WARNING":
            return 2
        if levelname == "INFO":
            return 1
        if levelname == "DEBUG":
            return 0
        return 0

    def create_message(self, record: logging.LogRecord) -> EnoLogMessage:
        checker_task: Optional[CheckerTaskMessage] = getattr(
            record, "checker_task", None
        )
        checker_name: Optional[str] = getattr(record, "checker_name", None)
        return EnoLogMessage(
            tool="enochecker3",
            type="infrastructure",
            severity=record.levelname,
            severity_level=self.to_level(record.levelname),
            timestamp=datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            message=record.msg,
            module=record.module,
            function=record.funcName,
            service_name=checker_name,
            task_id=getattr(checker_task, "task_id", None),
            method=getattr(checker_task, "method", None),
            team_id=getattr(checker_task, "team_id", None),
            team_name=getattr(checker_task, "team_name", None),
            current_round_id=getattr(checker_task, "current_round_id", None),
            related_round_id=getattr(checker_task, "related_round_id", None),
            flag=getattr(checker_task, "flag", None),
            variant_id=getattr(checker_task, "variant_id", None),
            task_chain_id=getattr(checker_task, "task_chain_id", None),
        )
