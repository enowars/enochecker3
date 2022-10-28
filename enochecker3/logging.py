import datetime
import logging
from typing import List, Optional

from .types import CheckerTaskMessage, EnoLogMessage

LOGGING_PREFIX = "##ENOLOGMESSAGE "


class DebugFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        if type(record.args) is tuple and len(record.args) > 0:
            record.msg = record.msg % record.args

        checker_task: Optional[CheckerTaskMessage] = getattr(
            record, "checker_task", None
        )

        timestamp: str = datetime.datetime.utcnow().strftime("%H:%M:%S.%f")[:-3]
        method: str = getattr(checker_task, "method", None) or "<method>"
        levelname: str = getattr(record, "levelname", None) or "<level>"
        task_id: str = getattr(checker_task, "task_id", None) or "<taskid>"
        info_line: str = "{} {} {} {}".format(timestamp, levelname, method, task_id)

        log_lines: List[str] = [info_line]
        for i, line in enumerate(record.msg.strip().split("\n")):
            log_lines.append("    | " + line)

        return "\n".join(log_lines)


class ELKFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        if type(record.args) is tuple and len(record.args) > 0:
            record.msg = record.msg % record.args

        msg: EnoLogMessage = self.create_message(record)
        message_size: int = len(msg.message.encode())
        if message_size > 32766:
            suffix: str = "... <SNIP>"
            trunc: int = message_size + len(suffix) - 32766
            msg.message = msg.message[:-trunc] + suffix

        return LOGGING_PREFIX + msg.json(by_alias=True)

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
        service_name: Optional[str] = getattr(record, "service_name", None)
        checker_name: Optional[str] = getattr(record, "checker_name", None)
        return EnoLogMessage(
            tool=checker_name,
            type="infrastructure",
            severity=record.levelname,
            severity_level=self.to_level(record.levelname),
            timestamp=datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            message=record.msg,
            module=record.module,
            function=record.funcName,
            service_name=service_name,
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
