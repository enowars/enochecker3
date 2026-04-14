from contextvars import ContextVar
from typing import Mapping, ClassVar, Any


"""
Common attributes are added to each span/log message within a scope.

USAGE:
with telemetry_attributes({"name": "abc"}):
    ...
"""


class OpenTelemetryCommonAttributes:
    def __init__(self, attributes: Mapping[str, Any] | None = None) -> None:
        self._attributes: dict[str, Any] = (
            dict(attributes.items()) if attributes else {}
        )

    def create_child(
        self, new_attributes: dict[str, Any]
    ) -> "OpenTelemetryCommonAttributes":
        return OpenTelemetryCommonAttributes(self.to_dict() | new_attributes)

    def to_dict(self) -> dict[str, Any]:
        return {k: str(v) for k, v in self._attributes.items()}


class OpenTelemetryCommonAttributesContext:
    _stack: ClassVar[ContextVar[list[OpenTelemetryCommonAttributes]]] = ContextVar(
        "otel_attributes_stack", default=[]
    )

    def __init__(self, attributes: OpenTelemetryCommonAttributes) -> None:
        self._attributes: OpenTelemetryCommonAttributes = attributes

    @classmethod
    def current_attributes(cls) -> OpenTelemetryCommonAttributes:
        stack: list[OpenTelemetryCommonAttributes] = cls._stack.get()
        if len(stack):
            return stack[-1]
        else:
            return OpenTelemetryCommonAttributes()

    def __enter__(self) -> "OpenTelemetryCommonAttributesContext":
        stack: list[OpenTelemetryCommonAttributes] = self._stack.get()
        if len(stack):
            self._stack.set(
                stack + [stack[-1].create_child(self._attributes.to_dict())]
            )
        else:
            self._stack.set([self._attributes])
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        self._stack.set(self._stack.get()[:-1])


def telemetry_attributes(d: Mapping[str, Any]) -> OpenTelemetryCommonAttributesContext:
    return OpenTelemetryCommonAttributesContext(OpenTelemetryCommonAttributes(d))
