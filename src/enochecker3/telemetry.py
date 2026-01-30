import logging
import os
from typing import Optional, Iterator, cast, Any

import httpx
from opentelemetry import trace
from opentelemetry._logs import set_logger_provider
from opentelemetry.context import Context
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs._internal.export import BatchLogRecordProcessor, LogRecordExporter
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider, Span as SdkSpan
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter
from opentelemetry.sdk.trace.sampling import ALWAYS_ON
from opentelemetry.trace import Tracer, SpanKind, _Links, Span
from opentelemetry.util import types
from opentelemetry.util._decorator import _agnosticcontextmanager

from enochecker3.telemetry_attributes import OpenTelemetryCommonAttributesContext


def _setup_logging(resource: Resource, log_exporter: LogRecordExporter) -> None:
    provider = LoggerProvider(resource=resource)
    processor = BatchLogRecordProcessor(log_exporter)
    provider.add_log_record_processor(processor)
    set_logger_provider(provider)
    logging.root.addHandler(LoggingHandler(level=logging.INFO, logger_provider=provider))
    logging.root.addFilter(CommonAttributesLogFilter())


def _setup_tracing(resource: Resource, span_exporter: SpanExporter) -> None:
    provider = SaarctfTracerProvider(
        sampler=ALWAYS_ON,
        resource=resource
    )
    processor = BatchSpanProcessor(span_exporter)
    provider.add_span_processor(processor)
    trace.set_tracer_provider(provider)


_telemetry_initialized = False


def setup_telemetry(component: str) -> None:
    global _telemetry_initialized

    otlp_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", None)
    otlp_key = os.environ.get("OTEL_EXPORTER_OTLP_HEADERS_AUTHORIZATION", None)

    if otlp_endpoint and not _telemetry_initialized:
        resource = Resource(attributes={SERVICE_NAME: component})

        headers = {}
        if otlp_key:
            headers["authorization"] = otlp_key

        span_exporter = OTLPSpanExporter(endpoint=otlp_endpoint, headers=headers)
        _setup_tracing(resource, span_exporter)
        log_exporter = OTLPLogExporter(endpoint=otlp_endpoint, headers=headers)
        _setup_logging(resource, log_exporter)

        _telemetry_initialized = True


class CommonAttributesLogFilter(logging.Filter):
    """Add common attributes to each log message"""

    def filter(self, record: logging.LogRecord) -> bool:
        for key, value in OpenTelemetryCommonAttributesContext.current_attributes().to_dict().items():
            setattr(record, key, value)
        return True


class SaarctfTracer(Tracer):
    """Wrap tracers to add common attributes to spans"""

    def __init__(self, tracer: Tracer) -> None:
        self._tracer = tracer

    @classmethod
    def add_span_attributes(cls, span: Span) -> Span:
        span = cast(SdkSpan, span)
        for k, v in OpenTelemetryCommonAttributesContext.current_attributes().to_dict().items():
            if not span.attributes or k not in span.attributes:
                span.set_attribute(k, v)
        return span

    def start_span(self,
                   name: str,
                   context: Optional[Context] = None,
                   kind: SpanKind = SpanKind.INTERNAL,
                   attributes: types.Attributes = None,
                   links: _Links = None,
                   start_time: Optional[int] = None,
                   record_exception: bool = True,
                   set_status_on_exception: bool = True) -> Span:
        span = self._tracer.start_span(name, context, kind, attributes, links, start_time, record_exception,
                                       set_status_on_exception)
        return self.add_span_attributes(span)

    @_agnosticcontextmanager
    def start_as_current_span(self,
                              name: str,
                              context: Optional[Context] = None,
                              kind: SpanKind = SpanKind.INTERNAL,
                              attributes: types.Attributes = None,
                              links: _Links = None,
                              start_time: Optional[int] = None,
                              record_exception: bool = True,
                              set_status_on_exception: bool = True,
                              end_on_exit: bool = True) -> Iterator[Span]:
        with self._tracer.start_as_current_span(name, context, kind, attributes, links, start_time, record_exception,
                                                set_status_on_exception,
                                                end_on_exit) as span:  # type: Span
            yield self.add_span_attributes(span)


class SaarctfTracerProvider(TracerProvider):
    """Wrap tracer providers to add common attributes to spans"""

    def get_tracer(self, instrumenting_module_name: str, instrumenting_library_version: Optional[str] = None,
                   schema_url: Optional[str] = None,
                   attributes: Optional[types.Attributes] = None) -> Tracer:
        return SaarctfTracer(
            super().get_tracer(instrumenting_module_name, instrumenting_library_version, schema_url, attributes))


def _nop(*args: Any, **kwargs: Any) -> None:
    pass


def instrument_httpx_without_propagation(client: httpx.AsyncClient) -> None:
    """
    We do not want to transport traceparent headers towards services (fingerprinting etc).
    There's no setting so we must nop out the injection.
    """
    from opentelemetry.instrumentation import httpx as httpx_instrumentation
    httpx_instrumentation._inject_propagation_headers = _nop
    httpx_instrumentation.inject = _nop
    httpx_instrumentation.HTTPXClientInstrumentor.instrument_client(client)
