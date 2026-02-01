import asyncio
import contextlib
import logging
import os
import sys
import traceback
from contextlib import AsyncExitStack
from inspect import Parameter, isawaitable, signature
from random import Random
from types import TracebackType
from typing import (
    Any,
    AsyncContextManager,
    AsyncIterator,
    Callable,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
    Type,
    Union,
    cast,
)

import httpx
import pymongo
import uvicorn
from fastapi import FastAPI
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.trace import get_current_span
from pymongo import AsyncMongoClient
from pymongo.asynchronous.collection import AsyncCollection
from pymongo.asynchronous.database import AsyncDatabase

from enochecker3.logging import DebugFormatter, ELKFormatter
from enochecker3.utils import FlagSearcher
from enochecker3.telemetry import (
    SaarctfTracer,
    instrument_httpx_without_propagation,
    CommonAttributesLogFilter,
    setup_telemetry,
)
from enochecker3.telemetry_attributes import telemetry_attributes

from .chaindb import ChainDB
from .types import (
    CheckerInfoMessage,
    CheckerMethod,
    CheckerResultMessage,
    CheckerTaskMessage,
    CheckerTaskResult,
    ExploitCheckerTaskMessage,
    GetflagCheckerTaskMessage,
    GetnoiseCheckerTaskMessage,
    HavocCheckerTaskMessage,
    InternalErrorException,
    MumbleException,
    OfflineException,
    PutflagCheckerTaskMessage,
    PutnoiseCheckerTaskMessage,
    TestCheckerTaskMessage,
)

METHOD_TO_TASK_MESSAGE_MAPPING = {
    CheckerMethod.PUTFLAG: PutflagCheckerTaskMessage,
    CheckerMethod.GETFLAG: GetflagCheckerTaskMessage,
    CheckerMethod.PUTNOISE: PutnoiseCheckerTaskMessage,
    CheckerMethod.GETNOISE: GetnoiseCheckerTaskMessage,
    CheckerMethod.HAVOC: HavocCheckerTaskMessage,
    CheckerMethod.EXPLOIT: ExploitCheckerTaskMessage,
    CheckerMethod.TEST: TestCheckerTaskMessage,
}

TIMEOUT_BUFFER = 2


AsyncSocket = AsyncIterator[Tuple[asyncio.StreamReader, asyncio.StreamWriter]]


class EnocheckerException(Exception):
    pass


class CircularDependencyException(EnocheckerException):
    pass


class InvalidVariantIdsException(EnocheckerException):
    pass


class DependencyInjector:
    """
    Runtime dependency injector for use within checker methods.

    This allows checker methods to dynamically request dependencies during execution
    using the `get()` method, rather than declaring them as function parameters.
    Useful for conditional dependency injection.

    Example:
        async def my_checker(injector: DependencyInjector):
            if some_condition:
                http_client = await injector.get(httpx.AsyncClient)
    """

    def __init__(self, checker: "Enochecker", task: CheckerTaskMessage):
        self.checker = checker
        self.task = task
        # AsyncExitStack manages cleanup of async context managers (like sockets, clients)
        self._exit_stack: AsyncExitStack = AsyncExitStack()

    async def __aenter__(self) -> "DependencyInjector":
        """Enter the async context and initialize the exit stack."""
        await self._exit_stack.__aenter__()
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> Optional[bool]:
        """Exit the async context, ensuring all managed resources are cleaned up."""
        return await self._exit_stack.__aexit__(exc_type, exc_value, traceback)

    async def get(self, t: type, name: str = "") -> Any:
        """
        Dynamically resolve and inject a dependency at runtime.

        Args:
            t: The type of dependency to inject (e.g., httpx.AsyncClient, ChainDB)
            name: Optional name prefix for named dependencies (e.g., "custom" for custom_string)

        Returns:
            The requested dependency instance
        """
        # Find the registered injector function for this type
        injector = self.checker.resolve_injector(name, t)
        # Recursively inject dependencies needed by the injector itself
        args = await self.checker._inject_dependencies(
            self.task, injector, self._exit_stack
        )
        # Call the injector with its dependencies
        res = injector(*args)
        if isawaitable(res):
            res = await res

        # If the result is a context manager, enter it and manage its lifecycle
        if hasattr(res, "__enter__") or hasattr(res, "__aenter__"):
            return await self._exit_stack.enter_async_context(res)
        return res


class Enochecker:
    def __init__(self, service_name: str, service_port: int):
        self.service_name: str = service_name
        self.service_port: int = service_port

        self.checker_name: str = service_name + "Checker"

        # Dependency injection registry: Maps (name_prefix, return_type) -> injector_function
        self._dependency_injections: Dict[Tuple[str, type], Callable[..., Any]] = {}
        self._logger: logging.Logger = logging.getLogger()
        self._logger.addFilter(CommonAttributesLogFilter())

        handler = logging.StreamHandler(sys.stdout)
        #if os.getenv("LOG_FORMAT") == "DEBUG":
        #    handler.setFormatter(DebugFormatter("%(message)s"))
        #else:
        #    handler.setFormatter(ELKFormatter("%(message)s"))

        self._logger.addHandler(handler)
        self._logger.setLevel(logging.DEBUG)

        if __name__ == "uvicorn":
            self._logger.setLevel(
                logging.getLogger("uvicorn.access").getEffectiveLevel()
            )

        # Register built-in dependencies that checker methods can use by declaring them
        # as parameters. For example:
        #   async def my_putflag(self, http_client: httpx.AsyncClient, db: ChainDB):
        # Will automatically receive an HTTP client and database instance
        self.register_dependency(self._get_http_client)  # httpx.AsyncClient
        self.register_dependency(self._get_chaindb)  # ChainDB
        self.register_dependency(self._get_motor_collection)  # AsyncCollection
        self.register_dependency(self._get_motor_database)  # AsyncDatabase
        self.register_dependency(self._get_flag_searcher)  # FlagSearcher
        self.register_dependency(self._get_logger_adapter)  # logging.LoggerAdapter
        self.register_dependency(
            self._get_async_socket
        )  # AsyncSocket (context manager)
        self.register_dependency(self._get_random)  # Random
        self.register_dependency(self._get_dependency_injector)  # DependencyInjector

        self._method_variants: Dict[CheckerMethod, Dict[int, Callable[..., Any]]] = {
            CheckerMethod.PUTFLAG: {},
            CheckerMethod.GETFLAG: {},
            CheckerMethod.PUTNOISE: {},
            CheckerMethod.GETNOISE: {},
            CheckerMethod.HAVOC: {},
            CheckerMethod.EXPLOIT: {},
            CheckerMethod.TEST: {},
        }

    async def _init(self) -> None:
        mongo_host = os.getenv("MONGO_HOST", "127.0.0.1")
        mongo_port = os.getenv("MONGO_PORT", 27017)
        mongo_user = os.getenv("MONGO_USER", None)
        mongo_password = os.getenv("MONGO_PASSWORD", None)

        if (mongo_user and not mongo_password) or (not mongo_user and mongo_password):
            raise ValueError(
                "Cannot set only MONGO_USER or MONGO_PASSWORD, must set none or both"
            )

        if mongo_user:
            connection_string = (
                f"mongodb://{mongo_user}:{mongo_password}@{mongo_host}:{mongo_port}"
            )
        else:
            connection_string = f"mongodb://{mongo_host}:{mongo_port}"

        self._mongo: AsyncMongoClient = AsyncMongoClient(connection_string)
        self._mongodb: AsyncDatabase = self._mongo[self.checker_name]

        self._chain_collection: AsyncCollection = self._mongodb["chain_db"]

        await self._chain_collection.create_index(
            [("task_chain_id", pymongo.ASCENDING), ("key", pymongo.ASCENDING)],
            name="task_chain_index",
            unique=True,
        )

    @contextlib.asynccontextmanager
    async def _lifespan(self, app: FastAPI) -> AsyncIterator[None]:
        setup_telemetry(self.checker_name)
        await self._init()
        yield

    def _define_method(
        self,
        method: CheckerMethod,
        *variant_ids: int,
    ) -> Callable[[Callable[..., Any]], None]:
        if not variant_ids:
            raise InvalidVariantIdsException(
                "Must specify at least one variant_id for a method"
            )

        if len(variant_ids) != len(set(variant_ids)):
            raise InvalidVariantIdsException("variant_id must be unique")

        for variant_id in variant_ids:
            if variant_id < 0:
                raise InvalidVariantIdsException(
                    f"variant_id {variant_id} must not be negative"
                )

            if variant_id in self._method_variants[method]:
                raise InvalidVariantIdsException(
                    f"Variant_id {variant_id} already defined for method {method}"
                )

        def wrapper(f: Callable[..., Any]) -> None:
            for variant_id in variant_ids:
                self._method_variants[method][variant_id] = f

        return wrapper

    def putflag(self, *variant_ids: int) -> Callable[[Callable[..., Any]], None]:
        return self._define_method(CheckerMethod.PUTFLAG, *variant_ids)

    def getflag(self, *variant_ids: int) -> Callable[[Callable[..., Any]], None]:
        return self._define_method(CheckerMethod.GETFLAG, *variant_ids)

    def putnoise(self, *variant_ids: int) -> Callable[[Callable[..., Any]], None]:
        return self._define_method(CheckerMethod.PUTNOISE, *variant_ids)

    def getnoise(self, *variant_ids: int) -> Callable[[Callable[..., Any]], None]:
        return self._define_method(CheckerMethod.GETNOISE, *variant_ids)

    def havoc(self, *variant_ids: int) -> Callable[[Callable[..., Any]], None]:
        return self._define_method(CheckerMethod.HAVOC, *variant_ids)

    def exploit(self, *variant_ids: int) -> Callable[[Callable[..., Any]], None]:
        return self._define_method(CheckerMethod.EXPLOIT, *variant_ids)

    def test(self, *variant_ids: int) -> Callable[[Callable[..., Any]], None]:
        return self._define_method(CheckerMethod.TEST, *variant_ids)

    def resolve_injector(self, name: str, t: type) -> Callable[..., Any]:
        """
        Resolve a dependency injector function based on parameter name and type.

        The resolution process:
        1. Try to find a named dependency: ("custom", httpx.AsyncClient) for parameter "custom_client"
        2. Fall back to generic dependency: ("", httpx.AsyncClient) for any AsyncClient parameter

        This enables both generic dependencies (e.g., any `http_client: AsyncClient`)
        and named dependencies (e.g., `custom_client: AsyncClient` specifically registered as "custom").

        Args:
            name: Parameter name from the function signature (e.g., "custom_client")
            t: Parameter type annotation (e.g., httpx.AsyncClient)

        Returns:
            The injector function that creates instances of the requested dependency

        Raises:
            ValueError: If no registered dependency matches the name/type combination
        """
        # Extract name prefix (before first underscore): "custom_client" -> "custom"
        key: Tuple[str, type] = (name.split("_", 1)[0], t)
        if key not in self._dependency_injections:
            # Try generic (unnamed) dependency with empty string prefix
            generic_key: Tuple[str, type] = ("", t)
            if generic_key not in self._dependency_injections:
                raise ValueError(
                    f"No registered dependency for name {key[0]} and/or type {key[1]}"
                )
            return self._dependency_injections[generic_key]
        return self._dependency_injections[key]

    async def _inject_dependencies(
        self,
        task: CheckerTaskMessage,
        f: Callable[..., Any],
        stack: AsyncExitStack,
        dependencies: Optional[Set[Callable[..., Any]]] = None,
    ) -> List[Any]:
        """
        Recursively inject dependencies for a function based on its parameter type annotations.

        This is the core of the dependency injection system. It:
        1. Inspects the function signature to find all parameters
        2. For each parameter, determines if it's a task message or a dependency
        3. Recursively injects dependencies (dependencies can depend on other dependencies)
        4. Handles async context managers (like sockets) by entering them and managing cleanup
        5. Detects circular dependencies to prevent infinite recursion

        Example flow for `async def my_check(task: PutflagTask, client: AsyncClient, db: ChainDB)`:
        1. `task: PutflagTask` -> directly inject the task message
        2. `client: AsyncClient` -> resolve _get_http_client, which needs `task` -> inject task -> call injector
        3. `db: ChainDB` -> resolve _get_chaindb, which needs `task` -> inject task -> call injector

        Args:
            task: The current checker task being executed
            f: The function whose dependencies need to be injected
            stack: AsyncExitStack for managing async context manager lifetimes
            dependencies: Set of injectors already in the call chain (for cycle detection)

        Returns:
            List of resolved dependency instances ready to be passed to the function

        Raises:
            CircularDependencyException: If a circular dependency is detected
        """
        dependencies = dependencies or set()

        sig = signature(f)
        # Get the specific task message type for this method (e.g., PutflagCheckerTaskMessage)
        task_message_type = METHOD_TO_TASK_MESSAGE_MAPPING[task.method]

        args: List[Union[AsyncContextManager[Any], Any]] = []
        # Iterate through each parameter in the function signature
        for v in sig.parameters.values():
            # Check if this parameter wants the task message itself
            try:
                subclass = issubclass(task_message_type, v.annotation)
                if subclass:
                    # This parameter wants the task message - inject it directly
                    args.append(task)
                    continue
            except TypeError:
                # Subscripted generics (e.g., Tuple[...]) can't be used in issubclass
                pass

            # This parameter wants a dependency - resolve and inject it
            injector = self.resolve_injector(v.name, v.annotation)

            # Circular dependency detection: if this injector is already being
            # resolved higher up in the call stack, we have a circular dependency
            if injector in dependencies:
                raise CircularDependencyException(
                    f"Detected circular dependency in {f} with injected type {v.annotation}"
                )

            # Recursively inject dependencies for the injector itself
            # (e.g., _get_async_socket needs a logger, which needs a task)
            args_ = await self._inject_dependencies(
                task, injector, stack, dependencies.union([injector])
            )
            # Call the injector with its dependencies to get the actual dependency instance
            arg = injector(*args_)
            if isawaitable(arg):
                arg = await arg
            args.append(arg)

        # Handle (async) context managers: enter them and let the exit stack manage cleanup
        # This ensures resources like sockets and HTTP clients are properly closed
        # new_args contains the return values of __aenter__, which is the "x" in "async with ... as x:"
        new_args = []
        for arg in args:
            if hasattr(arg, "__enter__") or hasattr(arg, "__aenter__"):
                # Enter the (async) context manager and let the stack manage its cleanup
                # note that enter_async_context also works with non-async contexts
                new_args.append(await stack.enter_async_context(arg))
            else:
                # Not a context manager - use as-is
                new_args.append(arg)

        return new_args

    async def _call_method_raw(self, task: CheckerTaskMessage) -> Optional[str | bytes]:
        variant_id = task.variant_id
        method = task.method
        try:
            f = self._method_variants[method][variant_id]
        except KeyError:
            raise AttributeError(
                f"Variant_id {variant_id} not defined for method {method}"
            )

        async with AsyncExitStack() as stack:
            args = await self._inject_dependencies(task, f, stack)
            res = await f(*args)

        if res is not None and not isinstance(res, str) and not isinstance(res, bytes):
            raise InternalErrorException(
                f"{task.method} method returned non-string object"
            )

        return res

    async def _call_method(self, task: CheckerTaskMessage) -> Optional[str | bytes]:
        try:
            return await asyncio.wait_for(
                self._call_method_raw(task),
                timeout=(task.timeout / 1000) - TIMEOUT_BUFFER,
            )
        except (MumbleException, OfflineException, InternalErrorException):
            raise
        except (httpx.ConnectError, httpx.ConnectTimeout):
            trace = traceback.format_exc()
            logger = self._get_logger_adapter(task)
            logger.info(f"Connection to service failed\n{trace}")
            raise OfflineException("Connection to service failed")
        except (EOFError, httpx.ReadError, httpx.WriteError):
            trace = traceback.format_exc()
            logger = self._get_logger_adapter(task)
            logger.error(f"Connection to service closed abruptly\n{trace}")
            raise MumbleException("Closed to service closed abruptly")
        except (TimeoutError, httpx.TimeoutException):
            trace = traceback.format_exc()
            logger = self._get_logger_adapter(task)
            logger.error(f"Service responding too slow\n{trace}")
            raise MumbleException("Service responding too slow")
        except (ConnectionResetError, httpx.CloseError):
            trace = traceback.format_exc()
            logger = self._get_logger_adapter(task)
            logger.error(f"Connection reset by service\n{trace}")
            raise MumbleException("Connection reset by services")
        except (httpx.RemoteProtocolError, httpx.DecodingError):
            trace = traceback.format_exc()
            logger = self._get_logger_adapter(task)
            logger.info(f"HTTP connection to service failed\n{trace}")
            raise OfflineException("HTTP connection to service failed")
        except Exception as e:
            trace = traceback.format_exc()
            logger = self._get_logger_adapter(task)
            logger.info(f"Checker internal error\n{trace}")
            raise InternalErrorException("Checker internal error", inner=e)

    async def _call_putflag(
        self, task: PutflagCheckerTaskMessage
    ) -> CheckerResultMessage:
        attack_info: Optional[str | bytes] = await self._call_method(task)
        if isinstance(attack_info, bytes):
            attack_info = attack_info.decode()
        return CheckerResultMessage(
            result=CheckerTaskResult.OK, attack_info=attack_info
        )

    async def _call_getflag(
        self, task: GetflagCheckerTaskMessage
    ) -> CheckerResultMessage:
        await self._call_method(task)
        return CheckerResultMessage(result=CheckerTaskResult.OK)

    async def _call_putnoise(
        self, task: PutnoiseCheckerTaskMessage
    ) -> CheckerResultMessage:
        await self._call_method(task)
        return CheckerResultMessage(result=CheckerTaskResult.OK)

    async def _call_getnoise(
        self, task: GetnoiseCheckerTaskMessage
    ) -> CheckerResultMessage:
        await self._call_method(task)
        return CheckerResultMessage(result=CheckerTaskResult.OK)

    async def _call_havoc(self, task: HavocCheckerTaskMessage) -> CheckerResultMessage:
        await self._call_method(task)
        return CheckerResultMessage(result=CheckerTaskResult.OK)

    async def _call_exploit(
        self, task: ExploitCheckerTaskMessage
    ) -> CheckerResultMessage:
        flag_text: str | bytes | None = await self._call_method(task)
        flag_searcher = self._get_flag_searcher(task)
        flag_bytes: bytes | None = flag_searcher.search_flag(flag_text or "")
        if flag_bytes is None:
            return CheckerResultMessage(
                result=CheckerTaskResult.MUMBLE, message="No flags found"
            )
        flag_text = flag_bytes.decode(errors="replace")
        return CheckerResultMessage(result=CheckerTaskResult.OK, flag=flag_text)

    async def _call_test(self, task: TestCheckerTaskMessage) -> CheckerResultMessage:
        await self._call_method(task)
        return CheckerResultMessage(result=CheckerTaskResult.OK)

    ########################
    # Dependency Injection #
    ########################

    def register_named_dependency(self, name: str = "") -> Callable[..., Any]:
        """
        Register a named dependency that can be injected into checker methods.

        Named dependencies allow multiple injectors for the same type, differentiated by name.
        For example, you can have both a generic AsyncClient and a "special_client: AsyncClient"
        that's configured differently.

        The registration key is formed from:
        - Name prefix (before first underscore in the name parameter)
        - Return type annotation of the injector function

        Example:
            @checker.register_named_dependency("custom")
            def get_custom_client(task: PutflagTask) -> httpx.AsyncClient:
                return httpx.AsyncClient(timeout=60.0)

            # Can now be injected as:
            async def my_checker(custom_client: httpx.AsyncClient):
                # Will use the custom configured client
                ...

        Args:
            name: Name prefix for this dependency (empty string for generic dependencies)

        Returns:
            Decorator function that registers the dependency

        Raises:
            AttributeError: If the injector function is missing a return type annotation
            ValueError: If a dependency with the same name and type is already registered
        """

        def decorator(f: Callable[..., Any]) -> Callable[..., Any]:
            sig = signature(f)
            # Extract name prefix and use the return type as the dependency type
            key: Tuple[str, type] = (name.split("_", 1)[0], sig.return_annotation)

            # Return type annotation is required so we know what type this injector provides
            if sig.return_annotation == Parameter.empty:
                raise AttributeError(f"missing return annotation for {f.__name__}")

            # Prevent duplicate registrations
            if key in self._dependency_injections:
                raise ValueError(
                    f"already registered a dependency with name {key[0]} and type {key[1]}"
                )

            self._dependency_injections[key] = f

            return f

        return decorator

    def register_dependency(self, f: Callable[..., Any]) -> Callable[..., Any]:
        """
        Register a generic (unnamed) dependency that can be injected into checker methods.

        This is a convenience wrapper around register_named_dependency("") for the common
        case of registering a dependency that doesn't need a specific name.

        Example:
            @checker.register_dependency
            def get_http_client(task: BaseCheckerTask) -> httpx.AsyncClient:
                return httpx.AsyncClient(base_url=f"http://{task.address}")

            # Can now be injected as any parameter named *_client with type AsyncClient:
            async def my_checker(http_client: httpx.AsyncClient):
                ...

        Args:
            f: The injector function (must have a return type annotation)

        Returns:
            The original function (unchanged)
        """
        return self.register_named_dependency("")(f)

    # Built-in dependency providers - these are automatically registered and can be
    # injected into any checker method by declaring them as parameters

    def _get_http_client(self, task: CheckerTaskMessage) -> httpx.AsyncClient:
        """
        Provide an HTTP client configured for the service being checked.

        Injectable as: http_client: httpx.AsyncClient

        The client is configured with:
        - Base URL pointing to the service (task.address:service_port)
        - SSL verification disabled (for CTF/testing environments)
        """
        client = httpx.AsyncClient(
            base_url=f"http://{task.address}:{self.service_port}", verify=False
        )
        instrument_httpx_without_propagation(client)
        return client

    def _get_chaindb(self, task: CheckerTaskMessage) -> ChainDB:
        """
        Provide a ChainDB instance for persistent storage across checker rounds.

        Injectable as: db: ChainDB

        ChainDB allows storing and retrieving data associated with a specific task chain,
        useful for storing attack info from putflag that needs to be retrieved in getflag.
        """
        return ChainDB(self._chain_collection, task.task_chain_id)

    def _get_motor_collection(self, task: CheckerTaskMessage) -> AsyncCollection:
        """
        Provide a MongoDB collection scoped to the current team.

        Injectable as: collection: AsyncCollection

        This gives direct access to a team-specific MongoDB collection for custom
        storage needs beyond what ChainDB provides.
        """
        return self._mongodb[f"team_{task.team_id}"]

    def _get_motor_database(self, task: CheckerTaskMessage) -> AsyncDatabase:
        """
        Provide the MongoDB database instance for this checker.

        Injectable as: database: AsyncDatabase

        This gives direct access to the checker's MongoDB database for advanced use cases.
        """
        _ = task
        return self._mongodb

    def _get_flag_searcher(self, task: ExploitCheckerTaskMessage) -> FlagSearcher:
        """
        Provide a FlagSearcher configured for the current exploit task.

        Injectable as: flag_searcher: FlagSearcher (only in exploit methods)

        The searcher uses the task's flag_regex and flag_hash to find and validate flags
        in the output from exploit attempts.
        """
        return FlagSearcher(task.flag_regex, task.flag_hash)

    def _get_logger_adapter(self, task: CheckerTaskMessage) -> logging.LoggerAdapter:
        """
        Provide a logger with task context automatically included.

        Injectable as: logger: logging.LoggerAdapter

        The logger adapter automatically includes service name, checker name, and task
        details in all log messages for better debugging and monitoring.
        """
        return logging.LoggerAdapter(
            self._logger,
            extra={
                "service_name": self.service_name,
                "checker_name": self.checker_name,
                "checker_task": task,
            },
        )

    @contextlib.asynccontextmanager
    async def _get_async_socket(
        self, task: CheckerTaskMessage, logger: logging.LoggerAdapter
    ) -> AsyncSocket:
        """
        Provide a raw TCP socket connection to the service.

        Injectable as: socket: AsyncSocket (note: this is an async context manager)

        Returns a tuple of (StreamReader, StreamWriter) for low-level protocol interaction.
        The connection is automatically closed when the checker method completes.

        Example:
            async def my_checker(socket: AsyncSocket):
                reader, writer = socket
                writer.write(b"HELLO\\n")
                response = await reader.readline()
        """
        try:
            conn = await asyncio.streams.open_connection(
                task.address, self.service_port
            )
        except:
            trace = traceback.format_exc()
            logger.info(f"Failed to connect to service\n{trace}")
            raise OfflineException("Could not establish socket connection to service")
        try:
            yield conn
        finally:
            # Ensure the socket is properly closed even if the checker crashes
            conn[1].close()
            await conn[1].wait_closed()

    def _get_random(self, task: CheckerTaskMessage) -> Random:
        """
        Provide a seeded random number generator for deterministic randomness.

        Injectable as: random: Random

        The RNG is seeded with the task_id, ensuring that the same task always generates
        the same "random" values. This enables reproducible fuzzing/testing: when a
        checker fails with specific random inputs, you can use the task_id from logs
        to reproduce the exact same random sequence for debugging.

        NOTE: Do NOT use this for exploit methods. Players don't have access to the
        checker's internal random state. Use attack_info (the return value from putflag)
        to provide targeting information to players instead.

        WARNING: In CTF environments, predictable checker behavior based on task_id can
        be a security risk if attackers can observe and exploit the patterns.
        """
        return Random(task.task_id)

    def _get_dependency_injector(self, task: CheckerTaskMessage) -> DependencyInjector:
        """
        Provide a DependencyInjector for runtime dependency resolution.

        Injectable as: injector: DependencyInjector

        This allows checker methods to dynamically request dependencies at runtime
        rather than declaring them all as parameters. Useful for conditional dependencies.
        """
        return DependencyInjector(self, task)

    #########################
    # variant_id validation #
    #########################

    def _validate_variant_ids(self) -> Tuple[int, int, int, int, int]:
        if env := os.environ.get("ENOCHECKER_FLAG_VARIANTS"):
            flag_variants = int(env)
        else:
            putflag_keys = self._method_variants[CheckerMethod.PUTFLAG].keys()
            getflag_keys = self._method_variants[CheckerMethod.GETFLAG].keys()
            if putflag_keys != getflag_keys:
                raise InvalidVariantIdsException(
                    "Mismatch between putflag and getflag variants"
                )
            flag_variants = len(self._method_variants[CheckerMethod.GETFLAG])

        if env := os.environ.get("ENOCHECKER_NOISE_VARIANTS"):
            noise_variants = int(env)
        else:
            putnoise_keys = self._method_variants[CheckerMethod.PUTNOISE].keys()
            getnoise_keys = self._method_variants[CheckerMethod.GETNOISE].keys()
            if putnoise_keys != getnoise_keys:
                raise InvalidVariantIdsException(
                    "Mismatch between putnoise and getnoise variants"
                )
            noise_variants = len(self._method_variants[CheckerMethod.GETNOISE])

        if env := os.environ.get("ENOCHECKER_HAVOC_VARIANTS"):
            havoc_variants = int(env)
        else:
            havoc_variants = len(self._method_variants[CheckerMethod.HAVOC])

        if env := os.environ.get("ENOCHECKER_EXPLOIT_VARIANTS"):
            exploit_variants = int(env)
        else:
            exploit_variants = len(self._method_variants[CheckerMethod.EXPLOIT])

        if env := os.environ.get("ENOCHECKER_TEST_VARIANTS"):
            test_variants = int(env)
        else:
            test_variants = len(self._method_variants[CheckerMethod.TEST])

        for method in self._method_variants.keys():
            self._ensure_sequential_variant_ids(method)

        return (
            flag_variants,
            noise_variants,
            havoc_variants,
            exploit_variants,
            test_variants,
        )

    def _ensure_sequential_variant_ids(self, method: CheckerMethod) -> None:
        keys = sorted(list(self._method_variants[method].keys()))
        for i, k in enumerate(keys):
            if i != k:
                raise InvalidVariantIdsException(
                    f"Expected variant_id {i} for {method}, was: {k}"
                )

    def get_service_info(self) -> CheckerInfoMessage:
        (
            flag_variants,
            noise_variants,
            havoc_variants,
            exploit_variants,
            test_variants,
        ) = self._validate_variant_ids()

        return CheckerInfoMessage(
            service_name=self.service_name,
            flag_variants=flag_variants,
            noise_variants=noise_variants,
            havoc_variants=havoc_variants,
            exploit_variants=exploit_variants,
            test_variants=test_variants,
        )

    ###########
    # FastAPI #
    ###########

    @property
    def app(self) -> FastAPI:
        app = FastAPI(lifespan=self._lifespan)

        try:
            service_info = self.get_service_info()
        except:
            print("error during service initializiation")
            traceback.print_exc()
            sys.exit(1)

        @app.get("/service", response_model=CheckerInfoMessage)
        def service() -> CheckerInfoMessage:
            print(service_info)
            return service_info

        @app.post("/", response_model=CheckerResultMessage)
        async def checker(task: CheckerTaskMessage) -> CheckerResultMessage:
            attributes = {
                "enochecker.method": str(task.method),
                "enochecker.team_id": task.team_id,
                "enochecker.variant_id": task.variant_id,
                "enochecker.related_round_id": task.related_round_id,
            }
            with telemetry_attributes(attributes):
                SaarctfTracer.add_span_attributes(get_current_span())
                cls = METHOD_TO_TASK_MESSAGE_MAPPING[task.method]
                _task = cls(**task.model_dump())
                logger = self._get_logger_adapter(_task)
                logger.debug(f"Received new checker task with payload: {_task}")
                try:
                    if task.method == CheckerMethod.PUTFLAG:
                        return await self._call_putflag(
                            cast(PutflagCheckerTaskMessage, _task)
                        )
                    elif task.method == CheckerMethod.GETFLAG:
                        return await self._call_getflag(
                            cast(GetflagCheckerTaskMessage, _task)
                        )
                    elif task.method == CheckerMethod.PUTNOISE:
                        return await self._call_putnoise(
                            cast(PutnoiseCheckerTaskMessage, _task)
                        )
                    elif task.method == CheckerMethod.GETNOISE:
                        return await self._call_getnoise(
                            cast(GetnoiseCheckerTaskMessage, _task)
                        )
                    elif task.method == CheckerMethod.HAVOC:
                        return await self._call_havoc(
                            cast(HavocCheckerTaskMessage, _task)
                        )
                    elif task.method == CheckerMethod.EXPLOIT:
                        return await self._call_exploit(
                            cast(ExploitCheckerTaskMessage, _task)
                        )
                    elif task.method == CheckerMethod.TEST:
                        return await self._call_test(
                            cast(TestCheckerTaskMessage, _task)
                        )
                    else:
                        return CheckerResultMessage(  # type: ignore
                            result=CheckerTaskResult.INTERNAL_ERROR,
                            message=f"Unsupported method: {task.method}",
                        )
                except MumbleException as e:
                    trace = traceback.format_exc()
                    if e.log_message:
                        logger.info(e.log_message)
                    logger.info(f"Encountered mumble exception:\n{trace}")
                    return CheckerResultMessage(
                        result=CheckerTaskResult.MUMBLE, message=e.message
                    )
                except OfflineException as e:
                    trace = traceback.format_exc()
                    if e.log_message:
                        logger.info(e.log_message)
                    logger.info(f"Encountered offline exception:\n{trace}")
                    return CheckerResultMessage(
                        result=CheckerTaskResult.OFFLINE, message=e.message
                    )
                except InternalErrorException as e:
                    trace = traceback.format_exc()
                    if e.log_message:
                        logger.info(e.log_message)
                    logger.info(f"Encountered internal error exception:\n{trace}")
                    return CheckerResultMessage(
                        result=CheckerTaskResult.INTERNAL_ERROR, message=e.message
                    )

        FastAPIInstrumentor().instrument_app(app)

        return app

    def run(self, port: Optional[int] = None) -> None:
        uvicorn.run(self.app, host="127.0.0.1", port=port or 8000)
