import asyncio
import contextlib
import logging
import os
import sys
import traceback
from contextlib import AsyncExitStack, asynccontextmanager
from inspect import Parameter, isawaitable, signature
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
from motor.motor_asyncio import (
    AsyncIOMotorClient,
    AsyncIOMotorCollection,
    AsyncIOMotorDatabase,
)

from enochecker3.logging import ELKFormatter
from enochecker3.utils import FlagSearcher

from .chaindb import ChainDB
from .types import (
    BaseCheckerTaskMessage,
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
)

METHOD_TO_TASK_MESSAGE_MAPPING = {
    CheckerMethod.PUTFLAG: PutflagCheckerTaskMessage,
    CheckerMethod.GETFLAG: GetflagCheckerTaskMessage,
    CheckerMethod.PUTNOISE: PutnoiseCheckerTaskMessage,
    CheckerMethod.GETNOISE: GetnoiseCheckerTaskMessage,
    CheckerMethod.HAVOC: HavocCheckerTaskMessage,
    CheckerMethod.EXPLOIT: ExploitCheckerTaskMessage,
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
    def __init__(self, checker: "Enochecker", task: BaseCheckerTaskMessage):
        self.checker = checker
        self.task = task
        self._exit_stack: AsyncExitStack = AsyncExitStack()

    async def __aenter__(self) -> "DependencyInjector":
        await self._exit_stack.__aenter__()
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> Optional[bool]:
        return await self._exit_stack.__aexit__(exc_type, exc_value, traceback)

    async def get(self, t: type) -> Any:
        if t not in self.checker._dependency_injections:
            raise ValueError(f"No registered dependency for type {t}")

        injector = self.checker._dependency_injections[t]
        args = await self._exit_stack.enter_async_context(
            self.checker._inject_dependencies(self.task, injector, None)
        )
        if isawaitable(injector):
            res = await injector(*args)
        else:
            res = injector(*args)

        if not hasattr(res, "__enter__") and not hasattr(res, "__aenter__"):
            return res
        return await self._exit_stack.enter_async_context(res)


class Enochecker:
    def __init__(self, name: str, service_port: int):
        self.name: str = name
        self.service_port: int = service_port

        self._dependency_injections: Dict[type, Callable[..., Any]] = {}
        self._logger: logging.Logger = logging.getLogger(__name__)
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(ELKFormatter("%(message)s"))
        self._logger.addHandler(handler)
        self._logger.setLevel(logging.DEBUG)

        """
        self._logger = logging.getLogger("uvicorn")
        self._logger.setLevel(
            logging.getLogger("uvicorn.access").getEffectiveLevel()
        )
        """

        self.register_dependency(self._get_http_client)
        self.register_dependency(self._get_chaindb)
        self.register_dependency(self._get_motor_collection)
        self.register_dependency(self._get_motor_database)
        self.register_dependency(self._get_flag_searcher)
        self.register_dependency(self._get_logger_adapter)
        self.register_dependency(self._get_async_socket)
        self.register_dependency(self._get_dependency_injector)

        self._method_variants: Dict[CheckerMethod, Dict[int, Callable[..., Any]]] = {
            CheckerMethod.PUTFLAG: {},
            CheckerMethod.GETFLAG: {},
            CheckerMethod.PUTNOISE: {},
            CheckerMethod.GETNOISE: {},
            CheckerMethod.HAVOC: {},
            CheckerMethod.EXPLOIT: {},
        }

    async def _init(self) -> None:
        mongo_host = os.getenv("MONGO_HOST", "127.0.0.1")
        mongo_port = os.getenv("MONGO_PORT", 27017)
        mongo_user = os.getenv("MONGO_USER", None)
        mongo_password = os.getenv("MONGO_PASSWORD", None)

        if (mongo_user and not mongo_password) or (not mongo_user and mongo_password):
            raise ValueError(
                "cannot set only MONGO_USER or MONGO_PASSWORD, must set none or both"
            )

        if mongo_user:
            connection_string = (
                f"mongodb://{mongo_user}:{mongo_password}@{mongo_host}:{mongo_port}"
            )
        else:
            connection_string = f"mongodb://{mongo_host}:{mongo_port}"

        self._mongo: AsyncIOMotorClient = AsyncIOMotorClient(connection_string)
        self._mongodb: AsyncIOMotorDatabase = self._mongo[self.name]

        self._chain_collection: AsyncIOMotorCollection = self._mongodb["chain_db"]

        await self._chain_collection.create_index(
            [("task_chain_id", pymongo.ASCENDING), ("key", pymongo.ASCENDING)],
            name="task_chain_index",
            unique=True,
        )

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
                    f"variant_id {variant_id} already defined for method {method}"
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

    @asynccontextmanager
    async def _inject_dependencies(
        self,
        task: BaseCheckerTaskMessage,
        f: Callable[..., Any],
        dependencies: Optional[Set[type]] = None,
    ) -> AsyncIterator[Any]:
        dependencies = dependencies or set()

        sig = signature(f)
        task_message_type = METHOD_TO_TASK_MESSAGE_MAPPING[task.method]

        args: List[Union[AsyncContextManager[Any], Any]] = []
        for v in sig.parameters.values():
            try:
                subclass = issubclass(task_message_type, v.annotation)
            except TypeError:
                # subscripted generics, e.g. AsyncSocket = Tuple[..., ...], cannot be used in issubclass
                subclass = False
            if subclass:
                args.append(task)
            elif v.annotation in dependencies:
                raise CircularDependencyException(
                    f"detected circular dependency in {f} with injected type {v.annotation}"
                )
            else:
                injector = self._dependency_injections[v.annotation]
                async with self._inject_dependencies(
                    task, injector, dependencies.union([v.annotation])
                ) as args_:
                    if isawaitable(injector):
                        args.append(await injector(*args_))
                    else:
                        args.append(injector(*args_))

        async with AsyncExitStack() as stack:
            # new_args contains the return values of __(a)enter__, which would be the "x" in "(async) with ... as x:"
            new_args = []
            for arg in args:
                if not hasattr(arg, "__enter__") and not hasattr(arg, "__aenter__"):
                    new_args.append(arg)
                    continue
                new_args.append(await stack.enter_async_context(arg))
            yield new_args

    async def _call_method_raw(self, task: BaseCheckerTaskMessage) -> Optional[str]:
        variant_id = task.variant_id
        method = task.method
        try:
            f = self._method_variants[method][variant_id]
        except KeyError:
            raise AttributeError(
                f"variant_id {variant_id} not defined for method {method}"
            )

        async with self._inject_dependencies(task, f) as args:
            return await f(*args)

    async def _call_method(self, task: BaseCheckerTaskMessage) -> Optional[str]:
        try:
            return await asyncio.wait_for(
                self._call_method_raw(task),
                timeout=(task.timeout / 1000) - TIMEOUT_BUFFER,
            )
        except asyncio.TimeoutError:
            trace = traceback.format_exc()
            logger = self._get_logger_adapter(task)
            logger.error(f"Checker task timed out\n{trace}")
            raise MumbleException(
                "Service responding too slow, allowed time for checker task exceeded"
            )
        except (httpx.ConnectTimeout, httpx.ConnectError):
            trace = traceback.format_exc()
            logger = self._get_logger_adapter(task)
            logger.info(f"Failed to connect to service\n{trace}")
            raise OfflineException("Could not establish HTTP connection to service")

    async def _call_putflag(
        self, task: PutflagCheckerTaskMessage
    ) -> CheckerResultMessage:
        attack_info: Optional[str] = await self._call_method(task)
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
        flag: Optional[str] = await self._call_method(task)
        if not flag:
            return CheckerResultMessage(
                result=CheckerTaskResult.MUMBLE, message="Flag not found"
            )
        return CheckerResultMessage(result=CheckerTaskResult.OK, flag=flag)

    ########################
    # Dependency Injection #
    ########################

    def register_dependency(self, f: Callable[..., Any]) -> None:
        sig = signature(f)
        if sig.return_annotation == Parameter.empty:
            raise AttributeError(f"missing return annotation for {f.__name__}")
        if sig.return_annotation in self._dependency_injections:
            raise ValueError(
                f"already registered a dependency with return type {sig.return_annotation}"
            )

        self._dependency_injections[sig.return_annotation] = f

    def _get_http_client(self, task: BaseCheckerTaskMessage) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=f"http://{task.address}:{self.service_port}", verify=False
        )

    def _get_chaindb(self, task: BaseCheckerTaskMessage) -> ChainDB:
        return ChainDB(self._chain_collection, task.task_chain_id)

    def _get_motor_collection(
        self, task: BaseCheckerTaskMessage
    ) -> AsyncIOMotorCollection:
        return self._mongodb[f"team_{task.team_id}"]

    def _get_motor_database(self, task: BaseCheckerTaskMessage) -> AsyncIOMotorDatabase:
        return self._mongodb

    def _get_flag_searcher(self, task: ExploitCheckerTaskMessage) -> FlagSearcher:
        return FlagSearcher(task.flag_regex, task.flag_hash)

    def _get_logger_adapter(
        self, task: BaseCheckerTaskMessage
    ) -> logging.LoggerAdapter:
        return logging.LoggerAdapter(
            self._logger,
            extra={
                "checker_name": self.name,
                "checker_task": task,
            },
        )

    @contextlib.asynccontextmanager
    async def _get_async_socket(
        self, task: BaseCheckerTaskMessage, logger: logging.LoggerAdapter
    ) -> AsyncSocket:
        try:
            conn = await asyncio.streams.open_connection(
                task.address, self.service_port
            )
        except (ConnectionError, asyncio.TimeoutError):
            trace = traceback.format_exc()
            logger.info(f"Failed to connect to service\n{trace}")
            raise OfflineException("Could not establish socket connection to service")
        try:
            yield conn
        finally:
            conn[1].close()
            await conn[1].wait_closed()

    def _get_dependency_injector(
        self, task: BaseCheckerTaskMessage
    ) -> DependencyInjector:
        return DependencyInjector(self, task)

    #########################
    # variant_id validation #
    #########################

    def _validate_variant_ids(self) -> Tuple[int, int, int, int]:
        putflag_keys = self._method_variants[CheckerMethod.PUTFLAG].keys()
        getflag_keys = self._method_variants[CheckerMethod.GETFLAG].keys()
        if putflag_keys != getflag_keys:
            raise InvalidVariantIdsException(
                "mismatch between putflag and getflag variants"
            )

        putnoise_keys = self._method_variants[CheckerMethod.PUTNOISE].keys()
        getnoise_keys = self._method_variants[CheckerMethod.GETNOISE].keys()
        if putnoise_keys != getnoise_keys:
            raise InvalidVariantIdsException(
                "mismatch between putnoise and getnoise variants"
            )

        for method in self._method_variants.keys():
            self._ensure_sequential_variant_ids(method)

        return (
            len(self._method_variants[CheckerMethod.PUTFLAG]),
            len(self._method_variants[CheckerMethod.PUTNOISE]),
            len(self._method_variants[CheckerMethod.HAVOC]),
            len(self._method_variants[CheckerMethod.EXPLOIT]),
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
        ) = self._validate_variant_ids()

        return CheckerInfoMessage(
            service_name=self.name,
            flag_variants=flag_variants,
            noise_variants=noise_variants,
            havoc_variants=havoc_variants,
            exploit_variants=exploit_variants,
        )

    ###########
    # FastAPI #
    ###########

    @property
    def app(self) -> FastAPI:
        app = FastAPI()

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
            cls = METHOD_TO_TASK_MESSAGE_MAPPING[task.method]
            _task = cls(**task.dict())
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
                    return await self._call_havoc(cast(HavocCheckerTaskMessage, _task))
                elif task.method == CheckerMethod.EXPLOIT:
                    return await self._call_exploit(
                        cast(ExploitCheckerTaskMessage, _task)
                    )
                else:
                    return CheckerResultMessage(
                        result=CheckerTaskResult.INTERNAL_ERROR,
                        message=f"Unsupported method: {task.method}",
                    )
            except MumbleException as e:
                trace = traceback.format_exc()
                logger.info(f"Encountered mumble exception:\n{trace}")
                return CheckerResultMessage(
                    result=CheckerTaskResult.MUMBLE, message=e.message
                )
            except OfflineException as e:
                trace = traceback.format_exc()
                logger.info(f"Encountered offline exception:\n{trace}")
                return CheckerResultMessage(
                    result=CheckerTaskResult.OFFLINE, message=e.message
                )
            except InternalErrorException as e:
                trace = traceback.format_exc()
                logger.info(f"Encountered explicit internal error exception:\n{trace}")
                return CheckerResultMessage(
                    result=CheckerTaskResult.INTERNAL_ERROR, message=e.message
                )
            except Exception as e:
                traceback.print_exc()
                trace = traceback.format_exc()
                logger.critical(f"Encountered internal exception:\n{trace}")
                return CheckerResultMessage(
                    result=CheckerTaskResult.INTERNAL_ERROR,
                    message=f"Unhandled exception of type {type(e)}",
                )

        app.on_event("startup")(self._init)

        return app

    def run(self, port: Optional[int] = None) -> None:
        uvicorn.run(self.app, host="127.0.0.1", port=port or 8000)
