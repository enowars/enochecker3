from unittest.mock import AsyncMock, patch

import httpx
import pytest
from pymongo.asynchronous.collection import AsyncCollection
from pymongo.asynchronous.database import AsyncDatabase

from enochecker3 import (
    DependencyInjector,
    Enochecker,
    HavocCheckerTaskMessage,
    InternalErrorException,
)
from enochecker3.chaindb import ChainDB
from enochecker3.enochecker import CircularDependencyException
from enochecker3.types import CheckerTaskResult


@pytest.fixture
def havoc_task() -> HavocCheckerTaskMessage:
    return HavocCheckerTaskMessage(
        task_id=0,
        address="127.0.0.1",
        team_id=0,
        team_name="team_name",
        current_round_id=0,
        related_round_id=0,
        variant_id=0,
        timeout=15000,
        round_length=60000,
        task_chain_id="task_chain_id",
    )


@pytest.mark.asyncio
async def test_basic(checker: Enochecker, havoc_task: HavocCheckerTaskMessage):
    @checker.register_dependency
    def inject_string() -> str:
        return "123"

    @checker.havoc(0)
    async def havoc(param: str):
        assert param == "123"

    await checker._call_havoc(havoc_task)


@pytest.mark.asyncio
async def test_unnamed(checker: Enochecker, havoc_task: HavocCheckerTaskMessage):
    @checker.register_dependency
    def inject_string() -> str:
        return "123"

    @checker.register_named_dependency("special")
    def inject_special_string() -> str:
        return "456"

    @checker.havoc(0)
    async def havoc(a: str, b: str, special: str):
        assert a == "123" and b == "123" and special == "456"

    await checker._call_havoc(havoc_task)


@pytest.mark.asyncio
async def test_recursive_dependency(
    checker: Enochecker, havoc_task: HavocCheckerTaskMessage
):
    @checker.register_dependency
    def inject_string(x: int) -> str:
        return f"int: {x}"

    @checker.register_dependency
    def inject_integer() -> int:
        return 15

    @checker.havoc(0)
    async def havoc(param: str):
        assert param == "int: 15"

    await checker._call_havoc(havoc_task)


@pytest.mark.asyncio
async def test_circular_dependency(
    checker: Enochecker, havoc_task: HavocCheckerTaskMessage
):
    @checker.register_dependency
    def inject_string(x: int) -> str:
        return f"int: {x}"

    @checker.register_dependency
    def inject_integer(x: str) -> int:
        return len(x)

    @checker.havoc(0)
    async def havoc(param: str):
        pass

    with pytest.raises(InternalErrorException) as exc_info:
        await checker._call_havoc(havoc_task)
    assert type(exc_info.value.inner) is CircularDependencyException


@pytest.mark.asyncio
async def test_dependency_injector_context_manager(
    checker: Enochecker, havoc_task: HavocCheckerTaskMessage
):
    mock_ctx = AsyncMock()

    @checker.register_dependency
    def register_async_mock() -> AsyncMock:
        return mock_ctx

    @checker.havoc(0)
    async def havoc_test(injector: DependencyInjector):
        await injector.get(AsyncMock)

    await checker._call_havoc(havoc_task)

    mock_ctx.__aenter__.assert_awaited_once()
    mock_ctx.__aexit__.assert_awaited_once()


@pytest.mark.asyncio
async def test_dependency_injector_no_context_manager(
    checker: Enochecker, havoc_task: HavocCheckerTaskMessage
):
    @checker.register_dependency
    def register_str() -> str:
        return "test"

    @checker.havoc(0)
    async def havoc_test(injector: DependencyInjector):
        await injector.get(str)

    await checker._call_havoc(havoc_task)


@pytest.mark.asyncio
async def test_async_dependency_injector_context_manager(
    checker: Enochecker, havoc_task: HavocCheckerTaskMessage
):
    mock_ctx = AsyncMock()

    @checker.register_dependency
    async def register_async_mock() -> AsyncMock:
        return mock_ctx

    @checker.havoc(0)
    async def havoc_test(injector: DependencyInjector):
        await injector.get(AsyncMock)

    await checker._call_havoc(havoc_task)

    mock_ctx.__aenter__.assert_awaited_once()
    mock_ctx.__aexit__.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_http_client_dependency(
    checker: Enochecker, havoc_task: HavocCheckerTaskMessage
):
    """Test that http_client dependency is correctly injected."""

    @checker.havoc(0)
    async def havoc_test(http_client: httpx.AsyncClient):
        assert isinstance(http_client, httpx.AsyncClient)
        assert http_client.base_url.host == "127.0.0.1"
        assert http_client.base_url.port == 1234

    result = await checker._call_havoc(havoc_task)
    assert result.result == CheckerTaskResult.OK


@pytest.mark.asyncio
@pytest.mark.mongodb
async def test_get_chaindb_dependency(
    checker: Enochecker, havoc_task: HavocCheckerTaskMessage
):
    """Test that ChainDB dependency is correctly injected."""

    # Initialize MongoDB
    with patch("enochecker3.enochecker.AsyncMongoClient") as mock_client:
        mock_db = AsyncMock()
        mock_collection = AsyncMock()
        mock_collection.create_index = AsyncMock()
        mock_db.__getitem__.return_value = mock_collection
        mock_client.return_value.__getitem__.return_value = mock_db

        await checker._init()

    @checker.havoc(0)
    async def havoc_test(db: ChainDB):
        assert isinstance(db, ChainDB)
        assert db.task_chain_id == "task_chain_id"

    result = await checker._call_havoc(havoc_task)
    assert result.result == CheckerTaskResult.OK


@pytest.mark.asyncio
@pytest.mark.mongodb
async def test_get_collection_dependency(
    checker: Enochecker, havoc_task: HavocCheckerTaskMessage
):
    """Test that AsyncCollection dependency is correctly injected."""

    # Initialize MongoDB
    with patch("enochecker3.enochecker.AsyncMongoClient") as mock_client:
        mock_db = AsyncMock()
        mock_collection = AsyncMock()
        mock_collection.create_index = AsyncMock()
        mock_db.__getitem__.return_value = mock_collection
        mock_client.return_value.__getitem__.return_value = mock_db

        await checker._init()

    @checker.havoc(0)
    async def havoc_test(collection: AsyncCollection):
        assert isinstance(collection, AsyncMock)

    result = await checker._call_havoc(havoc_task)
    assert result.result == CheckerTaskResult.OK


@pytest.mark.asyncio
@pytest.mark.mongodb
async def test_get_database_dependency(
    checker: Enochecker, havoc_task: HavocCheckerTaskMessage
):
    """Test that AsyncDatabase dependency is correctly injected."""

    # Initialize MongoDB
    with patch("enochecker3.enochecker.AsyncMongoClient") as mock_client:
        mock_db = AsyncMock()
        mock_collection = AsyncMock()
        mock_collection.create_index = AsyncMock()
        mock_db.__getitem__.return_value = mock_collection
        mock_client.return_value.__getitem__.return_value = mock_db

        await checker._init()

    @checker.havoc(0)
    async def havoc_test(database: AsyncDatabase):
        assert isinstance(database, AsyncMock)

    result = await checker._call_havoc(havoc_task)
    assert result.result == CheckerTaskResult.OK
