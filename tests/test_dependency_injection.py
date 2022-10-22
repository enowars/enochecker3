import pytest

from enochecker3 import Enochecker, HavocCheckerTaskMessage
from enochecker3.enochecker import CircularDependencyException


@pytest.fixture
def havoc_task() -> HavocCheckerTaskMessage:
    return HavocCheckerTaskMessage(
        task_id=0,
        address="127.0.0.1",
        team_id=0,
        team_name="team_name",
        current_round_id=0,
        variant_id=0,
        timeout=15000,
        round_length=60000,
        task_chain_id="task_chain_id",
    )


@pytest.mark.asyncio
async def test_basic(checker: Enochecker, havoc_task: HavocCheckerTaskMessage):
    @checker.register_dependency("x")
    def inject_string() -> str:
        return "123"

    @checker.havoc(0)
    async def havoc(x: str):
        assert x == "123"

    await checker._call_havoc(havoc_task)


@pytest.mark.asyncio
async def test_recursive_dependency(
    checker: Enochecker, havoc_task: HavocCheckerTaskMessage
):
    @checker.register_dependency("x")
    def inject_string(x: int) -> str:
        return f"int: {x}"

    @checker.register_dependency("x")
    def inject_integer() -> int:
        return 15

    @checker.havoc(0)
    async def havoc(x: str):
        assert x == "int: 15"

    await checker._call_havoc(havoc_task)


@pytest.mark.asyncio
async def test_circular_dependency(
    checker: Enochecker, havoc_task: HavocCheckerTaskMessage
):
    @checker.register_dependency("x")
    def inject_string(x: int) -> str:
        return f"int: {x}"

    @checker.register_dependency("x")
    def inject_integer(x: str) -> int:
        return len(x)

    @checker.havoc(0)
    async def havoc(x: str):
        pass

    with pytest.raises(CircularDependencyException):
        await checker._call_havoc(havoc_task)
