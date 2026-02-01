from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from typing import Union

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from enochecker3 import (
    Enochecker,
    ExploitCheckerTaskMessage,
    GetflagCheckerTaskMessage,
    GetnoiseCheckerTaskMessage,
    PutflagCheckerTaskMessage,
    PutnoiseCheckerTaskMessage,
    TestCheckerTaskMessage,
)
from enochecker3.types import CheckerResultMessage


@pytest.mark.asyncio
async def test_get_service_info():
    """Test that get_service_info returns correct checker information."""
    checker = Enochecker("test_service", 8080)

    @checker.putflag(0, 1)
    async def putflag_test() -> str:
        return "attack_info"

    @checker.getflag(0, 1)
    async def getflag_test() -> None:
        pass

    @checker.exploit(0)
    async def exploit_test() -> str:
        return "ENO{flag}"

    info = checker.get_service_info()

    assert info.service_name == "test_service"
    assert info.flag_variants == 2
    assert info.noise_variants == 0
    assert info.exploit_variants == 1
    assert info.havoc_variants == 0


@pytest.mark.parametrize(
    "task",
    [
        PutflagCheckerTaskMessage(
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
            flag="test",
        ),
        GetflagCheckerTaskMessage(
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
            flag="test",
        ),
        PutnoiseCheckerTaskMessage(
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
        ),
        GetnoiseCheckerTaskMessage(
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
        ),
        ExploitCheckerTaskMessage(
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
            flag_regex="test",
            flag_hash="test",
            attack_info="attack_info",
        ),
        TestCheckerTaskMessage(
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
        ),
    ],
)
def test_fastapi_app_property(
    checker: Enochecker,
    task: Union[
        PutflagCheckerTaskMessage,
        GetflagCheckerTaskMessage,
        PutnoiseCheckerTaskMessage,
        GetnoiseCheckerTaskMessage,
        ExploitCheckerTaskMessage,
        TestCheckerTaskMessage,
    ],
):
    @checker.putflag(0)
    async def putflag_test() -> str:
        return "attack_info"

    @checker.getflag(0)
    async def getflag_test() -> None:
        pass

    @checker.putnoise(0)
    async def putnoise_test() -> None:
        pass

    @checker.getnoise(0)
    async def getnoise_test() -> None:
        pass

    @checker.exploit(0)
    async def exploit_test() -> None:
        pass

    trace.set_tracer_provider(TracerProvider())

    app = checker.app
    client = TestClient(app)

    assert isinstance(app, FastAPI)

    # Check that routes are registered
    routes = [route.path for route in app.routes]
    assert "/service" in routes
    assert "/" in routes

    result = client.post("/", json=task.model_dump())
    result.raise_for_status()
    result_model = CheckerResultMessage(**result.json())
    if isinstance(task, PutflagCheckerTaskMessage):
        assert result_model.attack_info == "attack_info"
