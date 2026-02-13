from typing import Any, Optional

from opentelemetry import trace
from opentelemetry.trace import get_current_span
from pymongo.asynchronous.collection import AsyncCollection


class ChainDB:
    def __init__(self, collection: AsyncCollection, task_chain_id: str):
        self.collection: AsyncCollection = collection
        self.task_chain_id: str = task_chain_id

    async def get(self, key: str) -> Any:
        with (
            trace.get_tracer_provider()
            .get_tracer(__name__)
            .start_as_current_span(f"ChainDB.get({key})")
        ):
            val: Optional[Any] = await self.collection.find_one(
                {
                    "task_chain_id": self.task_chain_id,
                    "key": key,
                }
            )
            if val is None:
                raise KeyError(f"Key {key} not found")
            get_current_span().set_attribute(f"chaindb.value.{key}", val["value"])
            return val["value"]

    async def set(self, key: str, val: Any) -> None:
        with (
            trace.get_tracer_provider()
            .get_tracer(__name__)
            .start_as_current_span(f"ChainDB.set({key})")
        ):
            await self.collection.replace_one(
                {
                    "task_chain_id": self.task_chain_id,
                    "key": key,
                },
                {
                    "task_chain_id": self.task_chain_id,
                    "key": key,
                    "value": val,
                },
                upsert=True,
            )
            get_current_span().set_attribute(f"chaindb.value.{key}", val)
