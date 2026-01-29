from typing import Any, Optional

from pymongo.asynchronous.collection import AsyncCollection


class ChainDB:
    def __init__(self, collection: AsyncCollection, task_chain_id: str):
        self.collection: AsyncCollection = collection
        self.task_chain_id: str = task_chain_id

    async def get(self, key: str) -> Any:
        val: Optional[Any] = await self.collection.find_one(
            {
                "task_chain_id": self.task_chain_id,
                "key": key,
            }
        )
        if val is None:
            raise KeyError(f"Key {key} not found")
        return val["value"]

    async def set(self, key: str, val: Any) -> None:
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
