import secrets

import pymongo
import pytest
from motor.motor_asyncio import (
    AsyncIOMotorClient,
    AsyncIOMotorCollection,
    AsyncIOMotorDatabase,
)

from enochecker3 import ChainDB


@pytest.fixture
async def collection():
    mongo: AsyncIOMotorClient = AsyncIOMotorClient()
    db: AsyncIOMotorDatabase = mongo["enochecker3_tests"]
    chain_collection: AsyncIOMotorCollection = db["chain_db"]

    await chain_collection.create_index(
        [("task_chain_id", pymongo.ASCENDING), ("key", pymongo.ASCENDING)],
        name="task_chain_index",
        unique=True,
    )

    return chain_collection


@pytest.fixture
async def chaindb(collection):
    task_chain_id = secrets.token_hex(8)
    return ChainDB(collection, task_chain_id)


@pytest.mark.asyncio
@pytest.mark.mongodb
@pytest.mark.parametrize(
    "val",
    [
        123,
        [1, "asd", b"xyz"],
        {
            "complex": 123,
            "object": b"asd",
        },
    ],
)
async def test_basic(chaindb, val):
    await chaindb.set("asd", val)

    assert await chaindb.get("asd") == val


@pytest.mark.asyncio
@pytest.mark.mongodb
async def test_missing_key(chaindb):
    with pytest.raises(KeyError):
        await chaindb.get("asd")
