# Built-In Dependencies

Enochecker3 uses dependency injection to provide common resources to your checker methods. Declare a parameter with the correct type annotation and it will be injected automatically.

### HTTP Client (`httpx.AsyncClient`)

Make HTTP requests to the service being checked. Pre-configured with `base_url=http://{task.address}:{service_port}` and SSL verification disabled (suitable for CTF environments).

**Usage**:
```python
from httpx import AsyncClient

@checker.putflag(0)
async def putflag_web(task: PutflagCheckerTaskMessage, client: AsyncClient) -> str:
    # Client is pre-configured with base_url=http://{task.address}:{service_port}
    response = await client.post("/api/create", json={
        "title": "Secret Document",
        "content": task.flag
    })

    if response.status_code != 201:
        raise MumbleException("Failed to create document")

    doc_id = response.json()["id"]
    return doc_id  # Returned as attack_info (public, available to all players)
```

### ChainDB (`ChainDB`)

Store private data between putflag and getflag (not accessible to players). Automatically scoped to `task_chain_id` to link related rounds. Data persists across rounds in MongoDB. Throws `KeyError` if key doesn't exist. Use `await db.set(key, value)` and `await db.get(key)`.

**Contrast with attack_info**: ChainDB stores secrets (private), while putflag's return value becomes attack_info (public).

**Usage**:
```python
from enochecker3 import ChainDB

@checker.putflag(0)
async def putflag_with_storage(
    task: PutflagCheckerTaskMessage,
    client: AsyncClient,
    db: ChainDB
) -> str:
    # Generate credentials using secrets (cryptographically secure)
    username = f"user_{secrets.token_hex(8)}"
    password = secrets.token_hex(16)

    # Store PRIVATE data in ChainDB (only checker can access)
    await db.set("username", username)
    await db.set("password", password)

    # Register and store flag
    await client.post("/register", json={
        "username": username,
        "password": password,
        "bio": task.flag
    })

    # Return PUBLIC targeting info as attack_info
    # Players will know which user to attack, but not the password
    return username

@checker.getflag(0)
async def getflag_with_retrieval(
    task: GetflagCheckerTaskMessage,
    client: AsyncClient,
    db: ChainDB
) -> None:
    # Retrieve credentials from ChainDB
    try:
        username = await db.get("username")
        password = await db.get("password")
    except KeyError:
        raise MumbleException("Missing credentials in ChainDB")

    # Login and retrieve flag from profile
    login = await client.post("/login", json={
        "username": username,
        "password": password
    })
    assert_equals(login.status_code, 200, "Login failed")
    response = await client.get(f"/user/{username}/bio")
    assert_in(task.flag, response.text)
```

### MongoDB Collection (`AsyncCollection`)

Complex queries beyond key-value storage (rarely needed—try ChainDB first). Automatically scoped to `team_{task.team_id}`. Full MongoDB async API available.

**Usage**:
```python
from pymongo.asynchronous.collection import AsyncCollection
from enochecker3 import PutnoiseCheckerTaskMessage
from httpx import AsyncClient

@checker.putnoise(0)
async def putnoise_with_mongo(
    task: PutnoiseCheckerTaskMessage,
    client: AsyncClient,
    collection: AsyncCollection
) -> None:
    # Direct MongoDB access for complex queries
    user_data = {
        "username": f"noise_user_{task.task_id}",
        "created_at": task.current_round_id,
        "team_id": task.team_id
    }

    await collection.insert_one(user_data)

    # Later: find all noise users for this team
    noise_users = await collection.find({
        "team_id": task.team_id
    }).to_list(length=100)
```

### MongoDB Database (`AsyncDatabase`)

Multiple collections or database-wide operations (rarely needed—try ChainDB or AsyncCollection first).

**Usage**:
```python
from pymongo.asynchronous.database import AsyncDatabase
from enochecker3 import HavocCheckerTaskMessage

@checker.havoc(0)
async def havoc_with_database(
    task: HavocCheckerTaskMessage,
    database: AsyncDatabase
) -> None:
    # Access different collections within the checker's database
    users_collection = database["users"]
    sessions_collection = database["sessions"]

    # Run queries across collections
    user_count = await users_collection.count_documents({"team_id": task.team_id})
    recent_sessions = await sessions_collection.find(
        {"round": {"$gte": task.current_round_id - 5}}
    ).to_list(length=100)
```

### Logger (`logging.LoggerAdapter`)

Logging with automatic task context. Includes `service_name`, `checker_name`, and task details in all log messages. Outputs ELK-compatible JSON by default. Use `LOG_FORMAT=DEBUG` environment variable for human-readable logs.

**Usage**:
```python
import logging

@checker.exploit(0)
async def exploit_with_logging(
    task: ExploitCheckerTaskMessage,
    client: AsyncClient,
    searcher: FlagSearcher,
    logger: logging.LoggerAdapter
) -> Optional[str]:
    logger.info("Starting exploit attempt")

    try:
        response = await client.get("/api/admin/secrets")
        logger.debug(f"Got response with {len(response.text)} bytes")

        if flag := searcher.search_flag(response.text):
            logger.info("Successfully extracted flag")
            return flag
        else:
            logger.warning("No flag found in response")
    except Exception as e:
        logger.error(f"Exploit failed: {e}")
        raise
```

### Random Number Generator (`random.Random`)

Reproducible random data for testing and fuzzing. Seeded with `task_id` for deterministic behavior—when a test fails, use the `task_id` from logs to replay the exact random values.

**Use for**: Varied test data, decoy content, fuzzing patterns
**Never use for**: Passwords, tokens, or credentials (use `secrets` module instead)

**Security consideration**: In environments with predictable task IDs (like EnoEngine), using `Random` for credentials means attackers could predict them. In environments with random task IDs (like ecsc2025-gameserver), this is less risky. Consider your game engine when choosing between `Random` and `secrets`.

**Usage**:
```python
from random import Random
import secrets  # Use this for generating actual secrets!

@checker.putflag(0)
async def putflag_with_random(
    task: PutflagCheckerTaskMessage,
    client: AsyncClient,
    db: ChainDB,
    random: Random
) -> str:
    # IMPORTANT: Use secrets module for actual credentials, not Random!
    username = f"user_{secrets.token_hex(8)}"
    password = secrets.token_hex(16)

    await client.post("/auth/register", json={
        "username": username, "password": password
    })
    login = await client.post("/auth/login", json={
        "username": username, "password": password
    })
    token = login.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Generate deterministic "random" test data for fuzzing
    # Same task_id always produces the same sequence - useful for debugging
    num_decoy_posts = random.randint(3, 10)
    for _ in range(num_decoy_posts):
        await client.post("/api/posts", json={
            "title": f"Post {random.randint(1000, 9999)}",
            "content": f"Random content {random.randint(1, 1000)}"
        }, headers=headers)

    # Store the flag in one of this user's posts
    await client.post("/api/posts", json={
        "title": f"Note {random.randint(1000, 9999)}",
        "content": task.flag
    }, headers=headers)

    await db.set("username", username)
    await db.set("password", password)
    return username  # Players know which user to target, but not the password
```

### TCP Socket (`AsyncSocket`)

Binary protocols, custom network protocols, raw TCP. Returns `(StreamReader, StreamWriter)` tuple. Automatically connects to `task.address:service_port`. Connection closes automatically after method completes. Raises `OfflineException` if connection fails.

**Usage**:
```python
from enochecker3 import AsyncSocket

@checker.putflag(0)
async def putflag_binary_protocol(
    task: PutflagCheckerTaskMessage,
    socket: AsyncSocket,  # Tuple[StreamReader, StreamWriter]
    db: ChainDB
) -> str:
    reader, writer = socket

    # Send custom binary protocol commands
    writer.write(b"STORE\n")
    await writer.drain()

    # Read response
    response = await reader.readline()
    assert_equals(response, b"OK\n")

    # Send flag
    writer.write(task.flag.encode() + b"\n")
    await writer.drain()

    # Get storage ID
    storage_id = (await reader.readline()).decode().strip()
    await db.set("storage_id", storage_id)

    return storage_id
```

### Flag Searcher (`FlagSearcher`)

Find and validate flags in exploit methods. Only available in exploit methods. Automatically configured with `flag_regex` and `flag_hash` from task. Validates flag hash if provided. Accepts both `str` and `bytes` input. Returns `bytes` if flag found, `None` otherwise.

**Usage**:
```python
from enochecker3.utils import FlagSearcher

@checker.exploit(0)
async def exploit_with_flag_search(
    task: ExploitCheckerTaskMessage,
    client: AsyncClient,
    searcher: FlagSearcher
) -> Optional[str]:
    # Try to exploit the service
    response = await client.get("/api/debug/dump")

    # Searcher automatically uses task.flag_regex and validates task.flag_hash
    if flag := searcher.search_flag(response.text):
        return flag  # Returns validated flag as string

    # Can also search in binary data
    binary_response = (await client.get("/api/export")).content
    if flag := searcher.search_flag(binary_response):
        return flag

    # Return None if no flag found (results in MUMBLE)
    return None
```

### Dependency Injector (`DependencyInjector`)

Dynamic dependency resolution at runtime. Use when dependencies are conditional or not always needed. Must be used as async context manager if managing resources.

**Usage**:
```python
from enochecker3.enochecker import DependencyInjector

@checker.havoc(0)
async def havoc_conditional(
    task: HavocCheckerTaskMessage,
    injector: DependencyInjector
) -> None:
    # Conditionally request dependencies based on runtime logic
    if task.current_round_id % 10 == 0:
        # Only get database connection every 10 rounds
        database = await injector.get(AsyncDatabase)
        await database.command("ping")

    # Always get HTTP client
    client = await injector.get(AsyncClient)
    await client.get("/health")
```
