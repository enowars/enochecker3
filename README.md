# enochecker3

A FastAPI based checker library for writing async checkers in python. It is called enochecker3 even though enochecker2 never existed, because it is intended to be the reference implementation for version 3 of the enochecker API specification which is yet to come.

## Quick Start

Install `enochecker3` using
```
pip3 install enochecker3
```

Create an `example.py` file with the following content:
```python
import secrets
from typing import Optional

from httpx import AsyncClient

from enochecker3 import (
    ChainDB,
    Enochecker,
    GetflagCheckerTaskMessage,
    MumbleException,
    PutflagCheckerTaskMessage,
)
from enochecker3.utils import FlagSearcher, assert_equals, assert_in

checker = Enochecker("ExampleService", 1337)


@checker.putflag(0)
async def putflag_test(
    task: PutflagCheckerTaskMessage,
    client: AsyncClient,
    db: ChainDB,
) -> None:
    token = secrets.token_hex(32)
    r = await client.post("/note", json={"token": token, "flag": task.flag})
    assert_equals(r.status_code, 200, "storing note with flag failed")

    await db.set("token", token)


@checker.getflag(0)
async def getflag_test(
    task: GetflagCheckerTaskMessage, client: AsyncClient, db: ChainDB
) -> None:
    try:
        token = await db.get("token")
    except KeyError:
        raise MumbleException("Missing database entry from putflag")

    r = await client.get(f"/note/{token}")
    assert_equals(r.status_code, 200, "getting note with flag failed")
    assert_in(task.flag, r.text, "flag missing from note")


@checker.exploit(0)
async def exploit_test(searcher: FlagSearcher, client: AsyncClient) -> Optional[str]:
    r = await client.get(
        "/note/*",
    )
    assert not r.is_error

    if flag := searcher.search_flag(r.text):
        return flag
```

Start the checker using
```
uvicorn --reload example:checker.app
```

And browse to (http://localhost:8000/docs) to explore the web interface, which allows you to send requests to the checker.

## Built-In Dependencies

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

## Adding Custom Dependencies

You can register your own custom dependencies to encapsulate complex setup logic and make it reusable across checker methods.

### Key Points for Custom Dependencies

1. **Type annotations are required**: The return type is used to match parameters
2. **Dependencies can depend on dependencies**: They're recursively injected
3. **Context managers are supported**: Use `@asynccontextmanager` for automatic cleanup
4. **Circular dependencies are detected**: Will raise `CircularDependencyException`
5. **Each parameter gets a fresh instance**: Even if multiple parameters have the same type, each gets its own instance (see FAQ below)

### Example: Database Connection with Cleanup

Context manager dependencies are supported for automatic resource cleanup. Note that for context manager dependencies, the DI system matches on the return type annotation, so you must use a type alias and use the same alias in the parameter annotation.

```python
from contextlib import asynccontextmanager
from typing import AsyncIterator
import asyncpg

# Type alias for the managed connection. The DI system matches parameters
# by this alias. At runtime, the parameter receives the yielded value
# (asyncpg.Connection), not the iterator itself.
ManagedPgConnection = AsyncIterator[asyncpg.Connection]

@checker.register_dependency
@asynccontextmanager
async def _get_db_connection(task: CheckerTaskMessage) -> ManagedPgConnection:
    """PostgreSQL connection with automatic cleanup."""
    conn = await asyncpg.connect(
        host=task.address,
        port=5432,
        user="checker",
        password="checker_pass",
        database="ctf_service"
    )

    try:
        yield conn
    finally:
        await conn.close()

@checker.exploit(0)
async def exploit_sql_injection(
    task: ExploitCheckerTaskMessage,
    conn: ManagedPgConnection,  # Must use the same type alias
    searcher: FlagSearcher
) -> Optional[str]:
    rows = await conn.fetch(
        "SELECT * FROM secrets WHERE public = true"
    )

    all_data = "\n".join(str(row) for row in rows)
    return searcher.search_flag(all_data)
```

### Example: Authenticated HTTP Client (Named Dependency)

Named dependencies let you create multiple variants of the same type. This example demonstrates using named dependencies to create an authenticated client.

```python
import secrets
from httpx import AsyncClient
from enochecker3 import Enochecker, PutflagCheckerTaskMessage, GetflagCheckerTaskMessage, MumbleException, ChainDB
from enochecker3.utils import assert_equals, assert_in

checker = Enochecker("MyService", 8080)

# Register a named dependency called "authenticated"
# Named dependencies are resolved by matching the parameter name prefix (before underscore)
# to the name registered with register_named_dependency
@checker.register_named_dependency("authenticated")
async def _get_authenticated_client(
    db: ChainDB,
    client: AsyncClient  # Dependencies can depend on other dependencies!
) -> AsyncClient:
    """
    Retrieve credentials from ChainDB and return an authenticated HTTP client.

    This dependency will be injected into parameters that:
    - Have type annotation AsyncClient
    - Have parameter name starting with "authenticated_" (e.g., authenticated_client)
    """
    # Get credentials stored during putflag
    try:
        username = await db.get("username")
        password = await db.get("password")
    except KeyError:
        raise MumbleException("Missing credentials in ChainDB")

    # Login to get session token/cookie
    login_response = await client.post("/auth/login", json={
        "username": username,
        "password": password
    })

    if login_response.status_code != 200:
        raise MumbleException("Failed to login with stored credentials")

    # Extract session token and configure client
    session_token = login_response.json()["token"]
    client.headers["Authorization"] = f"Bearer {session_token}"

    # Return the authenticated client
    return client

# putflag creates the user and stores credentials
@checker.putflag(0)
async def putflag_with_auth(
    task: PutflagCheckerTaskMessage,
    client: AsyncClient,  # Regular unauthenticated client
    db: ChainDB
) -> str:
    # Generate credentials
    username = f"user_{secrets.token_hex(8)}"
    password = secrets.token_hex(16)

    # Register new account
    response = await client.post("/auth/register", json={
        "username": username,
        "password": password
    })
    assert_equals(response.status_code, 201, "Failed to register user")

    # Login and store flag in user's profile
    login_response = await client.post("/auth/login", json={
        "username": username,
        "password": password
    })
    token = login_response.json()["token"]

    await client.post(
        "/api/profile/bio",
        json={"bio": task.flag},
        headers={"Authorization": f"Bearer {token}"}
    )

    # Store credentials for getflag (PRIVATE - only checker knows these)
    await db.set("username", username)
    await db.set("password", password)

    # Return PUBLIC targeting info (tells players which user to attack)
    return username

# getflag uses the authenticated client dependency
@checker.getflag(0)
async def getflag_with_auth(
    task: GetflagCheckerTaskMessage,
    authenticated_client: AsyncClient,  # Named dependency resolved by "authenticated_" prefix
    db: ChainDB
) -> None:
    # Client is already authenticated via the named dependency
    username = await db.get("username")
    response = await authenticated_client.get(f"/api/user/{username}/bio")
    assert_in(task.flag, response.text)
```

## Good to Know / FAQ

### How does dependency injection work?

Enochecker3 matches parameter types to dependency providers:
1. Task message types inject the task directly
2. Other types look up registered dependency providers
3. Provider dependencies are resolved recursively
4. Context managers are entered automatically and cleaned up after method execution

### How do I share data between putflag and getflag?

Use ChainDB (private data, automatically scoped to task_chain_id):
```python
@checker.putflag(0)
async def putflag_example(task: PutflagCheckerTaskMessage, db: ChainDB) -> str:
    creds = create_account()
    await db.set("username", creds.username)
    await db.set("password", creds.password)
    return creds.username

@checker.getflag(0)
async def getflag_example(task: GetflagCheckerTaskMessage, db: ChainDB) -> None:
    username = await db.get("username")
    password = await db.get("password")
```

### What is attack_info and how does it work?

**Attack_info** is public targeting information (e.g., username, document ID, filename). It helps players know *where* to attack without having to enumerate all possible targets, but they still need to figure out *how* to exploit the service. When putflag returns a string, the game engine makes it available to all players as `task.attack_info`.

```python
@checker.putflag(0)
async def putflag_with_targeting(
    task: PutflagCheckerTaskMessage,
    client: AsyncClient,
    db: ChainDB
) -> str:
    username = f"user_{secrets.token_hex(8)}"
    password = secrets.token_hex(16)

    # Store PRIVATE data in ChainDB
    await db.set("username", username)
    await db.set("password", password)

    response = await client.post("/register", json={
        "username": username,
        "password": password,
        "bio": task.flag
    })

    return username  # PUBLIC attack_info - players know which user, not password

@checker.getflag(0)
async def getflag_with_targeting(
    task: GetflagCheckerTaskMessage,
    client: AsyncClient,
    db: ChainDB
) -> None:
    try:
        username = await db.get("username")
        password = await db.get("password")
    except KeyError:
        raise MumbleException("Missing credentials in ChainDB")

    await client.post("/login", json={
        "username": username,
        "password": password
    })
    response = await client.get(f"/user/{username}/bio")
    assert_in(task.flag, response.text)

@checker.exploit(0)
async def exploit_example(
    task: ExploitCheckerTaskMessage,
    client: AsyncClient,
    searcher: FlagSearcher
) -> Optional[str]:
    if not task.attack_info:
        return None

    username = task.attack_info  # PUBLIC - know which user, not password

    # Must exploit vulnerability (e.g., IDOR or SQLi) to get flag
    response = await client.get(f"/api/user/{username}/bio")
    return searcher.search_flag(response.text)
```

**Include:** User IDs, usernames, post IDs, file names, document IDs, session identifiers

**Exclude:** Passwords, tokens, encryption keys (use ChainDB), direct flag values, vulnerability hints

### Should getflag use attack_info?

No. `getflag` should retrieve all data from ChainDB. The attack_info is public and intended for exploit methods only. See the [attack_info FAQ](#what-is-attack_info-and-how-does-it-work) above for the correct pattern.

### Why is Random seeded with task_id?

For reproducible debugging. When a checker fails with task_id=12345, re-run with the same task_id to replay the exact random sequence.

```python
@checker.putnoise(0)
async def putnoise_fuzz(task: PutnoiseCheckerTaskMessage, client: AsyncClient, random: Random) -> None:
    num_requests = random.randint(5, 20)
    for i in range(num_requests):
        endpoint = random.choice(["/api/users", "/api/posts", "/api/comments"])
        await client.get(endpoint)
```

**Security consideration:** In environments with predictable task IDs (like EnoEngine), using Random for credentials means attackers could predict them. In environments with random task IDs (like ecsc2025-gameserver), this is less risky. Consider your game engine when choosing between Random and `secrets`.

### How do I handle HTTP errors?

Use assertion helpers or raise exceptions directly:

```python
from enochecker3.utils import assert_equals
from enochecker3 import MumbleException, OfflineException

@checker.putflag(0)
async def putflag_example(task: PutflagCheckerTaskMessage, client: AsyncClient):
    response = await client.post("/api/store", json={"data": task.flag})
    assert_equals(response.status_code, 200, "Failed to store data")  # Raises MumbleException

    # Or raise directly:
    if response.status_code == 503:
        raise OfflineException("Service unavailable")
```

Avoid `response.raise_for_status()` - it raises `httpx.HTTPStatusError`, which becomes `InternalErrorException` (checker bug) instead of `MumbleException`.

### What exceptions should I raise?

- **MumbleException**: Service online but broken (wrong data, protocol violation, flag not found)
- **OfflineException**: Service unreachable (connection refused, timeouts, 503 errors)
- **InternalErrorException**: Checker bug (programming error)

Network exceptions are automatically converted:
- `ConnectError`, `ConnectTimeout`, `RemoteProtocolError`, `DecodingError` → `OfflineException`
- `TimeoutException`, `TimeoutError`, `EOFError`, `ReadError`, `WriteError`, `ConnectionResetError`, `CloseError` → `MumbleException`
- Generic `Exception` → `InternalErrorException`

### How do I test my checker locally?

**Swagger UI** (interactive):
```bash
uvicorn example:checker.app --reload
# Browse to http://localhost:8000/docs
```

**curl** (command line):
```bash
curl -X POST http://localhost:8000/ -H "Content-Type: application/json" -d '{
  "method": "putflag", "address": "localhost", "teamId": 1, "teamName": "Test",
  "currentRoundId": 1, "relatedRoundId": 1, "flag": "ENO{test}", "variantId": 0,
  "timeout": 30000, "roundLength": 60000, "taskChainId": "test", "taskId": 1
}'
```

**Python API** (requires MongoDB):
```python
import asyncio
from enochecker3 import PutflagCheckerTaskMessage
from enochecker_core import CheckerMethod

async def test():
    await checker._init()
    task = PutflagCheckerTaskMessage(
        task_id=1, method=CheckerMethod.PUTFLAG, address="localhost",
        team_id=1, team_name="Test", current_round_id=1, related_round_id=1,
        flag="ENO{test}", variant_id=0, timeout=30000,
        round_length=60000, task_chain_id="test"
    )
    result = await checker._call_putflag(task)
    print(result)

asyncio.run(test())
```

### Do I need MongoDB running?

Yes, ChainDB requires MongoDB. Start it with Docker:
```bash
docker run -d -p 27017:27017 mongo:latest
```

Or configure connection to an existing MongoDB with environment variables:
```bash
export MONGO_HOST=mongodb.example.com
export MONGO_PORT=27017
export MONGO_USER=checker
export MONGO_PASSWORD=secret
```

### Can I use multiple variant ids in a single function?

Yes. Use shared functions when variants differ only in small details:

```python
@checker.putflag(0, 1, 2)
async def putflag_variants(task: PutflagCheckerTaskMessage, client: AsyncClient, db: ChainDB) -> str:
    username = f"user_{secrets.token_hex(8)}"
    password = secrets.token_hex(16)

    await client.post("/auth/register", json={"username": username, "password": password})
    login = await client.post("/auth/login", json={"username": username, "password": password})
    token = login.json()["token"]

    await db.set("username", username)
    await db.set("password", password)

    # Variants differ only in endpoint
    endpoints = {0: "/api/profile/bio", 1: "/api/profile/status", 2: "/api/profile/description"}
    await client.post(endpoints[task.variant_id], json={"data": task.flag}, headers={"Authorization": f"Bearer {token}"})
    return username
```

Use separate functions when logic differs significantly:

```python
@checker.putflag(0)
async def putflag_api(task: PutflagCheckerTaskMessage, client: AsyncClient, db: ChainDB) -> str:
    note_id = secrets.token_hex(16)
    await client.post("/api/notes", json={"id": note_id, "content": task.flag})
    await db.set("note_id", note_id)
    return note_id

@checker.putflag(1)
async def putflag_file(task: PutflagCheckerTaskMessage, client: AsyncClient, db: ChainDB) -> str:
    filename = f"secret_{secrets.token_hex(8)}.txt"
    await client.post("/api/upload", files={"file": (filename, task.flag.encode())})
    await db.set("filename", filename)
    return filename
```

### How do I debug dependency injection issues?

Enable debug logging:
```bash
export LOG_FORMAT=DEBUG
uvicorn example:checker.app
```

Check for missing return type annotations:
```python
@checker.register_dependency
def broken_dependency(task: CheckerTaskMessage):  # ERROR: missing return type
    return SomeObject()

@checker.register_dependency
def fixed_dependency(task: CheckerTaskMessage) -> SomeObject:  # OK
    return SomeObject()
```

Verify type annotations match exactly between dependency and parameter.

### Can dependencies be async?

Yes. Both sync and async work:

```python
@checker.register_dependency
def sync_dependency(task) -> SomeType:
    return SomeType()

@checker.register_dependency
async def async_dependency(task) -> OtherType:
    result = await async_operation()
    return OtherType(result)
```

### What if I need to clean up resources?

Use async context managers:

```python
@checker.register_dependency
@asynccontextmanager
async def managed_resource(task):
    resource = await create_resource()
    try:
        yield resource
    finally:
        await resource.close()  # Cleanup always runs
```

### How do I access the raw task message?

Declare it as a parameter:

```python
@checker.putflag(0)
async def putflag_example(task: PutflagCheckerTaskMessage):
    print(f"Team: {task.team_name}, Round: {task.current_round_id}, Flag: {task.flag}")
```

### Can I inject multiple instances of the same dependency type?

Yes. Each parameter gets its own instance:

```python
@checker.havoc(0)
async def havoc_concurrent(task: HavocCheckerTaskMessage, client1: AsyncClient, client2: AsyncClient) -> None:
    results = await asyncio.gather(client1.get("/api/endpoint1"), client2.get("/api/endpoint2"))
```

For different configurations, use named dependencies:

```python
@checker.register_named_dependency("admin")
def _get_admin_session(task: CheckerTaskMessage, client: AsyncClient) -> Session:
    return Session(client=client, role="admin")

@checker.register_named_dependency("user")
def _get_user_session(task: CheckerTaskMessage, client: AsyncClient) -> Session:
    return Session(client=client, role="user")

@checker.havoc(0)
async def havoc_test(task: HavocCheckerTaskMessage, admin_session: Session, user_session: Session) -> None:
    # do something...
```
