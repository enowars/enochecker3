# enochecker3

A FastAPI based checker library for writing async checkers in python. It is called enochecker3 even though enochecker2 never existed, because it is intended to be the reference implementation for version 3 of the enochecker API specification which is yet to come.

## Quick Start

Getting started is really easy. Simply install `enochecker3` using
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

Enochecker3 provides powerful dependency injection that automatically provides common resources to your checker methods. Simply declare them as parameters with the correct type annotation, and they'll be injected automatically.

### HTTP Client (`httpx.AsyncClient`)

**When to use**: Making HTTP requests to the service being checked

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
    return doc_id  # Return as attack_info for getflag
```

**Details**:
- Automatically configured with the service's base URL
- SSL verification disabled (suitable for CTF environments)

### ChainDB (`ChainDB`)

**When to use**: Storing **private** data between putflag and corresponding getflag rounds (data only the checker can access)

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
    # Get PUBLIC targeting info from attack_info
    username = task.attack_info  # Returned from putflag

    # Get PRIVATE data from ChainDB
    password = await db.get("password")  # Only checker knows this

    # Login and verify flag
    response = await client.post("/login", json={
        "username": username,
        "password": password
    })
    assert_in(task.flag, response.text)
```

**Details**:
- **Private storage**: Data in ChainDB is only accessible to the checker, never to players
- Automatically scoped to the task_chain_id (links putflag and getflag)
- Throws `KeyError` if key doesn't exist
- Persists across rounds in MongoDB
- Use `await db.set(key, value)` and `await db.get(key)`
- **Contrast with attack_info**: The return value from putflag becomes public attack_info, while ChainDB stores secrets

### MongoDB Collection (`AsyncCollection`)

**When to use**: Advanced MongoDB operations, team-specific data storage (should be rarely needed, check if ChainDB is sufficient for your use case)

**Usage**:
```python
from pymongo.asynchronous.collection import AsyncCollection

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

**Details**:
- Automatically scoped to the current team (`team_{task.team_id}`)
- Full MongoDB async API available
- Use for complex queries beyond simple key-value storage

### MongoDB Database (`AsyncDatabase`)

**When to use**: Accessing multiple collections or database-wide operations (should be rarely needed, check if ChainDB or AsyncCollection is sufficient for your use case)

**Usage**:
```python
from pymongo.asynchronous.database import AsyncDatabase

@checker.havoc(0)
async def havoc_cleanup(
    task: HavocCheckerTaskMessage,
    database: AsyncDatabase
) -> None:
    # Access different collections
    users_collection = database["users"]
    sessions_collection = database["sessions"]

    # Clean up old data
    await users_collection.delete_many({
        "round": {"$lt": task.current_round_id - 10}
    })
    await sessions_collection.delete_many({
        "expired": True
    })
```

### Logger (`logging.LoggerAdapter`)

**When to use**: Logging with automatic task context

**Usage**:
```python
import logging

@checker.exploit(0)
async def exploit_with_logging(
    task: ExploitCheckerTaskMessage,
    client: AsyncClient,
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

**Details**:
- Automatically includes service_name, checker_name, and task details in logs
- Outputs in ELK-compatible JSON format
- Use `LOG_FORMAT=DEBUG` environment variable for human-readable logs

### Random Number Generator (`random.Random`)

**When to use**: Generating reproducible random data for long-term testing and fuzzing

**Primary use case**: When you need to test your service with varied, "random" inputs over many rounds, but want to be able to reproduce specific test cases when issues are found. By using the seeded Random, you can look at the `task_id` in checker logs and replay the exact same random data that caused a problem.

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
    # Generate deterministic "random" test data
    # Same task_id always generates same values - useful for debugging
    num_decoy_posts = random.randint(3, 10)
    post_titles = [
        f"Post {random.randint(1000, 9999)}"
        for _ in range(num_decoy_posts)
    ]

    # IMPORTANT: Use secrets module for actual credentials, not Random!
    username = f"user_{secrets.token_hex(8)}"
    password = secrets.token_hex(16)

    # Create posts with varied but reproducible content
    for title in post_titles:
        await client.post("/api/posts", json={
            "title": title,
            "content": f"Random content {random.randint(1, 1000)}"
        })

    # Store the flag in a real post
    await client.post("/api/posts", json={
        "title": "My Secret",
        "content": task.flag
    })

    await db.set("username", username)
    await db.set("password", password)
    return username
```

**Details**:
- **CRITICAL**: Seeded with `task.task_id` for deterministic behavior
- Useful for fuzzing services with varied inputs while maintaining reproducibility
- When a test fails, you can use the `task_id` from logs to reproduce the exact random values
- **WARNING**: In CTF environments, predictable checker behavior can be a security risk. Attackers may predict checker actions and exploit them.
- **IMPORTANT**: Never use `Random` for generating passwords, tokens, or other secrets. Use `secrets.token_hex()`, `secrets.token_bytes()`, or similar cryptographically secure methods instead.

### TCP Socket (`AsyncSocket`)

**When to use**: Binary protocols, custom network protocols, raw TCP

**Usage**:
```python
from enochecker3.types import AsyncSocket

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

**Details**:
- Returns `(StreamReader, StreamWriter)` tuple
- Automatically connects to `task.address:service_port`
- Connection automatically closed after method completes
- Raises `OfflineException` if connection fails

### Flag Searcher (`FlagSearcher`)

**When to use**: Exploit methods to find and validate flags

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
    binary_response = await client.get("/api/export").content
    if flag := searcher.search_flag(binary_response):
        return flag

    # Return None if no flag found (results in MUMBLE)
    return None
```

**Details**:
- Only available in exploit methods
- Automatically configured with `flag_regex` and `flag_hash` from task
- Validates flag hash if provided
- Accepts both `str` and `bytes` input
- Returns `bytes` if flag found, `None` otherwise

### Dependency Injector (`DependencyInjector`)

**When to use**: Conditional or dynamic dependency resolution

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

**Details**:
- Allows dynamic dependency resolution at runtime
- Use when dependencies are conditional or not always needed
- Must be used as async context manager if managing resources

## Adding Custom Dependencies

You can register your own custom dependencies to encapsulate complex setup logic and make it reusable across checker methods.

### Example: Authenticated Session

```python
from dataclasses import dataclass
import secrets
from httpx import AsyncClient
from enochecker3 import Enochecker, PutflagCheckerTaskMessage

checker = Enochecker("MyService", 8080)

@dataclass
class AuthenticatedSession:
    """Custom dependency that provides an authenticated HTTP session."""
    client: AsyncClient
    username: str
    password: str
    session_token: str

@checker.register_dependency
def _get_authenticated_session(
    task: PutflagCheckerTaskMessage,  # Can depend on other dependencies!
    client: AsyncClient
) -> AuthenticatedSession:
    """Create a new user and return an authenticated session."""
    # Generate credentials
    username = f"checker_{secrets.token_hex(8)}"
    password = secrets.token_hex(16)

    # Register new account
    response = client.post("/auth/register", json={
        "username": username,
        "password": password
    })

    if response.status_code != 201:
        raise MumbleException("Failed to register user")

    # Login to get session token
    login_response = client.post("/auth/login", json={
        "username": username,
        "password": password
    })

    session_token = login_response.json()["token"]

    # Return authenticated session
    return AuthenticatedSession(
        client=client,
        username=username,
        password=password,
        session_token=session_token
    )

# Now use it in any checker method!
@checker.putflag(0)
async def putflag_with_auth(
    task: PutflagCheckerTaskMessage,
    session: AuthenticatedSession,  # Automatically created and logged in!
    db: ChainDB
) -> str:
    # Use the authenticated session
    response = await session.client.post(
        "/api/secrets",
        json={"secret": task.flag},
        headers={"Authorization": f"Bearer {session.session_token}"}
    )

    # Store credentials for getflag
    await db.set("username", session.username)
    await db.set("password", session.password)

    return session.username

@checker.getflag(0)
async def getflag_with_auth(
    task: GetflagCheckerTaskMessage,
    session: AuthenticatedSession,  # Gets a fresh authenticated session!
    db: ChainDB
) -> None:
    # This session is independent from putflag's session
    # Retrieve which user has the flag
    flag_username = await db.get("username")

    # Get the secret
    response = await session.client.get(
        f"/api/user/{flag_username}/secrets",
        headers={"Authorization": f"Bearer {session.session_token}"}
    )

    assert_in(task.flag, response.text)
```

### Example: Database Connection Pool

```python
from contextlib import asynccontextmanager
import asyncpg

@checker.register_dependency
@asynccontextmanager
async def _get_db_connection(task: PutflagCheckerTaskMessage):
    """Provide a PostgreSQL connection (with automatic cleanup)."""
    # Connect to the service's database
    conn = await asyncpg.connect(
        host=task.address,
        port=5432,
        user="checker",
        password="checker_pass",
        database="ctf_service"
    )

    try:
        yield conn  # Provide connection to checker method
    finally:
        await conn.close()  # Automatically closed after method completes

@checker.exploit(0)
async def exploit_sql_injection(
    task: ExploitCheckerTaskMessage,
    conn: asyncpg.Connection,  # Automatically managed!
    searcher: FlagSearcher
) -> Optional[str]:
    # Connection is already open and will be automatically closed
    rows = await conn.fetch(
        "SELECT * FROM secrets WHERE public = true"
    )

    all_data = "\\n".join(str(row) for row in rows)
    return searcher.search_flag(all_data)
```

### Named Dependencies

Create multiple variants of the same dependency type:

```python
@checker.register_named_dependency("admin")
def _get_admin_session(task: PutflagCheckerTaskMessage, client: AsyncClient) -> AuthenticatedSession:
    """Create an admin user session."""
    # Create user with admin privileges
    response = client.post("/auth/register", json={
        "username": "admin_" + secrets.token_hex(4),
        "password": secrets.token_hex(16),
        "role": "admin"
    })
    # ... rest of authentication logic
    return session

@checker.register_named_dependency("regular")
def _get_regular_session(task: PutflagCheckerTaskMessage, client: AsyncClient) -> AuthenticatedSession:
    """Create a regular user session."""
    # Create regular user
    response = client.post("/auth/register", json={
        "username": "user_" + secrets.token_hex(4),
        "password": secrets.token_hex(16),
        "role": "user"
    })
    # ... rest of authentication logic
    return session

@checker.havoc(0)
async def havoc_test_permissions(
    task: HavocCheckerTaskMessage,
    admin_session: AuthenticatedSession,     # Gets admin variant
    regular_session: AuthenticatedSession    # Gets regular variant
) -> None:
    # Test that regular users can't access admin endpoints
    response = await regular_session.client.get(
        "/api/admin/users",
        headers={"Authorization": f"Bearer {regular_session.session_token}"}
    )
    assert_equals(response.status_code, 403, "Regular user accessed admin endpoint!")

    # But admin can
    response = await admin_session.client.get(
        "/api/admin/users",
        headers={"Authorization": f"Bearer {admin_session.session_token}"}
    )
    assert_equals(response.status_code, 200, "Admin couldn't access admin endpoint!")
```

### Key Points for Custom Dependencies

1. **Type annotations are required**: The return type is used to match parameters
2. **Dependencies can depend on dependencies**: They're recursively injected
3. **Context managers are supported**: Use `@asynccontextmanager` for automatic cleanup
4. **Circular dependencies are detected**: Will raise `CircularDependencyException`
5. **Each parameter gets a fresh instance**: Even if multiple parameters have the same type, each gets its own instance (see FAQ below)

## Good to Know / FAQ

### How does dependency injection work?

When you declare a parameter with a type annotation, enochecker3:
1. Checks if the type is a task message type → injects the task directly
2. Looks up a registered dependency provider for that type
3. Recursively injects dependencies that the provider needs
4. Calls the provider to create the dependency instance
5. If it's a context manager, enters it and manages cleanup

### How do I share data between putflag and getflag?

Use ChainDB for **private** data (only accessible to the checker):
```python
@checker.putflag(0)
async def putflag_example(task: PutflagCheckerTaskMessage, db: ChainDB) -> str:
    creds = create_account()
    await db.set("username", creds.username)
    await db.set("password", creds.password)
    return creds.username

@checker.getflag(0)
async def getflag_example(task: GetflagCheckerTaskMessage, db: ChainDB) -> None:
    username = await db.get("username")  # Same task_chain_id
    password = await db.get("password")
    # ... use credentials
```

### What is attack_info and how does it work?

**Attack_info** is **public targeting information** provided to players for their exploits. It helps players know *where* to attack without having to enumerate all possible targets, but they still need to figure out *how* to exploit the service.

**How it works:**
1. Your `putflag` method returns a string
2. This string becomes the `attack_info` field in the task
3. The game engine makes this information **publicly available** to all players
4. Players can use this to target their exploits efficiently

**Example - User targeting:**
```python
@checker.putflag(0)
async def putflag_with_targeting(
    task: PutflagCheckerTaskMessage,
    client: AsyncClient,
    db: ChainDB
) -> str:
    # Create account with secure random credentials
    username = f"user_{secrets.token_hex(8)}"
    password = secrets.token_hex(16)

    # Store PRIVATE data in ChainDB (only checker can access)
    await db.set("password", password)

    # Register and store flag
    response = await client.post("/register", json={
        "username": username,
        "password": password,
        "bio": task.flag
    })

    # Return PUBLIC targeting info
    # This tells players "the flag is in this user's bio"
    # but they still need to exploit the service to get it
    return username  # This becomes attack_info

@checker.getflag(0)
async def getflag_with_targeting(
    task: GetflagCheckerTaskMessage,
    client: AsyncClient,
    db: ChainDB
) -> None:
    # Retrieve targeting info from attack_info
    username = task.attack_info  # PUBLIC info from putflag return value

    # Retrieve PRIVATE data from ChainDB
    password = await db.get("password")  # Only checker knows this

    # Login and retrieve flag
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
    # Players get the target username from attack_info
    username = task.attack_info  # PUBLIC: "user_abc123"

    # But they DON'T know the password (stored in ChainDB)
    # They need to find an actual vulnerability to get the flag
    # Example: maybe there's an IDOR vulnerability
    response = await client.get(f"/api/user/{username}/bio")

    # Or maybe there's an SQL injection
    # response = await client.get(f"/search?q={username}' OR '1'='1")

    return searcher.search_flag(response.text)
```

**Key principles:**
- **attack_info = targeting information**: Prevents resource-intensive enumeration (e.g., trying 10,000 usernames)
- **Not a free pass**: Players still need to find and exploit actual vulnerabilities
- **PUBLIC information**: All teams can see attack_info for all other teams' flags
- **Think of it as "where to look"**, not "how to get it"

**What to include in attack_info:**
- ✅ User IDs, usernames, post IDs (targeting info)
- ✅ File names, document IDs, session identifiers (where to find the flag)
- ❌ Passwords, tokens, encryption keys (should be in ChainDB)
- ❌ Direct flag values or hints about vulnerabilities

### Why is Random seeded with task_id?

The purpose is **reproducibility for debugging and long-term testing**. When you're fuzzing or testing a service over thousands of rounds with varied inputs, being able to reproduce a specific failure is crucial.

**How it helps debugging:**
1. Your checker runs with random test data and fails on task_id=12345
2. You look at the logs and see task_id=12345
3. You can re-run or debug with the same task_id and get the exact same "random" data
4. This makes it easy to reproduce and fix intermittent issues

**Example - Reproducible test data:**
```python
@checker.putnoise(0)
async def putnoise_fuzz_service(
    task: PutnoiseCheckerTaskMessage,
    client: AsyncClient,
    random: Random
) -> None:
    # Generate varied test data that's reproducible for debugging
    num_requests = random.randint(5, 20)
    for i in range(num_requests):
        # Each task_id creates different but reproducible request patterns
        endpoint = random.choice(["/api/users", "/api/posts", "/api/comments"])
        await client.get(endpoint)

    # If this fails, task_id in logs lets you replay the exact sequence
```

**Important notes:**
- **Never use Random for secrets**: Use `secrets.token_hex()` or similar for passwords, tokens, session IDs, etc.
- **Random is NOT for exploit methods**: Players don't have access to the checker's internal random state. If you need to give players targeting information (like which user to attack), return it from putflag as attack_info (see FAQ below). Exploits should be exploitable by players with only publicly available information.

### How do I handle HTTP errors?

Use the assertion helpers or raise exceptions directly:

```python
from enochecker3.utils import assert_equals, assert_in
from enochecker3 import MumbleException, OfflineException

@checker.putflag(0)
async def putflag_example(task: PutflagCheckerTaskMessage, client: AsyncClient):
    response = await client.post("/api/store", json={"data": task.flag})

    # Option 1: Use assertion helpers (raises MumbleException on failure)
    assert_equals(response.status_code, 200, "Failed to store data")

    # Option 2: Raise exceptions directly
    if response.status_code == 503:
        raise OfflineException("Service unavailable")
    elif response.status_code != 200:
        raise MumbleException(f"Unexpected status: {response.status_code}")

    # Option 3: Use httpx's built-in error handling
    response.raise_for_status()  # Raises exception on 4xx/5xx
```

### What exceptions should I raise?

- **MumbleException**: Service is online but behaving incorrectly (wrong data, protocol violation, flag not found)
- **OfflineException**: Service is not reachable or completely broken (connection refused, timeouts, 503 errors)
- **InternalErrorException**: Checker bug (wrong logic, programming error)

Most network exceptions are automatically converted:
- `httpx.ConnectError`, `httpx.ConnectTimeout` → `OfflineException`
- `httpx.TimeoutException`, `TimeoutError` → `MumbleException`
- `ConnectionResetError` → `MumbleException`
- Generic `Exception` → `InternalErrorException`

### How do I test my checker locally?

1. **Interactive testing via Swagger UI**:
   ```bash
   uvicorn example:checker.app --reload
   # Browse to http://localhost:8000/docs
   ```

2. **Send requests with curl**:
   ```bash
   curl -X POST http://localhost:8000/ -H "Content-Type: application/json" -d '{
     "method": "putflag",
     "address": "localhost",
     "team_id": 1,
     "team_name": "TestTeam",
     "current_round_id": 1,
     "related_round_id": 1,
     "flag": "ENO{test_flag_12345}",
     "variant_id": 0,
     "timeout": 30000,
     "round_length": 60000,
     "task_chain_id": "test_chain_123",
     "task_id": 1
   }'
   ```

3. **Use the Python API directly**:
   ```python
   import asyncio
   from enochecker3 import PutflagCheckerTaskMessage, CheckerMethod

   async def test():
       task = PutflagCheckerTaskMessage(
           task_id=1,
           method=CheckerMethod.PUTFLAG,
           address="localhost",
           team_id=1,
           team_name="Test",
           current_round_id=1,
           related_round_id=1,
           flag="ENO{test}",
           variant_id=0,
           timeout=30000,
           round_length=60000,
           task_chain_id="test"
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

Or configure connection with environment variables:
```bash
export MONGO_HOST=mongodb.example.com
export MONGO_PORT=27017
export MONGO_USER=checker
export MONGO_PASSWORD=secret
```

### Can I use multiple variant ids in a single function?

Yes! Variants let you have multiple strategies for the same checker method.

**When to use shared function with multiple variants:**
Use this approach when variants share most of their code and only differ in small details:

```python
@checker.putflag(0, 1, 2)  # Register three variants at once
async def putflag_storage_variants(
    task: PutflagCheckerTaskMessage,
    client: AsyncClient,
    db: ChainDB
) -> str:
    # Shared setup code
    username = f"user_{secrets.token_hex(8)}"
    password = secrets.token_hex(16)

    # Register user (same for all variants)
    response = await client.post("/auth/register", json={
        "username": username,
        "password": password
    })
    assert_equals(response.status_code, 201)

    # Store credentials for getflag (same for all variants)
    await db.set("username", username)
    await db.set("password", password)

    # Only the storage location differs based on variant
    if task.variant_id == 0:
        endpoint = "/api/profile/bio"
        field = "bio"
    elif task.variant_id == 1:
        endpoint = "/api/profile/status"
        field = "status"
    else:  # variant_id == 2
        endpoint = "/api/profile/description"
        field = "description"

    # Store flag (same logic, different endpoint)
    await client.post(endpoint, json={field: task.flag})

    return username

@checker.getflag(0, 1, 2)
async def getflag_storage_variants(
    task: GetflagCheckerTaskMessage,
    client: AsyncClient,
    db: ChainDB
) -> None:
    # Retrieve credentials (same for all variants)
    username = await db.get("username")
    password = await db.get("password")

    # Login (same for all variants)
    await client.post("/auth/login", json={
        "username": username,
        "password": password
    })

    # Retrieve from variant-specific location
    if task.variant_id == 0:
        response = await client.get(f"/api/user/{username}/bio")
    elif task.variant_id == 1:
        response = await client.get(f"/api/user/{username}/status")
    else:  # variant_id == 2
        response = await client.get(f"/api/user/{username}/description")

    assert_in(task.flag, response.text)
```

**When to use separate functions per variant:**
When variants have completely different logic with little code reuse, **prefer registering them separately** for better readability:

```python
# Preferred approach when logic differs significantly
@checker.putflag(0)
async def putflag_api_storage(
    task: PutflagCheckerTaskMessage,
    client: AsyncClient,
    db: ChainDB
) -> str:
    """Store flag in the API."""
    note_id = secrets.token_hex(16)
    await client.post("/api/notes", json={
        "id": note_id,
        "content": task.flag
    })
    await db.set("note_id", note_id)
    return note_id

@checker.putflag(1)
async def putflag_file_storage(
    task: PutflagCheckerTaskMessage,
    client: AsyncClient,
    db: ChainDB
) -> str:
    """Store flag in uploaded file."""
    filename = f"secret_{secrets.token_hex(8)}.txt"
    await client.post("/api/upload", files={
        "file": (filename, task.flag.encode())
    })
    await db.set("filename", filename)
    return filename

@checker.putflag(2)
async def putflag_database_storage(
    task: PutflagCheckerTaskMessage,
    client: AsyncClient,
    db: ChainDB
) -> str:
    """Store flag directly in database table."""
    record_id = secrets.token_hex(16)
    await client.post("/api/db/secrets", json={
        "id": record_id,
        "secret": task.flag,
        "public": False
    })
    await db.set("record_id", record_id)
    return record_id
```

**Best practice**: Unless you have significant code reuse, separate functions are clearer and easier to maintain.

### How do I debug dependency injection issues?

1. **Enable debug logging**:
   ```bash
   export LOG_FORMAT=DEBUG
   uvicorn example:checker.app
   ```

2. **Check for missing return type annotations**:
   ```python
   @checker.register_dependency
   def broken_dependency(task):  # ERROR: missing return type!
       return SomeObject()

   @checker.register_dependency
   def fixed_dependency(task) -> SomeObject:  # OK!
       return SomeObject()
   ```

3. **Verify type annotations match exactly**:
   ```python
   @checker.register_dependency
   def get_session(task) -> AuthSession:  # Returns AuthSession
       return AuthSession()

   @checker.putflag(0)
   async def putflag(task, session: AuthSession):  # Must match exactly!
       ...
   ```

### Can dependencies be async?

Yes! Both sync and async dependency providers work:

```python
@checker.register_dependency
def sync_dependency(task) -> SomeType:
    return SomeType()  # Sync creation

@checker.register_dependency
async def async_dependency(task) -> OtherType:
    result = await async_operation()
    return OtherType(result)  # Async creation
```

### What if I need to clean up resources?

Use async context managers:

```python
@checker.register_dependency
@asynccontextmanager
async def managed_resource(task):
    # Setup
    resource = await create_resource()

    try:
        yield resource  # Provide to checker
    finally:
        # Cleanup (always runs, even if checker raises exception)
        await resource.close()
```

### How do I access the raw task message?

Just declare it as a parameter with the appropriate type:

```python
@checker.putflag(0)
async def putflag_example(task: PutflagCheckerTaskMessage):  # No other dependencies needed
    print(f"Team: {task.team_name}")
    print(f"Round: {task.current_round_id}")
    print(f"Flag: {task.flag}")
    # ... rest of checker logic
```

### Can I mix new and old style parameter names?

The parameter name doesn't matter, only the type:

```python
@checker.putflag(0)
async def putflag_flexible(
    task: PutflagCheckerTaskMessage,
    http: AsyncClient,        # Works (type is AsyncClient)
    my_db: ChainDB,           # Works (type is ChainDB)
    foo: AsyncCollection,     # Works (type is AsyncCollection)
):
    # All dependencies are correctly injected based on their types
    ...
```

### Can I inject multiple instances of the same dependency type?

Yes! Each parameter gets its own independent instance, even if they have the same type annotation.

**Example: Multiple HTTP clients**

```python
@checker.havoc(0)
async def havoc_concurrent_requests(
    task: HavocCheckerTaskMessage,
    client1: AsyncClient,  # Gets its own instance
    client2: AsyncClient,  # Gets a different instance
    client3: AsyncClient   # Gets yet another instance
) -> None:
    # All three are separate AsyncClient instances
    # Useful for concurrent requests without interference
    results = await asyncio.gather(
        client1.get("/api/endpoint1"),
        client2.get("/api/endpoint2"),
        client3.post("/api/endpoint3", json={"data": "test"})
    )
```

**Example: Named dependencies for different configurations**

If you want instances with different configurations (not just separate instances of the same config), use named dependencies:

```python
from dataclasses import dataclass

@dataclass
class Session:
    client: AsyncClient
    role: str

@checker.register_named_dependency("admin")
def _get_admin_session(task, client: AsyncClient) -> Session:
    # Create admin user and return session
    return Session(client=client, role="admin")

@checker.register_named_dependency("user")
def _get_user_session(task, client: AsyncClient) -> Session:
    # Create regular user and return session
    return Session(client=client, role="user")

@checker.havoc(0)
async def havoc_test_permissions(
    task: HavocCheckerTaskMessage,
    admin_session: Session,  # Uses "admin" injector (name prefix before underscore)
    user_session: Session     # Uses "user" injector
) -> None:
    # admin_session and user_session are different instances
    # created by different injector functions
    assert admin_session.role == "admin"
    assert user_session.role == "user"
```

**Key points:**
- Each parameter always gets its own instance, even with the same type
- Parameter names don't affect this (except for named dependency resolution)
- Named dependencies (prefix before `_`) allow using different injector functions
- Useful for concurrent operations or testing different user roles/permissions
```
