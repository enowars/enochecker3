# Adding Custom Dependencies

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
