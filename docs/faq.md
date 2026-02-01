# Good to Know / FAQ

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
