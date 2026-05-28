# BouncyHSM transport / performance findings — 2026-05-28

## What the Pkcs11Lib actually uses

Despite the name (and our earlier assumption), the BouncyHSM PKCS#11 client
library does **NOT** speak HTTP/REST to the server. It uses a custom
MessagePack-RPC transport over **TCP/8765**:

- `src/Src/BouncyHsm.Pkcs11Lib/rpc/tcpTransport.c` — TCP transport
  implementation in C.
- `src/Src/BouncyHsm.Core/Rpc/Generated/MessagepackRpc.Abstraction.cs` —
  generated MessagePack RPC handlers in the .NET server.
- The `RpcGenerator` tool generates both sides from `RpcDefinition.yaml`.

The HTTP server (port 5000 in our Dockerfile, default 8080) is **only the
web admin UI + REST endpoints for slot management**. None of the PKCS#11
calls go through HTTP.

Default endpoint is `127.0.0.1:8765`. Override with the
`BOUNCY_HSM_CFG_STRING` env var, e.g.
`Server=hostname; Port=8765; LogTarget=Console; LogLevel=TRACE;`.

TCP already has `TCP_NODELAY` set:

```c
int flag = 1;
setsockopt(ctx->s, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(int));
```

## The actual bottleneck: connect() per RPC call

Searching the source, `connect()` lives inside `sock_writerequest()` —
which is the per-call entry point, not a per-session initializer:

```c
int sock_writerequest(void* user_ctx, void* request_data, size_t request_data_size)
{
    ...
    if ((ctx->s = socket(...)) == INVALID_SOCKET) { ... }
    if (connect(ctx->s, ctx->addr->ai_addr, ctx->addr->ai_addrlen) < 0) { ... }
    ...
}
```

So every PKCS#11 operation opens a fresh TCP socket, performs a 3-way
handshake to `127.0.0.1:8765`, sends the MessagePack request, reads the
response, and closes the socket — which then sits in TIME_WAIT.

Live measurement during a run (NEW comparison run, ~120 units in):

```
$ cat /proc/net/tcp | awk '$3 ~ /223D$/ && $4 == "06"' | wc -l
1077
```

1 077 TIME_WAIT sockets on the BouncyHSM RPC port at one snapshot. The
TCP three-way handshake + close adds ~50-100 µs to every PKCS#11 call on
loopback; for a test that already does TCP-bound HTTP-style overhead, the
total per-call cost is dominated by the .NET server's MessagePack
deserialization + handler dispatch, not the connection establishment
itself.

Linux on the container already has `net.ipv4.tcp_tw_reuse=2` (loopback
reuse enabled) and `tcp_fin_timeout=60`, so TIME_WAIT port exhaustion is
not currently happening.

## Implications for the slowness

Two layers contribute to bouncyhsm's per-call cost:

1. **TCP handshake per call** (~50-100 µs) — caused by the no-pool
   transport in `tcpTransport.c`. Fixing this needs an upstream change to
   keep a connection alive per session (or per process).
2. **.NET server MessagePack + handler** (the dominant remaining cost on
   loopback) — addressable with `DOTNET_gcServer=1`, `InMemory`
   persistence, lower `Logging:LogLevel`.

For our test runs, the per-test overhead removed by
`p11_module_session` (one C_OpenSession + C_Login amortized over the
file) already cuts the per-test connection count substantially.

## Recommended next steps (in priority order)

1. **`InMemory` persistence**: change `appsettings.Production.json` in
   `docker/bouncyhsm/Dockerfile` from `LiteDbFile` to `InMemory`. Tests
   don't need persistence between runs, and LiteDB writes to disk on
   every object create/modify. Cheapest measurable win.
2. **Server GC**: add `ENV DOTNET_gcServer=1` to the Dockerfile. Helps
   reduce per-call GC pause variance.
3. **Lower log level**: set `Logging:LogLevel:Default=Warning` in
   `appsettings.Production.json` to skip per-request log formatting.
4. **(Upstream)** Submit a PR to add connection pooling in
   `BouncyHsm.Pkcs11Lib/rpc/tcpTransport.c` — open one socket per
   session, reuse for the whole session, close at C_CloseSession.
   This would cut the per-call cost noticeably for long-running
   sessions, complementing our `p11_module_session` fixture.

## Measured results — InMemory persistence does NOT help

Tested on `test_wycheproof_ecdsa.py` (28 829 tests) on bouncyhsm:

| Configuration | Wall clock | Δ vs baseline |
|---|---|---|
| Baseline (LiteDb file + workstation GC) | **131.76 s** | — |
| InMemory + Server GC (`DOTNET_gcServer=1`) | 235.79 s | **+79 %** |
| InMemory only (no Server GC change) | 225.75 s | **+71 %** |

**Both proposed optimizations are slower than baseline.** Reverted both
changes; the Dockerfile is back to the working LiteDb configuration.

### Why InMemory was slower

Not measured directly, but plausible explanations:

1. **BouncyHSM's InMemory implementation** likely uses a
   `ConcurrentDictionary` (or equivalent locking primitive) for object
   storage. Reads against LiteDb's BSON store may be faster because
   LiteDb has its own in-memory page cache + indexed lookups, while
   InMemory does a per-call lock+lookup.
2. **GC pressure**: holding the entire token state on the .NET heap (no
   serialization) means more long-lived references and more frequent
   GC sweeps.
3. **Per-call cost is dominated by .NET request handler + MessagePack
   ser/deser**, not by storage — so swapping the storage backend doesn't
   help when storage isn't the bottleneck.

### Server GC made it slightly worse

Server GC (`DOTNET_gcServer=1`) added another ~10 s on top of InMemory.
Server GC is tuned for high-throughput multi-threaded long-running
services; for a short-lived single-threaded test session it introduces
larger generation pauses without amortizing the throughput benefit.

## What this leaves us with

The bouncyhsm slowness is structural to its RPC architecture (new TCP
connection per call inside `sock_writerequest`), not the storage backend.
The cheap configuration knobs do not move the needle — and one of them
moves it the wrong way.

Real wins for bouncyhsm performance would require upstream changes:

1. **Connection reuse in `tcpTransport.c`**: hoist `connect()` out of
   `sock_writerequest()` into session bind so the socket lives for the
   whole session. Biggest expected win.
2. **Batch RPC for multi-step operations**: send Init+Operation+Final
   as one round-trip when the caller knows the full buffer up front.
3. **Unix domain socket option**: skip TCP loopback entirely.

These are all upstream changes to the BouncyHSM project. From our side
the best remaining lever is the `p11_module_session` fixture — already
shipped — which amortizes session+login overhead across a test file.

## Update: deeper look at C_Login slowness and the connection model

After the InMemory/Server-GC measurements above came in negative, two
follow-up questions: (a) is the slow `C_Login` actually the connection
overhead, or intentional PIN-hardening? (b) since BouncyHSM's server is
C#, is there a cheap C#-side fix for connection pooling?

### C_Login is PBKDF2-SHA256 × 350 000 iterations — intentional

`src/Src/BouncyHsm.Infrastructure/Storage/LiteDbFile/LiteDbPersistentRepository.cs:118`:

```csharp
private Pbkdf2PasswordModel HashPassword(string password)
{
    const int iterations = 350_000;
    ...
    model.Hash = Rfc2898DeriveBytes.Pbkdf2(
        Encoding.UTF8.GetBytes(password),
        model.Salt,
        iterations,             // 350 000
        HashAlgorithmName.SHA256,
        64);
}
```

Measured locally:

```
$ python3 -c "import hashlib, time; ..."
PBKDF2-SHA256 × 350K iterations: 114.33 ms
```

That matches the 80.6 ms `C_Login` measurement on bouncyhsm (host CPU is
slightly faster than the container's effective core). It's exactly what a
KDF-protected PIN verifier is supposed to do — brute-force resistance.

`p11_module_session` already amortizes this: login fires once per file,
so ~268 files × 80 ms ≈ 21 s instead of ~100 k tests × 80 ms ≈ 130 min.
The 4.4× bouncyhsm speedup is driven by that, not by anything transport.

### Connection-per-call is in the C client, not C#

Every `C_*` entry point in `src/Src/BouncyHsm.Pkcs11Lib/bouncy-pkcs11.c`
follows the same pattern:

```c
CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)(...) {
    EncryptInitRequest request;
    EncryptInitEnvelope envelope;

    nmrpc_global_context_t ctx;
    SockContext_t tcp;                          // ← fresh stack-local socket context

    if (P11SocketInit(&tcp) != NMRPC_OK) ...    // ← connect to :8765
    nmrpc_global_context_tcp_init(&ctx, &tcp);

    ... // call nmrpc_call_EncryptInit
    // socket gets closed when function returns → goes into TIME_WAIT
}
```

So every PKCS#11 entry point declares its own `SockContext_t tcp;` on
the stack, connects, sends one RPC, gets the response, and lets the
socket close on function return. There is no C#-side fix because the
C# server isn't the one opening the per-call connection — the C client
is.

The minimal upstream patch would be in the C library:

1. Add a static `SockContext_t g_sock` (and a `static pid_t g_owner_pid`
   for fork-safety) in `globalContext.c`.
2. Replace `P11SocketInit(&tcp)` with a getter that lazy-inits the
   global socket and returns a borrowed reference.
3. Have `C_Finalize` close `g_sock`.
4. Detect EPIPE / fork-inherited stale fd and reconnect on next use.

That's ~50-80 lines of C, all upstream in `harrison314/BouncyHsm`. From
our side (pkcs11-check), the only handle we have on the runtime is the
loaded `.so`, so we can't change this without modifying the upstream
build.

### How much would connection pooling actually save?

After login PBKDF2 is amortized:

- ~108 k tests × ~3-5 PKCS#11 calls each = **~400 k TCP connections / run**
- Loopback handshake + close: ~50-100 µs
- 400 k × 75 µs = **~30 s of pure connection overhead** across 54 min

So connection pooling buys ~30 s on a 54-min run — roughly 1 %. The
remaining ~53 minutes is the actual .NET request handler + MessagePack
ser/deser + crypto work, which connection pooling doesn't touch.

### Updated lever summary

| Lever | Status | Why |
|---|---|---|
| Login PBKDF2 × 350K iterations | **Already amortized** | `p11_module_session` cut it from ~130 min to ~21 s |
| TCP connection-per-call | **~30 s / ~1 %** | Real but small after login is amortized; upstream-only fix |
| `InMemory` persistence | **−71 %** (slower) | LiteDb's page cache + indexed reads beat InMemory's per-call lock |
| `DOTNET_gcServer=1` | **−79 %** combined (slower) | Wrong GC mode for single-threaded test session |
| MessagePack handler + crypto | **The remaining ~53 min** | Not addressable from our side; needs upstream batched RPC or Unix-domain-socket transport |

The dominant remaining cost on bouncyhsm after `p11_module_session` is
BouncyHSM doing the actual cryptographic work on the .NET side, one RPC
per PKCS#11 call. Future wins would need upstream batched RPCs
(Init+Update+Final → one call) or a transport that skips loopback TCP.
