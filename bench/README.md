# bench

The benchmark harness for the whole product (#86). This directory grows
over week 5: the load runner first, then seeded datasets, pinned competitor
setups, resource collection, the CI regression gate and the BENCHMARKS.md
report.

| Path | What it is |
| --- | --- |
| `cmd/authzbench` | Open-loop load runner for a mix of operations |
| `cmd/authzdata` | Writes the seeded datasets, loads them into authz, SpiceDB or OpenFGA, and cross-checks their answers |
| `products` | The competitors at pinned versions with their production settings, and `verify.sh`, which proves the setups give authz's answers |
| `datasets` | Seeded generators: relationship graphs, the sign-in population, MCP tool catalogs |
| `load` | The open-loop scheduler and its coordinated-omission correction |
| `hdr` | High dynamic range latency histogram (standard library only) |
| `ops` | The operations: checks, bulk checks, lookups, writes, forward-auth, OIDC login, MCP `tools/call` |
| `image-baseline.json` | Image size baseline for the CI image gate (week 1) |

## Datasets

Every product is loaded with the same data, generated from a size and a
seed (default 1) by `bench/datasets`. Each user, group, folder and document
draws from its own random stream seeded from the dataset seed and its
number, so a dataset is identical on every machine and in every format,
any range of it can be generated on its own, and nothing is held in memory.

```
go build -o authzdata ./bench/cmd/authzdata
./authzdata manifest -size 10m                     # counts and the authzbench flags for them
./authzdata schema > dataset.schema                # -format openfga for the OpenFGA model
./authzdata graph -size 10m -o rels.txt            # type:id#relation@subject per line
./authzdata graph -size 10m -format openfga -o rels.jsonl   # {"user","relation","object"} per line
AUTHZBENCH_API_KEY=... ./authzdata load -size 10m -api http://127.0.0.1:8080 -schema
./authzdata users -size 10m -n 10000 -format credentials -o creds.txt   # authzbench -login-credentials @creds.txt
./authzdata users -size 10m -n 10000 -o users.jsonl                     # for provider imports
./authzdata tools -n 200 -o catalog.json           # a tools/list result
./authzdata tools -n 200 -calls 1000 -o calls.json # authzbench -mcp-tools @calls.json
```

**The graph** is document sharing: users in nested groups, folder trees
with inherited viewers, documents with an owner, editors and bans
(`datasets.Schema`; the OpenFGA model has the same relations and meaning).
For every ten documents there is one user, for every fifty users one group,
for every fifty documents one folder. Each user is a direct member of two
groups drawn Zipf (s 1.1, v 10), so a few groups are large (the first holds
about 6% of the users) and most are small; three groups in four nest in a
lower-numbered group, two levels deep at most. Folders form one tree per
thousand folders with eight subfolders each, four levels deep; each folder
has one viewer: a group, one in ten a user, one in a thousand `user:*`.
Each document has a parent folder, an owner, a user editor and a group
editor; one in fifty bans a user.

| Size | Relationships | Users | Groups | Folders | Documents |
| --- | ---: | ---: | ---: | ---: | ---: |
| `1m` | 999,999 | 23,466 | 469 | 4,693 | 234,660 |
| `10m` | 9,999,998 | 234,660 | 4,693 | 46,932 | 2,346,602 |
| `100m` | 99,999,998 | 2,346,602 | 46,932 | 469,320 | 23,466,026 |

IDs follow authzbench's naming (`doc:d<n>`, `user:u<n>`, `group:g<n>`,
`folder:f<n>`), so the manifest's `authzbench_flags` draw checks from
exactly the objects that exist. A test pins the digest of the 100k seed 1
dataset: a change to the generator that changes the data must change it on
purpose. Another loads a graph into the real API and compares 600 sampled
checks with an oracle that applies the schema's rules by hand to the
generated tuples.

**The sign-in population** is the graph's users: `u<n>` with the email
`u<n>@bench.example`, a password derived from the seed (public by design:
it exists so every provider signs in the same accounts) and the groups the
user is a direct member of in the graph, so group claims and relationships
agree. `authzdata users` writes it as JSON lines or as authzbench
credentials, and `authzdata import -target keycloak` imports it into
Keycloak through its admin API (`bench/products` says how).

**The MCP tool catalog** has `verb_noun` tools with one to six arguments
(strings with lengths, IDs with a pattern, bounded integers, booleans,
enums, string lists), closed object schemas and descriptions of ten to
forty words. Calls pick tools Zipf (s 1.2) and give every required
argument and about half the optional ones; a test checks every call with
the gateway's own schema validator.

Generating is cheap: 100M relationships stream out in 8.8 s at 7.8 MB peak
RSS (about 14M relationships per second on one core), 3.5 GB as tuples.
`authzdata load` wrote the 1m graph into `authz serve` (in memory, same
4 vCPU container) in 4.7 s, 215k relationships per second, in batches of
1,000 with four writes in flight; touches are idempotent, so a load can be
repeated or resumed with `-from`.

## authzbench

```
go build -o authzbench ./bench/cmd/authzbench
AUTHZBENCH_API_KEY=... ./authzbench -api http://127.0.0.1:8080 \
  -mix check=70,bulk_check=10,lookup=10,write=10 \
  -rate 2000 -warmup 5s -duration 30s -workers 64 \
  -resources 1000 -subjects 1000 -out result.json
```

Operations and what each one checks in the answer:

| Name | Request | Counted as a success when |
| --- | --- | --- |
| `check` | `POST /v1/check` of `-permission` on a drawn resource for a drawn subject | 200 with a boolean `allowed` |
| `bulk_check` | `POST /v1/check/bulk` of `-bulk-items` drawn checks (1 to 100) | 200, every item answered in order, no item error |
| `lookup` | `POST /v1/lookup/resources` for a drawn subject, up to `-lookup-limit` | 200 with `resource_ids` |
| `write` | `POST /v1/relationships/write`, one `touch` of `-relation` | 200 with `written_at` |
| `forward_auth` | `GET -forward-url` with `X-Forwarded-Host/Uri/Method/Proto` and a session cookie | status `-forward-expect` (default 200) |
| `oidc_login` | a browser sign-in from `-login-start`: follow redirects, fill the first form with a password field, submit, follow redirects | the answers set `-login-cookie` |
| `mcp_call` | JSON-RPC `tools/call` of a drawn tool from `-mcp-tools` on `-mcp-url` | 200, a result for the request's id, not `isError`; JSON or event stream |

Resources are `-resource-type:-resource-prefix<n>` for n below `-resources`,
subjects `-subject-type:-subject-prefix<n>` for n below `-subjects`, drawn
uniformly or, with `-zipf s` (s above 1), so that low numbers are hot.
Forward-auth sessions come from `-sessions-file` (one `NAME=VALUE` per line),
from `-sessions N` sign-ins run before the load starts, or both. MCP calls
speak the 2026-07-28 revision with no session by default; `-mcp-protocol
2025-06-18` opens a session per worker with `initialize`, for gateways that
do not speak the newer revision. Keys come from the environment only
(`AUTHZBENCH_API_KEY`, `AUTHZBENCH_MCP_KEY`), so they never appear in a
process list or in the result file, which records the arguments.

**SpiceDB and OpenFGA.** `-target spicedb` or `-target openfga` sends the
four authorization operations to that product's own API instead, asking
the same questions, so one mix and one keyspace measure all three products
(`bench/products` sets them up):

| Name | SpiceDB (HTTP gateway) | OpenFGA | Counted as a success when |
| --- | --- | --- | --- |
| `check` | `POST /v1/permissions/check` | `POST /stores/{id}/check` | a has or has-not permissionship; a boolean `allowed` |
| `bulk_check` | `POST /v1/permissions/checkbulk` | `POST /stores/{id}/batch-check`, at most 50 items (its default limit) | every item answered (SpiceDB: in order, for the resource asked; OpenFGA: every correlation ID), none with an error |
| `lookup` | `POST /v1/permissions/resources` with `optionalLimit`, a stream of one result a line | `POST /stores/{id}/list-objects` | every result a has-permission answer of `-resource-type`, no error in the stream, at most `-lookup-limit` |
| `write` | `POST /v1/relationships/write`, one `OPERATION_TOUCH` | `POST /stores/{id}/write`, one tuple with `on_duplicate: ignore` | a `writtenAt` token; 200 with an object |

`-consistency` takes `minimize_latency` (SpiceDB `minimizeLatency`, OpenFGA
`MINIMIZE_LATENCY`) or `fully_consistent` (`fullyConsistent`,
`HIGHER_CONSISTENCY`) for them. OpenFGA's requests name the store
`-openfga-store` (default `authz-bench`) and its newest model, found before
the run without writing anything; a store that is missing or whose model
is not the dataset's stops the run. ListObjects takes no limit in the
request, so `compose.yaml` sets the server's to 100 and an answer over
`-lookup-limit` fails rather than being compared with smaller ones. The
keys are `AUTHZBENCH_SPICEDB_KEY` and `AUTHZBENCH_OPENFGA_KEY`, as for
`authzdata`.

```
export AUTHZBENCH_SPICEDB_KEY=bench-spicedb-key-0123456789 AUTHZBENCH_OPENFGA_KEY=bench-openfga-key-0123456789
flags=$(./authzdata manifest -size 1m | jq -r '.authzbench_flags | join(" ")')
./authzbench -target spicedb -api http://127.0.0.1:18443 $flags -mix check=70,bulk_check=10,lookup=10,write=10 -rate 500
./authzbench -target openfga -api http://127.0.0.1:18081 $flags -mix check=70,bulk_check=10,lookup=10,write=10 -rate 500
```

### Method

The load is open loop. Send times are fixed before the run from `-rate`
(evenly spaced, or `-arrival poisson`) and `-seed`, and do not wait for
earlier answers, so a slow server cannot lower the load it is offered. Up
to `-workers` requests are in flight; due requests wait in a backlog of
`-backlog` (default four per worker) and then hold the scheduler.

Latency is measured from the time a request was **due**, not from when a
worker sent it. When the server stalls, every request due during the stall
is charged for its wait, which is the coordinated-omission correction of
wrk2 and HdrHistogram applied by construction. The time from the actual
send is reported as service time; the gap between the two is queueing in
the generator. A run that cannot keep up says so: the largest send lag is
printed, requests not sent within `-drain` of the end are `unsent`, and
requests still running then are cancelled and counted as errors.

Each worker records into its own histograms (three significant digits, 1 ns
to one minute, no allocation per record), merged when the run ends. The
result file holds p50, p90, p99, p99.9, max and mean per operation and for
the whole mix, both for latency and service time, with every histogram's
non-zero buckets, so runs can be merged or re-read by the report later.

The exit status is 0 when nothing was left unsent and failures stayed
within `-max-error-rate` (default 0.1%), 1 otherwise, and 2 for bad flags
or a failed setup.

### A first run

`authz serve` in memory with 1,000 documents shared through 50 groups of 20
users, the client and server on one 4 vCPU container, 2,000 requests per
second for 15 s after a 3 s warmup (the measured figures will come from the
pinned setups and datasets later this week):

```
   operation  requests  errors   per s  p50 ms  p90 ms  p99 ms  p99.9 ms   max ms  service p99 ms
       check     21044       0  1401.3   0.969   3.332   7.864    14.131   21.915           6.156
  bulk_check      3060       0   203.8   1.391   4.301   9.298    16.204   16.979           7.819
      lookup      2910       0   193.8  15.172  34.767  64.127    96.469  100.099          63.996
       write      2986       0   198.8   0.976   3.508   7.905    13.607   16.933           6.648
         all     30000       0  1997.7   1.159   7.377  34.439    63.308  100.099          33.686
offered 2000.0/s, achieved 1997.7/s; 30000 due, 30000 sent, 0 unsent; largest send lag 8.610324ms
```
