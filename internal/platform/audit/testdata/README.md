# Audit chains written by the old toolgate binary

These files show that `authz mcp` reads the audit logs that toolgate wrote
before it became part of authz. Do not regenerate them with the new binary:
their value is that the old one wrote them.

## toolgate-demo.jsonl

The audit log of one run of `toolgate/examples/demo.sh` at commit dec2e96, the
last commit before toolgate's packages moved to internal/agents. At that
commit toolgate was its own module under toolgate/ and the demo built
`toolgate/cmd/toolgate` and `toolgate/cmd/mcpfake`.

The run differed from the checked-in demo in two ways, both outside the
gateway:

- `TOOLGATE_AUDIT_KEY` was fixed at
  `05b2d3063867b16c4222d436cb3693975405b29dbf2877ed52ddd5c04ed22550` (the
  SHA-256 of `toolgate old binary audit fixture`) instead of random, so the
  `args_hmac` values can be checked again.
- The log was copied out at the start of step 8, before the demo tampers with
  it.

It has 23 records (19 `tool_call`, 2 `approval_requested`, 1
`approval_decided`, 1 `tool_quarantined`) and its head is
`69506072c64dd3d911c5528e3ff06f5fa3c8ba6f2886a44b1dce138d96f5ba95`. Its
recorded decisions match `toolgate/examples/demo_decisions.jsonl`.

## toolgate-demo-verify.txt

What the old binary's `toolgate audit verify` printed (stdout) and exited
with for the log and for five damaged copies of it. The tests in
cmd/authz/internal/mcp make the same copies and require `authz mcp audit
verify` to print the same lines and exit the same way. The copies, made from
the log's exact bytes:

| file | change |
| --- | --- |
| `tampered.jsonl` | the first `"decision":"deny"` becomes `"decision":"allow"` |
| `dropped-last.jsonl` | the last line removed |
| `torn.jsonl` | the last line cut to half its length, newline included |
| `swapped.jsonl` | lines 5 and 6 swapped |
| `dropped-first.jsonl` | the first line removed |
