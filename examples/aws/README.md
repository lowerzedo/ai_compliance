# Reciprocal AWS retrieval public alpha

This tutorial configures the supported public-alpha path:

> Reciprocal synthetic-canary retrieval-boundary verification for
> pre-instrumented AWS RAG applications.

It uses only synthetic values. Replace every account, role, API, region,
endpoint, and log-group value in both JSON files. The execution policy is an
operator-owned authorization boundary; review and distribute it independently
from the verification suite. Configuration IDs are public operator-controlled
labels and must not contain secrets or sensitive identifiers.

## 1. Install the AWS extra

```console
python -m pip install 'cai-verify[aws]'
```

Copy both files to an access-controlled working directory:

```console
cp examples/aws/reciprocal-retrieval-suite.json ./suite.json
cp examples/aws/reciprocal-retrieval-policy.json ./execution-policy.json
```

Edit both files so their exact account, partition, region, endpoint, action,
roles, and CloudWatch log group agree. The policy accepts no environment
references, expressions, patterns, wildcards, query strings, or field paths.
It authorizes exact values only.

Keep the reciprocal assertion limitation description shown in the example.
This public result field is intentionally restricted to evaluator-owned fixed
text; arbitrary limitation descriptions are rejected before AWS access.

## 2. Configure three least-privilege roles

Use two requester roles and a third, separate evidence-reader role:

- Requester A: only `execute-api:Invoke` for the exact deployed API stage,
  `POST` method, and `/retrieve` resource needed by requester A.
- Requester B: only `execute-api:Invoke` for the exact deployed API stage,
  `POST` method, and `/retrieve` resource needed by requester B.
- Evidence reader: only `logs:FilterLogEvents` for the exact named CloudWatch
  log group used by both probes.

Do not grant `Resource: "*"`, service-wide resources, log-group prefixes, or
unrelated read permissions. Express each API authorization as the one concrete
execute-api resource for the deployed API ID, stage, `POST`, and `retrieve`
path. Express Logs authorization using AWS's concrete log-group ARN form for
the one configured group, not a prefix or account-wide resource.

The credential source that starts the verifier needs only
`sts:AssumeRole` for the three exact role ARNs. Runtime identity acquisition is
limited to the existing bounded calls: `sts:AssumeRole` where declared and
`sts:GetCallerIdentity` for lease validation. The requester and evidence roles
need no other verifier-specific AWS permissions.

`GetCallerIdentity` must prove the exact declared assumed-role name and session
in the target account and partition. A same-account but different role is not
accepted as the declared identity.

The example sets `allowCurrentIdentity` to `false`. This does not prevent the
SDK credential source from making the exact AssumeRole calls; it prevents a
suite from declaring the ambient current identity as an execution identity.

## 3. Instrument exact application correlation

For each signed application request:

1. Read the `X-Cai-Correlation-Id` request header.
1. Return the identical value in the `X-Cai-Correlation-Id` response header.
1. Carry that value only in transient application context and the structured
   retrieval event.

Do not generate a replacement correlation value. Time, account, principal,
region, event kind, or another request cannot substitute for the exact header.

## 4. Emit the fixed retrieval event

After assembling the complete final retrieval context, scan that complete
context for the two configured synthetic canaries. Emit exactly one
duplicate-free JSON event after that scan and before model invocation:

```json
{
  "canaries": ["the-detected-synthetic-marker"],
  "correlationId": "the-exact-request-correlation",
  "eventKind": "retrievalCanary",
  "eventTime": "2026-07-28T12:00:00.000Z",
  "phase": "PRE_GENERATION",
  "retrievalStatus": "SUCCEEDED",
  "retrievedItemCount": 1,
  "scanStatus": "COMPLETE",
  "schemaVersion": "1"
}
```

The `canaries` array contains only configured synthetic markers actually found
anywhere in the final context. It must be duplicate-free. Do not log prompts,
queries, retrieved text, documents, chunks, model inputs, model outputs,
credentials, principals, or authorization data. A compromised or incorrectly
instrumented application can still emit false telemetry.

## 5. Pre-seed the reciprocal documents

Create two synthetic documents that are similarly relevant to the two fixed
queries:

- Document A is retrievable by requester A and contains only canary A.
- Document B is retrievable by requester B and contains only canary B.

Requester A declares A as its baseline and B as its boundary. Requester B
declares B as its baseline and A as its boundary. Seed the documents before the
run. The verifier does not create, mutate, ingest, or delete canaries or
documents.

Set the canaries interactively so their values do not enter shell history or
terminal output:

```console
read -r -s -p 'Requester A synthetic canary: ' CAI_REQUESTER_A_CANARY
export CAI_REQUESTER_A_CANARY
read -r -s -p 'Requester B synthetic canary: ' CAI_REQUESTER_B_CANARY
export CAI_REQUESTER_B_CANARY
```

Use distinct non-empty UTF-8 values of at most 1 KiB. Clear the variables after
the run:

```console
unset CAI_REQUESTER_A_CANARY CAI_REQUESTER_B_CANARY
```

## 6. Run readiness and reciprocal verification

Readiness checks configuration, the three scoped identities, canary bounds,
and exact Logs access. It does not execute the application:

```console
cai-verify doctor retrieval suite.json \
  --execution-policy execution-policy.json
```

Execute both directions in assertion-ID order and persist one bundle:

```console
cai-verify run-aws-reciprocal-retrieval suite.json \
  --scenario-id reciprocal-requester-retrieval \
  --execution-policy execution-policy.json \
  --run-id synthetic-reciprocal-001 \
  --evidence-root .cai-verify/runs \
  --report terminal
```

Aggregate exits are deterministic:

- `0`: both directions are `PASS`;
- `1`: either direction is `FAIL`;
- `2`: `ERROR` without `FAIL`, or a redacted operational failure;
- `3`: `INCONCLUSIVE` without `FAIL` or `ERROR`.

A passing direction never compensates for another direction.

## 7. Verify and retain evidence

Verify the finalized unsigned bundle without AWS or network access:

```console
cai-verify verify-evidence \
  .cai-verify/runs/synthetic-reciprocal-001 \
  --report json
```

A valid result means the manifest and stored bytes are internally consistent.
It does not authenticate who created them. Preserve completed bundles in an
access-controlled, retention-managed location.

An interrupted operational run is intentionally abandoned in place without
`manifest.json`; it is never complete, resumed, overwritten, or automatically
deleted. Before disposal, confirm the exact run ID and absence of a manifest.
Then use the organization's approved retention and deletion process on that
single directory. Filesystem deletion is not guaranteed forensic erasure on
SSDs, snapshots, or replicated storage. If investigation is required, retain
the directory with restrictive access instead.

## What this result proves

The result evaluates two declared synthetic retrieval paths from exact,
correlated, fresh, application-reported pre-generation facts. It supports a
focused technical assessment.

It does not prove universal tenant isolation, application instrumentation
correctness, compliance, evidence authenticity, every query/document/cache or
memory path, or production readiness. A protected manual run in a dedicated
synthetic AWS sandbox remains required before a release can be called publicly
validated.
