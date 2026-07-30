# Cloud AI Control Verifier

Cloud AI Control Verifier (`cai-verify`) is an AWS-first, open-source tool for
executing focused security-control tests against deployed AI applications and
producing machine-readable evidence.

The first public alpha supports one deliberately narrow AWS path:
**Reciprocal synthetic-canary retrieval-boundary verification for
pre-instrumented AWS RAG applications.** It is intended for a platform or
security engineer who already has two least-privilege requester roles, one
separate read-only evidence role, two pre-seeded synthetic canaries, and an
application that emits the required correlated retrieval event.

An optional local security console presents that same fixed workflow in a
browser on `127.0.0.1`. It does not add another runner, assertion, remote API,
database, authentication service, or compliance claim.

The repository also contains configuration models, adapters, evaluators,
doctors, diagnostic building blocks, and a local synthetic demonstration that
are not all composed into public-alpha runners. A suite being schema-valid
does not mean that every runner can execute every declaration.

The generated contracts are committed at:

- [`schemas/verification-suite-1alpha1.schema.json`](schemas/verification-suite-1alpha1.schema.json)
- [`schemas/aws-execution-policy-1alpha1.schema.json`](schemas/aws-execution-policy-1alpha1.schema.json)

Installed distributions expose the same reviewed resources without requiring
the AWS extra:

```console
cai-verify schema suite
cai-verify schema aws-execution-policy
```

## Public-alpha capability boundary

The supported reciprocal result is the aggregate of two existing
`retrievalBoundary` assertion results. It is not a third assertion or a
compliance determination.

| Capability                            | Configuration model | Evidence adapter | Evaluator | Executable runner                 | Public-alpha path |
| ------------------------------------- | ------------------- | ---------------- | --------- | --------------------------------- | ----------------- |
| Reciprocal AWS retrieval boundary     | Yes                 | Yes              | Yes       | Yes, fixed two-direction runner   | Yes               |
| Single AWS retrieval boundary         | Yes                 | Yes              | Yes       | Yes, diagnostic single-chain path | No                |
| Local synthetic control demonstration | Yes                 | Yes              | Yes       | Yes                               | No                |
| Bedrock/provider invocation evidence  | Yes                 | Yes              | No        | No generic AWS runner             | No                |
| CloudTrail audit-event evidence       | Yes                 | Yes              | No        | No generic AWS runner             | No                |
| Encryption checks                     | Yes                 | No               | No        | No                                | No                |
| Unauthorized-identity checks          | Yes                 | No               | No        | No                                | No                |

The public alpha can show, for two exact requester paths and one run, whether
each fresh, exactly correlated, application-reported final context included
its positive-control canary and excluded the other requester’s boundary
canary. A passing aggregate requires both directions to pass.

It does not establish universal tenant isolation, document-store policy
correctness, the correctness or honesty of application instrumentation,
evidence authenticity, or HIPAA, FedRAMP, NIST, or legal compliance. Generic
AWS suite execution; provider, audit, encryption, and unauthorized-identity
orchestration; S3/KMS assessment; signing; JUnit, SARIF, and OSCAL; compliance
mappings; OpenTelemetry; automatic canary creation; and production deployment
remain outside this alpha.

## Verification suite schema

`cai_verify.config.VerificationSuite` validates already-parsed suite mappings.
Version `1alpha1` has fixed local/AWS identity, HTTP/AWS SigV4 action,
local/CloudWatch Logs/CloudTrail probe, and deterministic assertion
vocabularies. Local-only variants cannot be mixed into a cloud target. Unknown
fields fail at every model boundary. Duplicate reference IDs, unresolved
component references, invalid freshness, mutation declarations, and missing
limitations also fail before planning.

Secret-capable values accept only explicit environment references:

```yaml
value:
  source: environment
  name: SYNTHETIC_APP_TOKEN
```

Literal action inputs must explicitly declare `sensitive: false`; sensitive
names and credential-shaped values are rejected from that channel. There is no
shell action, expression evaluator, template syntax, or literal credential
field. `VerificationSuite.render_resolved_redacted(environment)` checks
referenced variables without retaining their values and emits only `[REDACTED]`
in their place.

Configuration IDs are operator-controlled public labels. Action, probe,
assertion, scenario, target, and run IDs must never contain secrets, tenant or
user identifiers, account data, or other sensitive content.

Compatibility notes for `1alpha1`:

- Suite input uses the JSON Schema's lower-camel-case field names; Python
  snake-case aliases are not accepted.
- Scalars are not coerced. YAML sequences are normalized to immutable tuples.
- Freshness is a positive ISO-8601 hour/minute/second duration no longer than
  24 hours; clock skew is limited to five minutes.
- Non-local targets must explicitly declare both `awsRegion` and
  `awsAccountId`.
- Additive fields are rejected in this version. New fields or union variants
  require an explicit schema compatibility decision.
- A `cloudWatchLogs` probe requesting `telemetryCanary` must now declare a
  `canary` environment reference. Provider-only probes do not require it.
- A `cloudWatchLogs` probe requesting `bedrockInvocation` must declare an
  environment-backed Bedrock model ID and may declare one explicitly
  non-sensitive bounded model alias.
- A `cloudWatchLogs` probe requesting `retrievalCanary` must declare distinct
  environment-backed baseline and boundary canaries. This is an intentional
  additive change to the unreleased `1alpha1` contract; existing suites remain
  valid.
- `retrievalBoundary` is an additive assertion union member with only
  `actionRef`, `probeRef`, and inherited claim boundaries. It requires a
  matching non-local CloudWatch Logs probe requesting `retrievalCanary`.
- The built-in loader accepts bounded duplicate-free JSON. General YAML parsing
  remains out of scope; PyYAML is test-only.

Pydantic v2 is the direct runtime dependency required for the requested strict
models and Draft 2020-12 schema generation. It and its `pydantic-core`
dependency use the MIT license and are pinned through `uv.lock`; the major
version is capped for compatibility review. PyYAML and its type stubs are
development-only dependencies for fixtures.

Regenerate the schema after an intentional model change:

```console
uv run python scripts/generate_schemas.py
```

Tests compare the generated bytes with the committed artifact so drift fails
`make check`.

## Operator-owned AWS execution policy

The suite is untrusted and cannot authorize its own AWS target. Before any
AWS-capable `cai-verify` command can create an SDK session, call STS, send an
application request, collect CloudWatch Logs evidence, or reserve an evidence
run, the operator must supply a separate strict execution policy:

```console
--execution-policy POLICY.json
```

The versioned `1alpha1` policy authorizes exact values only: AWS account,
partition, region, normalized HTTPS endpoint, permitted method/path/service,
assumed-role ARNs, optional current-identity use (disabled by default), and
CloudWatch log groups. Its bounded loader accepts at most 64 KiB of
duplicate-free UTF-8 JSON. Unknown fields, URL credentials, query strings,
fragments, environment references, secrets, expressions, field paths, globs,
regular expressions, wildcards, and inconsistent region/partition/role
combinations are rejected.

Policy denial is an operational failure, not assertion evidence. Policy
contents are never copied into reports or evidence. Exact authorization also
does not discover or grant IAM permissions: the operator remains responsible
for independently configuring requester roles with only the required
`execute-api:Invoke` resources, the evidence role with
`logs:FilterLogEvents` on the exact log group, and the existing bounded STS
identity-acquisition calls.

This required option is an intentional pre-alpha security compatibility
change. It applies to `doctor aws`, `doctor retrieval`,
`run-aws-retrieval`, and `run-aws-reciprocal-retrieval`. See
[`examples/aws/README.md`](examples/aws/README.md) for the synthetic contract
and operator walkthrough.

## AWS identity doctor

Install the optional AWS support when installing the package:

```console
uv sync --extra aws --dev
```

Check the identities declared by a non-local JSON suite:

```console
uv run cai-verify doctor aws SUITE.json \
  --execution-policy POLICY.json
```

Use `--report json` for canonical machine-readable output. The command uses the
in-process AWS SDK; it does not execute the `aws` CLI. It performs only
`sts:GetCallerIdentity` and, for a declared assumed-role identity,
`sts:AssumeRole`. Current identities must match the suite's target account;
assumed identities must match their declared role account. All identities must
match the expected AWS partition and must not be expired.

Reports contain only match states and stable issue codes. They exclude AWS
account IDs, principal ARNs, profile values, external IDs, credentials, and SDK
exception text. `READY` exits `0`; any failed preflight exits `2`. Readiness
does not test service permissions, execute application actions, create
evidence, or establish a security or compliance result.

## Retrieval evidence readiness doctor

Check whether each scenario-local `retrievalBoundary` chain is ready for a
later execution attempt:

```console
uv run cai-verify doctor retrieval SUITE.json \
  --execution-policy POLICY.json
```

Use `--report json` for the canonical version-1 machine-readable result. The
command selects only chains from a retrieval-boundary assertion through its
referenced CloudWatch Logs retrieval-canary probe and action. It resolves only
the environment values and effective AWS identities those chains require,
validates the paired canary contract, and issues one bounded
`logs:FilterLogEvents` access preflight for each unique identity, target region,
and declared log group.

`READY TO ATTEMPT` exits `0`; not-ready, incomplete, resource-limit, and
unexpected failures exit `2`. Readiness means only that configuration,
identity boundaries, paired-canary declarations, and exact CloudWatch Logs
source access passed preflight. The doctor does not execute or sign the
application action, generate a correlation identifier, parse telemetry, or
create evidence. A later execution must still establish the exact action
correlation echo, exactly correlated pre-generation telemetry, baseline
document retrievability, boundary-document exclusion, and complete fresh
evidence. The command does not establish that telemetry was emitted, canary
documents exist, retrieval or context scanning occurred, tenant isolation
passed, or compliance was established.

## Minimal AWS retrieval runner

After preflight, one explicitly selected, pre-seeded retrieval-boundary chain
can be executed with:

```console
uv run cai-verify run-aws-retrieval SUITE.json \
  --assertion-id requester-a-retrieval-boundary \
  --execution-policy POLICY.json \
  --run-id synthetic-retrieval-run
```

The runner resolves that assertion's scenario-local action and CloudWatch Logs
probe, acquires their effective AWS identities once, performs one non-mutating
`execute-api` SigV4 action, collects the fixed CloudWatch Logs 1.2.0 retrieval
observation, and applies the deterministic `RetrievalBoundaryEvaluator`. Use
`--report json` for the canonical assertion report. Assertion exit codes retain
the normal `PASS`/`FAIL`/`ERROR`/`INCONCLUSIVE`/`SKIPPED` semantics.

This deliberately narrow runner handles one existing paired-canary chain. It
does not create canary documents, run multiple assertions, persist an evidence
bundle, mutate cloud state, discover permissions, or establish tenant isolation
beyond the selected fresh evidence path. It does not establish compliance.

## Reciprocal AWS retrieval runner

The public-alpha runner executes the two directions of one exact reciprocal
scenario:

```console
cai-verify run-aws-reciprocal-retrieval SUITE.json \
  --scenario-id reciprocal-requester-retrieval \
  --execution-policy POLICY.json \
  --run-id RUN_ID \
  --evidence-root .cai-verify/runs \
  --report terminal
```

The same orchestration is available through
`AwsReciprocalRetrievalRunOptions`,
`AwsReciprocalRetrievalRunResult`, and
`run_aws_reciprocal_retrieval`.

`AwsReciprocalRetrievalRunOptions` also accepts an optional fixed-enum progress
observer for the local console. Omitting it preserves the previous API and
runner behavior. Observer failures are ignored, and progress values contain no
target identifiers, correlations, credentials, or diagnostics.

The selected scenario must contain exactly two non-mutating `execute-api`
actions, two CloudWatch Logs probes requesting only `retrievalCanary`, and two
`retrievalBoundary` assertions. It must use two distinct effective requester
identities, one shared evidence identity distinct from both requesters, one
declared log group, reversed canary declarations, and one unique
action/probe/assertion chain per direction. Extra, duplicated, overlapping,
mixed-purpose, partially reciprocal, or ambiguous components fail before AWS
access.

Because assertion results are public artifacts, reciprocal assertion
limitation descriptions must be selected from the evaluator-owned
`RETRIEVAL_BOUNDARY_FIXED_LIMITATIONS`; arbitrary suite text is rejected
before reservation or AWS access. The example uses the fixed statement
`The retrieval evidence is application-reported.` Other suite text remains
schema-valid but is not runnable through this focused public-alpha path.

After pure validation and exact execution-policy authorization, the runner
reserves the run, acquires all three identities once, and validates every
lease before the first application call. It executes both chains sequentially
in assertion-ID order. Each requester lease closes immediately after its
action; the shared evidence-reader lease remains open only through the second
probe. All leases close before evaluation, reporting, or persistence. The
orchestration has a five-minute scheduling budget in addition to the existing
narrower in-flight limits and makes only the bounded STS operations, two
direct SigV4 requests, and two `logs:FilterLogEvents` collections.
Each assumed-role lease is bound by `sts:GetCallerIdentity` to the declared
role name and session, then checked against the exact target account and
partition. Required environment values are read once into an immutable,
minimal snapshot before authorization and are not reread from the caller's
mapping during execution.

Exact application correlation remains mandatory and transient. The two
successful actions cannot reuse one correlation value, and a correlation for
one direction cannot satisfy the other. No correlation, AWS request ID,
CloudWatch message, canary value, endpoint, log group, account, ARN, identity,
credential, environment reference, request content, response content, or SDK
diagnostic is written to output or evidence.

Both existing assertion results are always evaluated after trustworthy
normalized execution, even if the first direction is `FAIL`, `INCONCLUSIVE`,
or normalized `ERROR`. Aggregate status and exit code are conservative:

| Direction results                   | Aggregate      | Exit |
| ----------------------------------- | -------------- | ---: |
| Both `PASS`                         | `PASS`         |    0 |
| Either `FAIL`                       | `FAIL`         |    1 |
| `ERROR` without `FAIL`              | `ERROR`        |    2 |
| `INCONCLUSIVE` without either above | `INCONCLUSIVE` |    3 |

Operational failures, including invalid configuration or environment, policy
denial, identity acquisition, budget exhaustion, an invalid normalized shape,
run collision, persistence failure, or immediate integrity-verification
failure, emit only `AWS reciprocal retrieval run failed` on standard error,
produce no report on standard output, and exit `2`.

Every normalized status finalizes one redacted, unsigned, tamper-evident bundle
with exactly nine non-manifest artifacts: `run.json`; two hashed action
artifacts; two hashed probe artifacts; two hashed assertion-result artifacts;
`reports/report.json`; and `reports/terminal.txt`. The action and probe
artifacts are `INTERNAL`; results and reports are `PUBLIC`.
`manifest.json` is created last and verified immediately offline. A path is
returned only after that verification succeeds.

`run.json` stores no raw target ID. Its target digest is a stable SHA-256
pseudonym derived only from that operator-controlled label. This supports
determinism, but is not anonymity when the label is guessable. Interrupted or
failed unfinalized runs are preserved without `manifest.json`; they are never
resumed, adopted, overwritten, automatically deleted, or reported complete.
Operators must inspect and securely preserve or remove those abandoned
directories according to local policy.

## Local security console

Install both optional AWS and UI support:

```console
python -m pip install "cai-verify[aws,ui]"
```

From a repository checkout, use the locked development environment:

```console
uv sync --extra aws --extra ui --dev
```

Start the console:

```console
cai-verify ui --evidence-root .cai-verify/runs
```

The server binds only to `127.0.0.1` and selects an ephemeral port by default.
Use `--port PORT` to select a loopback port or `--no-open` to leave browser
startup to the operator. With `--no-open`, the command prints the one-use
loopback launch URL to standard output for the operator or local automation;
handle that URL as a short-lived local capability. There is no configurable
host or remote mode.

Prefix the launch command with `uv run` when using the repository environment.

The console supports the complete reciprocal public-alpha path:

1. load one bounded duplicate-free suite JSON file and one independently
   bounded execution-policy JSON file;
1. review the exact validated plan with sensitive configuration masked;
1. run the existing AWS identity and retrieval readiness checks;
1. explicitly confirm and start one fixed reciprocal run;
1. inspect both assertion results, the conservative aggregate, and fixed
   limitations; and
1. browse bounded local evidence history after manifest verification.

Configuration remains in bounded process memory and is discarded when the
console exits. The browser does not store configuration, credentials, canary
values, environment values, correlations, or evidence in local storage,
session storage, IndexedDB, or data-bearing cookies. An explicit temporary
reveal can show only allowlisted account, endpoint, role ARN, log-group, and
environment-reference names. It never reveals the referenced environment
values. The masked review covers both the selected reciprocal slice and every
role, action path, and log group authorized by the uploaded policy, including
authorizations that the selected slice does not use. Temporary reveal requests
are bound to that review's exact configuration revision.

Each console process creates one browser session through a one-use secret in a
URL fragment, then uses a host-only HttpOnly `SameSite=Strict` cookie and an
in-memory CSRF value. Exact `Host` and `Origin` checks, strict same-origin
response headers, and the loopback-only bind reduce cross-origin request and
DNS-rebinding risk. They are not remote authentication and do not protect
against a compromised local account, browser, process, or filesystem.

Only one run may be active. The console calls the existing Python runner in
process and adds no cancellation or runner-level retry. A stopped process may
therefore leave the same intentionally unfinalized evidence directory as an
interrupted CLI run.

Evidence history is not a generic artifact browser. It verifies finalized
manifests before reading only the fixed reciprocal `run.json` and public
`reports/report.json` shapes, classifies invalid or unfinalized runs, and
returns no raw evidence artifacts. A verified bundle remains unsigned:
manifest integrity is not creator authenticity or protection against complete
bundle replacement.

The localhost API is internal to the console and is not a supported remote
integration API. The protected live-AWS public-alpha release gate remains
pending, and using the console does not establish tenant isolation or legal,
regulatory, or framework compliance.

## AWS SigV4 application actions

The built-in `AwsSigV4ActionAdapter` consumes an acquired
`AwsScopedIdentity` and executes only validated, non-mutating `awsSigV4`
actions for `execute-api` or `bedrock-runtime`. It uses Botocore for signing,
supports literal and explicit environment inputs, and sends one bounded direct
HTTPS request to the target's exact allowlisted hostname. Action and target
regions must agree.

The adapter does not follow redirects, use proxy or SDK endpoint overrides,
retry requests, invoke the AWS CLI, or retain request bodies, response bodies,
credentials, signing headers, environment values, or SDK exception text in its
normalized result. The transport recognizes only the fixed AWS
`X-Amzn-RequestId` response header for later CloudTrail correlation. It retains
at most two bounded values in the additive, non-repr
`ActionExecutionResult.aws_request_ids` field so a probe can distinguish one
usable identifier from missing or multiple identifiers. Raw headers remain
excluded. `ActionExecutionResult.correlation_ids` is now also suppressed from
its representation while remaining available to evaluators and probes. This
representation-only hardening is an intentional pre-alpha compatibility
change for callers that asserted the previous dataclass `repr`. Constructor
and field-access behavior are unchanged. Caller-supplied `X-Amzn-RequestId` is
reserved.

The new action-result field defaults to an empty tuple, so existing
constructors remain source compatible. Local action evidence serialization is
unchanged. Alpha configurations that attempted to supply `X-Amzn-RequestId` as
an action input are now rejected. The adapter exposes an injected clock and
transport for network-isolated deterministic tests. The single-chain and fixed
reciprocal retrieval runners compose this adapter; general cloud
orchestration remains outside the alpha.

## AWS CloudWatch Logs evidence

The built-in `CloudWatchLogsProbeAdapter` consumes an acquired
`AwsScopedIdentity` and accepts only validated `cloudWatchLogs` declarations.
It performs only `logs:FilterLogEvents`, in the target's declared region,
against the probe's exact `logGroup`. SDK endpoint URL overrides are ignored.
The SDK uses three-second connection and five-second read timeouts with at most
two attempts.

This source normalizes only `bedrockInvocation`, `providerInvocation`,
`retrievalCanary`, and `telemetryCanary`. Bedrock and retrieval observations
carry their own opaque comparison declarations, and a telemetry-canary probe
carries its own explicit environment reference:

```yaml
type: cloudWatchLogs
actionRef: signed-request
observations:
  - bedrockInvocation
  - providerInvocation
  - retrievalCanary
  - telemetryCanary
logGroup: /aws/cai-verify/synthetic-assistant
bedrock:
  modelId:
    source: environment
    name: SYNTHETIC_BEDROCK_MODEL_ID
  modelAlias:
    source: literal
    value: synthetic-primary-model
    sensitive: false
canary:
  source: environment
  name: SYNTHETIC_TELEMETRY_CANARY
retrieval:
  baselineCanary:
    source: environment
    name: SYNTHETIC_BASELINE_CANARY
  boundaryCanary:
    source: environment
    name: SYNTHETIC_BOUNDARY_CANARY
```

Records use one fixed synthetic-application JSON format. Provider records
contain exactly `schemaVersion`, `correlationId`, `eventTime`, `eventKind`, and
`providerId`. Canary records replace `providerId` with `canary`. A version `1`
Bedrock record contains exactly `schemaVersion`, `correlationId`, `eventTime`,
`eventKind`, `invocationStatus`, `provider`, `modelId`, and `awsRegion`. It is
emitted only after a successful invocation; the provider must be exactly
`Amazon Bedrock`, the status must be `SUCCEEDED`, and the recorded region must
match the target. The adapter requires exactly one correlation ID from the
completed action and compares canaries and model IDs without returning their
values.

The fixed retrieval record contains exactly `schemaVersion`, `correlationId`,
`eventTime`, `eventKind`, `phase`, `retrievalStatus`, `scanStatus`,
`retrievedItemCount`, and `canaries`. The instrumented application emits it
once, after assembling and completely scanning the final retrieval context and
before model invocation. Phase must be `PRE_GENERATION`; retrieval must be
`SUCCEEDED`; and scanning must be `COMPLETE`. The two canaries are pre-seeded
synthetic data: the baseline belongs in a relevant document the requester is
intended to retrieve, and the boundary canary belongs in a similarly relevant
document across the intended data boundary. The probe never creates, changes,
or deletes those documents.

Time proximity, AWS request IDs, region, account, log group, event kind, and
another probe cannot replace the action's single exact application
correlation. Retrieval lookup covers the complete action interval plus
configured clock skew. If freshness or the ten-minute maximum would truncate
that interval, the probe fails closed before creating a client.

Collection is limited to 15 seconds, five pages, 100 examined events, 4 KiB per
message, 128 KiB of message text, one accepted Bedrock invocation, one accepted
retrieval record, 10,000 retrieved items, 32 retrieval markers, 1 KiB per
marker, 3 KiB of marker bytes, 1 KiB per environment-backed retrieval canary,
32 normalized provider identifiers, one 64-byte model alias, a 2 KiB
internally compared model ID, and 8 KiB pagination tokens. The SDK asks for 101
events to detect an over-limit response. Pagination, duplicate handling,
provider ordering, observations, and failure categories are deterministic.

Malformed, stale, future-dated, ambiguous, oversized, or partial data
suppresses Bedrock, provider, retrieval, and canary positives. Bedrock
observations contain only a zero-or-one accepted count, provider/model/region
match booleans, an optional explicitly non-sensitive alias, bounded state
flags, and a stable failure category. Retrieval observations contain only
completion and state facts,
bounded counts, nullable canary-presence and item-count facts, state flags, and
one stable failure category. Incomplete retrieval evidence uses `null` for
canary presence and item count rather than treating unknown as absent. Raw log
messages, model IDs and ARNs, canary values, prompts, queries, responses,
retrieved content, documents, credentials, environment values, correlations,
account IDs, principal ARNs, and SDK diagnostics are discarded.

CloudWatch telemetry is independently meaningful relative to action
configuration and SigV4 metadata because the fixed Bedrock record reports the
model argument and region used by the instrumented application after the
invocation. It is still application-reported evidence, so a compromised target
can emit false telemetry. The adapter normalizes facts only; it does not add a
Bedrock or retrieval assertion evaluator or decide compliance. Retrieval
records have the same trust limitation: a compromised or incorrectly
instrumented target can emit false records, and `PRE_GENERATION` is not
cryptographically proven. Model output, refusal, or silence cannot prove what
the final retrieval context contained.

Only the diagnostic single-chain runner and fixed reciprocal public-alpha
runner compose this probe. General AWS suite orchestration remains out of
scope.

## Paired-canary retrieval-boundary evaluation

The built-in `RetrievalBoundaryEvaluator` consumes only the existing normalized
`retrievalCanary` observation from `aws-cloudwatch-logs` version `1.2.0`. It
does not resolve environment references, repeat canary comparisons, inspect raw
telemetry or retrieved content, acquire credentials, or contact AWS.

The strict assertion declaration contains only fixed references:

```yaml
type: retrievalBoundary
actionRef: retrieve-as-requester-a
probeRef: requester-a-retrieval
```

A `PASS` requires fresh action and probe evidence, exactly one action
correlation and normalized retrieval record, complete pre-generation context
scanning, successful retrieval and action execution, the baseline canary
present, the declared boundary canary absent, and no undeclared marker. A fresh
complete declared boundary canary is a `FAIL`, even when the baseline is absent
or the application action later reports denial or error. Missing baselines,
undeclared markers, denials, stale/partial/ambiguous evidence, and unexercised
positive controls are `INCONCLUSIVE`; invalid or contradictory normalized
shapes and action execution errors without a boundary contradiction are
`ERROR`.

Results contain only bounded booleans, counts, normalized state, fixed reasons,
safe evidence IDs, and mandatory trust limitations. They never include canary
or environment values, raw telemetry, retrieved content, document, tenant,
identity, correlation, account or principal identifiers, credentials, prompts,
responses, or SDK diagnostics.

The committed
`tests/fixtures/suites/valid/reciprocal-retrieval.yaml` fixture defines
requester A, requester B, and a separate evidence-reader identity. It reverses
the baseline and boundary canaries for the two requesters and drives
network-isolated isolated/vulnerable evaluator contract tests. The fixture
does not execute AWS by itself. The diagnostic runner can select one assertion
from an equivalent validated runtime JSON suite; the reciprocal runner
orchestrates exactly both reversed assertions and aggregates their existing
statuses. There is no cross-action aggregate assertion.

## AWS CloudTrail audit evidence

The built-in `CloudTrailProbeAdapter` consumes an acquired
`AwsScopedIdentity`, accepts only a validated `cloudTrail` declaration
requesting `auditEvent`, and performs only regional
`cloudtrail:LookupEvents`. It ignores SDK endpoint URL overrides and uses the
same three-second connection, five-second read, and two-attempt client policy as
the other AWS adapters. It does not use the AWS CLI, CloudTrail Lake, trail
files, S3, Athena, or another CloudTrail API.

CloudTrail `LookupEvents` accepts only one lookup attribute. The adapter
therefore submits one exact `EventSource` attribute, then applies fixed local
checks for the declared event names, target region and account, consistent
outer/inner event IDs and times, and the action's single AWS request ID against
CloudTrail's fixed `requestID` field. It never treats time, source, name,
account, principal, region, another probe, or assertion input as correlation.
Missing, multiple, contradictory, or unmatched request IDs fail closed.

The lookup window is the action time plus or minus configured clock skew,
clipped by collection time and the effective probe-level or suite-level
freshness limit. Collection is limited to 15 seconds, a ten-minute maximum
window, five pages, 100 examined events, 64 KiB per `CloudTrailEvent`, 256 KiB
total event JSON, 32 accepted correlated events, 16 normalized event names, and
8 KiB pagination tokens. Each SDK request asks for 33 records, one beyond the
accepted correlated-event limit.

Malformed, duplicate-key, stale, future-dated, oversized, conflicting,
ambiguous, or partial evidence suppresses counts, event names, source/region
matches, and every other positive fact. Normalized output contains only bounded
counts, booleans, sorted event names, and a stable failure category. Raw
`CloudTrailEvent` JSON, request/response elements, identities, resources,
accounts, principals, addresses, user agents, credentials, environment values,
request IDs, and SDK diagnostics are discarded.

`LookupEvents` exposes recent CloudTrail event history, not CloudTrail Lake or
trail-file data. In particular, an application action recorded only as a data
event may not be available through this API; the result is missing evidence,
never a positive audit fact. `encryptionState` and every observation other than
`auditEvent` are unsupported because an event's existence, TLS, a KMS event
name, or service defaults cannot prove a narrowly defined encryption state.
The probe normalizes facts only and does not evaluate an assertion.

## Evidence runs

`cai_verify.evidence.create_run_directory` exclusively creates a run below a
configured root. `RunDirectory.write_evidence` accepts exact bytes plus a media
type and sensitivity classification. `RunDirectory.finalize_manifest` hashes
the stored bytes, checks the complete run inventory, and atomically creates the
canonical `manifest.json` last. Finalized runs cannot be reopened or
overwritten through the writer.

`cai_verify.evidence.verify_run_integrity` performs read-only offline checks for
the strict manifest schema, unsafe links and filesystem objects, missing or
unexpected files, sizes, and SHA-256 digests. Successful verification means the
unsigned bundle is internally consistent; it does not authenticate who created
the bundle. Writing and verification share bounded schema and I/O limits: 8 MiB
manifests, 10,000 artifacts, 64 MiB per artifact, and 512 MiB of artifact bytes
per run. Signing is intentionally not implemented yet.

The reciprocal AWS path uses fixed allowlist serializers for its exact
built-in action and retrieval-probe contracts. It never serializes generic
adapter objects, reflected fields, arbitrary redacted wrappers, arbitrary
adapter limitations, or exception strings. Verify a completed reciprocal run
without AWS access:

```console
cai-verify verify-evidence .cai-verify/runs/RUN_ID --report json
```

Tampering detection is integrity, not authenticity. Without a signature, key,
trust root, or independently trusted execution environment, an attacker who
can replace the complete bundle can produce a different internally consistent
unsigned bundle.

## Local synthetic demonstration

The committed suite uses only synthetic data and the standard-library loopback
HTTP server. Secure mode records an event label rather than request content;
vulnerable mode intentionally records the synthetic prompt so
`telemetry.canary-absent` fails. Both modes emit a pseudonymous correlated audit
event. No external model, cloud API, or internet access is used.

```console
uv run cai-verify run-local examples/local/synthetic-suite.json \
  --mode secure --run-id local-secure --evidence-root .cai-verify/runs
```

The secure command exits `0`. The same suite in vulnerable mode exits `1` and
reports only the canary-absence assertion as failed:

```console
uv run cai-verify run-local examples/local/synthetic-suite.json \
  --mode vulnerable --run-id local-vulnerable --evidence-root .cai-verify/runs
```

Use `--report json` for canonical JSON on standard output. Every run stores both
report formats, normalized action and probe evidence, individual assertion
results, and a finalized manifest. Verify the bundle offline with:

```console
uv run cai-verify verify-evidence .cai-verify/runs/local-secure --report json
```

Integrity verification exits `0` for an internally consistent unsigned bundle
and `2` for a missing, malformed, or modified artifact. It detects tampering but
does not authenticate who produced the evidence.

## Public-alpha release validation

Automated tests are deliberately network-isolated. A protected manual live-AWS
run in a dedicated synthetic sandbox is mandatory before describing a release
as publicly validated. The gate must demonstrate an isolated reciprocal
`PASS`, an intentionally vulnerable reciprocal `FAIL`, real CloudWatch
propagation, exact account/partition/region/identity/endpoint/log-group
authorization, bounded runtime, redacted output and artifacts, and successful
offline verification.

Until that protected run is recorded, the implementation may be described as
code-complete with live validation pending. Mocked or injected transports,
schema validation, and offline evidence verification do not satisfy this
gate.

## Requirements

- [uv](https://docs.astral.sh/uv/) 0.11.19 or a compatible 0.11 release
- GNU Make
- Python 3.14 (uv can install the version selected by `.python-version`)
- Node 22.12 or newer for front-end contributors only; packaged-console
  operators do not need Node

## Local setup

Create the locked Python and front-end development environments:

```console
make sync
```

Run the CLI in the managed environment:

```console
uv run cai-verify version
```

To invoke `cai-verify` directly, activate the environment first:

```console
source .venv/bin/activate
cai-verify version
```

Run the complete local quality gate:

```console
make check
```

The test configuration disables socket access by default. The local synthetic
integration tests permit only `127.0.0.1`; no normal test can reach the
internet or AWS.

## Development commands

| Command          | Purpose                                                        |
| ---------------- | -------------------------------------------------------------- |
| `make format`    | Format Python, Markdown, and front-end sources                 |
| `make lint`      | Check Python formatting and lint rules                         |
| `make typecheck` | Run mypy in strict mode                                        |
| `make test`      | Run pytest with network access disabled                        |
| `make docs`      | Check Markdown formatting                                      |
| `make ui-build`  | Rebuild the UI and compare it with committed packaged assets   |
| `make build`     | Build and validate the source and wheel artifacts              |
| `make audit`     | Audit locked Python and npm dependencies                       |
| `make check`     | Run Python/UI lint, types, tests, docs, and package validation |

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
