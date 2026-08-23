# Disposable AWS reference target

This repository-only fixture removes the largest onboarding obstacle for the
reciprocal retrieval workflow: it creates one small, deterministic AWS target
and generates the exact matching suite and execution policy.

It is a synthetic security-test fixture, not a production RAG application. It
uses API Gateway, Lambda, DynamoDB, CloudWatch Logs, and IAM. It deliberately
does not use Bedrock, S3, a vector database, a model, or generated text.

The fixture has two deploy-time modes:

- `isolated`: requester A retrieves only document A and requester B retrieves
  only document B, so the expected reciprocal result is `PASS`/`PASS`;
- `vulnerable`: both requesters retrieve both documents, so the expected result
  is `FAIL`/`FAIL`.

Neither outcome establishes universal isolation, DynamoDB row isolation,
production readiness, or compliance. The Lambda can read both synthetic
documents; this fixture tests only its fixed context-selection behavior and
the verifier's end-to-end evidence path.

## Safety boundary

Use a dedicated, non-production AWS account or an otherwise isolated personal
sandbox. Do not deploy this stack into an account that contains production
data or workloads.

The manager:

- accepts only stack names matching `cai-verify-ref-*`, with a short bounded
  suffix;
- requires an exact account, region, stack, and typed operation confirmation
  before any AWS command;
- reads only `ACCESS_KEY_ID` and `SECRET_ACCESS_KEY` from `.env` as literal
  bounded UTF-8 data—it never sources the file;
- clears profiles, shared credentials, session tokens, web-identity,
  container, and instance-metadata credential sources from AWS CLI children;
- requires AWS CLI v2 and verifies one exact non-root IAM-user caller with
  `sts:GetCallerIdentity` before mutation;
- invokes only fixed STS, CloudFormation, and DynamoDB command shapes without a
  shell, endpoint override, profile, arbitrary template, or pass-through AWS
  arguments;
- structurally compares the deployed original template with the bundled fixed
  template before every existing-stack update or deletion;
- places canaries only in a temporary mode-`0600` seed file and the disposable
  DynamoDB table; and
- writes only `suite.json` and `execution-policy.json`, in a mode-`0700`
  directory with mode-`0600` files.

Credentials and canaries are never printed or written into generated
configuration. AWS account IDs, role ARNs, the endpoint, and log-group name are
necessarily present in the private generated configuration.

The `.env` credential form exists for this local reference workflow because
that is the operator source currently in use. Long-lived IAM-user access keys
are not the preferred general AWS deployment model. Keep this user limited to
the dedicated sandbox, rotate or remove its keys after testing, and move a
future protected release gate to approved short-lived credentials or OIDC.

## What is deployed

- one regional REST API with exactly one `AWS_IAM`-authorized `POST /retrieve`
  method and no CORS, API key, custom domain, cache, tracing, access-body log,
  or public Lambda URL;
- one bounded Python 3.14 Lambda with 128 MiB and a ten-second timeout;
- one on-demand DynamoDB table containing exactly two synthetic documents;
- one one-day CloudWatch log group and one fixed evidence stream;
- requester A and B roles, each with only `execute-api:Invoke` on the exact
  API/stage/method/path;
- one evidence-reader role with only `logs:FilterLogEvents` on the exact log
  group; and
- one Lambda role with only `dynamodb:GetItem` on the exact table and
  `logs:PutLogEvents` on the exact stream.

The three verifier roles trust only the exact IAM user proven from `.env`, and
each trust policy requires the exact session name generated into the suite.
They have deterministic names derived from the confirmed stack name. The
requester roles cannot read logs, the evidence role cannot invoke the API, and
none of them can assume another verifier role.

The deployment IAM user still needs separately controlled setup permission to
create, update, seed, and delete these fixed CloudFormation resources, plus
`sts:AssumeRole` permission for the three deterministic verifier role ARNs.
Keep setup authority separate or temporary where possible. The stack's trust
policies do not grant identity-policy permission to that user by themselves.

## 1. Check locally

Install the project with both operator extras, plus AWS CLI v2 for the operator-only
deployment wrapper. AWS CLI is not a `cai-verify` runtime dependency.

```console
uv sync --all-extras --dev
uv run python -m examples.aws.reference_target.manager check
```

`check` composes and validates the fixed template locally. It does not read
`.env`, open a socket, or invoke AWS.

## 2. Prepare synthetic values

The manager accepts exactly this unquoted `.env` shape:

```dotenv
ACCESS_KEY_ID=replace-with-the-dedicated-sandbox-user-access-key
SECRET_ACCESS_KEY=replace-with-the-dedicated-sandbox-user-secret-key
```

Do not add a profile, session token, shell expression, quote, `export`, or
other key. Keep `.env` mode `0600` and outside version control. The manager
rejects a credential file owned by another user or readable by group/other;
set the mode explicitly before use:

```console
chmod 600 .env
```

In the same terminal that will deploy and run the verifier, enter distinct
ASCII synthetic canaries without echoing them:

```console
read -r -s 'CAI_REQUESTER_A_CANARY?Requester A synthetic canary: '
export CAI_REQUESTER_A_CANARY
read -r -s 'CAI_REQUESTER_B_CANARY?Requester B synthetic canary: '
export CAI_REQUESTER_B_CANARY
```

Each canary must contain 16–128 letters, digits, underscores, or hyphens. They
are synthetic markers, not credentials or real data. The manager refuses to
generate, persist locally, or display them.

## 3. Deploy isolated mode

Choose the exact dedicated sandbox account and one declared region. This is a
real mutating AWS operation. Review the account, region, and stack before
typing the confirmation shown by the manager.

```console
uv run python -m examples.aws.reference_target.manager deploy \
  --account-id 111122223333 \
  --region eu-west-2 \
  --stack-name cai-verify-ref-sandbox \
  --mode isolated \
  --env-file .env \
  --output-dir .cai-verify/reference-target
```

The operation checks AWS CLI v2, proves the exact IAM user and account, deploys
the fixed template, validates all stack outputs, atomically seeds both
documents, and generates:

```text
.cai-verify/reference-target/suite.json
.cai-verify/reference-target/execution-policy.json
```

It does not run the verifier or claim that the live gate passed.

If CloudFormation succeeds but document seeding or local configuration writing
fails, the manager reports a redacted failure and leaves the confirmed stack
in place. Do not assume rollback occurred. Fix the local problem and rerun the
same exact deploy command, or run the exact `destroy` command in section 6.

If deployment fails or rolls back, wait for CloudFormation to reach a terminal
state before using `destroy`. A complete stack must still expose the entire
fixed ownership/output contract. A failed terminal stack can be removed only
when its original deployed template structurally equals the bundled template
and its fixed `Project`, `Environment`, and `Purpose` ownership tags are still
present. In-progress, malformed, retagged, or different-template stacks fail
closed. If this recovery check refuses deletion, do not bypass it by changing
the manager; inspect and resolve the stack separately under the dedicated
sandbox account's normal administrative recovery procedure.

## Cost and cleanup

This fixture uses low-volume, on-demand API Gateway, Lambda, DynamoDB, and
CloudWatch Logs resources, but it is not guaranteed to be free. Before
deployment, configure an account budget and billing alarm appropriate for your
sandbox. The `ExpiresOn` tag is only an operator-visible cleanup reminder; it
does not schedule or perform deletion. Destroy the stack promptly after the
isolated and vulnerable runs, then verify that CloudFormation reports the
stack deleted.

The Lambda intentionally does not reserve function concurrency. Some new or
low-quota sandbox accounts enforce an unreserved-concurrency floor of ten and
reject any function reservation. Only the exact IAM-authenticated API Gateway
route can invoke this function, and that stage retains the fixed two-request-
per-second rate and four-request burst limits. This preserves a bounded test
ingress without requiring an account-level quota increase. Do not leave the
fixture deployed as a general service.

Deploy and destroy print only fixed progress stages and stable failure
categories. Raw AWS CLI output remains suppressed because it can contain
account identifiers, ARNs, resource names, request IDs, local paths, and SDK
diagnostics. The most recently printed stage identifies where a redacted
failure occurred.

## 4. Run the existing workflow

The AWS SDK recognizes `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`, while
the repository `.env` intentionally uses different local names. For direct CLI
use, map only those two already-validated values into the process environment
using an approved credential-aware launcher without sourcing the file. Do not
print the values or place them on a command line.

For the CLI:

```console
cai-verify doctor retrieval .cai-verify/reference-target/suite.json \
  --execution-policy .cai-verify/reference-target/execution-policy.json

cai-verify run-aws-reciprocal-retrieval \
  .cai-verify/reference-target/suite.json \
  --scenario-id reciprocal-requester-retrieval \
  --execution-policy .cai-verify/reference-target/execution-policy.json \
  --run-id reference-isolated-001 \
  --evidence-root .cai-verify/runs
```

For the local console, the manager provides that fixed credential-contained
launcher. It validates the generated account, region, deterministic roles, and
execution policy, requires one `LAUNCH` confirmation, then replaces itself
with the existing loopback console. It always disables automatic browser
launch so no browser process can inherit the AWS/canary environment: copy the
printed one-use loopback URL into your browser manually. It neither calls AWS
before launch nor passes credentials or canaries in process arguments.

```console
uv run python -m examples.aws.reference_target.manager ui \
  --account-id 111122223333 \
  --region eu-west-2 \
  --stack-name cai-verify-ref-sandbox \
  --env-file .env \
  --config-dir .cai-verify/reference-target \
  --evidence-root .cai-verify/runs
```

Upload the two generated JSON files. Readiness and execution repeat all exact
account, partition, region, endpoint, role, and log-source checks.

The verifier never reads `.env` itself. This is intentional credential
containment: the target manager owns its exact AWS CLI children and console
process, while the verifier continues to use the standard Boto3 credential
environment. Clear any values you exported when finished:

```console
unset ACCESS_KEY_ID SECRET_ACCESS_KEY AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
unset CAI_REQUESTER_A_CANARY CAI_REQUESTER_B_CANARY
```

## 5. Switch to vulnerable mode

Use the same exact account, region, stack, canaries, and output directory. The
deploy-time mode cannot be selected by an application request. `--replace`
allows the manager to stage and replace the same private contract files after
the stack update; the contract bytes do not depend on mode.

```console
uv run python -m examples.aws.reference_target.manager deploy \
  --account-id 111122223333 \
  --region eu-west-2 \
  --stack-name cai-verify-ref-sandbox \
  --mode vulnerable \
  --env-file .env \
  --output-dir .cai-verify/reference-target \
  --replace
```

Run the reciprocal workflow with a new safe run ID. Both directions should be
`FAIL`; a missing, late, malformed, or ambiguous record remains
`INCONCLUSIVE` or `ERROR`, never a pass or expected vulnerable fail.

## 6. Verify evidence and destroy

Verify each finalized evidence bundle offline using the existing command:

```console
cai-verify verify-evidence .cai-verify/runs/reference-isolated-001 \
  --report json
```

Then delete only the exact confirmed stack:

```console
uv run python -m examples.aws.reference_target.manager destroy \
  --account-id 111122223333 \
  --region eu-west-2 \
  --stack-name cai-verify-ref-sandbox \
  --env-file .env
```

Destroy removes the API, Lambda, table, log group, stream, and roles and waits
for CloudFormation deletion. It does not delete local configuration or
evidence. Confirm deletion in the dedicated sandbox and apply your normal
credential-rotation and local-retention procedures.

## Known live assumptions

All repository tests are socket-disabled and use synthetic clients. A
protected live run must still establish two AWS behaviors that mocks cannot:

1. API Gateway supplies the IAM caller ARN in the exact fail-closed form the
   handler expects.
1. A synchronously accepted `PutLogEvents` record becomes visible to
   `FilterLogEvents` within the probe's fixed evidence-only polling bound.

The probe repeats only a complete empty lookup for the same exact correlation
on a fixed 1, 2, 4, 4-second schedule. Pagination and polling share the existing
five-page and 15-second collection bounds. It never repeats an application
action, changes the correlation or window, or retries malformed, partial,
ambiguous, stale, future-dated, oversized, identity-invalid, or SDK-failure
results. Persistent absence remains `INCONCLUSIVE`, never `PASS`.
