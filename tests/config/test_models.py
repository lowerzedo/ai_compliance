"""Tests for strict verification-suite schema version ``1alpha1``."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import pytest
import yaml
from pydantic import ValidationError

from cai_verify.config import (
    ApplicationStatusAssertion,
    AuditEventPresentAssertion,
    AuditPrincipalCorrelatedAssertion,
    AwsSigV4Action,
    BedrockInvocationDeclaration,
    CloudTrailProbe,
    CloudWatchLogsProbe,
    HttpAction,
    LocalTelemetryProbe,
    RetrievalCanaryDeclaration,
    SafeModelAlias,
    SyntheticLocalIdentity,
    TelemetryCanaryAbsentAssertion,
    VerificationSuite,
    verification_suite_json_schema,
)

_FIXTURES = Path(__file__).parents[1] / "fixtures" / "suites"
_VALID_SUITE = _FIXTURES / "valid" / "full.yaml"
_SCHEMA_PATH = (
    Path(__file__).parents[2] / "schemas" / "verification-suite-1alpha1.schema.json"
)
_LOCAL_SUITE = Path(__file__).parents[2] / "examples/local/synthetic-suite.json"
_EXPECTED_UNKNOWN_FIELD_ERRORS = 2
_ENVIRONMENT = {
    "CAI_VERIFY_AWS_PROFILE": "readonly-profile",
    "CAI_VERIFY_EXTERNAL_ID": "external-id-value",
    "SYNTHETIC_APP_TOKEN": "literal-app-secret-must-not-leak",
    "SYNTHETIC_TELEMETRY_CANARY": "literal-canary-must-not-leak",
}

type SuiteMapping = dict[str, Any]


def _load_mapping(path: Path = _VALID_SUITE) -> SuiteMapping:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return cast("SuiteMapping", loaded)


def _validation_message(data: SuiteMapping) -> str:
    with pytest.raises(ValidationError) as caught:
        VerificationSuite.model_validate(data)
    return str(caught.value)


def test_full_yaml_fixture_validates_all_supported_component_kinds() -> None:
    """The valid fixture exercises every alpha action, probe, and assertion kind."""
    suite = VerificationSuite.model_validate(_load_mapping())
    scenario = suite.scenarios[0]

    assert suite.schema_version == "1alpha1"
    assert {type(action) for action in scenario.actions} == {
        HttpAction,
        AwsSigV4Action,
    }
    assert {type(probe) for probe in scenario.probes} == {
        CloudWatchLogsProbe,
        CloudTrailProbe,
    }
    assert {assertion.type for assertion in scenario.assertions} == {
        "unauthorizedIdentityDenied",
        "providerBoundary",
        "telemetryCanary",
        "auditCorrelation",
        "encryption",
    }


def test_local_json_fixture_validates_only_explicit_synthetic_components() -> None:
    """The local slice adds no cloud identity, probe, or action execution path."""
    loaded = json.loads(_LOCAL_SUITE.read_bytes())
    suite = VerificationSuite.model_validate(loaded)
    scenario = suite.scenarios[0]

    assert type(suite.identities[0]) is SyntheticLocalIdentity
    assert type(scenario.actions[0]) is HttpAction
    assert type(scenario.probes[0]) is LocalTelemetryProbe
    assert {type(assertion) for assertion in scenario.assertions} == {
        ApplicationStatusAssertion,
        TelemetryCanaryAbsentAssertion,
        AuditEventPresentAssertion,
        AuditPrincipalCorrelatedAssertion,
    }
    assert suite.target.aws_region is None
    assert suite.target.aws_account_id is None


def test_local_components_cannot_be_mixed_with_cloud_targets() -> None:
    """Local identities and telemetry never silently expand a cloud suite."""
    loaded = json.loads(_LOCAL_SUITE.read_bytes())
    loaded["target"].update(
        {
            "awsAccountId": "111122223333",
            "awsRegion": "eu-west-2",
            "endpoint": "https://example.test",
            "environment": "sandbox",
        },
    )
    loaded["target"]["allowedHosts"] = ["example.test"]

    message = _validation_message(cast("SuiteMapping", loaded))

    assert "syntheticLocal identities require a local target" in message


def test_cloud_target_requires_an_explicit_account_boundary() -> None:
    """Cloud execution cannot proceed without an expected AWS account."""
    data = _load_mapping()
    data["target"].pop("awsAccountId")

    assert "must declare awsRegion and awsAccountId" in _validation_message(data)


@pytest.mark.parametrize(
    "fixture_path",
    sorted((_FIXTURES / "invalid").glob("*.yaml")),
    ids=lambda path: path.stem,
)
def test_invalid_yaml_fixtures_are_rejected(fixture_path: Path) -> None:
    """Files containing forbidden execution languages never enter the model."""
    message = _validation_message(_load_mapping(fixture_path))

    assert "Unable to extract tag" in message or "union_tag_invalid" in message


def test_unknown_fields_are_rejected_at_every_model_boundary() -> None:
    """An extension-looking field cannot be silently ignored."""
    data = _load_mapping()
    data["metadata"]["unexpected"] = True
    data["scenarios"][0]["actions"][0]["retryScript"] = "do-something"

    message = _validation_message(data)

    assert (
        message.count("Extra inputs are not permitted")
        == _EXPECTED_UNKNOWN_FIELD_ERRORS
    )


def test_field_names_and_scalar_types_are_not_coerced() -> None:
    """Only the documented camel-case surface and scalar types are accepted."""
    snake_case = _load_mapping()
    snake_case["schema_version"] = snake_case.pop("schemaVersion")
    wrong_scalar = _load_mapping()
    wrong_scalar["scenarios"][0]["actions"][0]["timeoutSeconds"] = "15"

    assert "schemaVersion" in _validation_message(snake_case)
    assert "valid integer" in _validation_message(wrong_scalar)


@pytest.mark.parametrize(
    ("collection", "expected_kind"),
    [
        ("actions", "action id"),
        ("probes", "probe id"),
        ("assertions", "assertion id"),
    ],
)
def test_duplicate_scenario_component_ids_are_rejected(
    collection: str,
    expected_kind: str,
) -> None:
    """Scenario-local references never have ambiguous component targets."""
    data = _load_mapping()
    components = data["scenarios"][0][collection]
    components.append(deepcopy(components[0]))

    message = _validation_message(data)

    assert f"duplicate {expected_kind}" in message


@pytest.mark.parametrize("collection", ["identities", "scenarios"])
def test_duplicate_top_level_ids_are_rejected(collection: str) -> None:
    """Top-level identity and scenario reference namespaces are unique."""
    data = _load_mapping()
    data[collection].append(deepcopy(data[collection][0]))

    assert "duplicate" in _validation_message(data)


def test_component_ids_are_unique_across_scenarios() -> None:
    """Evidence-facing component IDs use a suite-wide namespace."""
    data = _load_mapping()
    second_scenario = deepcopy(data["scenarios"][0])
    second_scenario["id"] = "second-scenario"
    data["scenarios"].append(second_scenario)

    assert "duplicate action id across suite" in _validation_message(data)


@pytest.mark.parametrize(
    ("reference_owner", "missing_name"),
    [
        ("scenario", "missing-scenario-identity"),
        ("action", "missing-action-identity"),
        ("probe", "missing-probe-identity"),
    ],
)
def test_missing_identity_references_are_rejected(
    reference_owner: str,
    missing_name: str,
) -> None:
    """Every component identity reference resolves before planning."""
    data = _load_mapping()
    scenario = data["scenarios"][0]
    if reference_owner == "scenario":
        scenario["identityRef"] = missing_name
    elif reference_owner == "action":
        scenario["actions"][0]["identityRef"] = missing_name
    else:
        scenario["probes"][0]["identityRef"] = missing_name

    message = _validation_message(data)

    assert "references missing identities" in message
    assert missing_name in message


@pytest.mark.parametrize(
    "freshness",
    ["5m", "P1D", "PT0S", "PT60M", "PT24H1S", "-PT5M", 300],
)
def test_invalid_evidence_freshness_is_rejected(freshness: object) -> None:
    """Freshness is a positive, bounded, canonical ISO-8601 duration."""
    data = _load_mapping()
    data["evidencePolicy"]["maxAge"] = freshness

    message = _validation_message(data)

    assert "maxAge" in message


def test_invalid_probe_freshness_override_is_rejected() -> None:
    """Probe-specific freshness uses the same conservative bounds."""
    data = _load_mapping()
    data["scenarios"][0]["probes"][0]["maxAge"] = "PT25H"

    assert "no longer than PT24H" in _validation_message(data)


def test_cloudwatch_canary_requires_only_an_environment_reference() -> None:
    """Telemetry canary collection has one explicit secret-safe source."""
    missing = _load_mapping()
    missing["scenarios"][0]["probes"][0].pop("canary")
    literal = _load_mapping()
    literal["scenarios"][0]["probes"][0]["canary"] = (
        "literal-canary-must-not-be-accepted"
    )

    assert "requires a canary reference" in _validation_message(missing)
    assert "Input should be a valid dictionary" in _validation_message(literal)


def test_cloudwatch_canary_probe_and_assertion_must_match() -> None:
    """A canary assertion cannot silently describe another probe value."""
    data = _load_mapping()
    data["scenarios"][0]["probes"][0]["canary"]["name"] = "DIFFERENT_SYNTHETIC_CANARY"

    assert "must match the action, observation, and canary" in _validation_message(
        data,
    )


def test_cloudwatch_probe_rejects_unsupported_observation_kinds() -> None:
    """The schema advertises only the four fixed CloudWatch record kinds."""
    data = _load_mapping()
    data["scenarios"][0]["probes"][0]["observations"].append("auditEvent")

    assert (
        "supports bedrockInvocation, providerInvocation, retrievalCanary, "
        "and telemetryCanary only" in _validation_message(data)
    )


def test_provider_only_cloudwatch_probe_does_not_require_a_canary() -> None:
    """Provider normalization remains usable without a canary environment value."""
    probe = CloudWatchLogsProbe.model_validate(
        {
            "actionRef": "signed-request",
            "id": "provider-only",
            "logGroup": "/aws/cai-verify/provider-only",
            "observations": ["providerInvocation"],
            "type": "cloudWatchLogs",
        },
    )

    assert probe.canary is None
    assert probe.bedrock is None


def test_bedrock_observation_requires_only_its_explicit_declaration() -> None:
    """Bedrock model comparison is environment-backed and probe-owned."""
    missing = _load_mapping()
    probe = missing["scenarios"][0]["probes"][0]
    probe["observations"].append("bedrockInvocation")
    literal_model = deepcopy(missing)
    literal_model["scenarios"][0]["probes"][0]["bedrock"] = {
        "modelId": "synthetic.foundation-model-v1",
    }
    unrelated = _load_mapping()
    unrelated["scenarios"][0]["probes"][0]["bedrock"] = {
        "modelId": {
            "name": "SYNTHETIC_BEDROCK_MODEL_ID",
            "source": "environment",
        },
    }

    assert "requires a bedrock declaration" in _validation_message(missing)
    assert "Input should be a valid dictionary" in _validation_message(literal_model)
    assert "valid only when bedrockInvocation is requested" in _validation_message(
        unrelated
    )


@pytest.mark.parametrize(
    "alias",
    [
        "arn-tenant-model",
        "account-primary",
        "tenant-primary",
        "model-111122223333",
        "A-uppercase-alias",
        "a" * 65,
    ],
)
def test_bedrock_model_alias_is_explicitly_safe_and_bounded(alias: str) -> None:
    """Obvious raw identifiers cannot use the optional normalized alias channel."""
    data = _load_mapping()
    probe = data["scenarios"][0]["probes"][0]
    probe["observations"].append("bedrockInvocation")
    probe["bedrock"] = {
        "modelAlias": {
            "sensitive": False,
            "source": "literal",
            "value": alias,
        },
        "modelId": {
            "name": "SYNTHETIC_BEDROCK_MODEL_ID",
            "source": "environment",
        },
    }

    assert "modelAlias" in _validation_message(data)


def test_bedrock_declaration_and_alias_are_strict_models() -> None:
    """The public declaration has no expression or arbitrary mapping surface."""
    declaration = BedrockInvocationDeclaration.model_validate(
        {
            "modelAlias": {
                "sensitive": False,
                "source": "literal",
                "value": "synthetic-primary-model",
            },
            "modelId": {
                "name": "SYNTHETIC_BEDROCK_MODEL_ID",
                "source": "environment",
            },
        },
    )

    assert isinstance(declaration.model_alias, SafeModelAlias)
    assert declaration.model_alias.value == "synthetic-primary-model"
    with pytest.raises(ValidationError):
        BedrockInvocationDeclaration.model_validate(
            {
                "modelId": {
                    "expression": "$.request.modelId",
                    "name": "SYNTHETIC_BEDROCK_MODEL_ID",
                    "source": "environment",
                },
            },
        )


def test_retrieval_observation_requires_only_paired_environment_references() -> None:
    """Retrieval canaries are probe-owned references with no literal channel."""
    missing = _load_mapping()
    probe = missing["scenarios"][0]["probes"][0]
    probe["observations"].append("retrievalCanary")
    bare = deepcopy(missing)
    bare["scenarios"][0]["probes"][0]["retrieval"] = {
        "baselineCanary": "synthetic-baseline-marker",
        "boundaryCanary": "synthetic-boundary-marker",
    }
    literal = deepcopy(missing)
    literal["scenarios"][0]["probes"][0]["retrieval"] = {
        "baselineCanary": {
            "sensitive": False,
            "source": "literal",
            "value": "synthetic-baseline-marker",
        },
        "boundaryCanary": {
            "name": "SYNTHETIC_BOUNDARY_CANARY",
            "source": "environment",
        },
    }
    unrelated = _load_mapping()
    unrelated["scenarios"][0]["probes"][0]["retrieval"] = {
        "baselineCanary": {
            "name": "SYNTHETIC_BASELINE_CANARY",
            "source": "environment",
        },
        "boundaryCanary": {
            "name": "SYNTHETIC_BOUNDARY_CANARY",
            "source": "environment",
        },
    }

    assert "requires a retrieval declaration" in _validation_message(missing)
    assert "Input should be a valid dictionary" in _validation_message(bare)
    assert "environment" in _validation_message(literal)
    assert "valid only when retrievalCanary is requested" in _validation_message(
        unrelated
    )


def test_retrieval_declaration_is_a_strict_fixed_model() -> None:
    """The retrieval declaration has exactly two environment references."""
    declaration = RetrievalCanaryDeclaration.model_validate(
        {
            "baselineCanary": {
                "name": "SYNTHETIC_BASELINE_CANARY",
                "source": "environment",
            },
            "boundaryCanary": {
                "name": "SYNTHETIC_BOUNDARY_CANARY",
                "source": "environment",
            },
        },
    )

    assert declaration.baseline_canary.name == "SYNTHETIC_BASELINE_CANARY"
    assert declaration.boundary_canary.name == "SYNTHETIC_BOUNDARY_CANARY"
    with pytest.raises(ValidationError):
        RetrievalCanaryDeclaration.model_validate(
            {
                "baselineCanary": {
                    "name": "SYNTHETIC_BASELINE_CANARY",
                    "source": "environment",
                },
                "boundaryCanary": {
                    "name": "SYNTHETIC_BOUNDARY_CANARY",
                    "source": "environment",
                },
                "jsonPath": "$.context.canaries",
            },
        )


def test_clock_skew_tolerance_is_bounded_separately() -> None:
    """Source clock tolerance cannot consume an evidence freshness window."""
    data = _load_mapping()
    data["evidencePolicy"]["clockSkewTolerance"] = "PT5M1S"

    assert "cannot exceed PT5M" in _validation_message(data)


def test_mutating_actions_are_semantically_unsupported() -> None:
    """Declaring mutation does not enable a capability absent from 1alpha1."""
    data = _load_mapping()
    data["scenarios"][0]["actions"][0]["mutating"] = True

    message = _validation_message(data)

    assert "mutating actions are unsupported" in message
    assert "unsigned-request" in message


@pytest.mark.parametrize(
    "location",
    ["suite", "assertion", "control-reference"],
)
def test_limitations_are_mandatory_at_every_claim_boundary(location: str) -> None:
    """Neither suites, assertions, nor mappings can omit their limitations."""
    data = _load_mapping()
    if location == "suite":
        data.pop("limitations")
    elif location == "assertion":
        data["scenarios"][0]["assertions"][0].pop("limitations")
    else:
        control_ref = data["scenarios"][0]["assertions"][0]["controlRefs"][0]
        control_ref.pop("limitations")

    message = _validation_message(data)

    assert "limitations" in message
    assert "Field required" in message


def test_sensitive_request_inputs_require_environment_references() -> None:
    """A literal cannot occupy a secret-designated request location."""
    data = _load_mapping()
    secret_input = data["scenarios"][0]["actions"][0]["inputs"][0]
    secret_input["value"] = {
        "source": "literal",
        "sensitive": False,
        "value": "plain-text-token",
    }

    message = _validation_message(data)

    assert "must use an environment reference" in message


def test_literal_inputs_require_explicit_non_sensitive_classification() -> None:
    """A public literal cannot rely on an implicit sensitivity default."""
    data = _load_mapping()
    public_value = data["scenarios"][0]["actions"][0]["inputs"][1]["value"]
    public_value.pop("sensitive")

    message = _validation_message(data)

    assert "sensitive" in message
    assert "Field required" in message


def test_credential_shaped_values_are_rejected_even_under_public_names() -> None:
    """A mislabeled AWS key cannot bypass the explicit secret source rule."""
    data = _load_mapping()
    public_input = data["scenarios"][0]["actions"][0]["inputs"][1]
    public_input["value"]["value"] = "AKIAABCDEFGHIJKLMNOP"

    assert "credential-shaped values" in _validation_message(data)


def test_secret_fields_do_not_accept_bare_environment_syntax() -> None:
    """Environment references must be typed objects rather than expressions."""
    data = _load_mapping()
    secret_input = data["scenarios"][0]["actions"][0]["inputs"][0]
    secret_input["value"] = "${SYNTHETIC_APP_TOKEN}"

    message = _validation_message(data)

    assert "Input should be a valid dictionary" in message


def test_resolved_configuration_renders_only_redacted_values() -> None:
    """Resolution validates environment availability without exposing values."""
    suite = VerificationSuite.model_validate(_load_mapping())

    rendered = suite.render_resolved_redacted(_ENVIRONMENT)

    assert rendered == suite.render_resolved_redacted(
        dict(reversed(_ENVIRONMENT.items()))
    )
    assert rendered.count("[REDACTED]") == len(_ENVIRONMENT) + 1
    assert all(secret not in rendered for secret in _ENVIRONMENT.values())
    assert "SYNTHETIC_APP_TOKEN" in rendered
    assert "resolvedValue" in rendered


def test_resolution_errors_name_references_but_never_values() -> None:
    """Missing-variable diagnostics cannot leak environment contents."""
    suite = VerificationSuite.model_validate(_load_mapping())
    incomplete = dict(_ENVIRONMENT)
    incomplete.pop("SYNTHETIC_TELEMETRY_CANARY")

    with pytest.raises(ValueError, match="SYNTHETIC_TELEMETRY_CANARY") as caught:
        suite.render_resolved_redacted(incomplete)

    assert all(secret not in str(caught.value) for secret in incomplete.values())


def test_empty_environment_values_are_not_considered_resolved() -> None:
    """An explicitly referenced secret must resolve to a non-empty string."""
    suite = VerificationSuite.model_validate(_load_mapping())
    environment = dict(_ENVIRONMENT)
    environment["SYNTHETIC_APP_TOKEN"] = ""

    with pytest.raises(ValueError, match="must not be empty"):
        suite.render_resolved_redacted(environment)


def test_missing_action_and_probe_references_are_rejected() -> None:
    """Fixed evaluators cannot reference absent scenario components."""
    missing_action = _load_mapping()
    missing_action["scenarios"][0]["probes"][0]["actionRef"] = "not-an-action"
    missing_probe = _load_mapping()
    missing_probe["scenarios"][0]["assertions"][1]["probeRef"] = "not-a-probe"

    assert "probes reference missing actions" in _validation_message(missing_action)
    assert "assertions reference missing probes" in _validation_message(missing_probe)


def test_target_endpoint_must_be_https_or_local_and_allowlisted() -> None:
    """Target URLs cannot silently expand the network boundary."""
    cleartext = _load_mapping()
    cleartext["target"]["endpoint"] = "http://assistant.sandbox.example.test"
    not_allowlisted = _load_mapping()
    not_allowlisted["target"]["endpoint"] = "https://other.example.test"

    assert "must use HTTPS" in _validation_message(cleartext)
    assert "must appear in allowedHosts" in _validation_message(not_allowlisted)


def test_target_endpoint_rejects_literal_url_credentials() -> None:
    """URL userinfo cannot become an untyped secret channel."""
    data = _load_mapping()
    data["target"]["endpoint"] = (
        "https://literal-user:literal-secret@assistant.sandbox.example.test"
    )

    assert "must not contain literal credentials" in _validation_message(data)


def test_control_mapping_has_fixed_relationship_and_all_responsibilities() -> None:
    """Suite mappings cannot claim equivalence or omit a responsible party."""
    invalid_relationship = _load_mapping()
    mapping = invalid_relationship["scenarios"][0]["assertions"][0]["controlRefs"][0]
    mapping["relationship"] = "establishes-compliance"
    missing_party = _load_mapping()
    mapping = missing_party["scenarios"][0]["assertions"][0]["controlRefs"][0]
    mapping["responsibilities"][2] = deepcopy(mapping["responsibilities"][0])

    assert "supports-assessment" in _validation_message(invalid_relationship)
    assert "must cover verifier" in _validation_message(missing_party)


def test_committed_json_schema_matches_the_authoritative_model() -> None:
    """The reviewed schema artifact cannot drift from Pydantic behavior."""
    expected = json.dumps(
        verification_suite_json_schema(),
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )

    assert _SCHEMA_PATH.read_text(encoding="utf-8") == f"{expected}\n"


def test_json_schema_forbids_extras_and_execution_language_extensions() -> None:
    """The published contract advertises strict fixed vocabularies."""
    schema = verification_suite_json_schema()
    definitions = schema["$defs"]
    serialized = json.dumps(schema, sort_keys=True)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["properties"]["schemaVersion"]["const"] == "1alpha1"
    assert schema["additionalProperties"] is False
    assert all(
        definition.get("additionalProperties") is False
        for definition in definitions.values()
        if definition.get("type") == "object"
    )
    assert '"const": "shell"' not in serialized
    assert '"expression"' not in serialized
