"""Static least-privilege tests for the fixed CloudFormation template."""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import cast

from examples.aws.reference_target.manager import render_template

_ROOT = Path(__file__).parents[2]
_TEMPLATE = _ROOT / "examples/aws/reference_target/template.json"
_HANDLER = _ROOT / "examples/aws/reference_target/handler.py"
_FUNCTION_MEMORY_MIB = 128
_FUNCTION_TIMEOUT_SECONDS = 10
_RESERVED_CONCURRENCY = 2
_API_CONTRACT_RESOURCES = ("RestApi", "RetrieveResource", "RetrieveMethod")
_EXPECTED_RESOURCE_TYPES = {
    "ApiDeploymentE067fffcfc0a": "AWS::ApiGateway::Deployment",
    "ApiInvokePermission": "AWS::Lambda::Permission",
    "ApiStage": "AWS::ApiGateway::Stage",
    "DocumentsTable": "AWS::DynamoDB::Table",
    "EvidenceLogGroup": "AWS::Logs::LogGroup",
    "EvidenceLogStream": "AWS::Logs::LogStream",
    "EvidenceReaderRole": "AWS::IAM::Role",
    "LambdaExecutionRole": "AWS::IAM::Role",
    "RequesterARole": "AWS::IAM::Role",
    "RequesterBRole": "AWS::IAM::Role",
    "RestApi": "AWS::ApiGateway::RestApi",
    "RetrievalFunction": "AWS::Lambda::Function",
    "RetrieveMethod": "AWS::ApiGateway::Method",
    "RetrieveResource": "AWS::ApiGateway::Resource",
}


def test_template_has_one_fixed_authenticated_route_and_bounded_runtime() -> None:
    """The fixture has no public or generic application execution surface."""
    template = json.loads(_TEMPLATE.read_bytes())
    resources = template["Resources"]

    assert template.get("Transform") is None
    assert template.get("Conditions") is None
    assert {
        logical_id: resource["Type"] for logical_id, resource in resources.items()
    } == _EXPECTED_RESOURCE_TYPES
    assert {
        logical_id
        for logical_id, resource in resources.items()
        if resource["Type"] == "AWS::ApiGateway::Method"
    } == {"RetrieveMethod"}
    method = resources["RetrieveMethod"]["Properties"]
    assert method["AuthorizationType"] == "AWS_IAM"
    assert method["HttpMethod"] == "POST"
    assert method["ApiKeyRequired"] is False
    assert method["Integration"]["Type"] == "AWS_PROXY"
    assert resources["RetrieveResource"]["Properties"]["PathPart"] == "retrieve"
    assert not any(
        resource["Type"]
        in {
            "AWS::ApiGatewayV2::Api",
            "AWS::Lambda::Url",
            "AWS::CloudFormation::CustomResource",
        }
        for resource in resources.values()
    )
    function = resources["RetrievalFunction"]["Properties"]
    assert function["Runtime"] == "python3.14"
    assert function["MemorySize"] == _FUNCTION_MEMORY_MIB
    assert function["Timeout"] == _FUNCTION_TIMEOUT_SECONDS
    assert function["ReservedConcurrentExecutions"] == _RESERVED_CONCURRENCY
    assert resources["EvidenceLogGroup"]["Properties"]["RetentionInDays"] == 1
    assert resources["ApiStage"]["Properties"]["TracingEnabled"] is False
    assert resources["ApiStage"]["Properties"]["MethodSettings"][0] == {
        "CachingEnabled": False,
        "DataTraceEnabled": False,
        "HttpMethod": "POST",
        "LoggingLevel": "OFF",
        "MetricsEnabled": False,
        "ResourcePath": "/~1retrieve",
        "ThrottlingBurstLimit": 4,
        "ThrottlingRateLimit": 2,
    }


def test_every_role_has_one_exact_trust_and_runtime_permission_boundary() -> None:
    """Requester, evidence, and Lambda roles cannot cross their fixed purposes."""
    resources = json.loads(_TEMPLATE.read_bytes())["Resources"]
    roles = {
        name: resource
        for name, resource in resources.items()
        if resource["Type"] == "AWS::IAM::Role"
    }
    assert set(roles) == {
        "EvidenceReaderRole",
        "LambdaExecutionRole",
        "RequesterARole",
        "RequesterBRole",
    }
    expected_actions = {
        "RequesterARole": ["execute-api:Invoke"],
        "RequesterBRole": ["execute-api:Invoke"],
        "EvidenceReaderRole": ["logs:FilterLogEvents"],
        "LambdaExecutionRole": ["dynamodb:GetItem", "logs:PutLogEvents"],
    }
    invoke_resource = {
        "Fn::Sub": (
            "arn:${AWS::Partition}:execute-api:${AWS::Region}:"
            "${AWS::AccountId}:${RestApi}/sandbox/POST/retrieve"
        )
    }
    expected_statements = {
        "RequesterARole": [
            {
                "Action": "execute-api:Invoke",
                "Effect": "Allow",
                "Resource": invoke_resource,
            }
        ],
        "RequesterBRole": [
            {
                "Action": "execute-api:Invoke",
                "Effect": "Allow",
                "Resource": invoke_resource,
            }
        ],
        "EvidenceReaderRole": [
            {
                "Action": "logs:FilterLogEvents",
                "Effect": "Allow",
                "Resource": {
                    "Fn::Sub": (
                        "arn:${AWS::Partition}:logs:${AWS::Region}:"
                        "${AWS::AccountId}:log-group:${EvidenceLogGroup}"
                    )
                },
            }
        ],
        "LambdaExecutionRole": [
            {
                "Action": "dynamodb:GetItem",
                "Effect": "Allow",
                "Resource": {"Fn::GetAtt": ["DocumentsTable", "Arn"]},
            },
            {
                "Action": "logs:PutLogEvents",
                "Effect": "Allow",
                "Resource": {
                    "Fn::Sub": (
                        "arn:${AWS::Partition}:logs:${AWS::Region}:"
                        "${AWS::AccountId}:log-group:${EvidenceLogGroup}:"
                        "log-stream:retrieval-events"
                    )
                },
            },
        ],
    }
    role_names = {
        "EvidenceReaderRole": "${AWS::StackName}-evidence-reader",
        "LambdaExecutionRole": "${AWS::StackName}-lambda",
        "RequesterARole": "${AWS::StackName}-requester-a",
        "RequesterBRole": "${AWS::StackName}-requester-b",
    }
    for name, role in roles.items():
        properties = role["Properties"]
        assert properties.get("ManagedPolicyArns") is None
        assert properties["RoleName"] == {"Fn::Sub": role_names[name]}
        statements = [
            statement
            for policy in properties["Policies"]
            for statement in policy["PolicyDocument"]["Statement"]
        ]
        assert statements == expected_statements[name]
        actions = [cast("str", statement["Action"]) for statement in statements]
        assert actions == expected_actions[name]
        assert all(statement["Resource"] != "*" for statement in statements)
        trust = properties["AssumeRolePolicyDocument"]["Statement"]
        assert len(trust) == 1
        assert trust[0]["Action"] == "sts:AssumeRole"
        if name == "LambdaExecutionRole":
            assert trust[0]["Principal"] == {"Service": "lambda.amazonaws.com"}
        else:
            assert trust[0]["Principal"] == {"AWS": {"Ref": "OperatorPrincipalArn"}}
            condition = trust[0]["Condition"]["StringEquals"]
            assert set(condition) == {"sts:RoleSessionName"}
            assert "*" not in condition["sts:RoleSessionName"]

    requester_resource = roles["RequesterARole"]["Properties"]["Policies"][0][
        "PolicyDocument"
    ]["Statement"][0]["Resource"]["Fn::Sub"]
    evidence_resource = roles["EvidenceReaderRole"]["Properties"]["Policies"][0][
        "PolicyDocument"
    ]["Statement"][0]["Resource"]["Fn::Sub"]
    assert requester_resource.endswith("${RestApi}/sandbox/POST/retrieve")
    assert evidence_resource.endswith(":log-group:${EvidenceLogGroup}")
    assert not evidence_resource.endswith(":*")

    serialized_roles = json.dumps(roles, allow_nan=False, sort_keys=True)
    assert "NotAction" not in serialized_roles
    assert "NotResource" not in serialized_roles
    assert "NotPrincipal" not in serialized_roles


def test_lambda_permission_and_generated_inline_source_are_exact() -> None:
    """Only the fixed API route invokes the exact reviewed handler source."""
    rendered = json.loads(render_template())
    resources = rendered["Resources"]
    permission = resources["ApiInvokePermission"]["Properties"]

    assert permission["Principal"] == "apigateway.amazonaws.com"
    assert permission["SourceAccount"] == {"Ref": "AWS::AccountId"}
    assert permission["SourceArn"]["Fn::Sub"].endswith(
        "${RestApi}/sandbox/POST/retrieve"
    )
    assert resources["RetrievalFunction"]["Properties"]["Code"][
        "ZipFile"
    ] == _HANDLER.read_text(encoding="utf-8")


def test_api_deployment_is_bound_to_fixed_route_contract() -> None:
    """A reviewed API contract change must also replace its deployment resource."""
    template = json.loads(_TEMPLATE.read_bytes())
    resources = template["Resources"]
    contract = {name: resources[name] for name in _API_CONTRACT_RESOURCES}
    digest = sha256(
        json.dumps(
            contract,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()[:12]
    deployment_id = f"ApiDeployment{digest[0].upper()}{digest[1:]}"

    assert {
        name
        for name, resource in resources.items()
        if resource["Type"] == "AWS::ApiGateway::Deployment"
    } == {deployment_id}
    assert resources["ApiStage"]["Properties"]["DeploymentId"] == {"Ref": deployment_id}
    assert template["Outputs"]["OwnershipMarker"] == {
        "Value": "cai-verify-reference-target/1"
    }


def test_template_contains_no_canaries_or_out_of_scope_cloud_services() -> None:
    """Canary values are seeded transiently and no broad cloud feature is added."""
    serialized = _TEMPLATE.read_text(encoding="utf-8")

    assert "CAI_REQUESTER_A_CANARY" not in serialized
    assert "CAI_REQUESTER_B_CANARY" not in serialized
    assert "AWS::S3::" not in serialized
    assert "AWS::Bedrock::" not in serialized
    assert "AWS::Athena::" not in serialized
    assert "AWS::CloudTrail::" not in serialized
    assert "AdministratorAccess" not in serialized
    assert '"Principal": "*"' not in serialized
    assert '"Resource": "*"' not in serialized
