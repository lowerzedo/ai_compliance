"""Synthetic exact execution policies for network-isolated AWS tests."""

from __future__ import annotations

from cai_verify.aws import AwsExecutionPolicy
from cai_verify.config import (
    AssumedRoleIdentity,
    AwsSigV4Action,
    CloudWatchLogsProbe,
    CurrentAwsIdentity,
    VerificationSuite,
)


def authorizing_execution_policy(suite: VerificationSuite) -> AwsExecutionPolicy:
    """Build a test-only exact policy for one already validated synthetic suite."""
    account_id = suite.target.aws_account_id or "111122223333"
    region = suite.target.aws_region or "eu-west-2"
    endpoint = (
        str(suite.target.endpoint)
        if suite.target.aws_region is not None
        else "https://synthetic.sandbox.example.test/"
    )
    actions = sorted(
        {
            (action.method.value, action.path, action.service)
            for scenario in suite.scenarios
            for action in scenario.actions
            if isinstance(action, AwsSigV4Action)
        }
    )
    if not actions:
        actions = [("POST", "/synthetic", "execute-api")]
    log_groups = sorted(
        {
            probe.log_group
            for scenario in suite.scenarios
            for probe in scenario.probes
            if isinstance(probe, CloudWatchLogsProbe)
        }
    )
    if not log_groups:
        log_groups = ["/aws/cai-verify/synthetic"]
    role_arns = sorted(
        {
            identity.role_arn
            for identity in suite.identities
            if isinstance(identity, AssumedRoleIdentity)
        }
    )
    return AwsExecutionPolicy.model_validate(
        {
            "actions": [
                {"method": method, "path": path, "service": service}
                for method, path, service in actions
            ],
            "allowCurrentIdentity": any(
                isinstance(identity, CurrentAwsIdentity)
                for identity in suite.identities
            ),
            "applicationEndpoint": endpoint,
            "assumedRoleArns": role_arns,
            "awsAccountId": account_id,
            "cloudwatchLogGroups": log_groups,
            "partition": _partition(region),
            "region": region,
            "schemaVersion": "1alpha1",
        }
    )


def _partition(region: str) -> str:
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    if region.startswith("cn-"):
        return "aws-cn"
    return "aws"
