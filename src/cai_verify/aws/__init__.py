"""Built-in AWS readiness checks and identity providers."""

from cai_verify.aws.action import AwsActionFailureCode, AwsSigV4ActionAdapter
from cai_verify.aws.doctor import (
    AWS_DOCTOR_SCHEMA_VERSION,
    AwsDoctorIssueCode,
    AwsDoctorResult,
    AwsIdentityCheck,
    run_aws_doctor,
)
from cai_verify.aws.identity import (
    AssumedRoleAwsIdentityProvider,
    AwsIdentityError,
    AwsIdentityFailureCode,
    AwsScopedIdentity,
    AwsSession,
    AwsSessionFactory,
    AwsStsClient,
    Boto3AwsSessionFactory,
    CurrentAwsIdentityProvider,
)

__all__ = [
    "AWS_DOCTOR_SCHEMA_VERSION",
    "AssumedRoleAwsIdentityProvider",
    "AwsActionFailureCode",
    "AwsDoctorIssueCode",
    "AwsDoctorResult",
    "AwsIdentityCheck",
    "AwsIdentityError",
    "AwsIdentityFailureCode",
    "AwsScopedIdentity",
    "AwsSession",
    "AwsSessionFactory",
    "AwsSigV4ActionAdapter",
    "AwsStsClient",
    "Boto3AwsSessionFactory",
    "CurrentAwsIdentityProvider",
    "run_aws_doctor",
]
