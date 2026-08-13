"""Disposable AWS reciprocal-retrieval reference target."""

from examples.aws.reference_target.config import (
    REFERENCE_SCENARIO_ID,
    DeploymentDescriptor,
    ReferenceTargetError,
    generate_configuration,
    load_deployment_description,
    write_configuration,
)

__all__ = [
    "REFERENCE_SCENARIO_ID",
    "DeploymentDescriptor",
    "ReferenceTargetError",
    "generate_configuration",
    "load_deployment_description",
    "write_configuration",
]
