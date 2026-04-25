"""AWS Secrets Manager integration for resolving sensitive environment variables.

Convention: for each sensitive variable, set the corresponding ``_SECRET_ID``
env var to the AWS Secrets Manager secret name or ARN. The resolver fetches the
actual value at startup and writes it into ``os.environ`` under the original
variable name, so all downstream code (IntuneClient, DrataClient) reads from
``os.environ`` as normal -- no client changes required.

Sensitive variables and their ID counterparts:

    INTUNE_CLIENT_SECRET  <--  INTUNE_CLIENT_SECRET_ID
    DRATA_API_KEY         <--  DRATA_API_KEY_ID

If neither the ``_SECRET_ID`` variant nor the direct variable is set, the
client's own ``_require_env`` will raise at init time with a clear message.

If a ``_SECRET_ID`` is set, the direct variable is ignored for that run.

Local development: set the direct variable (``INTUNE_CLIENT_SECRET=...``).
Production: set only the ID variable (``INTUNE_CLIENT_SECRET_ID=...``).

AWS credential resolution follows boto3's standard chain:
    1. IAM role attached to the EC2 instance, ECS task, or Lambda function
    2. AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY environment variables
    3. ~/.aws/credentials + ~/.aws/config profile
    4. Container credentials endpoint (ECS)

The IAM principal must have ``secretsmanager:GetSecretValue`` on each secret ARN.

Secret format:
    Secrets may be stored as a plain string or a JSON object. For JSON objects:
    - If the object has a key matching the target env var name, that value is used.
    - If the object has exactly one key, its value is used.
    - Otherwise a RuntimeError is raised with guidance on how to structure the secret.
"""

from __future__ import annotations

import json
import os
from typing import Dict

import structlog

logger: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)

# Maps each sensitive env var to the env var that holds its AWS Secret ID.
# {target_env_var: id_env_var}
_MANAGED_SECRETS: Dict[str, str] = {
    "INTUNE_CLIENT_SECRET": "INTUNE_CLIENT_SECRET_ID",
    "DRATA_API_KEY":        "DRATA_API_KEY_ID",
}


def resolve_aws_secrets() -> None:
    """Fetch secrets from AWS Secrets Manager and inject them into ``os.environ``.

    Scans ``_MANAGED_SECRETS`` for any ``_SECRET_ID`` env vars that are set.
    For each one found, fetches the secret value from AWS SM and writes it
    into ``os.environ`` under the target variable name.

    If no ``_SECRET_ID`` vars are set, this function is a no-op and boto3 is
    never imported -- engineers not using AWS SM pay no dependency cost.

    Raises:
        ImportError:   ``boto3`` is not installed. Install with ``pip install boto3``.
        RuntimeError:  A secret could not be retrieved (permission denied, not
                       found, credential error, ambiguous JSON format).
    """
    to_resolve: Dict[str, str] = {}
    for target_var, id_var in _MANAGED_SECRETS.items():
        secret_id = os.environ.get(id_var, "").strip()
        if secret_id:
            to_resolve[target_var] = secret_id

    if not to_resolve:
        logger.debug(
            "aws_secrets_skipped",
            note="no _SECRET_ID vars set -- using direct env vars",
        )
        return

    # Import boto3 lazily so the module can be imported (and _extract_secret_value
    # can be tested) without boto3 installed.
    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError as exc:
        raise ImportError(
            "boto3 is required for AWS Secrets Manager integration. "
            "Install it with: pip install 'boto3>=1.34,<2.0'"
        ) from exc

    client = boto3.client("secretsmanager")

    for target_var, secret_id in to_resolve.items():
        logger.info(
            "resolving_aws_secret",
            target_var=target_var,
            secret_id=secret_id,
        )
        try:
            response = client.get_secret_value(SecretId=secret_id)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"]["Message"]
            raise RuntimeError(
                f"Failed to retrieve secret '{secret_id}' for {target_var}: "
                f"{code} -- {msg}"
            ) from exc
        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS credential or connectivity error while fetching '{secret_id}': {exc}. "
                "Ensure the execution environment has valid AWS credentials and the IAM "
                "principal has secretsmanager:GetSecretValue on this secret."
            ) from exc

        # SecretString is present for text secrets; SecretBinary for binary secrets.
        raw = response.get("SecretString") or response.get("SecretBinary", b"").decode("utf-8")

        secret_value = _extract_secret_value(secret_id, target_var, raw)
        os.environ[target_var] = secret_value

        logger.info("aws_secret_resolved", target_var=target_var, secret_id=secret_id)


def _extract_secret_value(secret_id: str, target_var: str, raw: str) -> str:
    """Extract the scalar secret value from a plain string or JSON object.

    Three supported formats:
        - Plain string: ``"my-secret-value"`` -- returned as-is.
        - JSON with a key matching ``target_var``:
          ``{"INTUNE_CLIENT_SECRET": "my-secret"}`` -- that value is returned.
        - JSON with exactly one key: ``{"value": "my-secret"}`` -- its value is returned.

    Raises:
        RuntimeError: The secret is a JSON object that does not match any of the
                      above formats.
    """
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw  # plain string

    if not isinstance(parsed, dict):
        # Non-dict JSON (array, number, etc.) -- treat as plain string.
        return raw

    # Prefer the key that matches the target env var name.
    if target_var in parsed:
        return str(parsed[target_var])

    # Fall back to single-key extraction.
    if len(parsed) == 1:
        return str(next(iter(parsed.values())))

    raise RuntimeError(
        f"Secret '{secret_id}' is a JSON object with {len(parsed)} keys and none "
        f"match '{target_var}'. Store the secret as one of:\n"
        f"  - A plain string: the raw secret value\n"
        f"  - A single-key JSON object: {{\"any_key\": \"value\"}}\n"
        f"  - A JSON object with '{target_var}' as a key: {{\"{target_var}\": \"value\"}}"
    )
