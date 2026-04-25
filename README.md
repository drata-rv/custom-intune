# Intune to Drata MDM Compliance Pipeline

Fetches Windows, macOS, Linux, and Android device compliance state from Microsoft
Intune via the Graph API and pushes it to Drata's Custom MDM Connection endpoint.

The pipeline runs as a single command. On the first run it pushes all devices.
On subsequent runs it only pushes devices whose payload has changed (SHA-256
delta detection against `drata_state.json`), so typical runs complete in seconds
rather than minutes.

## Prerequisites

- Python 3.10 or later
- An Azure AD App Registration with admin-consented Application permissions:
  - `DeviceManagementManagedDevices.Read.All`
  - `DeviceManagementConfiguration.Read.All`
- A Drata API key with the "Devices: Create Device" scope
- A Drata Custom MDM Connection ID (Drata App -> Connections -> MDM -> Custom Device Connection -> Account Information)

## Secrets Management

Production deployments must use AWS Secrets Manager. Direct secret values in
environment files are only supported for local development.

**Production (AWS Secrets Manager)**

Store `INTUNE_CLIENT_SECRET` and `DRATA_API_KEY` as secrets in AWS SM. Then,
instead of providing the secret values in the environment, provide the secret
name or ARN:

```
INTUNE_CLIENT_SECRET_ID=arn:aws:secretsmanager:us-east-1:123456789:secret:intune-client-secret
DRATA_API_KEY_ID=arn:aws:secretsmanager:us-east-1:123456789:secret:drata-api-key
```

At startup, the pipeline fetches the values from AWS SM and injects them into
the process environment. All other code reads from `os.environ` as normal.

The IAM principal running the pipeline (EC2 instance role, ECS task role,
Lambda execution role, etc.) must have:

```json
{
  "Effect": "Allow",
  "Action": "secretsmanager:GetSecretValue",
  "Resource": [
    "arn:aws:secretsmanager:...:secret:intune-client-secret",
    "arn:aws:secretsmanager:...:secret:drata-api-key"
  ]
}
```

Secrets may be stored as a plain string or a JSON object. For JSON objects, the
pipeline uses the key that matches the target variable name (e.g.,
`INTUNE_CLIENT_SECRET`), or the value of a single-key object. A JSON object
with multiple keys and no matching key name will raise an error at startup.

**Local development**

Set the secret values directly in `.env`:

```
INTUNE_CLIENT_SECRET=your-client-secret
DRATA_API_KEY=your-drata-api-key
```

Do not commit `.env`. The `*_SECRET_ID` variables take precedence when set, so
ensure they are unset or empty in your local `.env`.

## Setup

**1. Install dependencies**

```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

**2. Configure environment variables**

```bash
cp .env.example .env
```

Edit `.env` and fill in the values. For local development, set
`INTUNE_CLIENT_SECRET` and `DRATA_API_KEY` directly. For production, set the
corresponding `*_SECRET_ID` variables instead (see Secrets Management above).
The five `POLICY_NAME_*` variables are optional -- omit any whose corresponding
Intune policy does not exist yet, and that compliance field will be absent from
all payloads.

**3. Verify with a dry run**

```bash
python run.py --dry-run
```

This fetches all data from Intune, computes deltas, and logs what would be
pushed to Drata -- without making any Drata API calls.

## Running

```bash
python run.py
```

Output is structured JSON on stdout. Pipe to `jq` for readable output during
manual testing:

```bash
python run.py 2>&1 | jq .
```

## Configuration Reference

| Variable | Required | Description |
|---|---|---|
| `INTUNE_TENANT_ID` | Yes | Azure AD Directory (tenant) ID |
| `INTUNE_CLIENT_ID` | Yes | App Registration Application (client) ID |
| `INTUNE_CLIENT_SECRET` | Local dev | App Registration client secret (direct value) |
| `INTUNE_CLIENT_SECRET_ID` | Production | AWS SM secret name or ARN for the client secret |
| `DRATA_API_KEY` | Local dev | Drata API key with "Devices: Create Device" scope (direct value) |
| `DRATA_API_KEY_ID` | Production | AWS SM secret name or ARN for the Drata API key |
| `DRATA_CONNECTION_ID` | Yes | Numeric Drata Custom MDM Connection ID |
| `POLICY_NAME_SCREEN_LOCK` | No | Display name of the Intune compliance policy for screen lock |
| `POLICY_NAME_AUTO_UPDATES` | No | Display name of the Windows Update Ring (not a compliance policy) |
| `POLICY_NAME_PASSWORD_MANAGER` | No | Display name of the Intune compliance policy for password manager |
| `POLICY_NAME_ENCRYPTION` | No | Display name of the Intune compliance policy for encryption |
| `POLICY_NAME_ANTIVIRUS` | No | Display name of the Intune compliance policy for antivirus |
| `STATE_FILE_PATH` | No | Override default state file location (default: `./drata_state.json`) |
| `LOG_LEVEL` | No | `DEBUG`, `INFO`, `WARNING`, or `ERROR` (default: `INFO`) |

Set either the direct value or the `*_SECRET_ID` variant for each secret, not both.
When a `*_SECRET_ID` var is set, the direct value is ignored for that run.

`POLICY_NAME_AUTO_UPDATES` must match a Windows Update Ring display name under
`/deviceManagement/windowsUpdateForBusinessConfigurations`, not a compliance
policy. Update Rings and compliance policies are separate Intune resource types.
All other `POLICY_NAME_*` variables match compliance policies under
`/deviceManagement/deviceCompliancePolicies`. Display names are matched
case-insensitively. If a name does not match, the pipeline logs a warning and
omits that compliance field from all payloads for that run.

## Scheduling as a Cron Job

Add a cron entry to run daily. The pipeline is idempotent -- running it more
frequently is safe, but Drata rate-limits to 500 requests/minute and the
pipeline targets 420 req/min, so avoid concurrent executions.

```cron
# Run daily at 02:00, log to /var/log/intune-drata/pipeline.log
0 2 * * * /path/to/.venv/bin/python /path/to/run.py >> /var/log/intune-drata/pipeline.log 2>&1
```

Replace paths with the absolute paths for your environment. Create the log
directory beforehand and ensure the process user has write access to it and to
the working directory (for `drata_state.json`).

To use environment variables from a file rather than the system environment,
either source the file in a wrapper script or rely on the `.env` auto-loading
that `python-dotenv` performs at startup.

**Wrapper script approach (recommended for cron)**

```bash
#!/usr/bin/env bash
set -euo pipefail
cd /path/to/MDM-Intune-Clean
source .venv/bin/activate
exec python run.py "$@"
```

Schedule the wrapper:

```cron
0 2 * * * /path/to/run-pipeline.sh >> /var/log/intune-drata/pipeline.log 2>&1
```

## GitHub Actions

```yaml
name: Intune Compliance Sync

on:
  schedule:
    - cron: "0 2 * * *"
  workflow_dispatch:

jobs:
  sync:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Run pipeline
        env:
          INTUNE_TENANT_ID: ${{ secrets.INTUNE_TENANT_ID }}
          INTUNE_CLIENT_ID: ${{ secrets.INTUNE_CLIENT_ID }}
          INTUNE_CLIENT_SECRET_ID: ${{ secrets.INTUNE_CLIENT_SECRET_ID }}
          DRATA_API_KEY_ID: ${{ secrets.DRATA_API_KEY_ID }}
          DRATA_CONNECTION_ID: ${{ secrets.DRATA_CONNECTION_ID }}
          POLICY_NAME_SCREEN_LOCK: ${{ vars.POLICY_NAME_SCREEN_LOCK }}
          POLICY_NAME_AUTO_UPDATES: ${{ vars.POLICY_NAME_AUTO_UPDATES }}
          POLICY_NAME_PASSWORD_MANAGER: ${{ vars.POLICY_NAME_PASSWORD_MANAGER }}
          POLICY_NAME_ENCRYPTION: ${{ vars.POLICY_NAME_ENCRYPTION }}
          POLICY_NAME_ANTIVIRUS: ${{ vars.POLICY_NAME_ANTIVIRUS }}
        run: python run.py
```

Note: delta detection requires `drata_state.json` to persist between runs. For
stateless CI environments, upload and restore the state file using an artifact
or external storage (S3, Azure Blob, etc.) between workflow runs.

## Dry Run

```bash
python run.py --dry-run
```

Fetches all data from Intune and computes deltas, then logs what would be
pushed without making any Drata API calls. Useful for verifying configuration
and inspecting the delta count after policy changes.

## Output Files

| File | Description |
|---|---|
| `drata_payloads.json` | Debug artifact written after extraction. Contains all valid payloads from the last run. Not required by the pipeline -- payloads are passed in memory between stages. |
| `drata_state.json` | Persistent state file. Maps each `externalId` to the SHA-256 hash of its last successfully pushed payload. Delete this file to force a full re-push on the next run. |
| `dead_letter_YYYYMMDD_HHMMSS.ndjson` | Written when Drata responds with 400 or when all retries are exhausted for a device. One JSON record per line. Investigate payloads here if devices are consistently failing. |

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success, or `--dry-run` completed |
| `1` | Unrecoverable error. Check `CRITICAL` log entries. Common causes: missing or invalid credentials, Intune returned zero devices, Drata returned 401/403/412. |

## Compliance Field Semantics

The five compliance fields (`screenLockEnabled`, `autoUpdateEnabled`,
`passwordManagerEnabled`, `encryptionEnabled`, `antivirusEnabled`) follow a
strict omission rule:

- If the corresponding `POLICY_NAME_*` env var is not set, the field is absent from all payloads.
- If a device's policy state is indeterminate (`unknown`, `notApplicable`, `error`, `conflict`, `inGracePeriod`), the field is absent for that device.
- If a device is `compliant`, the field is `true`.
- If a device is `noncompliant`, the field is `false`. This is confirmed evidence and is always reported.

A field is never `null` in the Drata payload.

## Running Tests

```bash
pytest
```

The test suite covers normalization logic, Pydantic model validation, and
state management. Tests are pure in-process with no HTTP calls, no file I/O
beyond `tmp_path`, and no env vars required.

## Smoke Test Checklist

Before the first production run, verify the following:

1. The `deviceStatuses` compound ID format. The pipeline assumes the API returns
   `id` as `{managedDeviceId}_{userId}`. Confirm this against a real tenant
   response by enabling `LOG_LEVEL=DEBUG` and checking `policy_status_page_fetched`
   log entries.

2. Policy display name matching. Run with `--dry-run` and check that all five
   `policy_resolved` log entries appear (or appropriate `policy_not_found_in_intune`
   warnings for unconfigured checks).

3. Platform coverage. Check the `extractor_summary` log entry for `platform_skips`.
   A non-zero count is expected if iOS or iPadOS devices are enrolled -- those
   platforms are unsupported by Drata's Custom MDM Connection.
