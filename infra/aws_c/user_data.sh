#!/bin/bash
# SiteProof AWS-C single-use worker bootstrap. CANDIDATE / AWS LIVE NOT VERIFIED.
# Source of truth for the UserData in worker.template.json (kept identical by a test).
# Dollar-brace tokens are CloudFormation substitutions; shell variables use $NAME without
# braces, so the two can never be confused.
#
# 1. Dead-man timer FIRST. Whatever happens below, the OS powers off after this many
#    minutes, and the instance is configured to TERMINATE on OS shutdown. This layer
#    needs no AWS API, no DynamoDB and no Lambda.
shutdown -h +${MaxRuntimeMinutes} "siteproof pilot hard stop"

set -uo pipefail
umask 077

# 2. Any exit path (success, failure, missing tool) ends in an immediate power-off.
finish() {
  sync
  shutdown -h now
}
trap finish EXIT

export AWS_DEFAULT_REGION='${AWS::Region}'
export PILOT_RUN_ID='${PilotRunId}'
export HARD_DEADLINE_UTC='${HardDeadlineUtc}'
export TABLE_NAME='${ControlTableName}'
export EVIDENCE_BUCKET='${EvidenceBucketName}'
export SIGNING_KEY_ID='${SigningKeyId}'
export CODE_BUCKET='${CodeBucket}'
export BUNDLE_KEY='${WorkerBundleKey}'
export BUNDLE_VERSION='${WorkerBundleObjectVersion}'
export BUNDLE_SHA256='${WorkerBundleSha256}'
export ECR_REGISTRY='${EcrRegistry}'
export RUNTIME_IMAGE='${EcrRegistry}/${EcrRepositoryName}@${RuntimeImageDigest}'
export EVIDENCE_DIR=/var/lib/siteproof/evidence
export DOCKER_BIN=/usr/bin/docker

# 3. The machine image must already contain Docker and boto3. Nothing is installed from
#    the network at run time; a missing tool ends the run (and the instance).
command -v "$DOCKER_BIN" >/dev/null || exit 10
python3 -c 'import boto3, sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || exit 11
systemctl start docker || exit 12

install -d -m 700 /opt/siteproof /var/lib/siteproof "$EVIDENCE_DIR"

# 4. Fetch the exact reviewed source bundle version and verify its SHA-256 before use.
python3 - <<'PY' || exit 20
import hashlib, io, os, sys, zipfile
import boto3
body = boto3.client("s3").get_object(
    Bucket=os.environ["CODE_BUCKET"], Key=os.environ["BUNDLE_KEY"],
    VersionId=os.environ["BUNDLE_VERSION"])["Body"].read()
if hashlib.sha256(body).hexdigest() != os.environ["BUNDLE_SHA256"]:
    sys.exit("bundle hash mismatch")
zipfile.ZipFile(io.BytesIO(body)).extractall("/opt/siteproof")
PY

# 5. Registry login with the instance role, then pull the runtime image by digest only.
python3 - <<'PY' | "$DOCKER_BIN" login --username AWS --password-stdin "$ECR_REGISTRY" >/dev/null || exit 30
import base64
import boto3
token = boto3.client("ecr").get_authorization_token()["authorizationData"][0]["authorizationToken"]
print(base64.b64decode(token).decode().split(":", 1)[1], end="")
PY
"$DOCKER_BIN" pull "$RUNTIME_IMAGE" >/dev/null || exit 31

# 6. Start gate, fixture-only isolation harness, evidence publication (see worker_entry).
cd /opt/siteproof || exit 40
python3 -B -m src.aws_c.worker_entry \
  >/var/lib/siteproof/worker-result.json 2>/var/lib/siteproof/worker-stderr.log

# 7. The EXIT trap powers the instance off; shutdown behaviour = terminate.
