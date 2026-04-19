#!/usr/bin/env bash
# SWIFT — AWS App Runner deployment helper
# Prerequisites: AWS CLI configured, Docker running, ANTHROPIC_API_KEY set
set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
APP_NAME="swift-scanner"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
ECR_URI="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${APP_NAME}"
SECRET_NAME="swift/anthropic-api-key"

echo "==> Creating ECR repository (skip if exists)..."
aws ecr create-repository --repository-name "${APP_NAME}" --region "${REGION}" 2>/dev/null || true

echo "==> Building Docker image..."
docker build -t "${APP_NAME}:latest" .

echo "==> Authenticating Docker to ECR..."
aws ecr get-login-password --region "${REGION}" \
  | docker login --username AWS --password-stdin "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"

echo "==> Tagging and pushing image..."
docker tag "${APP_NAME}:latest" "${ECR_URI}:latest"
docker push "${ECR_URI}:latest"

echo "==> Storing ANTHROPIC_API_KEY in AWS Secrets Manager..."
if aws secretsmanager describe-secret --secret-id "${SECRET_NAME}" --region "${REGION}" >/dev/null 2>&1; then
  aws secretsmanager update-secret \
    --secret-id "${SECRET_NAME}" \
    --secret-string "${ANTHROPIC_API_KEY}" \
    --region "${REGION}"
  echo "    Secret updated."
else
  aws secretsmanager create-secret \
    --name "${SECRET_NAME}" \
    --secret-string "${ANTHROPIC_API_KEY}" \
    --region "${REGION}"
  echo "    Secret created."
fi

SECRET_ARN="$(aws secretsmanager describe-secret \
  --secret-id "${SECRET_NAME}" \
  --query ARN --output text --region "${REGION}")"

echo ""
echo "====================================================="
echo "  Image pushed: ${ECR_URI}:latest"
echo "  Secret ARN:   ${SECRET_ARN}"
echo "====================================================="
echo ""
echo "Next: deploy via AWS Console or CLI:"
echo ""
echo "  aws apprunner create-service \\"
echo "    --service-name ${APP_NAME} \\"
echo "    --source-configuration '{"
echo "      \"ImageRepository\": {"
echo "        \"ImageIdentifier\": \"${ECR_URI}:latest\","
echo "        \"ImageRepositoryType\": \"ECR\","
echo "        \"ImageConfiguration\": {"
echo "          \"Port\": \"8000\","
echo "          \"RuntimeEnvironmentVariables\": {"
echo "            \"SWIFT_LOG_LEVEL\": \"INFO\","
echo "            \"SWIFT_CONFIDENCE_THRESHOLD\": \"0.95\","
echo "            \"PYTHONPATH\": \"/app\""
echo "          },"
echo "          \"RuntimeEnvironmentSecrets\": {"
echo "            \"ANTHROPIC_API_KEY\": \"${SECRET_ARN}\""
echo "          }"
echo "        }"
echo "      }"
echo "    }' \\"
echo "    --instance-configuration '{\"Cpu\": \"1 vCPU\", \"Memory\": \"2 GB\"}' \\"
echo "    --region ${REGION}"
