#!/usr/bin/env bash
# regenerate.sh — Re-run role activity so CloudTrail captures data events,
# then re-generate the least-privilege policy.

set -euo pipefail

ROLE_ARN="${ROLE_ARN:?ROLE_ARN is not set. Export it first.}"
ROLE_NAME="IAM-Project-TestRole"
LOGS_DIR="logs/cloudtrail_trail"
OUTPUT_DIR="output"

echo "[*] Assuming role $ROLE_NAME..."
CREDS=$(aws sts assume-role \
  --role-arn "$ROLE_ARN" \
  --role-session-name iam-project-activity-v2 \
  --query 'Credentials' --output json)

export AWS_ACCESS_KEY_ID=$(echo "$CREDS" | jq -r '.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | jq -r '.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo "$CREDS" | jq -r '.SessionToken')

echo "[*] Running as:"
aws sts get-caller-identity

echo "[*] Generating S3 activity..."
BUCKET="iam-project-test-$(date +%s)"
aws s3 mb "s3://$BUCKET"
echo "data events test" > /tmp/regenerate.txt
aws s3 cp /tmp/regenerate.txt "s3://$BUCKET/test.txt"
aws s3 ls "s3://$BUCKET"
aws s3 cp "s3://$BUCKET/test.txt" /tmp/regenerate_downloaded.txt
aws s3 rm "s3://$BUCKET/test.txt"
aws s3 rb "s3://$BUCKET"

echo "[*] Generating EC2 activity..."
aws ec2 describe-instances --query 'Reservations[].Instances[].InstanceId' --output text
aws ec2 describe-vpcs --query 'Vpcs[].VpcId' --output text
aws ec2 describe-security-groups --query 'SecurityGroups[].GroupId' --output text

echo "[*] Bucket used: $BUCKET"

echo "[*] Clearing temporary credentials..."
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
aws sts get-caller-identity

echo ""
echo "[+] Activity complete. CloudTrail needs 10-15 minutes to write the logs."
echo "[+] After waiting, run:"
echo "    aws s3 sync s3://\$BUCKET/AWSLogs/\$AWS_ACCOUNT_ID/CloudTrail/ $LOGS_DIR/"
echo "    python scripts/generate_policy.py --logs-dir $LOGS_DIR --role-name $ROLE_NAME --output-dir $OUTPUT_DIR"
