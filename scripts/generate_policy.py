#!/usr/bin/env python3
"""
generate_policy.py — Generate a least-privilege IAM policy from CloudTrail logs.

Usage:
    python scripts/generate_policy.py --logs-dir logs/cloudtrail_trail \
        --role-name IAM-Project-TestRole --output-dir output
"""

import argparse
import gzip
import json
import os
import sys
from pathlib import Path

# Events that are identity confirmations, not permissions to grant
SKIP_EVENTS = {"GetCallerIdentity", "AssumeRole", "AssumeRoleWithSAML"}

# Actions used only during test cleanup — not real production needs.
# These would otherwise appear in the policy because the test workflow
# deletes the bucket it created.
SKIP_ACTIONS = {"s3:DeleteBucket", "s3:DeleteObject"}


def event_to_action(event_name, event_source):
    """Map a CloudTrail eventName + eventSource to an IAM action."""
    service = event_source.split(".")[0]  # s3.amazonaws.com -> s3
    return f"{service}:{event_name}"


def extract_resource(record):
    """Return (resource_arn, is_wildcard) for a CloudTrail record."""
    params = record.get("requestParameters") or {}
    event_source = record.get("eventSource", "")

    # S3: bucket name lives in requestParameters.bucketName
    if event_source == "s3.amazonaws.com" and "bucketName" in params:
        return f"arn:aws:s3:::{params['bucketName']}", False

    # If CloudTrail populated resources[], use the first ARN
    resources = record.get("resources") or []
    if resources and resources[0].get("ARN"):
        return resources[0]["ARN"], False

    # Everything else (describe calls) is account-wide
    return "*", True


def load_records(logs_dir):
    """Yield every CloudTrail record from every .json.gz file under logs_dir."""
    for path in Path(logs_dir).rglob("*.json.gz"):
        with gzip.open(path, "rt") as f:
            data = json.load(f)
        for record in data.get("Records", []):
            yield record


def collect_permissions(records, role_name):
    """Filter records to the role, extract actions and resources."""
    permissions = {}  # action -> set of resource ARNs

    for record in records:
        identity = record.get("userIdentity", {})
        arn = identity.get("arn", "") or ""
        if role_name not in arn:
            continue

        event_name = record.get("eventName", "")
        if event_name in SKIP_EVENTS:
            continue

        action = event_to_action(event_name, record.get("eventSource", ""))
        if action in SKIP_ACTIONS:
            continue

        resource, _is_wildcard = extract_resource(record)
        permissions.setdefault(action, set()).add(resource)

    return permissions


def write_crud_yml(permissions, output_dir):
    """Write a simple crud.yml-style manifest (for policy_sentry later)."""
    lines = []
    for action, resources in sorted(permissions.items()):
        service, action_name = action.split(":", 1)
        lines.append(f"# {action}")
        lines.append(f"{service}:")
        for resource in sorted(resources):
            lines.append(f"  - {resource}")
    content = "\n".join(lines)
    Path(output_dir, "crud.yml").write_text(content)
    return content


def write_plain_policy(permissions, output_dir):
    """Write a plain IAM policy JSON."""
    statements = []
    for action, resources in sorted(permissions.items()):
        statements.append({
            "Sid": action.replace(":", "").replace("*", "Wildcard"),
            "Effect": "Allow",
            "Action": action,
            "Resource": sorted(resources),
        })

    policy = {"Version": "2012-10-17", "Statement": statements}
    Path(output_dir, "least_privilege.json").write_text(json.dumps(policy, indent=2))
    return policy


def write_terraform(policy, output_dir, role_name):
    """Write Terraform that creates the policy and attaches it to the role."""
    policy_json = json.dumps(policy, indent=2)
    tf = f'''resource "aws_iam_policy" "least_privilege" {{
  name        = "{role_name}-least-privilege"
  description = "Generated from CloudTrail logs by generate_policy.py"

  policy = <<POLICY
{policy_json}
POLICY
}}

resource "aws_iam_role_policy_attachment" "least_privilege" {{
  role       = "{role_name}"
  policy_arn = aws_iam_policy.least_privilege.arn
}}
'''
    Path(output_dir, "main.tf").write_text(tf)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--logs-dir", default="logs/cloudtrail_trail")
    parser.add_argument("--role-name", required=True)
    parser.add_argument("--output-dir", default="output")
    args = parser.parse_args()

    output_dir = args.output_dir.rstrip("/")
    os.makedirs(output_dir, exist_ok=True)

    print(f"[*] Loading records from {args.logs_dir}...")
    records = list(load_records(args.logs_dir))
    print(f"[*] Loaded {len(records)} total records")

    print(f"[*] Filtering for role: {args.role_name}")
    permissions = collect_permissions(records, args.role_name)
    print(f"[*] Found {len(permissions)} unique actions")

    if not permissions:
        print("[!] No permissions found. Check your logs and role name.")
        sys.exit(1)

    print(f"[*] Writing output to {output_dir}/")
    write_crud_yml(permissions, output_dir)
    policy = write_plain_policy(permissions, output_dir)
    write_terraform(policy, output_dir, args.role_name)

    print("\n=== Generated policy ===")
    print(json.dumps(policy, indent=2))
    print(f"\n[+] Wrote {output_dir}/least_privilege.json")
    print(f"[+] Wrote {output_dir}/main.tf")
    print(f"[+] Wrote {output_dir}/crud.yml")


if __name__ == "__main__":
    main()
