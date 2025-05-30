# AWS Resource Cleanup Script

⚠️ WARNING: This script will irreversibly delete AWS resources including EC2, S3, IAM, RDS, Lambda, Glue, CloudTrail, DynamoDB, and more.

## Purpose

This script is intended for:
- Cleaning up AWS environments (test/dev)
- Automation demos
- Educational teardown workflows

**DO NOT** use in production environments.

## Usage

1. Ensure Python and `boto3` are installed:
   ```bash
   pip install boto3

