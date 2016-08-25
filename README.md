# AmazonInspectorAutoRemediation
This script is designed to run in AWS Lambda and will not work elsewhere.

This is an AWS Lambda job, written in Python, to automatically patch EC2 instances when an inspector assessment generates a CVE finding.

The job requires that the EC2 instance to be patched have the SSM (EC2 Simple System Manager) agent installed, and the agent must have a role attached with necessary SSM permissions.  For details on this, see https://docs.aws.amazon.com/ssm/latest/APIReference/Welcome.html.

The job is triggered by an SNS notification of a new finding from Inspector.  The job checks to make sure that the finding is a CVE missing patch finding, and if so, it checks to ensure tha the SSM agent is running.  It then uses SSM to issue the appropriate patch-and-reboot commands to either Ubuntu or Amazon Linux.
