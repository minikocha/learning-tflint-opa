package aws.iam_test

import data.aws.iam
import rego.v1

# -----
# CKV_AWS_60: "Ensure IAM role allows only specific services or principals to assume it"
# -----

allows_public_assume(type, schema, options) := terraform.mock_resources(
	type,
	schema,
	options,
	# NOTE: using `jsonencode()` fails to create mock resources, so use here-doc instead.
	{"main.tf": `
resource "awscc_iam_role" "failed_1" {
  assume_role_policy_document = <<-EOT
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Principal": {
            "AWS": "*"
          },
          "Effect": "Allow",
          "Action": "sts:AssumeRole"
        }
      ]
    }
  EOT
}

resource "awscc_iam_role" "failed_2" {
  assume_role_policy_document = <<-EOT
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Principal": {
            "AWS": ["*"]
          },
          "Effect": "Allow",
          "Action": "sts:AssumeRole"
        }
      ]
    }
  EOT
}`},
)

test_ckv_aws_60_failed if {
	issues := iam.ckv_aws_60 with terraform.resources as allows_public_assume
	count(issues) == 2
	every issue in issues {
		issue.msg == "Ensure IAM role allows only specific services or principals to assume it"
	}
}

allows_specific_assume(type, schema, options) := terraform.mock_resources(
	type,
	schema,
	options,
	# NOTE: using `jsonencode()` fails to create mock resources, so use here-doc instead.
	{"main.tf": `
resource "awscc_iam_role" "passed_1" {
  assume_role_policy_document = <<-EOT
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Principal": {
            "Service": "ec2.amazonaws.com"
          },
          "Effect": "Allow",
          "Action": "sts:AssumeRole"
        }
      ]
    }
  EOT
}

resource "awscc_iam_role" "passed_2" {
  assume_role_policy_document = <<-EOT
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Principal": {
            "AWS": "*"
          },
          "Effect": "Deny",
          "Action": "sts:AssumeRole"
        }
      ]
    }
  EOT
}`},
)

test_ckv_aws_60_passed if {
	issues := iam.ckv_aws_60 with terraform.resources as allows_specific_assume
	count(issues) == 0
}
