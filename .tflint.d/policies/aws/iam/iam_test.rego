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

# -----
# CKV_AWS_61: "Ensure AWS IAM policy does not allow assume role permission across all services"
# -----

allows_assume_from_account(type, schema, options) := terraform.mock_resources(
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
            "AWS": "123456789012"
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
            "AWS": ["arn:aws:iam::123456789012:root"]
          },
          "Effect": "Allow",
          "Action": "sts:AssumeRole"
        }
      ]
    }
  EOT
}`},
)

test_ckv_aws_61_failed if {
	issues := iam.ckv_aws_61 with terraform.resources as allows_assume_from_account
	count(issues) == 2
	every issue in issues {
		issue.msg == "Ensure AWS IAM policy does not allow assume role permission across all services"
	}
}

not_allows_assume_from_account(type, schema, options) := terraform.mock_resources(
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
            "AWS": "123456789012"
          },
          "Effect": "Deny",
          "Action": "sts:AssumeRole"
        }
      ]
    }
  EOT
}`},
)

test_ckv_aws_61_passed if {
	issues := iam.ckv_aws_61 with terraform.resources as not_allows_assume_from_account
	count(issues) == 0
}

# -----
# CKV_AWS_62: "Ensure IAM policies that allow full \"*-*\" administrative privileges are not created"
# -----

admin_privilege_policies(type, schema, options) := terraform.mock_resources(
	type,
	schema,
	options,
	# NOTE: using `jsonencode()` fails to create mock resources, so use here-doc instead.
	{"main.tf": `
resource "awscc_iam_group" "failed_1" {
  policies = [
    {
      policy_document = <<-EOT
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": "*",
              "Resource": "*"
            }
          ]
        }
      EOT
    },
  ]
}

resource "awscc_iam_group_policy" "failed_2" {
  policy_document = <<-EOT
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": ["*"],
          "Resource": ["*"]
        }
      ]
    }
  EOT
}

resource "awscc_iam_managed_policy" "failed_3" {
  policy_document = <<-EOT
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": ["*"],
          "Resource": ["*"]
        }
      ]
    }
  EOT
}

resource "awscc_iam_role" "failed_4" {
  policies = [
    {
      policy_document = <<-EOT
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": "*",
              "Resource": "*"
            }
          ]
        }
      EOT
    },
  ]
}

resource "awscc_iam_role_policy" "failed_5" {
  policy_document = <<-EOT
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": ["*"],
          "Resource": ["*"]
        }
      ]
    }
  EOT
}

resource "awscc_iam_user" "failed_6" {
  policies = [
    {
      policy_document = <<-EOT
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": "*",
              "Resource": "*"
            }
          ]
        }
      EOT
    },
  ]
}

resource "awscc_iam_user_policy" "failed_7" {
  policy_document = <<-EOT
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": ["*"],
          "Resource": ["*"]
        }
      ]
    }
  EOT
}`},
)

test_ckv_aws_62_failed if {
	issues := iam.ckv_aws_62 with terraform.resources as admin_privilege_policies
	count(issues) == 7
	every issue in issues {
		issue.msg == "Ensure IAM policies that allow full \"*-*\" administrative privileges are not created"
	}
}

non_admin_privilege_policies(type, schema, options) := terraform.mock_resources(
	type,
	schema,
	options,
	# NOTE: using `jsonencode()` fails to create mock resources, so use here-doc instead.
	{"main.tf": `
resource "awscc_iam_group" "passed_1" {
  policies = [
    {
      policy_document = <<-EOT
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Deny",
              "Action": "*",
              "Resource": "*"
            }
          ]
        }
      EOT
    },
  ]
}

resource "awscc_iam_group_policy" "passed_2" {
  policy_document = <<-EOT
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": ["s3:ListAllMyBuckets"],
          "Resource": ["*"]
        }
      ]
    }
  EOT
}`},
)

test_ckv_aws_62_passed if {
	issues := iam.ckv_aws_62 with terraform.resources as non_admin_privilege_policies
	count(issues) == 0
}
