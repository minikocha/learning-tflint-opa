package aws.s3_test

import data.aws.s3
import rego.v1

# -----
# CKV_AWS_18: Ensure the S3 bucket has access logging enabled
# -----

logging_disabled(type, schema, options) := terraform.mock_resources(
	type,
	schema,
	options,
	{"main.tf": `
resource "awscc_s3_bucket" "failed_1" {}

resource "awscc_s3_bucket" "failed_2" {
  logging_configuration = null
}`},
)

test_ckv_aws_18_failed if {
	issues := s3.ckv_aws_18 with terraform.resources as logging_disabled
	count(issues) == 2
	every issue in issues {
		issue.msg == "Ensure the S3 bucket has access logging enabled"
	}
}

logging_enabled(type, schema, options) := terraform.mock_resources(
	type,
	schema,
	options,
	{"main.tf": `
resource "awscc_s3_bucket" "passed_1" {
  logging_configuration = {}
}`},
)

test_ckv_aws_18_passed if {
	issues := s3.ckv_aws_18 with terraform.resources as logging_enabled
	count(issues) == 0
}

# -----
# CKV_AWS_21: Ensure the S3 bucket has versioning enabled
# -----

versioning_disabled(type, schema, options) := terraform.mock_resources(
	type,
	schema,
	options,
	{"main.tf": `
resource "awscc_s3_bucket" "failed_1" {}

resource "awscc_s3_bucket" "failed_2" {
  versioning_configuration = null
}

resource "awscc_s3_bucket" "failed_3" {
  versioning_configuration = {
    status = "Suspended"
  }
}`},
)

test_ckv_aws_21_failed if {
	issues := s3.ckv_aws_21 with terraform.resources as versioning_disabled
	count(issues) == 3
	every issue in issues {
		issue.msg == "Ensure the S3 bucket has versioning enabled"
	}
}

versioning_enabled(type, schema, options) := terraform.mock_resources(
	type,
	schema,
	options,
	{"main.tf": `
resource "awscc_s3_bucket" "passed_1" {
  versioning_configuration = {
    status = "Enabled"
  }
}`},
)

test_ckv_aws_21_passed if {
	issues := s3.ckv_aws_21 with terraform.resources as versioning_enabled
	count(issues) == 0
}

# -----
# CKV_AWS_53: Ensure S3 bucket has block public ACLs enabled
# -----

not_blocking_public_acls(type, schema, options) := terraform.mock_resources(
	type,
	schema,
	options,
	{"main.tf": `
resource "awscc_s3_bucket" "failed_1" {}

resource "awscc_s3_bucket" "failed_2" {
  public_access_block_configuration = null
}

resource "awscc_s3_bucket" "failed_3" {
  public_access_block_configuration = {}
}

resource "awscc_s3_bucket" "failed_4" {
  public_access_block_configuration = {
    block_public_acls = null
  }
}

resource "awscc_s3_bucket" "failed_5" {
  public_access_block_configuration = {
    block_public_acls = false
  }
}`},
)

test_ckv_aws_53_failed if {
	issues := s3.ckv_aws_53 with terraform.resources as not_blocking_public_acls
	count(issues) == 5
	every issue in issues {
		issue.msg == "Ensure S3 bucket has block public ACLs enabled"
	}
}

blocking_public_acls(type, schema, options) := terraform.mock_resources(
	type,
	schema,
	options,
	{"main.tf": `
resource "awscc_s3_bucket" "passed_1" {
  public_access_block_configuration = {
    block_public_acls = true
  }
}`},
)

test_ckv_aws_53_passed if {
	issues := s3.ckv_aws_53 with terraform.resources as blocking_public_acls
	count(issues) == 0
}

# -----
# CKV_AWS_54: Ensure S3 bucket has block public policy enabled
# -----

not_blocking_public_policy(type, schema, options) := terraform.mock_resources(
	type,
	schema,
	options,
	{"main.tf": `
resource "awscc_s3_bucket" "failed_1" {}

resource "awscc_s3_bucket" "failed_2" {
  public_access_block_configuration = null
}

resource "awscc_s3_bucket" "failed_3" {
  public_access_block_configuration = {}
}

resource "awscc_s3_bucket" "failed_4" {
  public_access_block_configuration = {
    block_public_policy = null
  }
}

resource "awscc_s3_bucket" "failed_5" {
  public_access_block_configuration = {
    block_public_policy = false
  }
}`},
)

test_ckv_aws_54_failed if {
	issues := s3.ckv_aws_54 with terraform.resources as not_blocking_public_policy
	count(issues) == 5
	every issue in issues {
		issue.msg == "Ensure S3 bucket has block public policy enabled"
	}
}

blocking_public_policy(type, schema, options) := terraform.mock_resources(
	type,
	schema,
	options,
	{"main.tf": `
resource "awscc_s3_bucket" "passed_1" {
  public_access_block_configuration = {
    block_public_policy = true
  }
}`},
)

test_ckv_aws_54_passed if {
	issues := s3.ckv_aws_54 with terraform.resources as blocking_public_policy
	count(issues) == 0
}

# -----
# CKV_AWS_55: Ensure S3 bucket has ignore public ACLs enabled
# -----

not_ignoring_public_acls(type, schema, options) := terraform.mock_resources(
	type,
	schema,
	options,
	{"main.tf": `
resource "awscc_s3_bucket" "failed_1" {}

resource "awscc_s3_bucket" "failed_2" {
  public_access_block_configuration = null
}

resource "awscc_s3_bucket" "failed_3" {
  public_access_block_configuration = {}
}

resource "awscc_s3_bucket" "failed_4" {
  public_access_block_configuration = {
    ignore_public_acls = null
  }
}

resource "awscc_s3_bucket" "failed_5" {
  public_access_block_configuration = {
    ignore_public_acls = false
  }
}`},
)

test_ckv_aws_55_failed if {
	issues := s3.ckv_aws_55 with terraform.resources as not_ignoring_public_acls
	count(issues) == 5
	every issue in issues {
		issue.msg == "Ensure S3 bucket has ignore public ACLs enabled"
	}
}

ignoring_public_acls(type, schema, options) := terraform.mock_resources(
	type,
	schema,
	options,
	{"main.tf": `
resource "awscc_s3_bucket" "passed_1" {
  public_access_block_configuration = {
    ignore_public_acls = true
  }
}`},
)

test_ckv_aws_55_passed if {
	issues := s3.ckv_aws_55 with terraform.resources as ignoring_public_acls
	count(issues) == 0
}

# -----
# CKV_AWS_56: Ensure S3 bucket has RestrictPublicBuckets enabled
# -----

not_restricting_public_buckets(type, schema, options) := terraform.mock_resources(
	type,
	schema,
	options,
	{"main.tf": `
resource "awscc_s3_bucket" "failed_1" {}

resource "awscc_s3_bucket" "failed_2" {
  public_access_block_configuration = null
}

resource "awscc_s3_bucket" "failed_3" {
  public_access_block_configuration = {}
}

resource "awscc_s3_bucket" "failed_4" {
  public_access_block_configuration = {
    restrict_public_buckets = null
  }
}

resource "awscc_s3_bucket" "failed_5" {
  public_access_block_configuration = {
    restrict_public_buckets = false
  }
}`},
)

test_ckv_aws_56_failed if {
	issues := s3.ckv_aws_56 with terraform.resources as not_restricting_public_buckets
	count(issues) == 5
	every issue in issues {
		issue.msg == "Ensure S3 bucket has RestrictPublicBuckets enabled"
	}
}

restricting_public_buckets(type, schema, options) := terraform.mock_resources(
	type,
	schema,
	options,
	{"main.tf": `
resource "awscc_s3_bucket" "passed_1" {
  public_access_block_configuration = {
    restrict_public_buckets = true
  }
}`},
)

test_ckv_aws_56_passed if {
	issues := s3.ckv_aws_56 with terraform.resources as restricting_public_buckets
	count(issues) == 0
}

# -----
# CKV_AWS_70: Ensure S3 bucket does not allow an action with any Principal
# -----

allows_any_principal(type, schema, options) := terraform.mock_resources(
	type,
	schema,
	options,
	# NOTE: using `jsonencode()` fails to create mock resources, so use here-doc instead.
	{"main.tf": `
resource "awscc_s3_bucket_policy" "failed_1" {
  bucket = ""
  policy_document = <<-EOT
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Principal": "*",
          "Effect": "Allow",
          "Action": "s3:PutObject",
          "Resource": "arn:aws:s3:::amzn-s3-demo-bucket/*"
        }
      ]
    }
  EOT
}

resource "awscc_s3_bucket_policy" "failed_2" {
  bucket = ""
  policy_document = <<-EOT
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Principal": {
            "AWS": "*"
          },
          "Effect": "Allow",
          "Action": "s3:PutObject",
          "Resource": "arn:aws:s3:::amzn-s3-demo-bucket/*"
        }
      ]
    }
  EOT
}

resource "awscc_s3_bucket_policy" "failed_3" {
  bucket = ""
  policy_document = <<-EOT
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Principal": {
            "AWS": ["*"]
          },
          "Effect": "Allow",
          "Action": "s3:PutObject",
          "Resource": "arn:aws:s3:::amzn-s3-demo-bucket/*"
        }
      ]
    }
  EOT
}`},
)

test_ckv_aws_70_failed if {
	issues := s3.ckv_aws_70 with terraform.resources as allows_any_principal
	count(issues) == 3
	every issue in issues {
		issue.msg == "Ensure S3 bucket does not allow an action with any Principal"
	}
}

allows_specific_principal(type, schema, options) := terraform.mock_resources(
	type,
	schema,
	options,
	# NOTE: using `jsonencode()` fails to create mock resources, so use here-doc instead.
	{"main.tf": `
resource "awscc_s3_bucket_policy" "passed_1" {
  bucket = ""
  policy_document = <<-EOT
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Principal": {
            "Service": "logging.s3.amazonaws.com"
          },
          "Effect": "Allow",
          "Action": "s3:PutObject",
          "Resource": "arn:aws:s3:::amzn-s3-demo-bucket/*"
        }
      ]
    }
  EOT
}

resource "awscc_s3_bucket_policy" "passed_2" {
  bucket = ""
  policy_document = <<-EOT
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Principal": "*",
          "Effect": "Deny",
          "Action": "*",
          "Resource": "arn:aws:s3:::amzn-s3-demo-bucket/*"
        }
      ]
    }
  EOT
}`},
)

test_ckv_aws_70_passed if {
	issues := s3.ckv_aws_70 with terraform.resources as allows_specific_principal
	count(issues) == 0
}

# -----
# CKV_AWS_93: Ensure S3 bucket policy does not lockout all but root user. (Prevent lockouts needing root account fixes)
# -----

locked_out_policy(type, schema, options) := terraform.mock_resources(
	type,
	schema,
	options,
	# NOTE: using `jsonencode()` fails to create mock resources, so use here-doc instead.
	{"main.tf": `
resource "awscc_s3_bucket_policy" "failed_1" {
  bucket = ""
  policy_document = <<-EOT
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Principal": "*",
          "Effect": "Deny",
          "Action": "s3:PutBucketPolicy",
          "Resource": "arn:aws:s3:::amzn-s3-demo-bucket"
        }
      ]
    }
  EOT
}

resource "awscc_s3_bucket_policy" "failed_2" {
  bucket = ""
  policy_document = <<-EOT
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Principal": {
            "AWS": "*"
          },
          "Effect": "Deny",
          "Action": "s3:*",
          "Resource": "arn:aws:s3:::amzn-s3-demo-bucket"
        }
      ]
    }
  EOT
}

resource "awscc_s3_bucket_policy" "failed_3" {
  bucket = ""
  policy_document = <<-EOT
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Principal": {
            "AWS": ["*"]
          },
          "Effect": "Deny",
          "Action": "s3:???BucketPolicy",
          "Resource": "arn:aws:s3:::amzn-s3-demo-bucket"
        }
      ]
    }
  EOT
}`},
)

test_ckv_aws_93_failed if {
	issues := s3.ckv_aws_93 with terraform.resources as locked_out_policy
	count(issues) == 3
	every issue in issues {
		issue.msg == "Ensure S3 bucket policy does not lockout all but root user. (Prevent lockouts needing root account fixes)"
	}
}

not_locked_out_policy(type, schema, options) := terraform.mock_resources(
	type,
	schema,
	options,
	# NOTE: using `jsonencode()` fails to create mock resources, so use here-doc instead.
	{"main.tf": `
resource "awscc_s3_bucket_policy" "passed_1" {
  bucket = ""
  policy_document = <<-EOT
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Principal": "*",
          "Effect": "Allow",
          "Action": "s3:???BucketPolicy",
          "Resource": "arn:aws:s3:::amzn-s3-demo-bucket"
        }
      ]
    }
  EOT
}

resource "awscc_s3_bucket_policy" "passed_2" {
  bucket = ""
  policy_document = <<-EOT
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Principal": {
            "AWS": "*"
          },
          "Effect": "Deny",
          "Action": "s3:*",
          "Resource": "arn:aws:s3:::amzn-s3-demo-bucket",
          "Condition": {
            "StringNotEquals": {
              "aws:PrincipalArn": "arn:aws:iam::012345678912:role/Administrator"
            }
          }
        }
      ]
    }
  EOT
}`},
)

test_ckv_aws_93_passed if {
	issues := s3.ckv_aws_93 with terraform.resources as not_locked_out_policy
	count(issues) == 0
}
