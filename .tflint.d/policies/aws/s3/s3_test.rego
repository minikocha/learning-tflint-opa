package aws.s3_test

import data.aws.s3
import rego.v1

# -----
# CKV_AWS_18: Ensure the S3 bucket has access logging enabled
# -----

non_logging_buckets(type, schema, options) := terraform.mock_resources(
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
	issues := s3.ckv_aws_18 with terraform.resources as non_logging_buckets
	count(issues) == 2
	some issue in issues
	issue.msg == "Ensure the S3 bucket has access logging enabled"
}

logging_buckets(type, schema, options) := terraform.mock_resources(
	type,
	schema,
	options,
	{"main.tf": `
resource "awscc_s3_bucket" "passed_1" {
  logging_configuration = {}
}`},
)

test_ckv_aws_18_passed if {
	issues := s3.ckv_aws_18 with terraform.resources as logging_buckets
	count(issues) == 0
}

# -----
# CKV_AWS_53: Ensure S3 bucket has block public ACLs enabled
# -----

non_blocking_public_acls_buckets(type, schema, options) := terraform.mock_resources(
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
	issues := s3.ckv_aws_53 with terraform.resources as non_blocking_public_acls_buckets
	count(issues) == 5
	some issue in issues
	issue.msg == "Ensure S3 bucket has block public ACLs enabled"
}

blocking_public_acls_buckets(type, schema, options) := terraform.mock_resources(
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
	issues := s3.ckv_aws_53 with terraform.resources as blocking_public_acls_buckets
	count(issues) == 0
}
