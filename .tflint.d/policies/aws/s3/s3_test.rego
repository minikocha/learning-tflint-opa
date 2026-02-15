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
