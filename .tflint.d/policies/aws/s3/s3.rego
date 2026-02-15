package aws.s3

import rego.v1

buckets := terraform.resources(
	"awscc_s3_bucket",
	{
		"logging_configuration": "any",
		"public_access_block_configuration": "map(bool)",
		"versioning_configuration": "object({status = string})",
	},
	{"expand_mode": "none"},
)

# -----
# CKV_AWS_18: Ensure the S3 bucket has access logging enabled
# -----

access_logs(config) if {
	not "logging_configuration" in object.keys(config)
}

access_logs(config) if {
	config.logging_configuration.value == null
}

ckv_aws_18 contains issue if {
	some i
	access_logs(buckets[i].config)
	issue := tflint.issue("Ensure the S3 bucket has access logging enabled", buckets[i].decl_range)
}
