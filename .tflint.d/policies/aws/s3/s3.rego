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

# -----
# CKV_AWS_53: Ensure S3 bucket has block public ACLs enabled
# -----

block_public_acls(config) if {
	not "public_access_block_configuration" in object.keys(config)
}

block_public_acls(config) if {
	config.public_access_block_configuration.value == null
}

block_public_acls(config) if {
	not "block_public_acls" in object.keys(config.public_access_block_configuration.value)
}

block_public_acls(config) if {
	config.public_access_block_configuration.value.block_public_acls == null
}

block_public_acls(config) if {
	config.public_access_block_configuration.value.block_public_acls == false
}

ckv_aws_53 contains issue if {
	some i
	block_public_acls(buckets[i].config)
	issue := tflint.issue("Ensure S3 bucket has block public ACLs enabled", buckets[i].decl_range)
}

# -----
# CKV_AWS_54: Ensure S3 bucket has block public policy enabled
# -----

block_public_policy(config) if {
	not "public_access_block_configuration" in object.keys(config)
}

block_public_policy(config) if {
	config.public_access_block_configuration.value == null
}

block_public_policy(config) if {
	not "block_public_policy" in object.keys(config.public_access_block_configuration.value)
}

block_public_policy(config) if {
	config.public_access_block_configuration.value.block_public_policy == null
}

block_public_policy(config) if {
	config.public_access_block_configuration.value.block_public_policy == false
}

ckv_aws_54 contains issue if {
	some i
	block_public_policy(buckets[i].config)
	issue := tflint.issue("Ensure S3 bucket has block public policy enabled", buckets[i].decl_range)
}
