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
# Functions
# -----

public_access_block_configuration(config, _) if {
	not "public_access_block_configuration" in object.keys(config)
}

public_access_block_configuration(config, _) if {
	config.public_access_block_configuration.value == null
}

public_access_block_configuration(config, property) if {
	not property in object.keys(config.public_access_block_configuration.value)
}

public_access_block_configuration(config, property) if {
	config.public_access_block_configuration.value[property] == null
}

public_access_block_configuration(config, property) if {
	config.public_access_block_configuration.value[property] == false
}

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

ckv_aws_53 contains issue if {
	some i
	public_access_block_configuration(buckets[i].config, "block_public_acls")
	issue := tflint.issue("Ensure S3 bucket has block public ACLs enabled", buckets[i].decl_range)
}

# -----
# CKV_AWS_54: Ensure S3 bucket has block public policy enabled
# -----

ckv_aws_54 contains issue if {
	some i
	public_access_block_configuration(buckets[i].config, "block_public_policy")
	issue := tflint.issue("Ensure S3 bucket has block public policy enabled", buckets[i].decl_range)
}
