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

bucket_policies := terraform.resources(
	"awscc_s3_bucket_policy",
	{"policy_document": "string"},
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
# CKV_AWS_21: Ensure the S3 bucket has versioning enabled
# -----

versioning(config) if {
	not "versioning_configuration" in object.keys(config)
}

versioning(config) if {
	config.versioning_configuration.value == null
}

versioning(config) if {
	not config.versioning_configuration.value.status == "Enabled"
}

ckv_aws_21 contains issue if {
	some i
	versioning(buckets[i].config)
	issue := tflint.issue("Ensure the S3 bucket has versioning enabled", buckets[i].decl_range)
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

# -----
# CKV_AWS_55: Ensure S3 bucket has ignore public ACLs enabled
# -----

ckv_aws_55 contains issue if {
	some i
	public_access_block_configuration(buckets[i].config, "ignore_public_acls")
	issue := tflint.issue("Ensure S3 bucket has ignore public ACLs enabled", buckets[i].decl_range)
}

# -----
# CKV_AWS_56: Ensure S3 bucket has RestrictPublicBuckets enabled
# -----

ckv_aws_56 contains issue if {
	some i
	public_access_block_configuration(buckets[i].config, "restrict_public_buckets")
	issue := tflint.issue("Ensure S3 bucket has RestrictPublicBuckets enabled", buckets[i].decl_range)
}

# -----
# CKV_AWS_70: Ensure S3 bucket does not allow an action with any Principal
# -----

allows_any_principal(policy_document) if {
	policy_document.Statement[_].Effect == "Allow"
	policy_document.Statement[_].Principal == "*"
}

allows_any_principal(policy_document) if {
	policy_document.Statement[_].Effect == "Allow"
	is_object(policy_document.Statement[_].Principal)
	"AWS" in object.keys(policy_document.Statement[_].Principal)
	policy_document.Statement[_].Principal.AWS == "*"
}

allows_any_principal(policy_document) if {
	policy_document.Statement[_].Effect == "Allow"
	is_object(policy_document.Statement[_].Principal)
	"AWS" in object.keys(policy_document.Statement[_].Principal)
	is_array(policy_document.Statement[_].Principal.AWS)
	"*" in policy_document.Statement[_].Principal.AWS
}

ckv_aws_70 contains issue if {
	some i
	doc := json.unmarshal(bucket_policies[i].config.policy_document.value)
	allows_any_principal(doc)
	issue := tflint.issue("Ensure S3 bucket does not allow an action with any Principal", bucket_policies[i].decl_range)
}
