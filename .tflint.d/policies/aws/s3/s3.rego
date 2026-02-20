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
# Functions(public_access_block_configuration)
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
# Functions(has_any_principal)
# -----

has_any_principal(stmt) if {
	"Principal" in object.keys(stmt)
	stmt.Principal == "*"
}

has_any_principal(stmt) if {
	"Principal" in object.keys(stmt)
	is_object(stmt.Principal)
	"AWS" in object.keys(stmt.Principal)
	stmt.Principal.AWS == "*"
}

has_any_principal(stmt) if {
	"Principal" in object.keys(stmt)
	is_object(stmt.Principal)
	"AWS" in object.keys(stmt.Principal)
	is_array(stmt.Principal.AWS)
	"*" in stmt.Principal.AWS
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

ckv_aws_70 contains issue if {
	some i
	doc := json.unmarshal(bucket_policies[i].config.policy_document.value)
	some stmt in doc.Statement
	stmt.Effect == "Allow"
	has_any_principal(stmt)
	issue := tflint.issue("Ensure S3 bucket does not allow an action with any Principal", bucket_policies[i].decl_range)
}

# -----
# CKV_AWS_93: Ensure S3 bucket policy does not lockout all but root user. (Prevent lockouts needing root account fixes)
# -----

# NOTE: 完全にチェックするなら下記パターンも確認すべきだが、checkovに倣って確認していない。
#   - NotPrincipalに"*"が含まれるパターン
#   - NotActionでs3:PutBucketPolicyを含まないパターン

# NOTE: NotPrincipalを考慮する場合は以下のように実装する。
#
# has_any_principal(stmt) if {
# 	"NotPrincipal" in object.keys(stmt)
# 	stmt.NotPrincipal == "*"
# }
#
# has_any_principal(stmt) if {
# 	"NotPrincipal" in object.keys(stmt)
# 	is_object(stmt.NotPrincipal)
# 	"AWS" in object.keys(stmt.NotPrincipal)
# 	stmt.NotPrincipal.AWS == "*"
# }
#
# has_any_principal(stmt) if {
# 	"NotPrincipal" in object.keys(stmt)
# 	is_object(stmt.NotPrincipal)
# 	"AWS" in object.keys(stmt.NotPrincipal)
# 	is_array(stmt.NotPrincipal.AWS)
# 	"*" in stmt.NotPrincipal.AWS
# }

has_put_bucket_policy_permission(stmt) if {
	"Action" in object.keys(stmt)
	is_array(stmt.Action)
	some action in stmt.Action
	replaced := regex.replace(regex.replace(sprintf("^%s$", [action]), `\?`, `.`), `(\*)`, `.$1`)
	regex.match(replaced, "s3:PutBucketPolicy")
}

has_put_bucket_policy_permission(stmt) if {
	"Action" in object.keys(stmt)
	not is_array(stmt.Action)
	replaced := regex.replace(regex.replace(sprintf("^%s$", [stmt.Action]), `\?`, `.`), `(\*)`, `.$1`)
	regex.match(replaced, "s3:PutBucketPolicy")
}

# NOTE: NotActionを考慮する場合は以下のように実装する。
#
# has_put_bucket_policy_permission(stmt) if {
# 	"NotAction" in object.keys(stmt)
# 	is_array(stmt.NotAction)
# 	some not_action in stmt.NotAction
#   replaced := regex.replace(regex.replace(sprintf("^%s$", [not_action]), `\?`, `.`), `(\*)`, `.$1`)
# 	not regex.match(replaced, "s3:PutBucketPolicy")
# }
#
# has_put_bucket_policy_permission(stmt) if {
# 	"NotAction" in object.keys(stmt)
# 	not is_array(stmt.NotAction)
#   replaced := regex.replace(regex.replace(sprintf("^%s$", [stmt.NotAction]), `\?`, `.`), `(\*)`, `.$1`)
# 	not regex.match(replaced, "s3:PutBucketPolicy")
# }

ckv_aws_93 contains issue if {
	some i
	doc := json.unmarshal(bucket_policies[i].config.policy_document.value)
	some stmt in doc.Statement
	not "Condition" in object.keys(stmt)
	stmt.Effect == "Deny"
	has_any_principal(stmt)
	has_put_bucket_policy_permission(stmt)
	issue := tflint.issue(
		"Ensure S3 bucket policy does not lockout all but root user. (Prevent lockouts needing root account fixes)",
		bucket_policies[i].decl_range,
	)
}
