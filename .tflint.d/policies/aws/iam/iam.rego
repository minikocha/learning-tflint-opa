package aws.iam

import rego.v1

roles := terraform.resources(
	"awscc_iam_role",
	{
		"assume_role_policy_document": "string",
		"managed_policy_arns": "list(string)",
		"policies": "list(object({policy_document = string}))",
	},
	{"expand_mode": "none"},
)

# -----
# CKV_AWS_60: "Ensure IAM role allows only specific services or principals to assume it"
# -----

iam_role_allows_public_assume(stmt) if {
	"Principal" in object.keys(stmt)
	is_object(stmt.Principal)
	"AWS" in object.keys(stmt.Principal)
	is_array(stmt.Principal.AWS)
	"*" in stmt.Principal.AWS
}

iam_role_allows_public_assume(stmt) if {
	"Principal" in object.keys(stmt)
	is_object(stmt.Principal)
	"AWS" in object.keys(stmt.Principal)
	not is_array(stmt.Principal.AWS)
	stmt.Principal.AWS == "*"
}

ckv_aws_60 contains issue if {
	some i
	doc := json.unmarshal(roles[i].config.assume_role_policy_document.value)
	some stmt in doc.Statement
	stmt.Effect == "Allow"
	iam_role_allows_public_assume(stmt)
	issue := tflint.issue(
		"Ensure IAM role allows only specific services or principals to assume it",
		roles[i].decl_range,
	)
}

# -----
# CKV_AWS_61: "Ensure AWS IAM policy does not allow assume role permission across all services"
# -----

iam_role_allow_assume_from_account(stmt) if {
	"Principal" in object.keys(stmt)
	is_object(stmt.Principal)
	"AWS" in object.keys(stmt.Principal)
	is_array(stmt.Principal.AWS)
	some aws in stmt.Principal.AWS
	regex.match(`([0-9]{12}|arn:aws:iam::[0-9]{12}:root)`, aws)
}

iam_role_allow_assume_from_account(stmt) if {
	"Principal" in object.keys(stmt)
	is_object(stmt.Principal)
	"AWS" in object.keys(stmt.Principal)
	not is_array(stmt.Principal.AWS)
	regex.match(`([0-9]{12}|arn:aws:iam::[0-9]{12}:root)`, stmt.Principal.AWS)
}

ckv_aws_61 contains issue if {
	some i
	doc := json.unmarshal(roles[i].config.assume_role_policy_document.value)
	some stmt in doc.Statement
	stmt.Effect == "Allow"
	iam_role_allow_assume_from_account(stmt)
	issue := tflint.issue(
		"Ensure AWS IAM policy does not allow assume role permission across all services",
		roles[i].decl_range,
	)
}
