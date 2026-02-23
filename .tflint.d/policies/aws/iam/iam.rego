package aws.iam

import rego.v1

groups := terraform.resources(
	"awscc_iam_group",
	{
		"managed_policy_arns": "list(string)",
		"policies": "list(object({policy_document = string}))",
	},
	{"expand_mode": "none"},
)

group_policies := terraform.resources(
	"awscc_iam_group_policy",
	{"policy_document": "string"},
	{"expand_mode": "none"},
)

managed_policies := terraform.resources(
	"awscc_iam_managed_policy",
	{"policy_document": "string"},
	{"expand_mode": "none"},
)

roles := terraform.resources(
	"awscc_iam_role",
	{
		"assume_role_policy_document": "string",
		"managed_policy_arns": "list(string)",
		"policies": "list(object({policy_document = string}))",
	},
	{"expand_mode": "none"},
)

role_policies := terraform.resources(
	"awscc_iam_role_policy",
	{"policy_document": "string"},
	{"expand_mode": "none"},
)

users := terraform.resources(
	"awscc_iam_user",
	{
		"managed_policy_arns": "list(string)",
		"policies": "list(object({policy_document = string}))",
	},
	{"expand_mode": "none"},
)

user_policies := terraform.resources(
	"awscc_iam_user_policy",
	{"policy_document": "string"},
	{"expand_mode": "none"},
)

# -----
# Functions(has_unconstrained_action)
# -----

has_unconstrained_action(stmt) if {
	"Action" in object.keys(stmt)
	is_array(stmt.Action)
	"*" in stmt.Action
}

has_unconstrained_action(stmt) if {
	"Action" in object.keys(stmt)
	not is_array(stmt.Action)
	stmt.Action == "*"
}

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

# -----
# CKV_AWS_62: "Ensure IAM policies that allow full \"*-*\" administrative privileges are not created"
# -----

has_unconstrained_resource(stmt) if {
	"Resource" in object.keys(stmt)
	is_array(stmt.Resource)
	"*" in stmt.Resource
}

has_unconstrained_resource(stmt) if {
	"Resource" in object.keys(stmt)
	not is_array(stmt.Resource)
	stmt.Resource == "*"
}

ckv_aws_62 contains issue if {
	some i
	"policies" in object.keys(groups[i].config)
	not is_null(groups[i].config.policies.value)
	count(groups[i].config.policies.value) > 0
	doc := json.unmarshal(groups[i].config.policies.value[_].policy_document)
	some stmt in doc.Statement
	stmt.Effect == "Allow"
	has_unconstrained_action(stmt)
	has_unconstrained_resource(stmt)
	issue := tflint.issue(
		"Ensure IAM policies that allow full \"*-*\" administrative privileges are not created",
		groups[i].decl_range,
	)
}

ckv_aws_62 contains issue if {
	some i
	"policy_document" in object.keys(group_policies[i].config)
	not is_null(group_policies[i].config.policy_document.value)
	not group_policies[i].config.policy_document.value == ""
	doc := json.unmarshal(group_policies[i].config.policy_document.value)
	some stmt in doc.Statement
	stmt.Effect == "Allow"
	has_unconstrained_action(stmt)
	has_unconstrained_resource(stmt)
	issue := tflint.issue(
		"Ensure IAM policies that allow full \"*-*\" administrative privileges are not created",
		group_policies[i].decl_range,
	)
}

ckv_aws_62 contains issue if {
	some i
	"policy_document" in object.keys(managed_policies[i].config)
	not is_null(managed_policies[i].config.policy_document.value)
	not managed_policies[i].config.policy_document.value == ""
	doc := json.unmarshal(managed_policies[i].config.policy_document.value)
	some stmt in doc.Statement
	stmt.Effect == "Allow"
	has_unconstrained_action(stmt)
	has_unconstrained_resource(stmt)
	issue := tflint.issue(
		"Ensure IAM policies that allow full \"*-*\" administrative privileges are not created",
		managed_policies[i].decl_range,
	)
}

ckv_aws_62 contains issue if {
	some i
	"policies" in object.keys(roles[i].config)
	not is_null(roles[i].config.policies.value)
	count(roles[i].config.policies.value) > 0
	doc := json.unmarshal(roles[i].config.policies.value[_].policy_document)
	some stmt in doc.Statement
	stmt.Effect == "Allow"
	has_unconstrained_action(stmt)
	has_unconstrained_resource(stmt)
	issue := tflint.issue(
		"Ensure IAM policies that allow full \"*-*\" administrative privileges are not created",
		roles[i].decl_range,
	)
}

ckv_aws_62 contains issue if {
	some i
	"policy_document" in object.keys(role_policies[i].config)
	not is_null(role_policies[i].config.policy_document.value)
	not role_policies[i].config.policy_document.value == ""
	doc := json.unmarshal(role_policies[i].config.policy_document.value)
	some stmt in doc.Statement
	stmt.Effect == "Allow"
	has_unconstrained_action(stmt)
	has_unconstrained_resource(stmt)
	issue := tflint.issue(
		"Ensure IAM policies that allow full \"*-*\" administrative privileges are not created",
		role_policies[i].decl_range,
	)
}

ckv_aws_62 contains issue if {
	some i
	"policies" in object.keys(users[i].config)
	not is_null(users[i].config.policies.value)
	count(users[i].config.policies.value) > 0
	doc := json.unmarshal(users[i].config.policies.value[_].policy_document)
	some stmt in doc.Statement
	stmt.Effect == "Allow"
	has_unconstrained_action(stmt)
	has_unconstrained_resource(stmt)
	issue := tflint.issue(
		"Ensure IAM policies that allow full \"*-*\" administrative privileges are not created",
		users[i].decl_range,
	)
}

ckv_aws_62 contains issue if {
	some i
	"policy_document" in object.keys(user_policies[i].config)
	not is_null(user_policies[i].config.policy_document.value)
	not user_policies[i].config.policy_document.value == ""
	doc := json.unmarshal(user_policies[i].config.policy_document.value)
	some stmt in doc.Statement
	stmt.Effect == "Allow"
	has_unconstrained_action(stmt)
	has_unconstrained_resource(stmt)
	issue := tflint.issue(
		"Ensure IAM policies that allow full \"*-*\" administrative privileges are not created",
		user_policies[i].decl_range,
	)
}

# -----
# CKV_AWS_63: "Ensure no IAM policies documents allow \"*\" as a statement's actions"
# -----

ckv_aws_63 contains issue if {
	some i
	"policies" in object.keys(groups[i].config)
	not is_null(groups[i].config.policies.value)
	count(groups[i].config.policies.value) > 0
	doc := json.unmarshal(groups[i].config.policies.value[_].policy_document)
	some stmt in doc.Statement
	stmt.Effect == "Allow"
	has_unconstrained_action(stmt)
	issue := tflint.issue(
		"Ensure no IAM policies documents allow \"*\" as a statement's actions",
		groups[i].decl_range,
	)
}

ckv_aws_63 contains issue if {
	some i
	"policy_document" in object.keys(group_policies[i].config)
	not is_null(group_policies[i].config.policy_document.value)
	not group_policies[i].config.policy_document.value == ""
	doc := json.unmarshal(group_policies[i].config.policy_document.value)
	some stmt in doc.Statement
	stmt.Effect == "Allow"
	has_unconstrained_action(stmt)
	issue := tflint.issue(
		"Ensure no IAM policies documents allow \"*\" as a statement's actions",
		group_policies[i].decl_range,
	)
}

ckv_aws_63 contains issue if {
	some i
	"policy_document" in object.keys(managed_policies[i].config)
	not is_null(managed_policies[i].config.policy_document.value)
	not managed_policies[i].config.policy_document.value == ""
	doc := json.unmarshal(managed_policies[i].config.policy_document.value)
	some stmt in doc.Statement
	stmt.Effect == "Allow"
	has_unconstrained_action(stmt)
	issue := tflint.issue(
		"Ensure no IAM policies documents allow \"*\" as a statement's actions",
		managed_policies[i].decl_range,
	)
}

ckv_aws_63 contains issue if {
	some i
	"policies" in object.keys(roles[i].config)
	not is_null(roles[i].config.policies.value)
	count(roles[i].config.policies.value) > 0
	doc := json.unmarshal(roles[i].config.policies.value[_].policy_document)
	some stmt in doc.Statement
	stmt.Effect == "Allow"
	has_unconstrained_action(stmt)
	issue := tflint.issue(
		"Ensure no IAM policies documents allow \"*\" as a statement's actions",
		roles[i].decl_range,
	)
}

ckv_aws_63 contains issue if {
	some i
	"policy_document" in object.keys(role_policies[i].config)
	not is_null(role_policies[i].config.policy_document.value)
	not role_policies[i].config.policy_document.value == ""
	doc := json.unmarshal(role_policies[i].config.policy_document.value)
	some stmt in doc.Statement
	stmt.Effect == "Allow"
	has_unconstrained_action(stmt)
	issue := tflint.issue(
		"Ensure no IAM policies documents allow \"*\" as a statement's actions",
		role_policies[i].decl_range,
	)
}

ckv_aws_63 contains issue if {
	some i
	"policies" in object.keys(users[i].config)
	not is_null(users[i].config.policies.value)
	count(users[i].config.policies.value) > 0
	doc := json.unmarshal(users[i].config.policies.value[_].policy_document)
	some stmt in doc.Statement
	stmt.Effect == "Allow"
	has_unconstrained_action(stmt)
	issue := tflint.issue(
		"Ensure no IAM policies documents allow \"*\" as a statement's actions",
		users[i].decl_range,
	)
}

ckv_aws_63 contains issue if {
	some i
	"policy_document" in object.keys(user_policies[i].config)
	not is_null(user_policies[i].config.policy_document.value)
	not user_policies[i].config.policy_document.value == ""
	doc := json.unmarshal(user_policies[i].config.policy_document.value)
	some stmt in doc.Statement
	stmt.Effect == "Allow"
	has_unconstrained_action(stmt)
	issue := tflint.issue(
		"Ensure no IAM policies documents allow \"*\" as a statement's actions",
		user_policies[i].decl_range,
	)
}

# -----
# CKV_AWS_274: "Disallow IAM roles, users, and groups from using the AWS AdministratorAccess policy"
# -----

has_administrator_access_policy(managed_policy_arns) if {
	not is_null(managed_policy_arns)
	some arn in managed_policy_arns
	regex.match(`^arn:(aws|aws-cn|aws-us-gov):iam::aws:policy/AdministratorAccess$`, arn)
}

ckv_aws_274 contains issue if {
	some i
	"managed_policy_arns" in object.keys(groups[i].config)
	has_administrator_access_policy(groups[i].config.managed_policy_arns.value)
	issue := tflint.issue(
		"Disallow IAM roles, users, and groups from using the AWS AdministratorAccess policy",
		groups[i].decl_range,
	)
}

ckv_aws_274 contains issue if {
	some i
	"managed_policy_arns" in object.keys(roles[i].config)
	has_administrator_access_policy(roles[i].config.managed_policy_arns.value)
	issue := tflint.issue(
		"Disallow IAM roles, users, and groups from using the AWS AdministratorAccess policy",
		roles[i].decl_range,
	)
}

ckv_aws_274 contains issue if {
	some i
	"managed_policy_arns" in object.keys(users[i].config)
	has_administrator_access_policy(users[i].config.managed_policy_arns.value)
	issue := tflint.issue(
		"Disallow IAM roles, users, and groups from using the AWS AdministratorAccess policy",
		users[i].decl_range,
	)
}
