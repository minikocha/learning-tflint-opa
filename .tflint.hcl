plugin "aws" {
  enabled = true
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
  version = "0.45.0"
}

plugin "opa" {
  enabled    = true
  policy_dir = ".tflint.d/policies"
  source     = "github.com/terraform-linters/tflint-ruleset-opa"
  version    = "0.10.0"
}

rule "terraform_required_providers" {
  enabled = false
}

rule "terraform_required_version" {
  enabled = false
}
