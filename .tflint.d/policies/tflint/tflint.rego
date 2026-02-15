package tflint

import data.aws.s3
import rego.v1

# -----
# S3
# -----

deny_ckv_aws_18 := s3.ckv_aws_18
deny_ckv_aws_53 := s3.ckv_aws_53
deny_ckv_aws_54 := s3.ckv_aws_54
