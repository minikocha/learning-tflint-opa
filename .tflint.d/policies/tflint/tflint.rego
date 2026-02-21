package tflint

import data.aws.iam
import data.aws.s3
import rego.v1

# -----
# IAM
# -----

deny_ckv_aws_60 := iam.ckv_aws_60
deny_ckv_aws_61 := iam.ckv_aws_61

# -----
# S3
# -----

notice_ckv_aws_18 := s3.ckv_aws_18
notice_ckv_aws_21 := s3.ckv_aws_21
warn_ckv_aws_53 := s3.ckv_aws_53
warn_ckv_aws_54 := s3.ckv_aws_54
warn_ckv_aws_55 := s3.ckv_aws_55
warn_ckv_aws_56 := s3.ckv_aws_56
warn_ckv_aws_70 := s3.ckv_aws_70
warn_ckv_aws_93 := s3.ckv_aws_93
