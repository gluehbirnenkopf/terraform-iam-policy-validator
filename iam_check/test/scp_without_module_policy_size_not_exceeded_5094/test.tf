terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

resource "aws_organizations_policy" "demo_scp_long" {
  name        = "security_baseline"
  content     = data.aws_iam_policy_document.long_policy_document.json
  description = "A baseline SCP for Security related controls"
}

data "aws_iam_policy_document" "long_policy_document" {
  statement {
    sid    = "denyTagActionsOnAbacTags"
    effect = "Deny"
    actions = [
      "secretsmanager:Tag*",
      "secretsmanager:Untag*",
      "lambda:Tag*",
      "lambda:Untag*"
    ]
    resources = ["*"]
    condition {
      test = "ForAnyValue:StringEquals"
      values = [
        "ABAC_EXAMPLE_TAG"
      ]
      variable = "aws:TagKeys"
    }
    condition {
      test     = "ArnNotLike"
      values   = [
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName1",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName2",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName3",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName4",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName5",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName6",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName7", 
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName8",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName9",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName10",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName11",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName12",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName13",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName14",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName15",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName16",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName17",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName18",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName19",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName20",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName21",
      ]
      variable = "aws:PrincipalARN"
    }
  }

  statement {
    sid    = "denyTagActionsOnAbacProtectedByScpTag"
    effect = "Deny"
    actions = [
      "secretsmanager:Tag*",
      "secretsmanager:Untag*",
      "lambda:Tag*",
      "lambda:Untag*",
      "ec2:CreateTags",
      "ec2:DeleteTags"
    ]
    resources = ["*"]
    condition {
      test = "ForAnyValue:StringEquals"
      values = [
        "ProtectedBySCP"
      ]
      variable = "aws:TagKeys"
    }
    condition {
      test     = "ArnNotLike"
      values   = [
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName1",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName2",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName3",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName4",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName5",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName6",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName7", 
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName8",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName9",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName10",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName11",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName12",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName13",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName14",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName15",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName16",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName17",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName18",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName19",
        "arn:aws:iam::*:role/ThisIsAnExceptionRoleWithIncredibleLongName20"
      ]
      variable = "aws:PrincipalARN"
    }
  }
}