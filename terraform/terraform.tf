terraform {
  required_version = ">= 1.15"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.7"
    }
  }

  # Remote state in S3. Point this at a bucket you control.
  # Create it once before first apply:
  #   aws s3 mb s3://REPLACE_ME-terraform-state --region us-east-1
  # Or supply these values at init time with:
  #   terraform init -backend-config=backend.hcl
  backend "s3" {
    bucket       = "REPLACE_ME-terraform-state"
    key          = "library-dependency-explorer/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true # native S3 conditional-write locking (no DynamoDB needed)
  }
}

