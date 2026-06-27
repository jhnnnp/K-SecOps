# Intentional misconfiguration for IaC regression (fixture only).
terraform {
  required_version = ">= 1.0"
}

resource "aws_s3_bucket" "customer_pii" {
  bucket = "kb-demo-customer-pii"
}

resource "aws_s3_bucket_acl" "public_acl" {
  bucket = aws_s3_bucket.customer_pii.id
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "disabled" {
  bucket = aws_s3_bucket.customer_pii.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_security_group" "wide_open" {
  name        = "kb-demo-wide-open"
  description = "Intentionally permissive SG for scanner regression"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
