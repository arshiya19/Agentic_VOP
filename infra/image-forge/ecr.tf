# ------------------------------------------------------------------------------
# Test ECR repository — publish target for the hardened base-image slice
# ------------------------------------------------------------------------------
# Scanning on push gives us a second, registry-side opinion in addition to the
# in-pipeline trivy scan. Lifecycle policy expires throwaway build artifacts so
# the test repo doesn't accumulate cost.

resource "aws_ecr_repository" "hardened_base_test" {
  name                 = var.ecr_repository_name
  image_tag_mutability = var.ecr_image_tag_mutability
  force_delete         = true # test repo — allow `terraform destroy` to clean up images

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    Name = var.ecr_repository_name
    Role = "hardened-base-test"
  }
}

# Expire untagged images (every rebuild leaves the previous digest untagged
# when a tag moves) so throwaway iterations don't accumulate indefinitely.
resource "aws_ecr_lifecycle_policy" "hardened_base_test" {
  repository = aws_ecr_repository.hardened_base_test.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images after ${var.ecr_untagged_expire_days} days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = var.ecr_untagged_expire_days
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}
