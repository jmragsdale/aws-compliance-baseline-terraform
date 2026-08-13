# Two provider configurations are always declared so that the replication
# target region is addressable even when replication is switched off. Terraform
# requires the alias to exist for the module call regardless of `count`.
provider "aws" {
  region = var.primary_region

  default_tags {
    tags = local.common_tags
  }
}

provider "aws" {
  alias  = "replica"
  region = var.replica_region

  default_tags {
    tags = local.common_tags
  }
}
