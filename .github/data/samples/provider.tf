terraform {
  required_providers {
    ncloud = {
      source = "NaverCloudPlatform/ncloud"
    }
  }
}

provider "ncloud" {
  access_key  = local.access_key
  secret_key  = local.secret_key
  region      = local.region
  support_vpc = local.support_vpc
}
