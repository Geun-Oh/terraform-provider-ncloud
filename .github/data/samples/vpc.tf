resource "ncloud_vpc" "test" {
	name               = "tf-test-vpc"
	ipv4_cidr_block    = "10.16.0.0/16"
}