resource "ncloud_vpc" "test" {
	ipv4_cidr_block    = "10.0.0.0/16"
}

resource "ncloud_subnet" "test" {
	vpc_no             = ncloud_vpc.test.vpc_no
	subnet             = "10.0.0.0/24"
	zone               = local.zone
	network_acl_no     = ncloud_vpc.test.default_network_acl_no
	subnet_type        = "PRIVATE"
	usage_type         = "LOADB"
}

resource "ncloud_lb_target_group" "test" {
  vpc_no   = ncloud_vpc.test.vpc_no
  protocol = "HTTP"
  target_type = "VSVR"
  port        = 8080
  name        = "terraform-testacc-tg"
  description = "for test"

  health_check {
	protocol = "HTTP"
    http_method = "GET"
    port           = 8080
    url_path       = "/monitor/l7check"
    cycle          = 30
    up_threshold   = 2
    down_threshold = 2
  }

  algorithm_type = "RR"
  use_sticky_session = true
}

resource "ncloud_lb" "test" {
    name = "tf-test-lb"
    description = "tf test description"
    network_type = "PRIVATE"
    idle_timeout = 30
    type = "APPLICATION"
    throughput_type = "SMALL"
    subnet_no_list = [ ncloud_subnet.test.subnet_no ]
}