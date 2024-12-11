resource "ncloud_vpc" "vpc" {
	name               = "test-ses-vpc"
	ipv4_cidr_block    = "172.16.0.0/16"
}

resource "ncloud_subnet" "node_subnet" {
	vpc_no             = ncloud_vpc.vpc.vpc_no
	name               = "tf-ses-subnet"
	subnet             = "172.16.1.0/24"
	zone               = "KR-1"
	network_acl_no     = ncloud_vpc.vpc.default_network_acl_no
	subnet_type        = "PRIVATE"
	usage_type         = "GEN"
}
data "ncloud_ses_versions" "version" {
}

data "ncloud_ses_node_os_images" "os_images" {
}

data "ncloud_ses_node_products" "product_codes" {
  os_image_code = data.ncloud_ses_node_os_images.os_images.images.0.id
  subnet_no = ncloud_subnet.node_subnet.id
}

resource "ncloud_login_key" "loginkey" {
  key_name = "tf-ses-loginkey"
}

resource "ncloud_ses_cluster" "cluster" {
  cluster_name                  = "tf-ses-cluster"
  os_image_code         		= data.ncloud_ses_node_os_images.os_images.images.0.id
  vpc_no                        = ncloud_vpc.vpc.id
  search_engine {
	  version_code    			= "133"
	  user_name       			= "admin"
	  user_password   			= "qwe123!@#"
      dashboard_port            = "5601"
  }
  manager_node {
	  is_dual_manager           = false
	  product_code     			= data.ncloud_ses_node_products.product_codes.codes.0.id
	  subnet_no        			= ncloud_subnet.node_subnet.id
  }
  data_node {
	  product_code       		= data.ncloud_ses_node_products.product_codes.codes.0.id
	  subnet_no           		= ncloud_subnet.node_subnet.id
	  count            		    = 3
	  storage_size        		= 100
  }
  login_key_name                = ncloud_login_key.loginkey.key_name
}