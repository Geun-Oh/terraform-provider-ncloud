resource "ncloud_nas_volume" "test" {
	volume_name_postfix = "pre"
	volume_size = "500"
	volume_allotment_protocol_type = "NFS"
}