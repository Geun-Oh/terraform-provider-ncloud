---
subcategory: "Server"
---


# Data Source: ncloud_server_images

To create a server instance (VM), you should select a server image. This data source gets a list of server images.

## Example Usage

```terraform
data "ncloud_server_images" "images" {
  output_file = "image.json" 
}

output "list_image" {
  value = {
    for image in data.ncloud_server_images.images.server_images:
    image.id => image.product_name
  }
}
```

Outputs: 
```hcl
list_image = {
  "SW.VSVR.OS.LNX64.ROCKY.0810.B050" = "Rocky Linux 8.10"
  "SW.VSVR.OS.WND64.WND.SVR2019EN.B100" = "Windows Server 2019 (64-bit) English Edition"
}
```

## Argument Reference

The following arguments are supported:

* `product_code` - (Optional) Product code you want to view on the list. Use this when searching for 1 product.
* `platform_type` - (Optional) Values required for identifying platform.
  The available values are as follows: Linux 32Bit(LNX32) | Linux 64Bit(LNX64) | Windows 32Bit(WND32) | Windows 64Bit(WND64) | Ubuntu Desktop 64Bit(UBD64) | Ubuntu Server 64Bit(UBS64)
* `infra_resource_detail_type_code` - (Optional) infra resource detail type code.
* `output_file` - (Optional) The name of file that can save data source after running `terraform plan`.
* `filter` - (Optional) Custom filter block as described below.
  * `name` - (Required) The name of the field to filter by
  * `values` - (Required) Set of values that are accepted for the given field.
  * `regex` - (Optional) is `values` treated as a regular expression.

## Attributes Reference

* `ids` - A List of server image product code.
* `server_images` - A List of server image product.

### Server Image Product Reference

`server_images` are also exported with the following attributes, when there are relevant: Each element supports the following:

* `id` - The ID of server image product.
* `product_code` - The ID of server image product. (It is the same result as `id`)
* `product_name` - Product name.
* `product_type` - Product type code.
* `product_description` - Product description.
* `platform_type` - Platform type code.
    The available values are as follows: Linux 32Bit(LNX32) | Linux 64Bit(LNX64) | Windows 32Bit(WND32) | Windows 64Bit(WND64) | Ubuntu Desktop 64Bit(UBD64) | Ubuntu Server 64Bit(UBS64).
* `infra_resource_detail_type_code` - infra resource detail type code.
* `infra_resource_type` - Infra resource type code.
* `base_block_storage_size` - Base block storage size.
* `os_information` - OS Information.
