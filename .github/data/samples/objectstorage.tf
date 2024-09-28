resource "ncloud_objectstorage_bucket" "testing_bucket" {
  bucket_name = "geunoh-test4"
}

resource "ncloud_objectstorage_bucket_acl" "testing_bucket_acl" {
  bucket_name = ncloud_objectstorage_bucket.testing_bucket.bucket_name
  rule        = "public-read"
}

resource "ncloud_objectstorage_object" "testing_object" {
  bucket = ncloud_objectstorage_bucket.testing_bucket.bucket_name
  key    = "media/test.md"
  source = "./test.md"
}

resource "ncloud_objectstorage_object_acl" "testing_acl" {
  object_id = ncloud_objectstorage_object.testing_object.id
  rule      = "public-read"
}
