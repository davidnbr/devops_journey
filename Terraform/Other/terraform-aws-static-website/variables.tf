# Good practice is to have variables in a separate file. This way, you can easily change the values without having to modify the main file.
# Default for S3 bucket is not recommended
variable "bucket_name" {
    type = string
    default = "mybucket-7865a"
    description = "This is the bucket name for S3"
}

variable "website_index_document" {
    type = string
    default = "index.html"
    description = "This is the index document for the website"
}