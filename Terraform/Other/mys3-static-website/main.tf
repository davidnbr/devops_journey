# Create S3 bucket
resource "aws_s3_bucket" "mybucket" {
    bucket = var.bucket_name
}

resource "aws_s3_bucket_ownership_controls" "s3_own_control" {
    bucket = aws_s3_bucket.mybucket.id
    rule {
        object_ownership = "BucketOwnerPreferred"
    }
}

resource "aws_s3_bucket_public_access_block" "s3_public_control" {
    bucket = aws_s3_bucket.mybucket.id
    block_public_acls = false
    block_public_policy = false
    ignore_public_acls = false
    restrict_public_buckets = false
}

resource "aws_s3_bucket_acl" "s3_acl" {
    depends_on = [ aws_s3_bucket_ownership_controls.s3_own_control,
                   aws_s3_bucket_public_access_block.s3_public_control ]
    
    bucket = aws_s3_bucket.mybucket.id
    acl = "public-read"
}

# Activate S3 bucket static website hosting
resource "aws_s3_object" "index" {
    bucket = aws_s3_bucket.mybucket.id
    key = "index.html"
    source = "index.html"
    acl = "public-read"
    content_type = "text/html"
}

resource "aws_s3_object" "error" {
    bucket = aws_s3_bucket.mybucket.id
    key = "error.html"
    source = "error.html"
    acl = "public-read"
    content_type = "text/html"
}

resource "aws_s3_object" "style" {
    bucket = aws_s3_bucket.mybucket.id
    key = "style.css"
    source = "style.css"
    acl = "public-read"
    content_type = "text/css"
}

resource "aws_s3_object" "profile" {
    bucket = aws_s3_bucket.mybucket.id
    key = "profile.jpg"
    source = "goku.jpg"
    acl = "public-read"
}

resource "aws_s3_bucket_website_configuration" "website" {
    bucket = aws_s3_bucket.mybucket.id
}