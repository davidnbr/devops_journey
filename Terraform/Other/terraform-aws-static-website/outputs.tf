# This is for giving an output when you run terraform plan and apply
output "s3_bucket_name" {
    value = aws_s3_bucket.website_bucket.id
}

output "cloudfront_distribution_domain_name" {
    value = aws_cloudfront_distribution.cloudfront_distribution.domain_name
}