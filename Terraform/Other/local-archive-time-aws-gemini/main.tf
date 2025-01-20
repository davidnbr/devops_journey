resource "local_file" "aws_configs" {
    content = ""
    filename = "${path.module}/aws_configs/config.tf"
}

data "archive_file" "lambda_zip" {
    type = "zip"
    source_dir = "${path.module}/lambda_code"
    output_file_mode = "0666"
    output_path = "${path.module}/lambda_function.zip"
}

# Add time_sleep resource
resource "time_sleep" "wait_30_seconds" {
    create_duration = "30s"
    depends_on = [aws_lambda_function.hello_world]
}

# Add lambda function resource
resource "aws_lambda_function" "hello_world" {
    filename = "${path.module}/lambda_function.zip"
    function_name = "hello_world_function"
    handler = "lambda_function.lambda_handler"
    runtime = "python3.9"

    #code = filebase64sha256("${path.module}/lambda_function.zip")
    source_code_hash = data.archive_file.lambda_zip.output_base64sha256
    #data.archive_file.lambda_zip.output_base64sha256

    role = aws_iam_role.lambda_role.arn # IAM Role ARN
}

# Add IAM Role resource
resource "aws_iam_role" "lambda_role" {
    name = "lambda_role"

    assume_role_policy = <<EOF
{
    "Version" : "2012-10-17",
    "Statement" : [
        {
            "Action" : "sts:AssumeRole",
            "Principal" : {
                "Service" : "lambda.amazonaws.com"
            },
            "Effect" : "Allow",
            "Sid" : ""
        }
    ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
    role = aws_iam_role.lambda_role.name
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}