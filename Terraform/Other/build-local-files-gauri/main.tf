resource "local_file" "devops" {
    filename = "${path.module}/demo.txt"
    content = "Demo Lecture on Terraform apply cmd"
}

resource "local_sensitive_file" "example" {
    filename = "${path.module}/example.txt"
    #content = "This is a sensitive file"
    source = "${path.module}/demo.txt"
}