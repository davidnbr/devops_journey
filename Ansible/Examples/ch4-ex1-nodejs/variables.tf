# Database variables
variable "db_name" {
  description = "Database name"
  type        = string
  default     = "test_db"
}

variable "db_user" {
  description = "Database user"
  type        = string
  sensitive   = true
}
