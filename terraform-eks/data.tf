# Data sources used across the module
data "aws_availability_zones" "available" {
  state = "available"
}