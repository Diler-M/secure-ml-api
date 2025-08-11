variable "aws_region" {
  default = "us-east-1"
}

variable "docker_image" {
  description = "Docker image to deploy"
}

variable "container_port" {
  default = 8000
}
