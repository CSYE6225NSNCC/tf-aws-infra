resource "aws_vpc" "my_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "Amruta_VPC"
  }
}

resource "aws_internet_gateway" "my_igw" {
  vpc_id = aws_vpc.my_vpc.id

  tags = {
    Name = "Amruta_InternetGateway"
  }
}

resource "aws_subnet" "public_subnet" {
  count             = length(var.public_subnet_cidrs)
  vpc_id            = aws_vpc.my_vpc.id
  cidr_block        = var.public_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = {
    Name = "Amruta_PublicSubnet${count.index + 1}"
    Type = "Public"
  }
}

resource "aws_subnet" "private_subnet" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.my_vpc.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = {
    Name = "Amruta_PrivateSubnet${count.index + 1}"
    Type = "Private"
  }
}

resource "aws_route_table" "public_route_table" {
  vpc_id = aws_vpc.my_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.my_igw.id
  }

  tags = {
    Name = "Amruta_PublicRouteTable"
  }
}

resource "aws_route_table_association" "public_association" {
  count          = length(var.public_subnet_cidrs)
  subnet_id      = aws_subnet.public_subnet[count.index].id
  route_table_id = aws_route_table.public_route_table.id
}

resource "aws_route_table" "private_route_table" {
  vpc_id = aws_vpc.my_vpc.id

  tags = {
    Name = "Amruta_PrivateRouteTable"
  }
}

resource "aws_route_table_association" "private_association" {
  count          = length(var.private_subnet_cidrs)
  subnet_id      = aws_subnet.private_subnet[count.index].id
  route_table_id = aws_route_table.private_route_table.id
}


# Create Application Security Group
resource "aws_security_group" "app_sg" {
  name        = "application_security_group"
  description = "Security group for web application EC2 instances"
  vpc_id      = aws_vpc.my_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = var.application_port
    to_port     = var.application_port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}


#s3 bucket

resource "aws_s3_bucket" "my_bucket" {
  bucket        = uuid()
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "block_public_access" {
  bucket = aws_s3_bucket.my_bucket.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "my_bucket_encryption" {
  bucket = aws_s3_bucket.my_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "my_bucket_lifecycle" {
  bucket = aws_s3_bucket.my_bucket.id

  rule {
    id     = "transition-to-standard-ia"
    status = "Enabled" # Specify the status of the rule

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    # Optionally, you can set expiration
    # expiration {
    #   days = 365
    # }
  }
}

# Create IAM Role for EC2 instances with S3 and CloudWatch permissions
resource "aws_iam_role" "ec2_role" {
  name = "EC2S3CloudWatchRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Effect = "Allow"
        Sid    = ""
      },
    ]
  })
}

resource "aws_iam_policy" "custom_s3_policy" {
  name        = "CustomS3Policy"
  description = "Custom policy for S3 access to manage photos"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = [
          "arn:aws:s3:::${aws_s3_bucket.my_bucket.id}",
          "arn:aws:s3:::${aws_s3_bucket.my_bucket.id}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_policy" "custom_cloudwatch_agent_policy" {
  name        = "CustomCloudWatchAgentPolicy"
  description = "Custom policy for CloudWatch Agent access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData",
          "cloudwatch:GetMetricData",
          "cloudwatch:ListMetrics"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "custom_cloudwatch_logs_policy" {
  name        = "CustomCloudWatchLogsPolicy"
  description = "Custom policy for CloudWatch Logs access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:GetLogEvents",
          "logs:DescribeLogStreams",
          "logs:DescribeLogGroups"
        ]
        Resource = "*"
      }
    ]
  })
}


# Attach the custom policies to the IAM role
resource "aws_iam_role_policy_attachment" "s3_policy_attachment" {
  policy_arn = aws_iam_policy.custom_s3_policy.arn
  role       = aws_iam_role.ec2_role.name
}

resource "aws_iam_role_policy_attachment" "cloudwatch_agent_policy_attachment" {
  policy_arn = aws_iam_policy.custom_cloudwatch_agent_policy.arn
  role       = aws_iam_role.ec2_role.name
}

resource "aws_iam_role_policy_attachment" "cloudwatch_logs_policy_attachment" {
  policy_arn = aws_iam_policy.custom_cloudwatch_logs_policy.arn
  role       = aws_iam_role.ec2_role.name
}

# Create IAM Instance Profile
resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "EC2InstanceProfile"
  role = aws_iam_role.ec2_role.name
}

# Create EC2 Instance
resource "aws_instance" "web_app_instance" {
  ami                         = var.custom_ami_id
  instance_type               = var.instance_type
  associate_public_ip_address = true
  security_groups             = [aws_security_group.app_sg.id]
  subnet_id                   = aws_subnet.public_subnet[0].id
  key_name                    = var.key_name

  # Attach the IAM Instance Profile here
  iam_instance_profile = aws_iam_instance_profile.ec2_instance_profile.name

  user_data = <<-EOF
                #!/bin/bash

                # Create a new file named webapp.env in /etc

                sudo chmod 600 /etc/webapp.env
                sudo chown root:root /etc/webapp.env

                echo "DB_HOST=${aws_db_instance.csye6225.address}" >> /etc/webapp.env
                echo "DB_USER=${var.db_username}" >> /etc/webapp.env
                echo "DB_PASSWORD=${var.db_password}" >> /etc/webapp.env
                echo "DB_NAME=${var.db_name}" >> /etc/webapp.env
                echo "S3_BUCKET_NAME=${aws_s3_bucket.my_bucket.bucket}" >> /etc/webapp.env
                echo "AWS_REGION=${var.aws_region}" >> /etc/webapp.env
                
                #Start cloudwatch agent with config file
                sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
                    -a fetch-config \
                    -m ec2 \
                    -c file:/opt/aws/amazon-cloudwatch-agent/etc/cwagent-config.json \
                    -s

                #Start cloud watch agent
                /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a start

                sudo systemctl daemon-reload
                sudo systemctl enable webapp.service
                sleep 30
                sudo systemctl restart webapp.service

              EOF

  root_block_device {
    volume_size           = 25
    volume_type           = "gp2"
    delete_on_termination = true
  }

  tags = {
    Name = "WebAppInstance"
  }
}


resource "aws_security_group" "db_security_group" {
  name        = "DBSecurityGroup"
  description = "Security group for RDS instances to allow access from application security group"
  vpc_id      = aws_vpc.my_vpc.id

  ingress {
    from_port       = 3306 # MySQL port
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.app_sg.id]
  }


  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"          # Allow all outbound traffic
    cidr_blocks = ["0.0.0.0/0"] # Modify as per your requirements
  }
}



# Create RDS Parameter Group
resource "aws_db_parameter_group" "my_db_parameter_group" {
  name        = "my-db-parameter-group"
  family      = "mysql8.0" # Change according to your DB engine/version
  description = "Custom parameter group for MySQL"

  parameter {
    name  = "max_connections"
    value = "200" # Example parameter, adjust as necessary
  }
}

# Create RDS Instance
resource "aws_db_instance" "csye6225" {
  identifier             = "csye6225"
  engine                 = "mysql"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  db_name                = var.db_name
  username               = var.db_username
  password               = var.db_password
  db_subnet_group_name   = aws_db_subnet_group.my_private_subnet_group.name
  vpc_security_group_ids = [aws_security_group.db_security_group.id]
  multi_az               = false
  publicly_accessible    = false

  tags = {
    Name = "CSYE6225 RDS Instance"
  }

  skip_final_snapshot = true
}

# RDS Subnet Group
resource "aws_db_subnet_group" "my_private_subnet_group" {
  name       = "my-private-subnet-group"
  subnet_ids = aws_subnet.private_subnet[*].id

  tags = {
    Name = "Private Subnet Group for RDS"
  }
}

# Data source to find the existing Route 53 hosted zone
#data "aws_route53_zone" "my_zone" {
#  name = var.domain_name
#}

# Create Route 53 A Record for the application
resource "aws_route53_record" "app_record" {
  zone_id    = var.zone_id     #data.aws_route53_zone.my_zone.id
  name       = var.domain_name # e.g., dev.your-domain-name.tld
  type       = "A"
  ttl        = 60
  records    = [aws_instance.web_app_instance.public_ip]
  depends_on = [aws_instance.web_app_instance]
}