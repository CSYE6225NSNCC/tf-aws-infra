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
    from_port       = var.application_port
    to_port         = var.application_port
    protocol        = "tcp"
    security_groups = [aws_security_group.load_balancer_sg.id]
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
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_key.id
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

resource "aws_iam_policy" "custom_secrets_manager_policy" {
  name        = "CustomSecretsManagerPolicy"
  description = "Policy to allow EC2 access to Secrets Manager and KMS decryption"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ],
        Resource = [
          aws_secretsmanager_secret.db_password_secret.arn,
          aws_secretsmanager_secret.email_credentials_secret.arn
        ]
      },
      {
        Effect = "Allow",
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ],
        Resource = aws_kms_key.secrets_key.arn
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

resource "aws_iam_role_policy_attachment" "secrets_manager_policy_attachment" {
  policy_arn = aws_iam_policy.custom_secrets_manager_policy.arn
  role       = aws_iam_role.ec2_role.name
}

resource "aws_iam_role_policy_attachment" "asg_policy_attachment" {
  policy_arn = aws_iam_policy.asg_policy.arn
  role       = aws_iam_role.ec2_role.name
}

# Create IAM Instance Profile
resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "EC2InstanceProfile"
  role = aws_iam_role.ec2_role.name
}

#Launch Template
resource "aws_launch_template" "web_app_template" {
  name          = var.launch_template
  image_id      = var.custom_ami_id
  instance_type = "t2.micro"
  key_name      = var.key_name
  user_data = base64encode(<<-EOF
                  #!/bin/bash
                  # Install required dependencies
                    sudo apt-get install -y curl jq

                  # Install AWS CLI v2
                    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
                    unzip awscliv2.zip
                    sudo ./aws/install

                  # Clean up installation files
                    rm -rf aws awscliv2.zip

                  # Verify installations
                    aws --version
                    jq --version

                  # Error logging and debugging
                    exec > >(tee /var/log/user-data.log) 2>&1

                  # Create a new file named webapp.env in /etc

                    sudo chmod 600 /etc/webapp.env
                    sudo chown root:root /etc/webapp.env

                    echo "DB_HOST=${aws_db_instance.csye6225.address}" >> /etc/webapp.env
                    echo "DB_USER=${var.db_username}" >> /etc/webapp.env
                    DB_SECRET=$(aws secretsmanager get-secret-value --secret-id ${aws_secretsmanager_secret.db_password_secret.id} --query SecretString --output text)

                    # Parse the JSON and extract the password with error handling
                    DB_PASSWORD=$(echo "$DB_SECRET" | jq -r '.password // empty')

                    echo "DB_PASSWORD=$DB_PASSWORD" >> /etc/webapp.env
                    echo "DB_NAME=${var.db_name}" >> /etc/webapp.env
                    echo "S3_BUCKET_NAME=${aws_s3_bucket.my_bucket.bucket}" >> /etc/webapp.env
                    echo "AWS_REGION=${var.aws_region}" >> /etc/webapp.env
                    echo "VERIFICATION_TOPIC_ARN=${aws_sns_topic.user_verification_topic.arn}" >> /etc/webapp.env
                    
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
  )
  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_instance_profile.name
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = var.root_volume_size
      volume_type           = var.root_volume_type
      delete_on_termination = true
      kms_key_id            = aws_kms_key.ec2_key.arn
      encrypted             = true
    }
  }

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.app_sg.id]
  }
  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "webapp-instance"
    }
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
  password               = random_password.db_password.result
  db_subnet_group_name   = aws_db_subnet_group.my_private_subnet_group.name
  vpc_security_group_ids = [aws_security_group.db_security_group.id]
  multi_az               = false
  publicly_accessible    = false
  storage_encrypted      = true
  kms_key_id             = aws_kms_key.rds_key.arn

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

# Create Route 53 A Record for the application
//resource "aws_route53_record" "app_record" {
//  zone_id = var.zone_id     #data.aws_route53_zone.my_zone.id
//  name    = var.domain_name # e.g., dev.your-domain-name.tld
//  type    = "A"
//TTL      = 60
# records    = [aws_instance.web_app_instance.public_ip] //Commented after creating launch template and removing ec2 instance
# depends_on = [aws_instance.web_app_instance] //Commented after creating launch template and removing ec2 instance
//  alias {
//    name                   = aws_lb.my_lb.dns_name
//    zone_id                = aws_lb.my_lb.zone_id
//    evaluate_target_health = true
//  }
//}

#Load balancer security group
resource "aws_security_group" "load_balancer_sg" {
  name        = "load_balancer_sg"
  description = "Security group for the load balancer"
  vpc_id      = aws_vpc.my_vpc.id

  ingress {
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"] # Allow traffic from anywhere
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1" # Allow all outbound traffic
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "LoadBalancerSecurityGroup"
  }
}

#load balancer
resource "aws_lb" "my_lb" {
  name               = "my-load-balancer"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.load_balancer_sg.id] # Attach security group here
  subnets            = aws_subnet.public_subnet[*].id

  enable_deletion_protection = false
}

#Auto Scaling Group that utilizes the Launch Template just created
resource "aws_autoscaling_group" "web_app_asg" {
  name                = var.asg
  desired_capacity    = var.desired_capacity # Desired number of instances
  min_size            = var.min_size         # Minimum number of instances
  max_size            = var.max_size         # Maximum number of instances
  vpc_zone_identifier = aws_subnet.public_subnet[*].id

  launch_template {
    id      = aws_launch_template.web_app_template.id
    version = "$Latest"

  }

  # Attach the target group to the Auto Scaling Group 
  target_group_arns = [aws_lb_target_group.web_app_target_group.arn]

  # Add tags for the instances
  tag {
    key                 = "Name"
    value               = "WebAppInstance"
    propagate_at_launch = true
  }

  health_check_type         = "EC2"
  health_check_grace_period = var.health_check_grace_period
}

#Define a target group for the load balancer to connect Auto Scaling Group with the load balancer
resource "aws_lb_target_group" "web_app_target_group" {
  name     = "web-app-target-group"
  port     = var.application_port
  protocol = "HTTP"
  vpc_id   = aws_vpc.my_vpc.id

  health_check {
    path                = "/healthz"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 3
    unhealthy_threshold = 2
  }
  tags = {
    Name = "WebAppTargetGroup"
  }
}

data "aws_acm_certificate" "imported_certificate" {
  domain = var.domain_name

  # Optional: If you have multiple certificates, use this to ensure the correct one is fetched.
  statuses    = ["ISSUED"]
  types       = ["IMPORTED"]
  most_recent = true
}


resource "aws_lb_listener" "https_listener" {
  load_balancer_arn = aws_lb.my_lb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = data.aws_acm_certificate.imported_certificate.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web_app_target_group.arn
  }
}


#create a listener for the load balancer that routes traffic to target group

#resource "aws_lb_listener" "http_listener" {
#  load_balancer_arn = aws_lb.my_lb.arn
#  port              = 80
#  protocol          = "HTTP"

#  default_action {
#    type             = "forward"
#    target_group_arn = aws_lb_target_group.web_app_target_group.arn
#  }
#}


#create two CloudWatch alarms: one for scaling up and one for scaling down
resource "aws_cloudwatch_metric_alarm" "scale_up_alarm" {
  alarm_name          = "scale-up-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = var.period
  statistic           = var.statistic
  threshold           = var.scale_up_threshold
  alarm_description   = "Alarm when CPU exceeds 5%"
  alarm_actions       = [aws_autoscaling_policy.scale_up_policy.arn]

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.web_app_asg.name
  }
}

resource "aws_cloudwatch_metric_alarm" "scale_down_alarm" {
  alarm_name          = "scale-down-alarm"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = var.period
  statistic           = var.statistic
  threshold           = var.scale_down_threshold
  alarm_description   = "Alarm when CPU is below 3%"
  alarm_actions       = [aws_autoscaling_policy.scale_down_policy.arn]

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.web_app_asg.name
  }
}

#define the scaling policies that will be triggered by the alarms
resource "aws_autoscaling_policy" "scale_up_policy" {
  name                   = "scale-up-policy"
  adjustment_type        = var.adjustment_type
  scaling_adjustment     = 1
  cooldown               = 60
  autoscaling_group_name = aws_autoscaling_group.web_app_asg.name
  policy_type            = var.policy_type
}

resource "aws_autoscaling_policy" "scale_down_policy" {
  name                   = "scale-down-policy"
  adjustment_type        = var.adjustment_type
  scaling_adjustment     = -1
  cooldown               = 60
  autoscaling_group_name = aws_autoscaling_group.web_app_asg.name
  policy_type            = var.policy_type
}

resource "aws_iam_role" "asg_role" {
  name = "ASGRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Principal = {
          Service = "ec2.amazonaws.com"
        },
        Effect = "Allow",
        Sid    = ""
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "asg_role_policy_attachment" {
  role       = aws_iam_role.asg_role.name
  policy_arn = aws_iam_policy.asg_policy.arn
}

resource "aws_iam_instance_profile" "asg_instance_profile" {
  name = "ASGInstanceProfile"
  role = aws_iam_role.asg_role.name
}


# Define the SNS Topic
resource "aws_sns_topic" "user_verification_topic" {
  name = "user-verification-topic"
}

output "user_verification_topic_arn" {
  value = aws_sns_topic.user_verification_topic.arn
}


resource "aws_sns_topic_policy" "verification_topic_policy" {
  arn = aws_sns_topic.user_verification_topic.arn

  policy = jsonencode({
    Version = "2012-10-17",
    Id      = "EmailVerificationTopicPolicy",
    Statement = [
      {
        Sid    = "AllowLambdaToPublish",
        Effect = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        },
        Action   = "sns:Publish",
        Resource = aws_sns_topic.user_verification_topic.arn,
        Condition = {
          ArnLike : {
            "AWS:SourceArn" : aws_lambda_function.user_verification_lambda.arn
          }
        }
      },
      {
        Sid    = "AllowSpecificIAMRoleToPublish",
        Effect = "Allow",
        Principal = {
          AWS = aws_iam_role.ec2_role.arn
        },
        Action   = "sns:Publish",
        Resource = aws_sns_topic.user_verification_topic.arn
      }
    ]
  })
}

resource "aws_lambda_function" "user_verification_lambda" {
  function_name = "UserVerificationLambda"
  role          = aws_iam_role.lambda_execution_role.arn
  handler       = "index.handler"
  runtime       = "nodejs18.x"
  timeout       = 120
  memory_size   = 128
  # Ensure your Lambda zip file exists or use S3 for deployment
  filename = "C:/Users/Amruta/OneDrive/Documents/Northeastern University/Semester 2/Cloud/Assignments/Assignment 9/serverless-fork/verification-lambda.zip"

}

resource "aws_iam_role" "lambda_execution_role" {
  name = "LambdaExecutionRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action    = "sts:AssumeRole",
        Principal = { Service = "lambda.amazonaws.com" },
        Effect    = "Allow"
      }
    ]
  })
}

resource "aws_iam_policy" "lambda_policy" {
  name        = "LambdaSNSRDSPolicy"
  description = "Policy for Lambda to access SNS, RDS, and EC2 for VPC connectivity"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = ["secretsmanager:GetSecretValue"],
        Resource = aws_secretsmanager_secret.email_credentials_secret.arn
      },
      {
        Effect   = "Allow",
        Action   = ["sns:Publish"],
        Resource = aws_sns_topic.user_verification_topic.arn
      },
      {
        Effect = "Allow",
        Action = [
          "rds-db:connect",
          "rds:DescribeDBInstances",
        ],
        Resource = aws_db_instance.csye6225.arn
      },
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_policy_attachment" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

#Create SNS Topic Subscription to Lambda
resource "aws_sns_topic_subscription" "sns_lambda_subscription" {
  topic_arn = aws_sns_topic.user_verification_topic.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.user_verification_lambda.arn
}

#Allow SNS to Invoke Lambda
resource "aws_lambda_permission" "allow_sns_invocation" {
  statement_id  = "AllowSNSInvoke"
  action        = "lambda:InvokeFunction"
  principal     = "sns.amazonaws.com"
  function_name = aws_lambda_function.user_verification_lambda.function_name
  source_arn    = aws_sns_topic.user_verification_topic.arn
}


resource "aws_kms_key" "ec2_key" {
  description         = "KMS key for encrypting EC2 volumes with full administrative access"
  enable_key_rotation = true
  key_usage           = "ENCRYPT_DECRYPT"

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [{
      "Sid" : "Enable IAM User Permissions",
      "Effect" : "Allow",
      "Principal" : {
        "AWS" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      },
      "Action" : "kms:*",
      "Resource" : "*"
      },
      {
        "Sid" : "Allow service-linked role use of the customer managed key",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : [
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
          ]
        },
        "Action" : [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        "Resource" : "*"
      },
      {
        "Sid" : "Allow attachment of persistent resources",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : [
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
          ]
        },
        "Action" : [
          "kms:CreateGrant"
        ],
        "Resource" : "*",
        "Condition" : {
          "Bool" : {
            "kms:GrantIsForAWSResource" : true
          }
        }
      }
    ] }
  )
}


resource "aws_kms_key" "rds_key" {
  description         = "KMS key for encrypting RDS instance"
  enable_key_rotation = true
  key_usage           = "ENCRYPT_DECRYPT"

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [{
      "Sid" : "Enable IAM User Permissions",
      "Effect" : "Allow",
      "Principal" : {
        "AWS" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      },
      "Action" : "kms:*",
      "Resource" : "*"
      },
      {
        "Sid" : "Allow service-linked role use of the customer managed key",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : [
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
          ]
        },
        "Action" : [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        "Resource" : "*"
      },
      {
        "Sid" : "Allow attachment of persistent resources",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : [
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
          ]
        },
        "Action" : [
          "kms:CreateGrant"
        ],
        "Resource" : "*",
        "Condition" : {
          "Bool" : {
            "kms:GrantIsForAWSResource" : true
          }
        }
      }
    ] }
  )
}

resource "aws_kms_key" "s3_key" {
  description         = "KMS key for encrypting S3 buckets"
  enable_key_rotation = true
  key_usage           = "ENCRYPT_DECRYPT"

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [{
      "Sid" : "Enable IAM User Permissions",
      "Effect" : "Allow",
      "Principal" : {
        "AWS" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      },
      "Action" : "kms:*",
      "Resource" : "*"
      },
      {
        "Sid" : "Allow service-linked role use of the customer managed key",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : [
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
          ]
        },
        "Action" : [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        "Resource" : "*"
      },
      {
        "Sid" : "Allow attachment of persistent resources",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : [
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
          ]
        },
        "Action" : [
          "kms:CreateGrant"
        ],
        "Resource" : "*",
        "Condition" : {
          "Bool" : {
            "kms:GrantIsForAWSResource" : true
          }
        }
      }
    ] }
  )
}

resource "aws_kms_key" "secrets_key" {
  description         = "KMS key for encrypting Secrets Manager secrets"
  enable_key_rotation = true
  key_usage           = "ENCRYPT_DECRYPT"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid       = "AllowAdminFullAccess",
        Effect    = "Allow",
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" },
        Action    = "kms:*",
        Resource  = "*"
      },
      {
        Sid    = "AllowSecretsManagerAccess",
        Effect = "Allow",
        Principal = {
          AWS = [
            "${aws_iam_role.lambda_execution_role.arn}",
            "${aws_iam_role.ec2_role.arn}"
          ]
        },
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:ReEncrypt*"
        ],
        Resource = "*"
      }
    ]
  })
}

output "kms_keys" {
  value = {
    ec2_key     = aws_kms_key.ec2_key.arn
    rds_key     = aws_kms_key.rds_key.arn
    s3_key      = aws_kms_key.s3_key.arn
    secrets_key = aws_kms_key.secrets_key.arn
  }
}

data "aws_caller_identity" "current" {}

# Generate database password
resource "random_password" "db_password" {
  length           = 16
  special          = true
  override_special = "!#$%&()*+,-.:;<=>?[]^_`{|}~" # Exclude invalid characters
}

# Store database password in Secrets Manager
resource "aws_secretsmanager_secret" "db_password_secret" {
  name        = "db-password"
  kms_key_id  = aws_kms_key.secrets_key.id
  description = "Database password for RDS instance"
}

resource "aws_secretsmanager_secret_version" "db_password_secret" {
  secret_id = aws_secretsmanager_secret.db_password_secret.id
  secret_string = jsonencode({
    username = var.db_username
    password = random_password.db_password.result
  })
}

# Update user-data to retrieve password from Secrets Manager
data "aws_secretsmanager_secret" "db_password_retrieve" {
  name = aws_secretsmanager_secret.db_password_secret.name
}

data "aws_secretsmanager_secret_version" "db_password_retrieve" {
  secret_id = data.aws_secretsmanager_secret.db_password_retrieve.id
}


# Store email credentials in Secrets Manager
resource "aws_secretsmanager_secret" "email_credentials_secret" {
  name        = "email-credentials"
  kms_key_id  = aws_kms_key.secrets_key.id
  description = "Email service credentials for Lambda"
}

resource "aws_secretsmanager_secret_version" "email_credentials_secret" {
  secret_id = aws_secretsmanager_secret.email_credentials_secret.id
  secret_string = jsonencode({
    sendgrid_api_key = var.sendgrid_api_key
    email_from       = var.email_from
  })
}

resource "aws_route53_record" "webapp_https" {
  zone_id = var.zone_id
  name    = var.domain_name
  type    = "A"
  alias {
    name                   = aws_lb.my_lb.dns_name
    zone_id                = aws_lb.my_lb.zone_id
    evaluate_target_health = true
  }
}

resource "aws_iam_policy" "asg_policy" {
  name        = "ASGPolicy"
  description = "Policy for Auto Scaling, EC2, ELB, and CloudWatch actions"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "autoscaling:DescribeAutoScalingGroups",
          "autoscaling:UpdateAutoScalingGroup",
          "autoscaling:DescribeLaunchConfigurations",
          "autoscaling:DescribeScalingActivities",
          "autoscaling:TerminateInstanceInAutoScalingGroup",
          "autoscaling:SetDesiredCapacity"
        ],
        Resource = "*"
      },
      {
        Effect = "Allow",
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeLaunchTemplates",
          "ec2:RunInstances",
          "ec2:TerminateInstances",
          "ec2:StopInstances",
          "ec2:StartInstances",
          "ec2:CreateTags",
          "ec2:DescribeSecurityGroups"
        ],
        Resource = "*"
      },
      {
        Effect = "Allow",
        Action = [
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:RegisterTargets",
          "elasticloadbalancing:DeregisterTargets",
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeListeners",
          "elasticloadbalancing:ModifyTargetGroup",
          "elasticloadbalancing:DescribeTargetHealth"
        ],
        Resource = "*"
      },
      {
        Effect = "Allow",
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:ReEncrypt*"
        ],
        Resource = [
          "${aws_kms_key.ec2_key.arn}",
          "${aws_kms_key.rds_key.arn}",
          "${aws_kms_key.s3_key.arn}"
        ]
      }
    ]
  })
}