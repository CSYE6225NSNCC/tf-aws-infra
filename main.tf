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

# Create EC2 Instance
resource "aws_instance" "web_app_instance" {
  ami                         = var.custom_ami_id
  instance_type               = var.instance_type
  associate_public_ip_address = true
  security_groups             = [aws_security_group.app_sg.id]
  subnet_id                   = aws_subnet.public_subnet[0].id
  key_name                    = var.key_name

  user_data = <<-EOF
              #!/bin/bash

              # Create a new file named webapp.env in /etc

              sudo chmod 600 /etc/webapp.env
              sudo chown root:root /etc/webapp.env

              echo "DB_HOST=${aws_db_instance.csye6225.address}" >> /etc/webapp.env
              echo "DB_USER=csye6225" >> /etc/webapp.env
              echo "DB_PASSWORD=${var.db_password}" >> /etc/webapp.env
              echo "DB_NAME=csye6225" >> /etc/webapp.env
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
  engine                 = "mysql"       # Change as needed
  instance_class         = "db.t3.micro" # Cheapest option
  allocated_storage      = 20
  db_name                = "csye6225"
  username               = "csye6225"
  password               = var.db_password # Use a strong password
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