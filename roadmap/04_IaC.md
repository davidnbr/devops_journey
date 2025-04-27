# 4. Infrastructure as Code & Configuration Management

## Infrastructure as Code

### Terraform Deep Dive

#### Terraform Architecture
- **Components**:
  - Core: Reads configuration and manages resource lifecycle
  - Provider Plugins: Interface to service APIs
  - State Backend: Stores infrastructure state
  - CLI: Command line interface
- **Code Organization**:
  ```
  ├── main.tf
  ├── variables.tf
  ├── outputs.tf
  ├── providers.tf
  ├── backend.tf
  ├── modules/
  │   ├── networking/
  │   ├── compute/
  │   └── database/
  ├── environments/
  │   ├── dev/
  │   ├── staging/
  │   └── prod/
  └── terraform.tfvars
  ```

#### HCL Language Features
- **Basic Syntax**:
  ```hcl
  resource "aws_instance" "web" {
    ami           = "ami-0c55b159cbfafe1f0"
    instance_type = "t2.micro"
    
    tags = {
      Name = "WebServer"
      Environment = var.environment
    }
  }
  ```
- **Variables and Types**:
  ```hcl
  variable "region" {
    type        = string
    default     = "us-west-2"
    description = "AWS region for resources"
  }
  
  variable "instance_count" {
    type        = number
    default     = 2
    description = "Number of instances to create"
  }
  
  variable "allowed_cidr_blocks" {
    type        = list(string)
    default     = ["10.0.0.0/16", "172.16.0.0/12"]
    description = "List of allowed CIDR blocks"
  }
  
  variable "instance_config" {
    type = object({
      ami           = string
      instance_type = string
      tags          = map(string)
    })
    default = {
      ami           = "ami-0c55b159cbfafe1f0"
      instance_type = "t2.micro"
      tags          = {
        Environment = "dev"
      }
    }
  }
  ```
- **Functions**:
  ```hcl
  locals {
    common_tags = {
      Environment = var.environment
      Project     = var.project_name
      Owner       = "DevOps Team"
      ManagedBy   = "Terraform"
      Timestamp   = formatdate("YYYY-MM-DD hh:mm:ss", timestamp())
    }
    
    uppercase_env = upper(var.environment)
    instance_name = "${var.project_name}-${var.environment}-instance"
    
    # Conditional expressions
    instance_type = var.environment == "prod" ? "t3.large" : "t3.small"
    
    # For expressions
    instance_names = [for i in range(var.instance_count) : "${local.instance_name}-${i+1}"]
    
    # Splat expressions
    all_private_ips = aws_instance.app[*].private_ip
    
    # Dynamic blocks
    security_group_rules = [
      {
        port        = 80
        protocol    = "tcp"
        description = "HTTP"
      },
      {
        port        = 443
        protocol    = "tcp"
        description = "HTTPS"
      }
    ]
  }
  ```
- **Dynamic Blocks**:
  ```hcl
  resource "aws_security_group" "web" {
    name        = "web-sg"
    description = "Web server security group"
    
    dynamic "ingress" {
      for_each = local.security_group_rules
      content {
        from_port   = ingress.value.port
        to_port     = ingress.value.port
        protocol    = ingress.value.protocol
        cidr_blocks = ["0.0.0.0/0"]
        description = ingress.value.description
      }
    }
  }
  ```
- **Provider Configuration**:
  ```hcl
  provider "aws" {
    region = var.region
    
    default_tags {
      tags = local.common_tags
    }
    
    assume_role {
      role_arn     = var.role_arn
      session_name = "TerraformSession"
    }
  }
  
  # Multiple provider configurations
  provider "aws" {
    alias  = "us-east-1"
    region = "us-east-1"
  }
  
  # Use aliased provider
  resource "aws_s3_bucket" "logs" {
    provider = aws.us-east-1
    bucket   = "my-logs-bucket"
  }
  ```

#### State Management
- **State Backends**:
  ```hcl
  # S3 backend
  terraform {
    backend "s3" {
      bucket         = "terraform-state-bucket"
      key            = "path/to/my/key"
      region         = "us-west-2"
      encrypt        = true
      dynamodb_table = "terraform-locks"
    }
  }
  
  # Remote backend (Terraform Cloud)
  terraform {
    backend "remote" {
      organization = "my-org"
      workspaces {
        name = "my-workspace"
      }
    }
  }
  ```
- **State Locking**:
  - Preventing concurrent modifications
  - DynamoDB for locking with S3 backend
  - Consul locks for Consul backend
- **State Operations**:
  ```bash
  # List resources in state
  terraform state list
  
  # Show specific resource
  terraform state show aws_instance.web
  
  # Move resource within state
  terraform state mv aws_instance.web aws_instance.app
  
  # Remove resource from state
  terraform state rm aws_instance.web
  
  # Import existing resource
  terraform import aws_instance.imported i-abcd1234
  
  # Pull current state
  terraform state pull > terraform.tfstate
  
  # Push state
  terraform state push terraform.tfstate
  ```
- **Workspaces**:
  ```bash
  # Create workspace
  terraform workspace new dev
  
  # List workspaces
  terraform workspace list
  
  # Select workspace
  terraform workspace select prod
  
  # Show current workspace
  terraform workspace show
  ```
  ```hcl
  # Workspace-specific configuration
  resource "aws_instance" "app" {
    count = terraform.workspace == "prod" ? 3 : 1
    
    ami           = var.ami
    instance_type = terraform.workspace == "prod" ? "t3.large" : "t3.small"
    
    tags = {
      Name = "app-${terraform.workspace}"
    }
  }
  ```

#### Module Design
- **Module Structure**:
  ```
  modules/vpc/
  ├── main.tf
  ├── variables.tf
  ├── outputs.tf
  ├── README.md
  └── examples/
      └── simple/
          ├── main.tf
          └── terraform.tfvars
  ```
- **Module Development Best Practices**:
  - Composability
  - Clear API (inputs/outputs)
  - Default values
  - Validation
  - Documentation
  - Examples
  - Versioning
- **Module Sources**:
  ```hcl
  # Local path
  module "vpc" {
    source = "./modules/vpc"
  }
  
  # Git repository
  module "vpc" {
    source = "git::https://github.com/org/terraform-aws-vpc.git?ref=v2.0.0"
  }
  
  # Terraform Registry
  module "vpc" {
    source  = "terraform-aws-modules/vpc/aws"
    version = "3.14.0"
  }
  ```
- **Output Usage**:
  ```hcl
  # Module outputs
  output "vpc_id" {
    value       = aws_vpc.this.id
    description = "The ID of the VPC"
  }
  
  # Using module outputs
  module "vpc" {
    source = "./modules/vpc"
    # ...
  }
  
  resource "aws_instance" "app" {
    subnet_id = module.vpc.subnet_ids[0]
  }
  ```
- **Module Composition**:
  ```hcl
  module "vpc" {
    source = "./modules/vpc"
    # VPC parameters
  }
  
  module "security_groups" {
    source = "./modules/security_groups"
    vpc_id = module.vpc.vpc_id
  }
  
  module "load_balancer" {
    source = "./modules/load_balancer"
    vpc_id = module.vpc.vpc_id
    subnet_ids = module.vpc.public_subnet_ids
    security_group_ids = [module.security_groups.lb_sg_id]
  }
  
  module "instances" {
    source = "./modules/instances"
    subnet_ids = module.vpc.private_subnet_ids
    security_group_ids = [module.security_groups.instance_sg_id]
    load_balancer_dns = module.load_balancer.dns_name
  }
  ```

#### Advanced Features
- **Provider Meta-Arguments**:
  - `depends_on`
  - `count`
  - `for_each`
  - `provider`
  - `lifecycle`
- **Custom Providers**:
  - Provider development
  - Custom resources and data sources
- **External Data**:
  ```hcl
  data "external" "example" {
    program = ["python", "${path.module}/script.py"]
    
    query = {
      environment = var.environment
    }
  }
  
  output "external_result" {
    value = data.external.example.result
  }
  ```
- **Provisioners**:
  ```hcl
  resource "aws_instance" "web" {
    # ...
    
    provisioner "file" {
      source      = "files/app.conf"
      destination = "/etc/app/app.conf"
      
      connection {
        type        = "ssh"
        user        = "ec2-user"
        private_key = file(var.private_key_path)
        host        = self.public_ip
      }
    }
    
    provisioner "remote-exec" {
      inline = [
        "sudo systemctl restart app"
      ]
    }
  }
  ```
- **Terraform Functions**:
  - String functions: `format`, `substr`, `replace`
  - Numeric functions: `min`, `max`, `ceil`, `floor`
  - Collection functions: `concat`, `merge`, `flatten`
  - Encoding functions: `base64encode`, `jsonencode`
  - Filesystem functions: `file`, `fileexists`, `templatefile`
  - Date/Time functions: `formatdate`, `timeadd`
  - Hash/Crypto functions: `md5`, `sha256`, `bcrypt`
  - IP Network functions: `cidrsubnet`, `cidrhost`
- **Local-exec**:
  ```hcl
  resource "null_resource" "example" {
    provisioner "local-exec" {
      command = "echo '${aws_instance.web.public_ip}' > ip_address.txt"
    }
  }
  ```

#### Testing & Validation
- **Input Validation**:
  ```hcl
  variable "environment" {
    type        = string
    description = "Environment name"
    
    validation {
      condition     = contains(["dev", "staging", "prod"], var.environment)
      error_message = "Environment must be one of: dev, staging, prod."
    }
  }
  
  variable "instance_type" {
    type        = string
    description = "EC2 instance type"
    
    validation {
      condition     = can(regex("^t[23]\\.", var.instance_type))
      error_message = "Only t2 and t3 instance types are allowed."
    }
  }
  ```
- **Preconditions and Postconditions**:
  ```hcl
  resource "aws_instance" "example" {
    ami           = var.ami_id
    instance_type = var.instance_type
    
    lifecycle {
      precondition {
        condition     = data.aws_ami.selected.architecture == "x86_64"
        error_message = "The selected AMI must be x86_64 architecture."
      }
    }
  }
  
  output "instance_ip" {
    value = aws_instance.example.private_ip
    
    precondition {
      condition     = aws_instance.example.private_ip != ""
      error_message = "Private IP must not be empty."
    }
  }
  ```
- **Terraform Validate**:
  ```bash
  terraform validate
  ```
- **Testing Frameworks**:
  - Terratest
  - Kitchen-Terraform
  - Terraform Compliance
  - Checkov

#### CI/CD Integration
- **Automated Workflows**:
  - Plan on pull request
  - Apply on merge
  - Scheduled drift detection
- **Pipeline Stages**:
  1. Init
  2. Validate
  3. Format Check
  4. Plan
  5. Security Scan
  6. Cost Estimation
  7. Apply
  8. Test
  9. Documentation
- **GitOps Approaches**:
  - Atlantis
  - Terraform Cloud
  - Custom CI/CD pipelines

#### Advanced Terraform Techniques
- **Zero-Downtime Deployments**:
  - Create before destroy
  - Blue/Green deployments
  - Incremental changes
- **Multi-Region, Multi-Account**:
  - Provider aliases
  - Assume role configurations
  - Module composition
- **Handling Secrets**:
  - External vaults (HashiCorp Vault, AWS Secrets Manager)
  - Avoiding sensitive data in state
  - Using `-var-file` for sensitive inputs
- **State Migration**:
  - Changing backends
  - Importing existing resources
  - Handling resource moves and renames
- **Performance Optimization**:
  - Parallelism
  - Optimization flags
  - Resource targeting

#### Infrastructure Testing
- **Infrastructure Unit Testing**:
  ```go
  // Terratest example
  package test
  
  import (
      "testing"
      "github.com/gruntwork-io/terratest/modules/terraform"
      "github.com/stretchr/testify/assert"
  )
  
  func TestTerraformAwsExample(t *testing.T) {
      terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
          TerraformDir: "../examples/aws-instance",
          Vars: map[string]interface{}{
              "region": "us-east-1",
          },
      })
  
      defer terraform.Destroy(t, terraformOptions)
      terraform.InitAndApply(t, terraformOptions)
  
      instanceID := terraform.Output(t, terraformOptions, "instance_id")
      assert.NotEmpty(t, instanceID)
  }
  ```
- **Integration Testing**:
  - Testing complete infrastructure stacks
  - Verifying service connectivity
  - Testing failure scenarios
- **Compliance Testing**:
  ```gherkin
  # Terraform Compliance example
  Feature: My Infrastructure Requirements
    
    Scenario: Ensure all S3 buckets are encrypted
      Given I have aws_s3_bucket defined
      Then it must contain server_side_encryption_configuration
  
    Scenario: Ensure all resources have tags
      Given I have any resource defined
      When its type is not aws_iam_policy
      Then it must contain tags
      And its tags must contain key Owner
  ```

#### Advanced Resources
- [Terraform Documentation](https://www.terraform.io/docs/index.html)
- [Terraform Up & Running](https://www.terraformupandrunning.com/) (book)
- [Terraform Best Practices](https://www.terraform-best-practices.com/)
- [Gruntwork Blog](https://blog.gruntwork.io/)

### CloudFormation
- **Template Structure**
- **Intrinsic Functions**
- **Resource Types**
- **CloudFormation vs Terraform**
- **Nested Stacks**
- **Custom Resources**

### Pulumi
- **Infrastructure as Real Code**
- **Supported Languages (TypeScript, Python, Go, C#)**
- **State Management**
- **Providers**
- **Testing**

### Other IaC Tools
- **Ansible (Declarative Mode)**
- **Chef Infra**
- **ARM Templates**
- **Bicep**
- **CDK**

## Configuration Management

### Ansible Deep Dive

#### Ansible Architecture
- **Components**:
  - Control Node
  - Managed Nodes
  - Inventory
  - Modules
  - Plugins
  - Playbooks
  - Roles
  - Collections
- **Execution Flow**:
  1. Parse playbook
  2. Gather facts
  3. Execute tasks
  4. Handle results

#### Inventory Management
- **Inventory Types**:
  - Static: INI, YAML, JSON
  - Dynamic: Scripts, plugins
- **Static Inventory Example**:
  ```ini
  # Basic grouping
  [webservers]
  web1.example.com
  web2.example.com
  
  [dbservers]
  db1.example.com
  db2.example.com
  
  # Range of hosts
  [workers]
  worker[01:20].example.com
  
  # Variables
  [webservers:vars]
  http_port=80
  
  # Nested groups
  [production:children]
  webservers
  dbservers
  
  [production:vars]
  env=production
  ```
- **Dynamic Inventory**:
  ```bash
  # AWS dynamic inventory
  ansible-playbook -i aws_ec2.yaml site.yml
  ```
  ```yaml
  # aws_ec2.yaml
  plugin: aws_ec2
  regions:
    - us-east-1
    - us-west-2
  filters:
    tag:Environment: production
  keyed_groups:
    - key: tags.Role
      prefix: role
  ```
- **Inventory Variables**:
  - Group variables (`group_vars/`)
  - Host variables (`host_vars/`)
  - Directory structure:
  ```
  inventory/
  ├── group_vars/
  │   ├── all.yml
  │   ├── webservers.yml
  │   └── dbservers.yml
  ├── host_vars/
  │   ├── web1.example.com.yml
  │   └── db1.example.com.yml
  └── hosts
  ```

#### Playbook Development
- **Playbook Structure**:
  ```yaml
  ---
  - name: Configure webservers
    hosts: webservers
    become: true
    vars:
      http_port: 80
      max_clients: 200
    vars_files:
      - vars/common.yml
    
    pre_tasks:
      - name: Update apt cache
        apt:
          update_cache: yes
          cache_valid_time: 3600
    
    roles:
      - common
      - webserver
    
    tasks:
      - name: Ensure Apache is installed
        apt:
          name: apache2
          state: present
    
      - name: Start Apache service
        service:
          name: apache2
          state: started
          enabled: yes
    
    handlers:
      - name: restart apache
        service:
          name: apache2
          state: restarted
  ```
- **Task Options**:
  - `name`: Task description
  - `become`: Privilege escalation
  - `when`: Conditional execution
  - `loop`, `with_items`: Iteration
  - `register`: Capturing output
  - `ignore_errors`: Error handling
  - `changed_when`, `failed_when`: Change detection
  - `notify`: Handler triggering
  - `tags`: Task classification
- **Variables & Templates**:
  ```yaml
  # Variables
  vars:
    app_port: 8080
    app_dir: /opt/myapp
    db_connection:
      host: db.example.com
      port: 5432
      user: app
      name: app_db
  
  # Using variables
  tasks:
    - name: Configure application
      template:
        src: app.conf.j2
        dest: "{{ app_dir }}/config/app.conf"
        owner: app
        group: app
        mode: '0644'
  ```
  ```jinja
  # app.conf.j2 (Jinja2 template)
  server {
    listen {{ app_port }};
    server_name {{ inventory_hostname }};
    
    location / {
      root {{ app_dir }}/public;
      index index.html;
    }
    
    {% if enable_ssl | default(false) %}
    ssl on;
    ssl_certificate {{ ssl_cert_path }};
    ssl_certificate_key {{ ssl_key_path }};
    {% endif %}
  }
  
  # Database configuration
  db.host={{ db_connection.host }}
  db.port={{ db_connection.port }}
  db.name={{ db_connection.name }}
  db.user={{ db_connection.user }}
  db.password={{ db_password }}
  ```
- **Control Structures**:
  ```yaml
  # Conditionals
  - name: Install MySQL (Debian)
    apt:
      name: mysql-server
      state: present
    when: ansible_os_family == "Debian"
  
  - name: Install MySQL (RedHat)
    yum:
      name: mariadb-server
      state: present
    when: ansible_os_family == "RedHat"
  
  # Loops
  - name: Create application users
    user:
      name: "{{ item.name }}"
      groups: "{{ item.groups }}"
      shell: "{{ item.shell | default('/bin/bash') }}"
    loop:
      - name: app
        groups: www-data
      - name: backup
        groups: admin
        shell: /sbin/nologin
  
  # Block/Rescue/Always
  - block:
      - name: Install application
        apt:
          name: myapp
          state: present
      
      - name: Configure application
        template:
          src: myapp.conf.j2
          dest: /etc/myapp/config.conf
    rescue:
      - name: Log failure
        shell: echo "Installation failed at {{ ansible_date_time.iso8601 }}" >> /var/log/ansible_failures.log
    always:
      - name: Cleanup temp files
        file:
          path: /tmp/myapp_installer
          state: absent
  ```

#### Role Development
- **Role Structure**:
  ```
  roles/webserver/
  ├── defaults/
  │   └── main.yml       # Default variables
  ├── files/
  │   └── ssl.conf       # Static files
  ├── handlers/
  │   └── main.yml       # Handlers
  ├── meta/
  │   └── main.yml       # Role metadata
  ├── tasks/
  │   ├── main.yml       # Main tasks
  │   ├── install.yml    # Installation tasks
  │   └── configure.yml  # Configuration tasks
  ├── templates/
  │   └── vhost.conf.j2  # Jinja2 templates
  └── vars/
      └── main.yml       # Role variables
  ```
- **Role Defaults**:
  ```yaml
  # defaults/main.yml
  webserver_port: 80
  webserver_enable_ssl: false
  webserver_document_root: /var/www/html
  webserver_log_level: warn
  ```
- **Role Tasks**:
  ```yaml
  # tasks/main.yml
  - name: Include OS-specific variables
    include_vars: "{{ ansible_os_family }}.yml"
  
  - name: Include installation tasks
    import_tasks: install.yml
  
  - name: Include configuration tasks
    import_tasks: configure.yml
  ```
- **Role Dependencies**:
  ```yaml
  # meta/main.yml
  dependencies:
    - role: common
      vars:
        common_user: webserver
    
    - role: firewall
      vars:
        firewall_allow_ports:
          - "{{ webserver_port }}"
  ```
- **Role Testing**:
  - Molecule
  - Ansible-test
  - Testing methodologies

#### Collections
- **Collection Structure**:
  ```
  collection/
  ├── docs/
  ├── galaxy.yml          # Collection metadata
  ├── plugins/            # Plugin code
  │   ├── modules/
  │   ├── inventory/
  │   └── filter/
  ├── playbooks/          # Playbooks
  ├── roles/              # Roles
  └── README.md
  ```
- **Collection Installation**:
  ```bash
  ansible-galaxy collection install community.general
  ```
- **Using Collections**:
  ```yaml
  ---
  - hosts: all
    collections:
      - community.general
      - company.custom_collection
    
    tasks:
      - name: Use collection module
        community.general.json_query:
          # ...
  ```
- **Developing Custom Collections**:
  - Creating plugins
  - Building collections
  - Publishing to Galaxy

#### Ansible Automation Platform (AAP)
- **Platform Components**:
  - Automation Controller (Tower)
  - Automation Hub
  - Automation Analytics
- **Controller Features**:
  - Job Templates
  - Surveys
  - Workflows
  - RBAC
  - Credentials Management
  - Scheduling
  - Dynamic Inventory
  - RESTful API
- **AWX (Open Source Tower)**:
  - Installation
  - Configuration
  - API Usage

#### Advanced Ansible Techniques
- **Performance Optimization**:
  - Mitogen accelerator
  - SSH pipelining
  - Fact caching
  - Async tasks
  - Forks and parallelism
  ```yaml
  # ansible.cfg
  [defaults]
  forks = 50
  gathering = smart
  fact_caching = jsonfile
  fact_caching_timeout = 86400
  fact_caching_connection = /tmp/ansible_fact_cache
  
  [ssh_connection]
  pipelining = True
  control_path = /tmp/ansible-ssh-%%h-%%p-%%r
  ```
- **Ansible Vault**:
  ```bash
  # Create encrypted file
  ansible-vault create secrets.yml
  
  # Edit encrypted file
  ansible-vault edit secrets.yml
  
  # Encrypt existing file
  ansible-vault encrypt vars/credentials.yml
  
  # Run playbook with vault
  ansible-playbook --ask-vault-pass site.yml
  ```
  ```yaml
  # Using encrypted variables
  - name: Configure database connection
    template:
      src: db_config.j2
      dest: /etc/app/database.ini
    vars:
      db_password: !vault |
        $ANSIBLE_VAULT;1.1;AES256
        38623365396362333738616630323435383734636134636662613732306566386436353764323
        3764383164656161613435633462363663333464363732300a653434363037636331633066393
        61643933353739386638323493...
  ```
- **Custom Modules & Plugins**:
  - Module development
  - Filter plugins
  - Callback plugins
  - Inventory plugins
  - Lookup plugins
- **Error Handling & Recovery**:
  ```yaml
  - name: Try to start application
    service:
      name: myapp
      state: started
    register: service_result
    ignore_errors: yes
  
  - name: Fix application configuration
    template:
      src: myapp.conf.j2
      dest: /etc/myapp/config.conf
    when: service_result is failed
  
  - name: Retry starting application
    service:
      name: myapp
      state: started
    when: service_result is failed
  ```
- **Dynamic Includes**:
  ```yaml
  - name: Include tasks based on environment
    include_tasks: "{{ item }}"
    loop:
      - "tasks/{{ ansible_os_family }}.yml"
      - "tasks/{{ env }}.yml"
  
  - name: Include role dynamically
    include_role:
      name: "{{ application_type }}"
    vars:
      app_port: 8080
  ```
- **Delegation & Local Actions**:
  ```yaml
  - name: Create DNS record for new server
    community.aws.route53:
      zone: example.com
      record: "{{ inventory_hostname }}.example.com"
      type: A
      value: "{{ ansible_host }}"
    delegate_to: localhost
  
  - name: Wait for server to be reachable
    wait_for:
      host: "{{ ansible_host }}"
      port: 22
      timeout: 300
    delegate_to: localhost
  ```

#### Idempotency & Best Practices
- **Ensuring Idempotency**:
  - Using state parameters
  - Checking before changing
  - Handling edge cases
- **Testing & Validation**:
  - Syntax checking
  - Linting with ansible-lint
  - Molecule testing framework
  - CI/CD pipeline integration
- **Security Best Practices**:
  - Vault for sensitive data
  - Least privilege principle
  - No plaintext secrets
  - SSH hardening
- **Performance Optimization**:
  - Task organization
  - Fact gathering control
  - Async tasks for long-running operations
- **Documentation**:
  - Role documentation
  - Playbook comments
  - README files
  - Tagging and naming conventions

#### Advanced Resources
- [Ansible Documentation](https://docs.ansible.com/)
- [Ansible for DevOps](https://www.ansiblefordevops.com/) (book)
- [Ansible Galaxy](https://galaxy.ansible.com/)
- [Ansible Best Practices](https://docs.ansible.com/ansible/latest/user_guide/playbooks_best_practices.html)

### Chef
- **Chef Architecture**
- **Cookbooks & Recipes**
- **Resources & Providers**
- **Attributes & Data Bags**
- **Chef vs Ansible**

### Puppet
- **Puppet Architecture**
- **Manifests & Modules**
- **Resources & Providers**
- **Hiera Data**
- **Puppet vs Ansible**

### SaltStack
- **Salt Architecture**
- **States & Pillars**
- **Execution Modules**
- **Event-Driven Automation**
- **Salt vs Ansible**
