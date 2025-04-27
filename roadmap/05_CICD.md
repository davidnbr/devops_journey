# 5. CI/CD Pipelines & Cloud Infrastructure

## CI/CD Pipelines

### CI/CD Concepts
- **Continuous Integration**: Frequent merging of code changes
- **Continuous Delivery**: Automation to release-ready state
- **Continuous Deployment**: Automated deployment to production
- **Pipeline Stages**:
  - Source (Code Checkout)
  - Build
  - Test (Unit, Integration, etc.)
  - Package
  - Deploy
  - Validation
- **Pipeline Types**:
  - Linear Pipelines
  - Parallel Pipelines
  - Matrix Builds
  - Fan-in/Fan-out
- **Quality Gates**:
  - Code Quality Checks
  - Security Scans
  - Test Coverage
  - Performance Metrics

### GitHub Actions

#### Core Concepts
- **Workflows**: YAML files in `.github/workflows/`
- **Events**: Triggers like `push`, `pull_request`, etc.
- **Jobs**: Collections of steps
- **Steps**: Individual tasks
- **Actions**: Reusable units of code
- **Runners**: Execution environments (GitHub-hosted or self-hosted)

#### Workflow Configuration
```yaml
name: CI Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]
  schedule:
    - cron: '0 2 * * *'

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  build:
    runs-on: ubuntu-latest
    
    strategy:
      matrix:
        node-version: [14.x, 16.x]
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Node.js ${{ matrix.node-version }}
        uses: actions/setup-node@v3
        with:
          node-version: ${{ matrix.node-version }}
          cache: 'npm'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Run linter
        run: npm run lint
      
      - name: Run tests
        run: npm test
        
      - name: Upload test results
        uses: actions/upload-artifact@v3
        with:
          name: test-results
          path: test-results/
          retention-days: 5
  
  security-scan:
    runs-on: ubuntu-latest
    needs: build
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Run security scan
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
      
      - name: Run SAST
        uses: github/codeql-action/analyze@v2
  
  docker-build:
    runs-on: ubuntu-latest
    needs: [build, security-scan]
    if: github.event_name != 'pull_request'
    
    permissions:
      contents: read
      packages: write
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v2
      
      - name: Login to Container Registry
        uses: docker/login-action@v2
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v4
        with:
          images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
          tags: |
            type=semver,pattern={{version}}
            type=ref,event=branch
            type=sha,format=short
      
      - name: Build and push
        uses: docker/build-push-action@v3
        with:
          context: .
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
  
  deploy:
    runs-on: ubuntu-latest
    needs: docker-build
    if: github.ref == 'refs/heads/main'
    environment: production
    
    concurrency: 
      group: production
      cancel-in-progress: false
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v1
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-west-2
      
      - name: Deploy to ECS
        uses: aws-actions/amazon-ecs-deploy-task-definition@v1
        with:
          task-definition: task-definition.json
          service: my-service
          cluster: my-cluster
          wait-for-service-stability: true
```

#### Advanced GitHub Actions Features
- **Matrix Builds**:
  ```yaml
  strategy:
    matrix:
      os: [ubuntu-latest, windows-latest, macos-latest]
      node: [14, 16, 18]
      include:
        - os: ubuntu-latest
          node: 18
          experimental: true
      exclude:
        - os: macos-latest
          node: 14
  ```
- **Reusable Workflows**:
  ```yaml
  # .github/workflows/reusable.yml
  name: Reusable workflow
  
  on:
    workflow_call:
      inputs:
        environment:
          required: true
          type: string
      secrets:
        deploy_token:
          required: true
  
  jobs:
    deploy:
      runs-on: ubuntu-latest
      environment: ${{ inputs.environment }}
      steps:
        # Steps here...
  
  # Calling workflow
  jobs:
    call-workflow:
      uses: ./.github/workflows/reusable.yml
      with:
        environment: production
      secrets:
        deploy_token: ${{ secrets.DEPLOY_TOKEN }}
  ```
- **Composite Actions**:
  ```yaml
  # action.yml
  name: 'Setup and Test'
  description: 'Sets up environment and runs tests'
  inputs:
    node-version:
      description: 'Node.js version'
      required: true
      default: '16'
  
  runs:
    using: "composite"
    steps:
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: ${{ inputs.node-version }}
      
      - name: Install dependencies
        run: npm ci
        shell: bash
      
      - name: Run tests
        run: npm test
        shell: bash
  ```
- **Self-Hosted Runners**:
  ```yaml
  jobs:
    deploy:
      runs-on: self-hosted
      # Or with labels
      runs-on: [self-hosted, linux, arm64]
  ```
- **Environment Protection Rules**:
  - Required reviewers
  - Wait timer
  - Deployment branches

### GitLab CI/CD

#### Core Concepts
- **Pipeline**: `.gitlab-ci.yml` configuration
- **Stages**: Sequential groups of jobs
- **Jobs**: Scripts running in containers
- **Runners**: Execution environments
- **Artifacts**: Build outputs passed between jobs

#### Pipeline Configuration
```yaml
image: node:16-alpine

stages:
  - build
  - test
  - security
  - package
  - deploy

variables:
  DOCKER_DRIVER: overlay2
  DOCKER_TLS_CERTDIR: ""

cache:
  key: ${CI_COMMIT_REF_SLUG}
  paths:
    - node_modules/

build:
  stage: build
  script:
    - npm ci
    - npm run build
  artifacts:
    paths:
      - dist/
    expire_in: 1 week

unit-test:
  stage: test
  script:
    - npm ci
    - npm run test:unit
  artifacts:
    paths:
      - coverage/
    reports:
      junit: junit.xml

integration-test:
  stage: test
  services:
    - name: mongo:4.4
      alias: mongodb
  variables:
    MONGODB_URI: "mongodb://mongodb:27017/test"
  script:
    - npm ci
    - npm run test:integration

sast:
  stage: security
  image: docker:stable
  variables:
    DOCKER_DRIVER: overlay2
  allow_failure: true
  script:
    - echo "Running SAST scan..."
  artifacts:
    reports:
      sast: gl-sast-report.json

container-scan:
  stage: security
  image: docker:stable
  services:
    - docker:dind
  variables:
    DOCKER_DRIVER: overlay2
  script:
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
    - echo "Running container scan..."
  artifacts:
    reports:
      container_scanning: gl-container-scanning-report.json

docker-build:
  stage: package
  image: docker:stable
  services:
    - docker:dind
  variables:
    DOCKER_DRIVER: overlay2
  script:
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
    - docker tag $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA $CI_REGISTRY_IMAGE:latest
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
    - docker push $CI_REGISTRY_IMAGE:latest
  only:
    - main

deploy-staging:
  stage: deploy
  image: alpine:latest
  environment:
    name: staging
    url: https://staging.example.com
  script:
    - apk add --no-cache curl
    - curl -X POST -F token=$DEPLOY_TOKEN -F ref=main https://gitlab.example.com/api/v4/projects/$CI_PROJECT_ID/trigger/pipeline
  only:
    - main

deploy-production:
  stage: deploy
  image: alpine:latest
  environment:
    name: production
    url: https://example.com
  when: manual
  script:
    - apk add --no-cache curl
    - curl -X POST -F token=$DEPLOY_TOKEN -F ref=main https://gitlab.example.com/api/v4/projects/$CI_PROJECT_ID/trigger/pipeline
  only:
    - main
  needs:
    - deploy-staging
```

#### Advanced GitLab CI/CD Features
- **Multi-project Pipelines**:
  ```yaml
  trigger_downstream:
    stage: deploy
    trigger:
      project: group/project
      branch: main
      strategy: depend
  ```
- **Parent-Child Pipelines**:
  ```yaml
  # Main .gitlab-ci.yml
  stages:
    - triggers
  
  trigger_backend:
    stage: triggers
    trigger:
      include: backend/.gitlab-ci.yml
  
  trigger_frontend:
    stage: triggers
    trigger:
      include: frontend/.gitlab-ci.yml
  ```
- **Dynamic Pipelines**:
  ```yaml
  # Using rules
  build:
    script: npm run build
    rules:
      - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
        when: never
      - if: '$CI_COMMIT_BRANCH == "main"'
        when: always
      - if: '$CI_COMMIT_BRANCH =~ /^feature\//'
        when: manual
  
  # Using resource_group for deployment locks
  deploy:
    script: ./deploy.sh
    resource_group: production
  ```
- **Directed Acyclic Graph (DAG)**:
  ```yaml
  build-a:
    stage: build
    script: echo "Building A"
  
  build-b:
    stage: build
    script: echo "Building B"
  
  test-a:
    stage: test
    script: echo "Testing A"
    needs:
      - build-a
  
  test-b:
    stage: test
    script: echo "Testing B"
    needs:
      - build-b
  
  deploy:
    stage: deploy
    script: echo "Deploying"
    needs:
      - test-a
      - test-b
  ```
- **GitLab Environments & Deployments**:
  - Environment definitions
  - Deployment tracking
  - Review apps for merge requests
  ```yaml
  deploy_review:
    stage: deploy
    script:
      - echo "Deploy to review app"
    environment:
      name: review/$CI_COMMIT_REF_SLUG
      url: https://$CI_COMMIT_REF_SLUG.example.com
      on_stop: stop_review
    only:
      - merge_requests
  
  stop_review:
    stage: deploy
    script:
      - echo "Remove review app"
    environment:
      name: review/$CI_COMMIT_REF_SLUG
      action: stop
    when: manual
    only:
      - merge_requests
  ```

### Jenkins

#### Core Concepts
- **Architecture**:
  - Controller (Master)
  - Agents (Slaves/Nodes)
  - Executors
  - Jobs & Builds
  - Plugins
- **Job Types**:
  - Freestyle
  - Pipeline (Scripted & Declarative)
  - Multi-configuration
  - Folder
  - Organization folder
  - Multibranch Pipeline

#### Declarative Pipeline
```groovy
pipeline {
    agent {
        kubernetes {
            yaml """
            apiVersion: v1
            kind: Pod
            spec:
              containers:
              - name: maven
                image: maven:3.8.4-openjdk-11
                command: ['cat']
                tty: true
              - name: docker
                image: docker:20.10
                command: ['cat']
                tty: true
                volumeMounts:
                - name: docker-sock
                  mountPath: /var/run/docker.sock
              volumes:
              - name: docker-sock
                hostPath:
                  path: /var/run/docker.sock
            """
        }
    }
    
    environment {
        DOCKER_REGISTRY = 'registry.example.com'
        IMAGE_NAME = 'myapp'
        IMAGE_TAG = "${env.BUILD_NUMBER}"
    }
    
    options {
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timeout(time: 1, unit: 'HOURS')
        disableConcurrentBuilds()
        timestamps()
    }
    
    triggers {
        pollSCM('H/15 * * * *')
        cron('@daily')
    }
    
    parameters {
        choice(name: 'ENVIRONMENT', choices: ['dev', 'staging', 'prod'], description: 'Deployment environment')
        booleanParam(name: 'RUN_TESTS', defaultValue: true, description: 'Run tests')
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Build') {
            steps {
                container('maven') {
                    sh 'mvn clean package -DskipTests'
                }
            }
        }
        
        stage('Test') {
            when {
                expression { return params.RUN_TESTS }
            }
            parallel {
                stage('Unit Tests') {
                    steps {
                        container('maven') {
                            sh 'mvn test'
                        }
                    }
                    post {
                        always {
                            junit '**/target/surefire-reports/*.xml'
                        }
                    }
                }
                stage('Integration Tests') {
                    steps {
                        container('maven') {
                            sh 'mvn verify -DskipUnitTests'
                        }
                    }
                }
            }
        }
        
        stage('Code Analysis') {
            steps {
                container('maven') {
                    withSonarQubeEnv('SonarQube') {
                        sh 'mvn sonar:sonar'
                    }
                }
            }
        }
        
        stage('Build & Push Docker Image') {
            steps {
                container('docker') {
                    withCredentials([usernamePassword(credentialsId: 'docker-registry', usernameVariable: 'DOCKER_USER', passwordVariable: 'DOCKER_PASSWORD')]) {
                        sh '''
                            docker build -t ${DOCKER_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG} .
                            echo ${DOCKER_PASSWORD} | docker login ${DOCKER_REGISTRY} -u ${DOCKER_USER} --password-stdin
                            docker push ${DOCKER_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}
                        '''
                    }
                }
            }
        }
        
        stage('Deploy to Dev') {
            when {
                expression { return params.ENVIRONMENT == 'dev' }
            }
            steps {
                echo "Deploying to Development environment"
                // Deployment steps here
            }
        }
        
        stage('Deploy to Staging') {
            when {
                expression { return params.ENVIRONMENT == 'staging' }
            }
            steps {
                echo "Deploying to Staging environment"
                // Deployment steps here
            }
        }
        
        stage('Deploy to Production') {
            when {
                expression { return params.ENVIRONMENT == 'prod' }
                beforeInput true
            }
            input {
                message "Deploy to Production?"
                ok "Yes, deploy it!"
                submitter "approvers"
            }
            steps {
                echo "Deploying to Production environment"
                // Deployment steps here
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'target/*.jar', fingerprint: true
            cleanWs()
        }
        success {
            echo 'Build succeeded!'
            // Send success notification
        }
        failure {
            echo 'Build failed!'
            // Send failure notification
        }
    }
}
```

#### Advanced Jenkins Features
- **Shared Libraries**:
  ```groovy
  // In Jenkinsfile
  @Library('my-shared-library')_
  
  pipeline {
      agent any
      stages {
          stage('Build') {
              steps {
                  // Using a shared library step
                  buildApp()
              }
          }
      }
  }
  
  // In shared library (vars/buildApp.groovy)
  def call() {
      sh 'mvn clean package'
  }
  ```
- **Jenkins Configuration as Code (JCasC)**:
  ```yaml
  jenkins:
    systemMessage: "Jenkins configured automatically by JCasC"
    numExecutors: 5
    labelString: "master"
    securityRealm:
      local:
        allowsSignup: false
        users:
          - id: admin
            password: ${ADMIN_PASSWORD}
    authorizationStrategy:
      matrix:
        permissions:
          - "Overall/Administer:admin"
          - "Overall/Read:authenticated"
  
  credentials:
    system:
      domainCredentials:
        - credentials:
            - usernamePassword:
                scope: GLOBAL
                id: docker-registry
                username: jenkins
                password: ${DOCKER_REGISTRY_PASSWORD}
  ```
- **Master-Slave Architecture**:
  - Agent types (SSH, JNLP, Docker, Kubernetes)
  - Node management
  - Node labels & selectors
- **Pipeline Best Practices**:
  - Keep pipelines simple and maintainable
  - Use declarative syntax when possible
  - Put complex logic in shared libraries
  - Implement proper error handling
  - Set appropriate timeout values
  - Archive only necessary artifacts
  - Implement appropriate cleanup

### CI/CD Pipeline Design Principles
- **Pipeline as Code**:
  - Version controlled pipeline definitions
  - Self-documenting
  - Reusable components
  - Testable pipelines
- **Idempotency**:
  - Running the pipeline multiple times with the same inputs produces the same outputs
  - No side effects from reruns
- **Fast Feedback**:
  - Fail fast principles
  - Quick running tests first
  - Parallel execution where possible
- **Environment Parity**:
  - Consistent environments across stages
  - Containerization to ensure consistency
  - Infrastructure as code for environment definitions
- **Security Integration**:
  - Secrets management
  - Security scanning (SAST, DAST, SCA)
  - Compliance checks
- **Quality Gates**:
  - Clearly defined acceptance criteria
  - Automated quality checks
  - Manual approval for critical environments

### Deployment Strategies
- **Basic Deployment**:
  - Simple replacement of old with new
  - Suitable for non-critical applications
  - Downtime during deployment
- **Blue/Green Deployment**:
  - Two identical environments (Blue = current, Green = new)
  - Switch traffic all at once
  - Easy rollback by switching back
  - Zero downtime
  - Resource intensive (double infrastructure)
- **Canary Deployment**:
  - Gradually route traffic to new version
  - Monitor for issues before full rollout
  - Reduces risk by limiting exposure
  - Complex routing configuration
- **A/B Testing**:
  - Route traffic based on specific criteria
  - Used for feature testing
  - Requires metrics collection
  - Complex analysis
- **Rolling Deployment**:
  - Update instances in batches
  - Balance between availability and resource usage
  - Slower than all-at-once
- **Progressive Delivery**:
  - Combination of deployment strategies
  - Feature flags for controlled exposure
  - Automated rollbacks based on metrics
  - Advanced monitoring and observability

### Artifact Management
- **Artifact Repositories**:
  - Nexus Repository Manager
  - JFrog Artifactory
  - GitHub Packages
  - Docker Registry
  - AWS ECR / GCP Artifact Registry / Azure Container Registry
- **Repository Types**:
  - Maven repositories
  - npm registries
  - Docker registries
  - Helm chart repositories
  - Generic binary repositories
- **Version Management**:
  - Semantic versioning
  - Immutable artifacts
  - Promotion across environments
  - Retention policies
- **Metadata & Provenance**:
  - Build information
  - Git commit reference
  - Signatures & checksums
  - Vulnerability scan results
- **Access Control**:
  - Repository permissions
  - Deployment credentials
  - Token-based authentication

### Advanced CI/CD Practices
- **GitOps Workflow**:
  - Git as single source of truth
  - Pull-based deployments
  - Declarative configurations
  - Automated reconciliation
  - Tools: ArgoCD, Flux, Jenkins X
- **ChatOps**:
  - Triggering pipelines from chat
  - Deployment notifications
  - Approval workflows
  - Status dashboards
- **Feature Flags**:
  - Decoupling deployment from release
  - Targeted feature rollout
  - A/B testing
  - Kill switches
  - Tools: LaunchDarkly, Flagsmith, Split
- **Metrics-Driven Deployment**:
  - Automatic rollbacks based on metrics
  - Canary analysis
  - Performance validation
  - Tools: Spinnaker, Flagger, ArgoRollouts
- **Self-Service Platforms**:
  - Internal developer platforms
  - Golden paths
  - Standardized pipelines
  - Developer autonomy with guardrails

### Integrating Security into CI/CD (DevSecOps)
- **Shift Left Security**:
  - Security testing early in the pipeline
  - Developer security education
  - Pre-commit hooks
- **Secret Management**:
  - Vault integration
  - Just-in-time secrets
  - Rotation policies
  - No hardcoded secrets
- **Security Scanning**:
  - SAST (Static Application Security Testing)
  - DAST (Dynamic Application Security Testing)
  - SCA (Software Composition Analysis)
  - Container scanning
  - Infrastructure as Code scanning
- **Compliance Automation**:
  - Policy as code
  - Automated compliance checks
  - Evidence collection
  - Audit trails
- **Build Integrity**:
  - Reproducible builds
  - Binary authorization
  - Supply chain security
  - SLSA framework

### CI/CD Metrics & Monitoring
- **Pipeline Metrics**:
  - Build frequency
  - Build duration
  - Success rate
  - Mean time to recovery
  - Change lead time
  - Deployment frequency
- **Quality Metrics**:
  - Test coverage
  - Code quality
  - Security issues
  - Technical debt
- **Pipeline Observability**:
  - Pipeline visualization
  - Tracing builds across systems
  - Root cause analysis
  - Performance bottlenecks
- **Continuous Improvement**:
  - Pipeline analytics
  - Retrospectives
  - Incremental optimization
  - Benchmark against industry standards

### Advanced Resources
- [Continuous Delivery](https://continuousdelivery.com/) by Jez Humble and David Farley
- [DevOps Handbook](https://itrevolution.com/the-devops-handbook/) by Gene Kim et al.
- [Implementing Continuous Delivery](https://www.manning.com/books/implementing-continuous-delivery) by Alex Yates
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [GitLab CI/CD Documentation](https://docs.gitlab.com/ee/ci/)
- [Jenkins Documentation](https://www.jenkins.io/doc/)

## Cloud Platforms & Infrastructure

### AWS (Amazon Web Services)

#### Core Services Overview
- **Compute**:
  - EC2: Virtual servers in the cloud
  - Lambda: Serverless functions
  - ECS/EKS: Container orchestration
  - Fargate: Serverless containers
  - Elastic Beanstalk: PaaS offering
- **Storage**:
  - S3: Object storage
  - EBS: Block storage for EC2
  - EFS: Network file system
  - Glacier: Long-term archival storage
  - Storage Gateway: Hybrid storage integration
- **Database**:
  - RDS: Managed relational databases
  - DynamoDB: NoSQL database
  - ElastiCache: In-memory cache
  - Redshift: Data warehouse
  - Neptune: Graph database
  - DocumentDB: MongoDB-compatible database
- **Networking**:
  - VPC: Virtual private cloud
  - Route 53: DNS service
  - CloudFront: CDN
  - API Gateway: API management
  - Direct Connect: Dedicated network connection
  - Transit Gateway: Network transit hub
- **Security**:
  - IAM: Identity and access management
  - WAF: Web application firewall
  - Shield: DDoS protection
  - GuardDuty: Threat detection
  - Security Hub: Security posture management
- **Monitoring & Management**:
  - CloudWatch: Monitoring and observability
  - CloudTrail: API activity tracking
  - Config: Resource inventory and change tracking
  - Systems Manager: Resource management
  - Organizations: Multi-account management

#### Advanced AWS Concepts

##### VPC Architecture
- **Components**:
  - Subnets (public/private)
  - Route tables
  - Internet Gateway
  - NAT Gateway
  - Network ACLs
  - Security Groups
  - VPC Endpoints
  - VPC Peering
  - Transit Gateway
- **Multi-tier Architecture**:
  ```
  VPC (10.0.0.0/16)
  ├── Public Subnet (10.0.1.0/24)
  │   ├── Internet-facing load balancer
  │   ├── Bastion hosts
  │   └── NAT Gateway
  ├── Application Subnet (10.0.2.0/24)
  │   ├── Application servers
  │   └── Internal load balancer
  └── Database Subnet (10.0.3.0/24)
      └── Database servers
  ```
- **Network Security Layers**:
  - Network ACLs (subnet level, stateless)
  - Security Groups (instance level, stateful)
  - Host-based firewalls
  - Application firewalls

##### EC2 Optimization
- **Instance Types**:
  - General Purpose (T3, M5)
  - Compute Optimized (C5)
  - Memory Optimized (R5)
  - Storage Optimized (I3, D2)
  - Accelerated Computing (P3, G4)
- **Purchase Options**:
  - On-Demand
  - Reserved Instances (Standard, Convertible, Scheduled)
  - Savings Plans
  - Spot Instances
  - Dedicated Hosts
- **Auto Scaling**:
  - Launch Templates/Configurations
  - Auto Scaling Groups
  - Scaling Policies (Target tracking, Step, Simple)
  - Predictive Scaling
  - Lifecycle Hooks

##### S3 Best Practices
- **Storage Classes**:
  - Standard
  - Intelligent-Tiering
  - Standard-IA (Infrequent Access)
  - One Zone-IA
  - Glacier Instant Retrieval
  - Glacier Flexible Retrieval
  - Glacier Deep Archive
- **Performance Optimization**:
  - Multipart uploads
  - Byte-range fetches
  - Request rate optimization
  - Prefix naming for parallelization
- **Security**:
  - Bucket policies
  - ACLs
  - Block Public Access
  - Encryption (SSE-S3, SSE-KMS, SSE-C)
  - Versioning
  - Object Lock
- **Lifecycle Management**:
  - Transition rules
  - Expiration rules
  - Intelligent-Tiering

##### RDS Management
- **Database Engines**:
  - MySQL
  - PostgreSQL
  - MariaDB
  - Oracle
  - SQL Server
  - Aurora
- **High Availability**:
  - Multi-AZ deployments
  - Read replicas
  - Aurora Global Database
- **Performance Features**:
  - Instance sizing
  - Storage optimization
  - Parameter groups
  - Performance Insights
- **Backup and Recovery**:
  - Automated backups
  - Manual snapshots
  - Point-in-time recovery
  - Cross-region backups
- **Security**:
  - Network isolation
  - Encryption at rest
  - Encryption in transit
  - IAM DB authentication

##### IAM Best Practices
- **Principle of Least Privilege**:
  - Specific permissions instead of wildcard
  - Resource-level permissions
  - Service-linked roles
- **Identity Federation**:
  - AWS SSO
  - SAML federation
  - Web identity federation
  - Custom identity broker
- **Cross-Account Access**:
  - Role assumption
  - Resource-based policies
  - AWS Organizations
- **IAM Policy Structure**:
  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "s3:GetObject",
          "s3:ListBucket"
        ],
        "Resource": [
          "arn:aws:s3:::my-bucket",
          "arn:aws:s3:::my-bucket/*"
        ],
        "Condition": {
          "IpAddress": {
            "aws:SourceIp": "203.0.113.0/24"
          }
        }
      }
    ]
  }
  ```
- **Security Tools**:
  - Access Analyzer
  - IAM Access Advisor
  - Credential Report
  - Organizations Service Control Policies

##### CloudFormation
- **Template Structure**:
  ```yaml
  AWSTemplateFormatVersion: '2010-09-09'
  Description: 'Example template for a web application'
  
  Parameters:
    EnvironmentName:
      Type: String
      Default: dev
      AllowedValues:
        - dev
        - staging
        - prod
  
  Mappings:
    EnvironmentMap:
      dev:
        InstanceType: t3.small
      staging:
        InstanceType: t3.medium
      prod:
        InstanceType: m5.large
  
  Resources:
    WebServerSecurityGroup:
      Type: AWS::EC2::SecurityGroup
      Properties:
        GroupDescription: Security group for web servers
        SecurityGroupIngress:
          - IpProtocol: tcp
            FromPort: 80
            ToPort: 80
            CidrIp: 0.0.0.0/0
  
    WebServerLaunchConfig:
      Type: AWS::AutoScaling::LaunchConfiguration
      Properties:
        ImageId: !Ref LatestAMI
        InstanceType: !FindInMap [EnvironmentMap, !Ref EnvironmentName, InstanceType]
        SecurityGroups:
          - !Ref WebServerSecurityGroup
        UserData:
          Fn::Base64: !Sub |
            #!/bin/bash -xe
            yum update -y
            yum install -y httpd
            systemctl start httpd
            systemctl enable httpd
  
  Outputs:
    SecurityGroupId:
      Description: Security Group ID
      Value: !Ref WebServerSecurityGroup
  ```
- **Stack Management**:
  - Stack creation and updating
  - Change sets
  - Drift detection
  - Nested stacks
  - Stack sets (multi-account/region)
- **Custom Resources**:
  - Lambda-backed custom resources
  - Resource providers
  - Third-party resources
- **Best Practices**:
  - Template validation
  - Parameter constraints
  - Stack policies
  - Stack naming conventions
  - DeletionPolicy for critical resources

#### AWS CLI & SDK Mastery
- **CLI Configuration**:
  ```bash
  # Configure profiles
  aws configure --profile prod
  
  # Use named profile
  aws s3 ls --profile prod
  
  # Use a specific region
  aws ec2 describe-instances --region us-west-2
  
  # Use different output formats
  aws ec2 describe-instances --output json
  aws ec2 describe-instances --output table
  aws ec2 describe-instances --output text
  ```
- **Advanced CLI Commands**:
  ```bash
  # Use query parameter to filter output
  aws ec2 describe-instances \
    --query 'Reservations[*].Instances[*].{ID:InstanceId,Name:Tags[?Key==`Name`].Value|[0],Type:InstanceType,State:State.Name}' \
    --output table
  
  # Use filters to narrow results
  aws ec2 describe-instances \
    --filters "Name=instance-state-name,Values=running" "Name=tag:Environment,Values=Production"
  
  # Use waiters
  aws ec2 run-instances --image-id ami-12345678 --instance-type t2.micro
  aws ec2 wait instance-running --instance-ids i-1234567890abcdef0
  ```
- **Infrastructure Scripting**:
  ```bash
  #!/bin/bash
  
  # Create a VPC and capture the ID
  VPC_ID=$(aws ec2 create-vpc \
    --cidr-block 10.0.0.0/16 \
    --query 'Vpc.VpcId' \
    --output text)
  
  # Tag the VPC
  aws ec2 create-tags \
    --resources $VPC_ID \
    --tags Key=Name,Value=MyVPC
  
  # Enable DNS support
  aws ec2 modify-vpc-attribute \
    --vpc-id $VPC_ID \
    --enable-dns-support "{\"Value\":true}"
  
  # Create a subnet
  SUBNET_ID=$(aws ec2 create-subnet \
    --vpc-id $VPC_ID \
    --cidr-block 10.0.1.0/24 \
    --query 'Subnet.SubnetId' \
    --output text)
  
  # Create an internet gateway
  IGW_ID=$(aws ec2 create-internet-gateway \
    --query 'InternetGateway.InternetGatewayId' \
    --output text)
  
  # Attach the internet gateway to the VPC
  aws ec2 attach-internet-gateway \
    --vpc-id $VPC_ID \
    --internet-gateway-id $IGW_ID
  
  # Create a route table
  ROUTE_TABLE_ID=$(aws ec2 create-route-table \
    --vpc-id $VPC_ID \
    --query 'RouteTable.RouteTableId' \
    --output text)
  
  # Create a route to the internet
  aws ec2 create-route \
    --route-table-id $ROUTE_TABLE_ID \
    --destination-cidr-block 0.0.0.0/0 \
    --gateway-id $IGW_ID
  
  # Associate the route table with the subnet
  aws ec2 associate-route-table \
    --subnet-id $SUBNET_ID \
    --route-table-id $ROUTE_TABLE_ID
  ```
- **Python with Boto3**:
  ```python
  import boto3
  import json
  
  # Create EC2 client
  ec2 = boto3.client('ec2')
  
  # Get all running instances
  response = ec2.describe_instances(
      Filters=[
          {
              'Name': 'instance-state-name',
              'Values': ['running']
          }
      ]
  )
  
  # Extract instance information
  instances = []
  for reservation in response['Reservations']:
      for instance in reservation['Instances']:
          name = 'Unnamed'
          for tag in instance.get('Tags', []):
              if tag['Key'] == 'Name':
                  name = tag['Value']
                  break
          
          instances.append({
              'id': instance['InstanceId'],
              'type': instance['InstanceType'],
              'state': instance['State']['Name'],
              'name': name,
              'private_ip': instance.get('PrivateIpAddress', 'N/A'),
              'public_ip': instance.get('PublicIpAddress', 'N/A')
          })
  
  # Print instance information
  print(json.dumps(instances, indent=2))
  
  # Create a snapshot
  def create_snapshot(volume_id, description):
      response = ec2.create_snapshot(
          VolumeId=volume_id,
          Description=description,
          TagSpecifications=[
              {
                  'ResourceType': 'snapshot',
                  'Tags': [
                      {
                          'Key': 'Name',
                          'Value': f'Snapshot for {volume_id}'
                      },
                      {
                          'Key': 'CreatedBy',
                          'Value': 'AutomationScript'
                      }
                  ]
              }
          ]
      )
      return response['SnapshotId']
  ```

#### AWS Security Best Practices
- **Account Level**:
  - Enable MFA for all users
  - Implement AWS Organizations with SCPs
  - Use AWS Control Tower for multi-account governance
  - Configure CloudTrail in all regions
  - Implement AWS Config with conformance packs
  - Use AWS SSO for identity federation
- **Network Level**:
  - Implement VPC flow logs
  - Use security groups and NACLs effectively
  - Implement AWS Shield and WAF for critical applications
  - Use VPC endpoints for AWS services
  - Implement GuardDuty for threat detection
- **Resource Level**:
  - Encrypt all data at rest (S3, EBS, RDS)
  - Implement appropriate IAM policies
  - Use Secret Manager for secrets
  - Implement Systems Manager Session Manager instead of SSH
  - Use instance profiles for EC2 instances
- **Monitoring and Incident Response**:
  - Configure CloudWatch alarms for critical metrics
  - Implement EventBridge rules for automated responses
  - Use AWS Security Hub to aggregate security findings
  - Configure Amazon Detective for root cause analysis
  - Implement AWS Backup for disaster recovery

### Microsoft Azure

#### Core Services
- **Compute**:
  - Virtual Machines
  - App Service
  - Azure Functions
  - Azure Kubernetes Service (AKS)
  - Container Instances
- **Storage**:
  - Blob Storage
  - File Storage
  - Disk Storage
  - Table Storage
  - Queue Storage
- **Database**:
  - Azure SQL Database
  - Cosmos DB
  - Azure Database for MySQL/PostgreSQL
  - SQL Managed Instance
  - Azure Cache for Redis
- **Networking**:
  - Virtual Network
  - Load Balancer
  - Application Gateway
  - DNS
  - CDN
  - ExpressRoute
- **Security**:
  - Azure Active Directory
  - Key Vault
  - Security Center
  - Sentinel
  - DDoS Protection
- **Monitoring**:
  - Azure Monitor
  - Application Insights
  - Log Analytics
  - Network Watcher
  - Service Health

#### Advanced Azure Concepts
- **Azure Resource Manager (ARM)**
- **Azure Policy & Governance**
- **Azure DevOps Integration**
- **Landing Zone Implementation**
- **Hybrid Cloud Scenarios**

### Google Cloud Platform (GCP)

#### Core Services
- **Compute**:
  - Compute Engine
  - Google Kubernetes Engine (GKE)
  - App Engine
  - Cloud Functions
  - Cloud Run
- **Storage**:
  - Cloud Storage
  - Persistent Disk
  - Filestore
- **Database**:
  - Cloud SQL
  - Cloud Spanner
  - Firestore
  - Bigtable
  - Memorystore
- **Networking**:
  - VPC
  - Cloud Load Balancing
  - Cloud CDN
  - Cloud DNS
  - Cloud Interconnect
- **Security**:
  - IAM
  - Security Command Center
  - KMS
  - Secret Manager
  - Binary Authorization
- **Operations**:
  - Cloud Monitoring
  - Cloud Logging
  - Cloud Trace
  - Cloud Profiler
  - Error Reporting

#### Advanced GCP Concepts
- **GCP Organization Structure**
- **Cloud IAM Best Practices**
- **GKE Enterprise Features**
- **Anthos for Hybrid Cloud**
- **Cloud Deployment Manager**

### Multi-Cloud & Hybrid Cloud

#### Architecture Patterns
- **Infrastructure Abstraction**:
  - Common services layer
  - Infrastructure as code templates
  - API abstraction
- **Application Distribution**:
  - DR/Failover between clouds
  - Geographic distribution
  - Vendor-specific service utilization
- **Data Management**:
  - Cross-cloud data replication
  - Consistent data synchronization
  - Distributed databases

#### Management Tools
- **Terraform for Multi-Cloud**
- **Kubernetes for Workload Portability**
- **Monitoring Solutions**:
  - Prometheus/Grafana
  - Datadog
  - Dynatrace
  - New Relic
- **Identity Federation**:
  - Centralized authentication
  - Single sign-on
  - Identity providers

#### Challenges & Solutions
- **Consistent Security Posture**
- **Cost Management**
- **Skill Requirements**
- **Operational Complexity**
- **Data Governance**

### Advanced Cloud Architecture

#### Serverless Architecture
- **Benefits & Limitations**
- **Design Patterns**:
  - Event-driven architecture
  - Microservices
  - Backend for Frontend (BFF)
- **Serverless Frameworks**:
  - AWS SAM
  - Serverless Framework
  - Azure Functions Core Tools
- **Best Practices**:
  - Cold start mitigation
  - Idempotent functions
  - Error handling
  - Testing strategies

#### Microservices
- **Architecture Patterns**
- **Service Discovery**
- **API Gateway Patterns**
- **Event-Driven Communication**
- **Data Consistency Challenges**

#### Containerization & Orchestration
- **Container Registries**
- **CI/CD for Containers**
- **Advanced Kubernetes Features**:
  - Custom controllers
  - Operators
  - Extension API servers
  - Multi-cluster management
- **Service Mesh**:
  - Istio
  - Linkerd
  - Consul Connect

#### Resilient Architecture
- **Failure Modes Analysis**
- **Chaos Engineering**
- **Circuit Breakers & Bulkheads**
- **Health Checks & Monitoring**
- **Multi-Region Deployments**

### Advanced Resources
- [AWS Documentation](https://docs.aws.amazon.com/)
- [Azure Documentation](https://docs.microsoft.com/en-us/azure/)
- [GCP Documentation](https://cloud.google.com/docs)
- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)
- [The Cloud Adoption Framework](https://docs.microsoft.com/en-us/azure/cloud-adoption-framework/)
- [Google Cloud Architecture Framework](https://cloud.google.com/architecture/framework/)
