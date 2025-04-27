# DevOps Engineer Deep Dive: Comprehensive Guide

## 1. Foundation: Linux & Command Line

### Linux Distributions
- **Enterprise-Focused**: RHEL, CentOS, Rocky Linux, AlmaLinux
  - RPM-based package management (yum/dnf)
  - System V init vs systemd
  - SELinux security model
- **Debian-Based**: Debian, Ubuntu, Linux Mint
  - APT package management
  - AppArmor security model
- **Minimal/Specialized**: Alpine (containers), CoreOS (cluster deployments)
- **Immutable**: NixOS, Fedora Silverblue

### Linux Kernel Basics
- **Process Management**: Understanding `fork()`, `exec()`, and process states
- **Memory Management**: Virtual memory, page tables, swap
- **I/O Scheduling**: Different I/O schedulers and their use cases
- **Network Stack**: TCP/IP implementation, network namespaces
- **Modules**: Loading/unloading kernel modules with `modprobe`

### Filesystem Hierarchy
- `/etc`: System-wide configuration
- `/var`: Variable data (logs, caches)
- `/proc`: Process and kernel information
- `/sys`: Hardware and kernel feature information
- `/dev`: Device files
- `/usr`: User utilities and applications
- `/boot`: Boot loader files
- `/home`: User home directories
- `/opt`: Optional application software packages
- `/mnt` & `/media`: Mount points

### Filesystem Types
- **ext4**: Standard Linux filesystem
- **XFS**: High-performance journaling filesystem
- **Btrfs**: Modern filesystem with advanced features
- **ZFS**: Advanced filesystem with volume management
- **OverlayFS**: Union mount filesystem (used by Docker)

### User and Permission Management
- **User Management Commands**:
  ```bash
  useradd -m -s /bin/bash username
  usermod -aG sudo username
  passwd username
  userdel -r username
  ```
- **Permission Concepts**:
  - Standard permissions: read (4), write (2), execute (1)
  - Special permissions: setuid, setgid, sticky bit
  - Extended attributes and ACLs
  ```bash
  # Set permissions
  chmod 755 file
  
  # Change owner
  chown user:group file
  
  # Set ACL
  setfacl -m u:username:rwx file
  
  # List ACLs
  getfacl file
  ```

### Process Management
- **Viewing Processes**:
  ```bash
  ps aux
  top
  htop
  pstree
  ```
- **Signals and Control**:
  ```bash
  kill -9 PID
  killall process_name
  pkill pattern
  ```
- **Background & Foreground**:
  ```bash
  command &         # Start in background
  Ctrl+Z, bg        # Send to background
  fg                # Bring to foreground
  jobs              # List background jobs
  ```
- **Priority Management**:
  ```bash
  nice -n 10 command
  renice -n 10 -p PID
  ```
- **cgroups**: Resource limiting for processes

### System Configuration
- **systemd Management**:
  ```bash
  systemctl status service
  systemctl enable service
  systemctl disable service
  systemctl start service
  systemctl stop service
  systemctl restart service
  systemctl reload service
  journalctl -u service
  ```
- **Configuration Files**:
  - `/etc/fstab`: Filesystem mounts
  - `/etc/hosts`: Static hostname resolution
  - `/etc/resolv.conf`: DNS configuration
  - `/etc/ssh/sshd_config`: SSH server configuration
  - `/etc/sudoers`: sudo privileges

### Network Configuration
- **IP Configuration**:
  ```bash
  ip addr show
  ip link set dev eth0 up
  ip route show
  ip route add default via 192.168.1.1
  ```
- **Network Troubleshooting**:
  ```bash
  ping host
  traceroute host
  mtr host
  dig domain
  nslookup domain
  tcpdump -i eth0 'port 80'
  netstat -tuln
  ss -tuln
  ```
- **Network Manager**:
  ```bash
  nmcli device status
  nmcli connection show
  nmcli connection add type ethernet ...
  ```
- **Firewall Configuration**:
  ```bash
  # UFW (Ubuntu)
  ufw allow 22
  ufw enable
  
  # firewalld (RHEL/CentOS)
  firewall-cmd --add-service=http --permanent
  firewall-cmd --reload
  ```
- **VPN Setup**: WireGuard, OpenVPN configurations

### Text Processing & Shell Tools
- **grep Advanced Usage**:
  ```bash
  grep -r "pattern" /path  # Recursive
  grep -v "pattern" file   # Inverse match
  grep -A 3 "pattern" file # Show 3 lines after match
  grep -B 2 "pattern" file # Show 2 lines before match
  grep -C 1 "pattern" file # Show 1 line context
  grep -E "regex" file     # Extended regex
  ```
- **sed Deep Dive**:
  ```bash
  # Replace text
  sed 's/old/new/g' file
  
  # Delete lines
  sed '/pattern/d' file
  
  # Print specific lines
  sed -n '5,10p' file
  
  # Multiple commands
  sed -e 's/old/new/g' -e '/pattern/d' file
  
  # In-place editing
  sed -i 's/old/new/g' file
  ```
- **awk Mastery**:
  ```bash
  # Print specific fields
  awk '{print $1, $3}' file
  
  # Filter rows
  awk '$3 > 100' file
  
  # Built-in variables
  awk '{sum+=$1} END {print sum}' file
  
  # Custom field separator
  awk -F: '{print $1}' /etc/passwd
  
  # Complex processing
  awk '
    BEGIN {print "Start processing"}
    /pattern/ {count++}
    END {print "Found", count, "matches"}
  ' file
  ```
- **find Command**:
  ```bash
  # Find by name
  find /path -name "*.log"
  
  # Find by type
  find /path -type f -size +100M
  
  # Find and execute
  find /path -name "*.tmp" -exec rm {} \;
  
  # Complex conditions
  find /path -type f -mtime +30 -name "*.log" -size +10M
  ```
- **xargs Usage**:
  ```bash
  find /path -name "*.log" | xargs grep "error"
  find /path -name "*.tmp" | xargs -I {} mv {} /archive/
  ```

### Advanced Shell Topics
- **Shell Startup Files**:
  - `/etc/profile`, `/etc/bash.bashrc`: System-wide
  - `~/.bash_profile`, `~/.bashrc`: User-specific
- **Environment Variables**:
  ```bash
  export PATH=$PATH:/new/path
  export EDITOR=vim
  ```
- **Shell Functions**:
  ```bash
  function mkcd() {
    mkdir -p "$1" && cd "$1"
  }
  ```
- **Shell Options**:
  ```bash
  set -e  # Exit on error
  set -x  # Print commands before execution
  set -u  # Treat unset variables as error
  ```
- **Process Substitution**:
  ```bash
  diff <(ls dir1) <(ls dir2)
  ```
- **Here Documents**:
  ```bash
  cat <<EOF > file.txt
  This is line 1
  This is line 2
  EOF
  ```

### Storage Management
- **Disk Partitioning**:
  ```bash
  fdisk /dev/sda
  parted /dev/sda
  ```
- **Logical Volume Management (LVM)**:
  ```bash
  pvcreate /dev/sdb
  vgcreate vg_name /dev/sdb
  lvcreate -L 10G -n lv_name vg_name
  mkfs.ext4 /dev/vg_name/lv_name
  lvextend -L +5G /dev/vg_name/lv_name
  resize2fs /dev/vg_name/lv_name
  ```
- **Disk Health Monitoring**:
  ```bash
  smartctl -a /dev/sda
  ```
- **RAID Management**:
  ```bash
  mdadm --create --verbose /dev/md0 --level=1 --raid-devices=2 /dev/sda1 /dev/sdb1
  ```

### System Performance
- **Resource Monitoring**:
  ```bash
  top
  htop
  iotop
  iostat
  vmstat
  mpstat
  ```
- **System Metrics**:
  ```bash
  free -h
  df -h
  du -sh /path
  ```
- **Performance Tuning**:
  - CPU governor settings
  - Disk I/O schedulers
  - Network parameters in `/etc/sysctl.conf`
  - Process niceness

### Practical Linux Server Administration
- **SSH Hardening**:
  ```bash
  # /etc/ssh/sshd_config
  PermitRootLogin no
  PasswordAuthentication no
  X11Forwarding no
  ```
- **Log Management**:
  - `/var/log` directory structure
  - `logrotate` configuration
  - `journalctl` usage for systemd logs
- **Backup Strategies**:
  - `rsync` for file synchronization
  - Using `cron` for scheduled backups
  - Snapshot-based backups
- **Emergency Recovery**:
  - Rescue mode/single-user mode
  - Emergency chroot
  - Disk recovery tools

### Advanced Resources
- [Linux Kernel Documentation](https://www.kernel.org/doc/)
- [Linux Performance by Brendan Gregg](https://www.brendangregg.com/linuxperf.html)
- [The Linux Programming Interface](https://man7.org/tlpi/) (book)
- [Linux System Administrator's Guide](https://tldp.org/LDP/sag/html/index.html)

## 2. Scripting & Programming

### Bash Scripting Mastery
- **Script Structure & Best Practices**:
  ```bash
  #!/bin/bash
  set -euo pipefail
  
  # Define variables
  readonly LOG_FILE="/var/log/myscript.log"
  
  # Define functions
  log() {
    local message="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $message" | tee -a "$LOG_FILE"
  }
  
  # Main logic
  main() {
    log "Script started"
    # ... main code here
    log "Script completed"
  }
  
  # Run main function
  main "$@"
  ```
- **Error Handling**:
  ```bash
  if ! command -v aws &> /dev/null; then
    echo "Error: AWS CLI not installed" >&2
    exit 1
  fi
  
  # Trap for cleanup
  cleanup() {
    rm -f "$TEMP_FILE"
    log "Cleanup completed"
  }
  trap cleanup EXIT
  ```
- **Input Validation**:
  ```bash
  validate_input() {
    if [[ ! $1 =~ ^[0-9]+$ ]]; then
      echo "Error: Input must be a number" >&2
      return 1
    fi
    return 0
  }
  ```
- **Command Substitution**:
  ```bash
  current_date=$(date '+%Y-%m-%d')
  users_logged_in=$(who | wc -l)
  ```
- **Parameter Expansion**:
  ```bash
  # Default values
  name=${1:-"Anonymous"}
  
  # Variable substitution
  echo ${variable/pattern/replacement}
  
  # Substring extraction
  echo ${variable:0:5}
  
  # Variable length
  echo ${#variable}
  ```
- **Control Structures**:
  ```bash
  # Case statement
  case "$option" in
    start)
      start_service
      ;;
    stop)
      stop_service
      ;;
    restart)
      restart_service
      ;;
    *)
      echo "Usage: $0 {start|stop|restart}"
      exit 1
      ;;
  esac
  
  # For loops
  for file in *.log; do
    process_file "$file"
  done
  
  # While loops with read
  while IFS=, read -r name email; do
    create_user "$name" "$email"
  done < users.csv
  ```
- **Advanced Text Processing**:
  ```bash
  # Process JSON with jq
  aws ec2 describe-instances | jq '.Reservations[].Instances[].InstanceId'
  
  # Process XML with xmlstarlet
  xmlstarlet sel -t -v "//server/name" config.xml
  ```

### Python for DevOps
- **Environment Management**:
  ```bash
  # Create virtual environment
  python -m venv venv
  source venv/bin/activate
  
  # Create requirements file
  pip freeze > requirements.txt
  
  # Install dependencies
  pip install -r requirements.txt
  ```
- **Script Structure & Best Practices**:
  ```python
  #!/usr/bin/env python3
  """
  Description: This script manages AWS EC2 instances.
  Author: Your Name
  Date: 2023-01-01
  """
  
  import argparse
  import logging
  import sys
  from typing import List, Dict, Any
  
  # Configure logging
  logging.basicConfig(
      level=logging.INFO,
      format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
  )
  logger = logging.getLogger(__name__)
  
  def parse_arguments() -> argparse.Namespace:
      """Parse command line arguments."""
      parser = argparse.ArgumentParser(description="EC2 Instance Manager")
      parser.add_argument("--region", default="us-west-2", help="AWS region")
      parser.add_argument("--action", choices=["start", "stop", "list"], required=True)
      return parser.parse_args()
  
  def main() -> int:
      """Main function."""
      try:
          args = parse_arguments()
          logger.info(f"Starting with action: {args.action} in region: {args.region}")
          # Main logic here
          return 0
      except Exception as e:
          logger.exception(f"Error occurred: {e}")
          return 1
  
  if __name__ == "__main__":
      sys.exit(main())
  ```
- **Working with APIs**:
  ```python
  import requests
  import json
  from typing import Dict, Any
  
  def get_github_repo_info(owner: str, repo: str) -> Dict[str, Any]:
      """Get GitHub repository information."""
      url = f"https://api.github.com/repos/{owner}/{repo}"
      headers = {"Accept": "application/vnd.github.v3+json"}
      
      response = requests.get(url, headers=headers)
      response.raise_for_status()  # Raise exception for HTTP errors
      
      return response.json()
  
  def create_jira_ticket(summary: str, description: str) -> str:
      """Create a Jira ticket and return its ID."""
      url = "https://your-jira-instance.atlassian.net/rest/api/2/issue"
      headers = {
          "Content-Type": "application/json",
          "Authorization": f"Basic {get_auth_token()}"
      }
      payload = {
          "fields": {
              "project": {"key": "PROJECT"},
              "summary": summary,
              "description": description,
              "issuetype": {"name": "Task"}
          }
      }
      
      response = requests.post(url, headers=headers, data=json.dumps(payload))
      response.raise_for_status()
      
      return response.json()["key"]
  ```
- **File Operations**:
  ```python
  # Reading/writing text files
  def read_config(file_path: str) -> Dict[str, Any]:
      with open(file_path, 'r') as f:
          return json.load(f)
  
  def write_config(config: Dict[str, Any], file_path: str) -> None:
      with open(file_path, 'w') as f:
          json.dump(config, f, indent=2)
  
  # CSV processing
  import csv
  
  def process_csv(file_path: str) -> List[Dict[str, str]]:
      results = []
      with open(file_path, 'r', newline='') as csvfile:
          reader = csv.DictReader(csvfile)
          for row in reader:
              results.append(row)
      return results
  ```
- **Process Management**:
  ```python
  import subprocess
  
  def run_command(command: List[str]) -> str:
      """Run shell command and return output."""
      try:
          result = subprocess.run(
              command,
              stdout=subprocess.PIPE,
              stderr=subprocess.PIPE,
              text=True,
              check=True
          )
          return result.stdout
      except subprocess.CalledProcessError as e:
          logger.error(f"Command failed: {e.stderr}")
          raise
  
  # Example usage
  output = run_command(["docker", "ps", "-a"])
  ```
- **AWS Automation with boto3**:
  ```python
  import boto3
  
  def list_ec2_instances(region: str) -> List[Dict[str, Any]]:
      """List all EC2 instances in the specified region."""
      ec2 = boto3.client('ec2', region_name=region)
      response = ec2.describe_instances()
      
      instances = []
      for reservation in response['Reservations']:
          for instance in reservation['Instances']:
              instances.append({
                  'id': instance['InstanceId'],
                  'type': instance['InstanceType'],
                  'state': instance['State']['Name'],
                  'private_ip': instance.get('PrivateIpAddress', 'N/A'),
                  'public_ip': instance.get('PublicIpAddress', 'N/A')
              })
      
      return instances
  
  def start_ec2_instance(instance_id: str, region: str) -> Dict[str, Any]:
      """Start an EC2 instance."""
      ec2 = boto3.client('ec2', region_name=region)
      response = ec2.start_instances(InstanceIds=[instance_id])
      return response
  ```

### Go for DevOps
- **Project Structure**:
  ```
  /project-name
  ├── cmd/
  │   └── main.go
  ├── internal/
  │   ├── config/
  │   │   └── config.go
  │   └── service/
  │       └── service.go
  ├── pkg/
  │   └── utils/
  │       └── utils.go
  ├── go.mod
  ├── go.sum
  └── README.md
  ```
- **Basic CLI Tool**:
  ```go
  package main
  
  import (
      "flag"
      "fmt"
      "log"
      "os"
  )
  
  func main() {
      // Parse command line flags
      region := flag.String("region", "us-west-2", "AWS region")
      action := flag.String("action", "", "Action to perform (required)")
      flag.Parse()
  
      // Validate input
      if *action == "" {
          flag.Usage()
          os.Exit(1)
      }
  
      // Configure logging
      log.SetFlags(log.LstdFlags | log.Lshortfile)
      log.Printf("Starting with action: %s in region: %s", *action, *region)
  
      // Main logic
      if err := run(*action, *region); err != nil {
          log.Fatalf("Error: %v", err)
      }
  }
  
  func run(action, region string) error {
      switch action {
      case "start":
          return startInstances(region)
      case "stop":
          return stopInstances(region)
      default:
          return fmt.Errorf("unknown action: %s", action)
      }
  }
  
  func startInstances(region string) error {
      fmt.Println("Starting instances in", region)
      // Implementation here
      return nil
  }
  
  func stopInstances(region string) error {
      fmt.Println("Stopping instances in", region)
      // Implementation here
      return nil
  }
  ```
- **Error Handling**:
  ```go
  // Custom error types
  type NotFoundError struct {
      Resource string
      ID       string
  }
  
  func (e NotFoundError) Error() string {
      return fmt.Sprintf("%s with ID %s not found", e.Resource, e.ID)
  }
  
  // Error handling
  func getResource(id string) (*Resource, error) {
      resource, err := repository.Find(id)
      if err != nil {
          if errors.Is(err, sql.ErrNoRows) {
              return nil, NotFoundError{Resource: "Resource", ID: id}
          }
          return nil, fmt.Errorf("database error: %w", err)
      }
      return resource, nil
  }
  ```
- **Concurrency Patterns**:
  ```go
  // Worker pool pattern
  func processItems(items []string, numWorkers int) error {
      var wg sync.WaitGroup
      jobsCh := make(chan string, len(items))
      errorsCh := make(chan error, len(items))
      
      // Start workers
      for i := 0; i < numWorkers; i++ {
          wg.Add(1)
          go func() {
              defer wg.Done()
              for job := range jobsCh {
                  if err := processItem(job); err != nil {
                      errorsCh <- err
                  }
              }
          }()
      }
      
      // Send jobs
      for _, item := range items {
          jobsCh <- item
      }
      close(jobsCh)
      
      // Wait for completion
      wg.Wait()
      close(errorsCh)
      
      // Check for errors
      if len(errorsCh) > 0 {
          return <-errorsCh
      }
      return nil
  }
  ```
- **Working with APIs**:
  ```go
  // HTTP client
  type Client struct {
      httpClient *http.Client
      baseURL    string
      token      string
  }
  
  func NewClient(baseURL, token string) *Client {
      return &Client{
          httpClient: &http.Client{Timeout: 10 * time.Second},
          baseURL:    baseURL,
          token:      token,
      }
  }
  
  func (c *Client) GetResource(id string) (*Resource, error) {
      url := fmt.Sprintf("%s/api/resources/%s", c.baseURL, id)
      req, err := http.NewRequest("GET", url, nil)
      if err != nil {
          return nil, err
      }
      
      req.Header.Set("Authorization", "Bearer "+c.token)
      req.Header.Set("Content-Type", "application/json")
      
      resp, err := c.httpClient.Do(req)
      if err != nil {
          return nil, err
      }
      defer resp.Body.Close()
      
      if resp.StatusCode != http.StatusOK {
          return nil, fmt.Errorf("API returned status: %d", resp.StatusCode)
      }
      
      var resource Resource
      if err := json.NewDecoder(resp.Body).Decode(&resource); err != nil {
          return nil, err
      }
      
      return &resource, nil
  }
  ```
- **AWS SDK Usage**:
  ```go
  import (
      "context"
      "log"
  
      "github.com/aws/aws-sdk-go-v2/aws"
      "github.com/aws/aws-sdk-go-v2/config"
      "github.com/aws/aws-sdk-go-v2/service/ec2"
  )
  
  func listInstances(region string) error {
      // Load AWS configuration
      cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
      if err != nil {
          return err
      }
      
      // Create EC2 client
      client := ec2.NewFromConfig(cfg)
      
      // Describe instances
      resp, err := client.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{})
      if err != nil {
          return err
      }
      
      // Process results
      for _, reservation := range resp.Reservations {
          for _, instance := range reservation.Instances {
              log.Printf("ID: %s, State: %s, Type: %s",
                  *instance.InstanceId,
                  instance.State.Name,
                  instance.InstanceType,
              )
          }
      }
      
      return nil
  }
  ```

### Advanced Programming Concepts
- **Design Patterns**:
  - Factory Pattern
  - Strategy Pattern
  - Observer Pattern
  - Dependency Injection
- **Data Structures & Algorithm Complexity**:
  - Time and space complexity (Big O notation)
  - Common data structures (arrays, linked lists, trees, graphs, hash tables)
  - Searching and sorting algorithms
- **Testing Strategies**:
  - Unit tests
  - Integration tests
  - Property-based testing
  - Mocking external dependencies
- **Asynchronous Programming**:
  - Callbacks
  - Promises/futures
  - Async/await patterns
- **Performance Optimization**:
  - Profiling
  - Memory management
  - CPU optimization
  - I/O optimization

### DevOps-Specific Programming Tasks
- **Writing Custom CLI Tools**
- **API Integrations**
- **Config Parsers and Generators**
- **Log Analyzers**
- **Custom Monitoring Solutions**
- **Deployment Automations**
- **Infrastructure Validation Scripts**

### Advanced Resources
- [Python for DevOps](https://www.oreilly.com/library/view/python-for-devops/9781492057680/) (book)
- [Go Programming Language](https://golang.org/doc/)
- [Advanced Bash-Scripting Guide](https://tldp.org/LDP/abs/html/index.html)
- [Clean Code](https://www.amazon.com/Clean-Code-Handbook-Software-Craftsmanship/dp/0132350882) (book)

## 3. Version Control with Git

### Git Internals
- **Objects Model**:
  - Blobs: File contents
  - Trees: Directory listings
  - Commits: Snapshots with metadata
  - Tags: Named references
- **References**:
  - Branches: Pointers to commits
  - HEAD: Pointer to current branch/commit
  - Remote references
- **Storage Mechanism**:
  - `.git` directory structure
  - Objects database
  - Pack files

### Advanced Git Commands
- **Rewriting History**:
  ```bash
  # Interactive rebase
  git rebase -i HEAD~5
  
  # Squash commits
  git reset --soft HEAD~3 && git commit
  
  # Change author information
  git commit --amend --author="Name <email>"
  
  # Filter branch (complex history rewriting)
  git filter-branch --tree-filter 'rm -f passwords.txt' HEAD
  ```
- **Searching and Blame**:
  ```bash
  # Advanced log filtering
  git log --grep="bug fix" --author="John" --since="2 weeks ago"
  
  # Show changes to a specific function
  git log -L :function_name:file.py
  
  # Find when a line was introduced
  git blame -L 10,20 file.py
  
  # Binary search for bugs
  git bisect start
  git bisect bad
  git bisect good v1.0
  ```
- **Patch Management**:
  ```bash
  # Create patch
  git format-patch master..feature-branch
  
  # Apply patch
  git apply patch_file.patch
  
  # Apply patch with author information
  git am patch_file.patch
  ```
- **Submodules & Subtrees**:
  ```bash
  # Add submodule
  git submodule add https://github.com/user/repo path/to/submodule
  
  # Update submodules
  git submodule update --init --recursive
  
  # Add subtree
  git subtree add --prefix=path/to/subtree https://github.com/user/repo master --squash
  
  # Update subtree
  git subtree pull --prefix=path/to/subtree https://github.com/user/repo master --squash
  ```
- **Reflog**:
  ```bash
  # View reflog
  git reflog
  
  # Recover deleted branch
  git checkout -b recovered-branch HEAD@{1}
  
  # Recover after hard reset
  git reset --hard HEAD@{1}
  ```

### Git Branching Strategies
- **Feature Branch Workflow**:
  - Main branch remains stable
  - Features developed in isolated branches
  - PRs for code review
  - Branch → Code → PR → Review → Merge
- **Gitflow Workflow**:
  - `master`: Production releases
  - `develop`: Integration branch
  - `feature/*`: New features
  - `release/*`: Release preparation
  - `hotfix/*`: Production fixes
  - Complex but structured approach
- **Trunk-Based Development**:
  - Small, frequent commits to main branch
  - Heavy use of feature flags
  - CI/CD focused
  - Emphasis on automated testing
- **GitHub Flow**:
  - Simplified Gitflow
  - Branch → Code → PR → Review → Merge → Deploy
  - Works well with continuous delivery
- **GitLab Flow**:
  - Environment branches (`production`, `staging`)
  - Feature branches merge to main
  - Main merges to environment branches

### Git Hooks
- **Client-Side Hooks**:
  - `pre-commit`: Check code before committing
  - `prepare-commit-msg`: Modify commit message
  - `commit-msg`: Validate commit message
  - `post-commit`: Notification after commit
  - `pre-push`: Check before pushing
- **Server-Side Hooks**:
  - `pre-receive`: Validate pushes
  - `update`: Check individual refs
  - `post-receive`: Notification after receive
- **Sample pre-commit Hook**:
  ```bash
  #!/bin/sh
  # .git/hooks/pre-commit
  
  # Check for syntax errors in Python files
  for file in $(git diff --cached --name-only | grep -E '\.py$')
  do
    if ! python -m py_compile "$file"; then
      echo "Syntax error in $file"
      exit 1
    fi
  done
  
  # Run linting
  if ! pylint $(git diff --cached --name-only | grep -E '\.py$'); then
    echo "Linting issues found"
    exit 1
  fi
  
  exit 0
  ```

### Git in CI/CD Pipelines
- **Integration with CI Tools**:
  - GitHub Actions trigger on push/PR
  - GitLab CI integration with merge requests
  - Jenkins pipeline with Git triggers
- **Automated Testing**:
  - Run tests on each commit/PR
  - Report results back to Git provider
  - Block merges for failing tests
- **Deployment Automation**:
  - Deploy from specific branches
  - Tag-triggered deployments
  - GitOps approaches

### Advanced Git Workflows
- **Monorepo Management**:
  - Handling large repositories
  - Partial clones and sparse checkouts
  - Using Git LFS for binary files
- **Code Review Practices**:
  - PR templates
  - Review automation
  - Code owners
- **Release Management**:
  - Semantic versioning
  - Tag management
  - Release notes generation

### Security Best Practices
- **Sensitive Data Protection**:
  - Prevent committing secrets
  - Tools like Git-secrets
  - History cleaning for accidentally committed secrets
- **GPG Signing**:
  ```bash
  # Configure signing
  git config --global user.signingkey YOUR_GPG_KEY_ID
  git config --global commit.gpgsign true
  
  # Sign commits
  git commit -S -m "Signed commit message"
  
  # Sign tags
  git tag -s v1.0.0 -m "Signed tag"
  
  # Verify signatures
  git verify-commit HEAD
  git verify-tag v1.0.0
  ```
- **Access Control**:
  - Branch protection rules
  - Required reviews
  - Status checks
  - Protected tags

### Git Performance Optimization
- **Repository Maintenance**:
  ```bash
  # Garbage collection
  git gc
  
  # Prune unreachable objects
  git prune
  
  # Optimize local repository
  git gc --aggressive
  
  # Clean up old branches
  git remote prune origin
  ```
- **Large Repository Handling**:
  ```bash
  # Shallow clone
  git clone --depth=1 repository-url
  
  # Sparse checkout
  git clone --filter=blob:none repository-url
  git sparse-checkout set directory1 directory2
  
  # Git LFS setup
  git lfs install
  git lfs track "*.psd"
  ```

### Advanced Resources
- [Pro Git Book](https://git-scm.com/book/en/v2)
- [Git Internals PDF](https://github.com/pluralsight/git-internals-pdf)
- [Atlassian Git Tutorials](https://www.atlassian.com/git/tutorials)
- [Git Best Practices](https://sethrobertson.github.io/GitBestPractices/)

## 4. Containers & Orchestration

### Docker Deep Dive

#### Docker Architecture
- **Components**:
  - Docker daemon (dockerd)
  - REST API
  - Docker CLI
  - containerd
  - runc
- **OCI (Open Container Initiative)**:
  - Runtime Specification
  - Image Specification
  - Distribution Specification

#### Container Storage
- **Storage Drivers**:
  - overlay2 (recommended)
  - devicemapper
  - btrfs
  - zfs
  - aufs (legacy)
- **Union Filesystem**:
  - How layers are combined
  - Copy-on-write mechanism
- **Volumes vs Bind Mounts vs tmpfs**:
  ```bash
  # Volume
  docker volume create my_volume
  docker run -v my_volume:/data nginx
  
  # Bind mount
  docker run -v /host/path:/container/path nginx
  
  # tmpfs
  docker run --tmpfs /tmp nginx
  ```
- **Volume Drivers**:
  - local
  - nfs
  - aws (EBS)
  - azure (Azure File Storage)
  - Custom plugins

#### Container Networking
- **Network Modes**:
  - bridge (default)
  - host
  - none
  - overlay (multi-host)
  - macvlan
  - ipvlan
- **Network Commands**:
  ```bash
  # Create network
  docker network create --driver bridge my-network
  
  # Connect container to network
  docker run --network=my-network nginx
  
  # Inspect network
  docker network inspect my-network
  ```
- **Port Mapping**:
  ```bash
  # Publish port
  docker run -p 8080:80 nginx
  
  # Publish all exposed ports
  docker run -P nginx
  ```
- **DNS and Service Discovery**:
  - Container name resolution
  - Custom DNS servers
  - Network aliases

#### Advanced Dockerfile Techniques
- **Multi-stage Builds**:
  ```dockerfile
  # Build stage
  FROM golang:1.18 as builder
  WORKDIR /app
  COPY . .
  RUN go build -o app
  
  # Final stage
  FROM alpine:latest
  COPY --from=builder /app/app /usr/local/bin/
  ENTRYPOINT ["app"]
  ```
- **BuildKit Features**:
  - Parallel stage execution
  - Skipping unused stages
  - Secret mounting
  ```dockerfile
  # Mount secret during build
  RUN --mount=type=secret,id=npmrc cat /run/secrets/npmrc > .npmrc && \
      npm install && \
      rm .npmrc
  ```
- **Optimization Techniques**:
  - Layer caching strategy
  - Minimizing layer size
  - Using .dockerignore
  - Optimizing dependencies
- **Builder Pattern**:
  - Using different containers for build and runtime
  - Keeping containers minimal
  - Reducing attack surface

#### Container Security
- **Attack Surface Reduction**:
  - Running as non-root
  ```dockerfile
  RUN adduser -D appuser
  USER appuser
  ```
  - Minimal base images
  - Multi-stage builds
- **Image Scanning**:
  - Trivy
  - Clair
  - Anchore
  - Snyk
- **Runtime Security**:
  - AppArmor profiles
  - Seccomp profiles
  - Read-only filesystems
  ```bash
  docker run --read-only nginx
  ```
- **Secrets Management**:
  ```bash
  # Create secret
  docker secret create my_secret secret.txt
  
  # Use secret in service
  docker service create --secret my_secret nginx
  ```
- **Content Trust**:
  ```bash
  # Enable content trust
  export DOCKER_CONTENT_TRUST=1
  
  # Sign image
  docker push username/image:tag
  ```

#### Container Orchestration with Docker Compose
- **Compose File Versions**:
  - Version 3.x features
  - Compatibility with Swarm/Kubernetes
- **Advanced Compose Features**:
  ```yaml
  version: '3.8'
  services:
    web:
      build: 
        context: ./
        dockerfile: Dockerfile.web
        args:
          VERSION: 1.0
      deploy:
        replicas: 2
        resources:
          limits:
            cpus: '0.5'
            memory: 50M
      configs:
        - source: app_config
          target: /etc/app/config.json
      secrets:
        - source: app_secret
          target: /run/secrets/app_secret
      healthcheck:
        test: ["CMD", "curl", "-f", "http://localhost"]
        interval: 30s
        timeout: 10s
        retries: 3
        start_period: 10s
  
  volumes:
    data: {}
  
  configs:
    app_config:
      file: ./config.json
  
  secrets:
    app_secret:
      file: ./secret.txt
  ```
- **Environment Handling**:
  - Using .env files
  - Variable substitution
  - Environment-specific overrides
- **Local Development Workflows**:
  - Development vs production differences
  - Volume mounting for live reloading
  - Debugging inside containers

#### Docker Swarm
- **Swarm Architecture**:
  - Manager nodes
  - Worker nodes
  - Raft consensus
- **Service Deployment**:
  ```bash
  # Initialize swarm
  docker swarm init
  
  # Create service
  docker service create --name web --replicas 3 -p 80:80 nginx
  
  # Update service
  docker service update --image nginx:alpine web
  
  # Scale service
  docker service scale web=5
  ```
- **Swarm Networking**:
  - Overlay networks
  - Ingress networking
  - Load balancing
- **Secrets and Configs**:
  ```bash
  # Create secrets
  echo "secret_data" | docker secret create app_secret -
  
  # Create config
  docker config create app_config config.json
  
  # Use in service
  docker service create --name web \
    --secret app_secret \
    --config app_config \
    nginx
  ```
- **Stacks**:
  ```bash
  # Deploy stack
  docker stack deploy -c docker-compose.yml myapp
  
  # List stacks
  docker stack ls
  
  # Remove stack
  docker stack rm myapp
  ```
- **Health Checks and Rollbacks**:
  - Container health monitoring
  - Automatic rollbacks
  - Update failure policies

### Kubernetes Architecture

#### Cluster Components
- **Control Plane**:
  - API Server
  - etcd
  - Scheduler
  - Controller Manager
  - Cloud Controller Manager
- **Node Components**:
  - kubelet
  - kube-proxy
  - Container Runtime
- **Add-ons**:
  - DNS
  - Dashboard
  - Metrics Server
  - Network Plugin

#### Kubernetes Objects
- **Pods**:
  ```yaml
  apiVersion: v1
  kind: Pod
  metadata:
    name: nginx
    labels:
      app: nginx
  spec:
    containers:
    - name: nginx
      image: nginx:1.21
      ports:
      - containerPort: 80
      resources:
        requests:
          cpu: "100m"
          memory: "128Mi"
        limits:
          cpu: "500m"
          memory: "256Mi"
      livenessProbe:
        httpGet:
          path: /
          port: 80
        initialDelaySeconds: 3
        periodSeconds: 3
      readinessProbe:
        httpGet:
          path: /
          port: 80
        initialDelaySeconds: 5
        periodSeconds: 5
    volumes:
    - name: html
      emptyDir: {}
  ```
- **Controllers**:
  - Deployments
  - ReplicaSets
  - StatefulSets
  - DaemonSets
  - Jobs/CronJobs
- **Services & Networking**:
  - ClusterIP
  - NodePort
  - LoadBalancer
  - ExternalName
  - Ingress
  - Network Policies
- **Storage**:
  - PersistentVolumes
  - PersistentVolumeClaims
  - StorageClasses
  - CSI Drivers
- **Configuration**:
  - ConfigMaps
  - Secrets
  - Resource Quotas
  - Limit Ranges

#### Advanced Pod Management
- **Pod Lifecycle**:
  - Pending → Running → Succeeded/Failed
  - Container states: Waiting, Running, Terminated
  - Restart policies
- **Pod Quality of Service**:
  - Guaranteed QoS
  - Burstable QoS
  - BestEffort QoS
- **Init Containers**:
  ```yaml
  spec:
    initContainers:
    - name: init-db
      image: busybox
      command: ["sh", "-c", "until nslookup db; do echo waiting for db; sleep 2; done"]
    containers:
    - name: app
      image: myapp
  ```
- **Pod Disruption Budgets**:
  ```yaml
  apiVersion: policy/v1
  kind: PodDisruptionBudget
  metadata:
    name: app-pdb
  spec:
    minAvailable: 2
    selector:
      matchLabels:
        app: myapp
  ```
- **Affinity & Anti-Affinity**:
  ```yaml
  spec:
    affinity:
      nodeAffinity:
        requiredDuringSchedulingIgnoredDuringExecution:
          nodeSelectorTerms:
          - matchExpressions:
            - key: kubernetes.io/e2e-az-name
              operator: In
              values:
              - e2e-az1
              - e2e-az2
      podAffinity:
        requiredDuringSchedulingIgnoredDuringExecution:
        - labelSelector:
            matchExpressions:
            - key: app
              operator: In
              values:
              - cache
          topologyKey: "kubernetes.io/hostname"
      podAntiAffinity:
        preferredDuringSchedulingIgnoredDuringExecution:
        - weight: 100
          podAffinityTerm:
            labelSelector:
              matchExpressions:
              - key: app
                operator: In
                values:
                - web
            topologyKey: "kubernetes.io/hostname"
  ```
- **Taints & Tolerations**:
  ```yaml
  # Node with taint
  kubectl taint nodes node1 key=value:NoSchedule
  
  # Pod with toleration
  spec:
    tolerations:
    - key: "key"
      operator: "Equal"
      value: "value"
      effect: "NoSchedule"
  ```

#### Advanced Deployments
- **Deployment Strategies**:
  - RollingUpdate (default)
  - Recreate
  - Blue/Green (using services)
  - Canary (using services or service mesh)
- **Progressive Delivery**:
  - Argo Rollouts
  - Flagger
  - Traffic splitting
- **Custom Update Parameters**:
  ```yaml
  spec:
    strategy:
      type: RollingUpdate
      rollingUpdate:
        maxSurge: 25%
        maxUnavailable: 25%
  ```
- **Rollbacks**:
  ```bash
  kubectl rollout history deployment/myapp
  kubectl rollout undo deployment/myapp
  kubectl rollout undo deployment/myapp --to-revision=2
  ```

#### StatefulSets
- **StatefulSet Characteristics**:
  - Stable network identities
  - Stable storage
  - Ordered deployment and scaling
- **StatefulSet Use Cases**:
  - Databases
  - Clustered applications
  - Applications requiring stable identifiers
- **Headless Services**:
  ```yaml
  apiVersion: v1
  kind: Service
  metadata:
    name: db
  spec:
    clusterIP: None
    selector:
      app: db
    ports:
    - port: 3306
  ```

#### Kubernetes Networking
- **Service Types**:
  - ClusterIP: Internal only
  - NodePort: Exposed on node ports
  - LoadBalancer: External load balancer
  - ExternalName: CNAME record
- **Ingress Controllers**:
  - Nginx Ingress
  - Traefik
  - HAProxy
  - Kong
- **Network Policies**:
  ```yaml
  apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata:
    name: api-allow
  spec:
    podSelector:
      matchLabels:
        app: api
    policyTypes:
    - Ingress
    - Egress
    ingress:
    - from:
      - podSelector:
          matchLabels:
            app: web
      ports:
      - protocol: TCP
        port: 8080
    egress:
    - to:
      - podSelector:
          matchLabels:
            app: db
      ports:
      - protocol: TCP
        port: 5432
  ```
- **CNI Plugins**:
  - Calico
  - Cilium
  - Flannel
  - Weave Net
  - Comparison of features and performance

#### Kubernetes Storage
- **Volume Types**:
  - emptyDir
  - hostPath
  - configMap
  - secret
  - persistentVolumeClaim
  - CSI (Container Storage Interface)
- **Storage Classes**:
  ```yaml
  apiVersion: storage.k8s.io/v1
  kind: StorageClass
  metadata:
    name: fast
  provisioner: kubernetes.io/aws-ebs
  parameters:
    type: gp2
  reclaimPolicy: Retain
  allowVolumeExpansion: true
  ```
- **Dynamic Provisioning**:
  ```yaml
  apiVersion: v1
  kind: PersistentVolumeClaim
  metadata:
    name: data-pvc
  spec:
    accessModes:
      - ReadWriteOnce
    storageClassName: fast
    resources:
      requests:
        storage: 10Gi
  ```
- **StatefulSet Storage**:
  ```yaml
  apiVersion: apps/v1
  kind: StatefulSet
  metadata:
    name: db
  spec:
    serviceName: db
    replicas: 3
    selector:
      matchLabels:
        app: db
    template:
      metadata:
        labels:
          app: db
      spec:
        containers:
        - name: db
          image: mysql:8.0
          volumeMounts:
          - name: data
            mountPath: /var/lib/mysql
    volumeClaimTemplates:
    - metadata:
        name: data
      spec:
        accessModes: [ "ReadWriteOnce" ]
        storageClassName: fast
        resources:
          requests:
            storage: 10Gi
  ```

#### Kubernetes Security
- **Authentication Methods**:
  - X.509 client certificates
  - Static token files
  - OpenID Connect
  - Webhook token authentication
  - Service account tokens
- **Authorization Modes**:
  - RBAC (Role-Based Access Control)
  - ABAC (Attribute-Based Access Control)
  - Node authorization
  - Webhook mode
- **RBAC Resources**:
  ```yaml
  # Role
  apiVersion: rbac.authorization.k8s.io/v1
  kind: Role
  metadata:
    namespace: default
    name: pod-reader
  rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "watch", "list"]
  
  # RoleBinding
  apiVersion: rbac.authorization.k8s.io/v1
  kind: RoleBinding
  metadata:
    name: read-pods
    namespace: default
  subjects:
  - kind: User
    name: jane
    apiGroup: rbac.authorization.k8s.io
  roleRef:
    kind: Role
    name: pod-reader
    apiGroup: rbac.authorization.k8s.io
  ```
- **Pod Security Policies** (deprecated in 1.21, replaced by Pod Security Standards):
  - Pod Security Standards: Baseline, Restricted, Privileged
  - Pod Security Admission Controller
- **Security Context**:
  ```yaml
  spec:
    securityContext:
      runAsUser: 1000
      runAsGroup: 3000
      fsGroup: 2000
    containers:
    - name: app
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop:
          - ALL
          add:
          - NET_BIND_SERVICE
  ```
- **Secrets Management**:
  - Kubernetes Secrets
  - External Secrets Operators
  - HashiCorp Vault integration
  - Sealed Secrets
- **Network Security**:
  - Network Policies
  - Service Mesh (Istio, Linkerd)
  - API Gateway security

#### Advanced Kubernetes Features
- **Custom Resources & Operators**:
  - Custom Resource Definitions (CRDs)
  - Operator Framework
  - Kubernetes Controller Pattern
- **Service Mesh**:
  - Istio
  - Linkerd
  - Consul
  - Features: traffic management, security, observability
- **Helm**:
  - Chart structure
  - Template functions
  - Hooks
  - Repositories
  - Helm 3 vs Helm 2
- **Cluster API**:
  - Declarative cluster management
  - Provider implementations
  - Machine objects
- **Federation**:
  - Multi-cluster management
  - KubeFed
  - Cluster API

#### Kubernetes Operations
- **Cluster Upgrades**:
  - Control plane upgrades
  - Node upgrades
  - Version skew policies
- **Backup & Restore**:
  - etcd backup
  - Velero
  - Application-level backup
- **Troubleshooting**:
  - Analyzing pod status
  - Logs and events
  - Debugging with ephemeral containers
  - Network troubleshooting
- **Capacity Planning**:
  - Resource requests and limits
  - Cluster autoscaling
  - Quotas and limits
- **Cost Optimization**:
  - Right-sizing workloads
  - Spot instances
  - Multi-tenancy
  - Namespace resource quotas

#### Advanced Resources
- [Kubernetes Documentation](https://kubernetes.io/docs/home/)
- [Kubernetes Patterns](https://k8spatterns.io/) (book)
- [Kubernetes in Action](https://www.manning.com/books/kubernetes-in-action) (book)
- [Kubernetes the Hard Way](https://github.com/kelseyhightower/kubernetes-the-hard-way)
- [Docker Documentation](https://docs.docker.com/)
- [The Docker Book](https://dockerbook.com/)

## 5. Infrastructure as Code

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

## 6. Configuration Management

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

## 7. CI/CD Pipelines

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

#### Advanced Features
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
