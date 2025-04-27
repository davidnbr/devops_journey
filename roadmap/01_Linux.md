# 1. Linux & Scripting Foundations

## Foundation: Linux & Command Line

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

## Scripting & Programming

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
