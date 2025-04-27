# 3. Containers & Orchestration

## Docker Deep Dive

### Docker Architecture
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

### Container Storage
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

### Container Networking
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

### Advanced Dockerfile Techniques
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

### Container Security
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

### Container Orchestration with Docker Compose
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

### Docker Swarm
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

## Kubernetes Architecture

### Cluster Components
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

### Kubernetes Objects
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

### Advanced Pod Management
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

### Advanced Deployments
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

### StatefulSets
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

### Kubernetes Networking
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

### Kubernetes Storage
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

### Kubernetes Security
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

### Advanced Kubernetes Features
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

### Kubernetes Operations
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

### Advanced Resources
- [Kubernetes Documentation](https://kubernetes.io/docs/home/)
- [Kubernetes Patterns](https://k8spatterns.io/) (book)
- [Kubernetes in Action](https://www.manning.com/books/kubernetes-in-action) (book)
- [Kubernetes the Hard Way](https://github.com/kelseyhightower/kubernetes-the-hard-way)
- [Docker Documentation](https://docs.docker.com/)
- [The Docker Book](https://dockerbook.com/)
