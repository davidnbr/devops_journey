# 6. Monitoring & Observability

## Monitoring Fundamentals

### Core Concepts
- **Metrics**: Numeric measurements collected at regular intervals
- **Logs**: Timestamped records of discrete events
- **Traces**: Records of operations across distributed systems
- **Events**: Significant occurrences within systems
- **Alerts**: Notifications based on predefined conditions
- **Dashboards**: Visual representations of system state

### Monitoring Layers
- **Infrastructure Monitoring**:
  - Hardware metrics (CPU, memory, disk, network)
  - OS metrics (load, processes, file descriptors)
  - Virtualization metrics (hypervisor stats)
- **Network Monitoring**:
  - Throughput
  - Latency
  - Packet loss
  - Connection states
  - DNS performance
- **Application Monitoring**:
  - Response times
  - Error rates
  - Throughput
  - Saturation
  - Utilization
- **Business Monitoring**:
  - User activity
  - Conversion rates
  - Transaction volumes
  - Revenue metrics
  - Service level indicators

### Monitoring Architecture
- **Push vs. Pull Models**:
  - Pull: Monitoring system scrapes metrics (e.g., Prometheus)
  - Push: Systems send metrics to collector (e.g., StatsD)
- **Collection Methods**:
  - Agents (node_exporter, Datadog Agent)
  - APIs (AWS CloudWatch API)
  - Log shippers (Fluentd, Logstash)
  - Service meshes (Istio, Linkerd)
- **Storage Considerations**:
  - Time series databases (Prometheus, InfluxDB)
  - Data retention policies
  - Aggregation and downsampling
  - Sharding and federation
- **Scalability Patterns**:
  - Hierarchical collection
  - Streaming telemetry
  - Sampling techniques
  - Edge processing

## Prometheus

### Architecture
- **Components**:
  - Prometheus Server (scraping, storage, rule evaluation)
  - Alertmanager (alert handling and routing)
  - Pushgateway (for batch jobs)
  - Exporters (metrics collection)
  - Client Libraries (instrumentation)
- **Data Model**:
  - Metrics and Labels
  - Time Series identifier: `metric_name{label1="value1", label2="value2"}`
  - Sample: A specific value at a specific time
- **Storage**:
  - Local storage (TSDB)
  - Remote storage integrations

### Configuration
```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - 'rules/*.yml'

alerting:
  alertmanagers:
  - static_configs:
    - targets:
      - 'alertmanager:9093'

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node'
    static_configs:
      - targets: ['node-exporter:9100']

  - job_name: 'application'
    metrics_path: '/metrics'
    scheme: 'https'
    basic_auth:
      username: 'prometheus'
      password: 'password'
    tls_config:
      insecure_skip_verify: false
    static_configs:
      - targets: ['app:8080']
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance
        regex: '(.*):.*'
        replacement: '${1}'
```

### PromQL (Prometheus Query Language)
```promql
# Basic query - CPU usage rate
rate(node_cpu_seconds_total{mode="user"}[5m])

# Aggregation - Average CPU usage per instance
avg by (instance) (rate(node_cpu_seconds_total{mode="user"}[5m]))

# Alert condition - High error rate
sum(rate(http_requests_total{status=~"5.."}[5m])) /
sum(rate(http_requests_total[5m])) > 0.1

# Recording rule - Calculate 95th percentile latency
histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le, service))

# Range vector - Last week's error rate
sum(rate(http_requests_total{status=~"5.."}[1h])) by (day) [1w:1h]
```

### Alerting
```yaml
# alerting_rules.yml
groups:
- name: availability
  rules:
  - alert: HighErrorRate
    expr: sum(rate(http_requests_total{status=~"5.."}[5m])) by (service) / sum(rate(http_requests_total[5m])) by (service) > 0.1
    for: 5m
    labels:
      severity: critical
      team: backend
    annotations:
      summary: "High error rate for {{ $labels.service }}"
      description: "{{ $labels.service }} has an error rate above 10% for more than 5 minutes. Current value: {{ $value | printf \"%.2f\" }}%"
      runbook: "https://runbooks.example.com/high-error-rate"
      
  - alert: InstanceDown
    expr: up == 0
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "Instance {{ $labels.instance }} down"
      description: "{{ $labels.instance }} has been down for more than 5 minutes."
```

### Exporter Development
```go
package main

import (
    "net/http"
    "log"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
    activeConnections = prometheus.NewGauge(prometheus.GaugeOpts{
        Name: "app_active_connections",
        Help: "Current number of active connections",
    })
    
    requestsTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "app_requests_total",
            Help: "Total number of requests by status code and method",
        },
        []string{"code", "method"},
    )
    
    requestDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "app_request_duration_seconds",
            Help:    "Request duration in seconds",
            Buckets: prometheus.DefBuckets,
        },
        []string{"handler", "method"},
    )
)

func init() {
    prometheus.MustRegister(activeConnections)
    prometheus.MustRegister(requestsTotal)
    prometheus.MustRegister(requestDuration)
}

func main() {
    // Expose metrics
    http.Handle("/metrics", promhttp.Handler())
    
    // Start server
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

## Grafana

### Dashboard Creation
- **Panel Types**:
  - Time Series
  - Gauge
  - Bar Chart
  - Stat
  - Table
  - Heatmap
  - Logs
  - Node Graph
- **Variables**:
  - Query Variables
  - Custom Variables
  - Text Box Variables
  - Interval Variables
  - Data Source Variables
- **Templating**:
  - Multi-value selections
  - Variable formats
  - Repeating panels and rows
- **Annotations**:
  - Time-based markers
  - Region annotations
  - Query-based annotations

### Alerting
- **Alert Rules**:
  - Condition Types
  - Multiple Conditions
  - Alert States
  - No Data & Error Handling
- **Notification Channels**:
  - Email
  - Slack
  - PagerDuty
  - Webhooks
  - OpsGenie
  - VictorOps
- **Alert Grouping and Routing**:
  - Contact Points
  - Notification Policies
  - Mute Timings
  - Alert Grouping

### Provisioning
```yaml
# datasources.yml
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: false
    jsonData:
      timeInterval: "15s"
      httpMethod: POST
    
  - name: Loki
    type: loki
    access: proxy
    url: http://loki:3100
    editable: false
```

```yaml
# dashboards.yml
apiVersion: 1

providers:
  - name: 'default'
    orgId: 1
    folder: 'General'
    type: file
    disableDeletion: false
    updateIntervalSeconds: 30
    options:
      path: /etc/grafana/provisioning/dashboards
      foldersFromFilesStructure: true
```

## ELK Stack (Elasticsearch, Logstash, Kibana)

### Elasticsearch
- **Core Concepts**:
  - Indices and Documents
  - Shards and Replicas
  - Mappings and Types
  - Analyzers and Tokenizers
- **Cluster Management**:
  - Node Roles
  - Discovery and Cluster Formation
  - Shard Allocation
  - Index Lifecycle Management
- **Query DSL**:
  ```json
  {
    "query": {
      "bool": {
        "must": [
          { "match": { "service": "api-gateway" } }
        ],
        "filter": [
          { "term": { "level": "error" } },
          { "range": { "@timestamp": { "gte": "now-15m" } } }
        ],
        "should": [
          { "match": { "message": "timeout" } }
        ],
        "minimum_should_match": 1
      }
    },
    "aggs": {
      "errors_by_endpoint": {
        "terms": {
          "field": "endpoint.keyword",
          "size": 10
        }
      }
    },
    "sort": [
      { "@timestamp": { "order": "desc" } }
    ],
    "size": 100
  }
  ```

### Logstash
- **Pipeline Components**:
  - Inputs
  - Filters
  - Outputs
- **Configuration Example**:
  ```ruby
  input {
    beats {
      port => 5044
    }
    kafka {
      bootstrap_servers => "kafka1:9092,kafka2:9092"
      topics => ["logs"]
      codec => json
    }
  }
  
  filter {
    if [type] == "nginx" {
      grok {
        match => { "message" => "%{COMBINEDAPACHELOG}" }
      }
      date {
        match => [ "timestamp", "dd/MMM/yyyy:HH:mm:ss Z" ]
        target => "@timestamp"
      }
      geoip {
        source => "clientip"
        target => "geoip"
      }
    }
    
    if [type] == "application" {
      json {
        source => "message"
      }
      mutate {
        add_field => {
          "correlation_id" => "%{[request][id]}"
        }
      }
    }
  }
  
  output {
    elasticsearch {
      hosts => ["elasticsearch:9200"]
      index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
      user => "elastic"
      password => "${ELASTIC_PASSWORD}"
    }
    if [loglevel] == "error" {
      http {
        url => "http://alert-service:8080/api/alert"
        http_method => "post"
        content_type => "application/json"
        format => "json"
        mapping => {
          "service" => "%{service}"
          "error" => "%{message}"
          "timestamp" => "%{@timestamp}"
        }
      }
    }
  }
  ```

### Kibana
- **Discover and Search**
- **Visualizations and Dashboards**
- **Canvas and Lens**
- **TSVB and Logs UI**
- **Security and Role-Based Access**

## Distributed Tracing

### OpenTelemetry
- **Components**:
  - API
  - SDK
  - Collector
  - Exporters
- **Instrumentation**:
  ```java
  // Java example
  import io.opentelemetry.api.OpenTelemetry;
  import io.opentelemetry.api.trace.Span;
  import io.opentelemetry.api.trace.Tracer;
  
  public class OrderProcessor {
      private final Tracer tracer;
      
      public OrderProcessor(OpenTelemetry openTelemetry) {
          this.tracer = openTelemetry.getTracer("com.example.OrderProcessor");
      }
      
      public void processOrder(Order order) {
          Span span = tracer.spanBuilder("processOrder").startSpan();
          try {
              span.setAttribute("order.id", order.getId());
              span.setAttribute("order.amount", order.getAmount());
              
              // Process the order
              validateOrder(order, span);
              reserveInventory(order, span);
              chargePayment(order, span);
              
              span.setStatus(StatusCode.OK);
          } catch (Exception e) {
              span.setStatus(StatusCode.ERROR, e.getMessage());
              span.recordException(e);
              throw e;
          } finally {
              span.end();
          }
      }
      
      private void validateOrder(Order order, Span parentSpan) {
          Span span = tracer.spanBuilder("validateOrder")
              .setParent(Context.current().with(parentSpan))
              .startSpan();
          try {
              // Validation logic
              span.setStatus(StatusCode.OK);
          } catch (Exception e) {
              span.setStatus(StatusCode.ERROR, e.getMessage());
              span.recordException(e);
              throw e;
          } finally {
              span.end();
          }
      }
      
      // Similar methods for reserveInventory and chargePayment
  }
  ```
- **Context Propagation**:
  ```java
  // Server handling request
  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response) {
      Context extractedContext = textMapPropagator.extract(Context.current(), request, getter);
      Span span = tracer.spanBuilder("handleRequest")
          .setParent(extractedContext)
          .startSpan();
          
      try (Scope scope = span.makeCurrent()) {
          // Process request
          // ...
          
          // Make downstream call
          URL url = new URL("http://otherservice:8080/api");
          HttpURLConnection con = (HttpURLConnection) url.openConnection();
          textMapPropagator.inject(Context.current(), con, setter);
          
          // Continue processing
      } catch (Exception e) {
          span.recordException(e);
      } finally {
          span.end();
      }
  }
  ```

### Jaeger
- **Architecture**:
  - Agent
  - Collector
  - Storage (Elasticsearch, Cassandra)
  - Query Service
  - UI
- **Deployment Models**:
  - All-in-one
  - Production with collectors
  - With Kafka as buffer
- **Sampling Strategies**:
  - Constant
  - Probabilistic
  - Rate Limiting
  - Remote Controlled

### Zipkin
- **Architecture**:
  - Collector
  - Storage
  - Query API
  - Web UI
- **Instrumentation**
- **B3 Propagation**
- **Integration with Service Meshes**

## SLI, SLO, and SLA

### Service Level Indicators (SLIs)
- **Latency**:
  - Request/response time
  - Processing time
  - Queue time
- **Availability**:
  - Uptime percentage
  - Successful request rate
- **Throughput**:
  - Requests per second
  - Transactions per second
- **Error Rates**:
  - Failed requests
  - Error codes
  - Exceptions
- **Saturation**:
  - Resource utilization
  - Queue depth
  - Connection pool usage

### Service Level Objectives (SLOs)
- **Setting Target Values**:
  - Common targets (99%, 99.9%, 99.99%)
  - Realistic vs aspirational
- **Time Windows**:
  - Rolling windows (last 30 days)
  - Calendar windows (monthly, quarterly)
- **Error Budgets**:
  - Calculation methods
  - Budget consumption tracking
  - Actionable alerts

### Service Level Agreements (SLAs)
- **Components**:
  - Service description
  - Performance metrics
  - Measurement methodology
  - Exclusions
  - Remedies
- **Relationship to SLOs**:
  - SLA targets looser than SLOs
  - Buffer between internal and external commitments
- **Financial Implications**:
  - Penalties
  - Credits
  - Termination rights

## Advanced Monitoring & Alerting

### Alert Design Philosophy
- **Alert Fatigue Prevention**:
  - Actionable alerts only
  - Proper thresholds
  - Correlation and de-duplication
- **Alert Severity Levels**:
  - Critical (immediate action required)
  - Warning (action needed soon)
  - Info (attention may be required)
- **On-Call Rotations**:
  - Escalation policies
  - Follow-the-sun
  - Specialized rotations

### Advanced Alerting Patterns
- **Multi-condition Alerts**:
  - Compound conditions
  - Duration conditions
  - Rate of change
- **Anomaly Detection**:
  - Statistical methods
  - Machine learning
  - Seasonality-aware algorithms
- **Correlation**:
  - Topology-based correlation
  - Time-based correlation
  - Causal analysis

### Incident Management
- **Incident Lifecycle**:
  - Detection
  - Response
  - Mitigation
  - Resolution
  - Post-mortem
- **Response Procedures**:
  - Playbooks
  - Communication templates
  - Escalation paths
- **Post-Incident Analysis**:
  - Blameless post-mortems
  - Timeline reconstruction
  - Action items tracking
  - Systemic improvements

## Logs Management

### Log Collection Architecture
- **Collection Methods**:
  - Agents (Filebeat, Fluentd, Vector)
  - Sidecar containers
  - Direct application shipping
  - API integrations
- **Processing Pipeline**:
  - Parsing
  - Enrichment
  - Filtering
  - Transformation
  - Routing
- **Storage Solutions**:
  - Elasticsearch
  - Loki
  - Amazon CloudWatch Logs
  - Google Cloud Logging
  - Azure Monitor Logs

### Structured Logging
- **JSON Logging Format**:
  ```json
  {
    "timestamp": "2023-05-04T12:34:56.789Z",
    "level": "ERROR",
    "logger": "com.example.OrderService",
    "thread": "http-nio-8080-exec-1",
    "message": "Failed to process order",
    "context": {
      "orderId": "ORD-12345",
      "userId": "USR-67890",
      "amount": 99.95
    },
    "exception": {
      "class": "java.lang.IllegalStateException",
      "message": "Insufficient inventory",
      "stacktrace": "..."
    },
    "service": "order-service",
    "environment": "production",
    "version": "1.2.3",
    "traceId": "abcdef1234567890",
    "spanId": "0987654321fedcba"
  }
  ```
- **Contextual Information**:
  - Request IDs
  - User IDs
  - Session IDs
  - Trace IDs

### Log Retention & Compliance
- **Retention Policies**:
  - Hot/warm/cold storage tiers
  - Compression techniques
  - Indexing strategies
- **Compliance Requirements**:
  - PCI DSS
  - HIPAA
  - GDPR
  - SOX
- **Sensitive Data Handling**:
  - Masking
  - Encryption
  - Access controls

## Cost-Effective Monitoring

### Scaling Strategies
- **Sampling**:
  - Head-based sampling
  - Tail-based sampling
  - Priority sampling
- **Filtering**:
  - Data reduction at source
  - Selective monitoring
  - Importance-based routing
- **Aggregation**:
  - Pre-aggregation
  - Client-side aggregation
  - Downsampling

### Retention Optimization
- **Data Lifecycle Management**:
  - High resolution → low resolution
  - Raw data → aggregated data
  - Automated pruning
- **Storage Tiering**:
  - Hot storage (recent data)
  - Warm storage (medium-term)
  - Cold storage (archival)
- **Query Efficiency**:
  - Materialized views
  - Pre-computed aggregates
  - Caching strategies

### Vendor Selection
- **Open Source vs Commercial**:
  - Feature comparison
  - Support considerations
  - Total cost of ownership
- **Multi-tool Strategy**:
  - Best-of-breed approach
  - Integration challenges
  - Unified dashboards

## Advanced Resources
- [Google SRE Books](https://sre.google/books/)
- [Prometheus Documentation](https://prometheus.io/docs/introduction/overview/)
- [Grafana Documentation](https://grafana.com/docs/)
- [OpenTelemetry Documentation](https://opentelemetry.io/docs/)
- [Elasticsearch Documentation](https://www.elastic.co/guide/index.html)
- [Distributed Systems Observability](https://www.oreilly.com/library/view/distributed-systems-observability/9781492033431/) (book)
