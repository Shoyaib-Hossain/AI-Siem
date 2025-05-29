SIEM System Architecture 


                            🛡️ COMPREHENSIVE SIEM ARCHITECTURE 🛡️
                                    
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                 DATA SOURCES LAYER                                      │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│  🖥️  MAC HOST SYSTEM                          🌐 NETWORK LAYER                        │
│  ┌─────────────────────────┐                  ┌─────────────────────────┐              │
│  │ • Authentication Logs   │                  │ • Network Connections   │              │
│  │ • System Kernel Events  │                  │ • Traffic Analysis      │              │
│  │ • Application Logs      │                  │ • Firewall Events       │              │
│  │ • Security Events       │                  │ • IDS/IPS Alerts        │              │
│  │ • Process Activity      │                  │ • DNS Queries           │              │
│  │ • File System Changes   │                  │ • Bandwidth Usage       │              │
│  └─────────────────────────┘                  └─────────────────────────┘              │
│           │                                            │                                │
│           ▼                                            ▼                                │
└─────────────────────────────────────────────────────────────────────────────────────────┘
           │                                            │
           ▼                                            ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                               COLLECTION LAYER                                          │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│  📡 LOG COLLECTORS                                                                      │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │                                                                                  │  │
│  │  mac_host_logs.py           real_log_collector.py                               │  │
│  │  ┌─────────────────┐       ┌──────────────────────┐                            │  │
│  │  │ • Auth Events   │       │ • System Resources   │                            │  │
│  │  │ • Network Logs  │  ───▶ │ • Process Monitor    │                            │  │
│  │  │ • System Logs   │       │ • Network Activity   │                            │  │
│  │  │ • App Events    │       │ • Security Events    │                            │  │
│  │  │ • Security Logs │       │ • Synthetic Data     │                            │  │
│  │  └─────────────────┘       └──────────────────────┘                            │  │
│  │           │                           │                                        │  │
│  │           └───────────┬───────────────┘                                        │  │
│  │                       ▼                                                        │  │
│  │              ┌─────────────────┐                                               │  │
│  │              │ Log Normalizer  │                                               │  │
│  │              │ • JSON Format   │                                               │  │
│  │              │ • Timestamps    │                                               │  │
│  │              │ • Field Mapping │                                               │  │
│  │              └─────────────────┘                                               │  │
│  └──────────────────────────────────────────────────────────────────────────────────┘  │
│                                  │                                                     │
└─────────────────────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼ HTTP POST /api/ingest_log
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                               INGESTION LAYER                                           │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│  🔄 LOG INGESTION SERVICE (Port 8000)                                                  │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │  siem_architecture.py [log_ingestion]                                            │  │
│  │  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐             │  │
│  │  │ REST API        │    │ Data Validation │    │ Rate Limiting   │             │  │
│  │  │ /ingest         │───▶│ • Schema Check  │───▶│ • Throttling    │             │  │
│  │  │ • POST Handler  │    │ • Sanitization  │    │ • Queue Mgmt    │             │  │
│  │  │ • JSON Parser   │    │ • Enrichment    │    │ • Load Balance  │             │  │
│  │  └─────────────────┘    └─────────────────┘    └─────────────────┘             │  │
│  └──────────────────────────────────────────────────────────────────────────────────┘  │
│                                  │                                                     │
└─────────────────────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼ In-Memory Queue
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                            PROCESSING LAYER                                             │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│  🤖 ANOMALY DETECTION SERVICE (Port 8001)     🔍 DETECTION RULES ENGINE               │
│  ┌─────────────────────────────────────┐      ┌─────────────────────────────────────┐  │
│  │ siem_architecture.py [anomaly]      │      │ detection_rules.py                  │  │
│  │ ┌─────────────────────────────────┐ │      │ ┌─────────────────────────────────┐ │  │
│  │ │ 🧠 Machine Learning Engine      │ │      │ │ 📋 Rule-Based Detection         │ │  │
│  │ │ • Isolation Forest             │ │◀────▶│ │ • Brute Force Detection         │ │  │
│  │ │ • Feature Engineering          │ │      │ │ • Login Velocity Analysis       │ │  │
│  │ │ • Batch Processing (n=10)      │ │      │ │ • Multi-IP Access Patterns      │ │  │
│  │ │ • Anomaly Scoring              │ │      │ │ • Error Rate Spike Detection    │ │  │
│  │ │ • Model Training               │ │      │ │ • Suspicious Pattern Matching   │ │  │
│  │ └─────────────────────────────────┘ │      │ │ • Response Time Anomalies       │ │  │
│  │                                     │      │ └─────────────────────────────────┘ │  │
│  │ 🎯 Feature Extraction:              │      │                                     │  │
│  │ • Response Time                     │      │ 🚨 Rule Categories:                 │  │
│  │ • Status Codes                      │      │ • Authentication Attacks           │  │
│  │ • Request Patterns                  │      │ • Network Anomalies                │  │
│  │ • User Behavior                     │      │ • System Resource Abuse            │  │
│  │ • Network Traffic                   │      │ • Injection Attacks                │  │
│  └─────────────────────────────────────┘      │ • Data Exfiltration                │  │
│                   │                           └─────────────────────────────────────┘  │
│                   ▼                                           │                        │
│                                                              ▼                        │
│              ┌─────────────────────────────────────────────────────────────────┐      │
│              │                🔬 BAYESIAN SCORING ENGINE                        │      │
│              │ ┌─────────────────────────────────────────────────────────────┐ │      │
│              │ │ bayesian_score(event, prior=0.5, likelihood_normal=0.8,    │ │      │
│              │ │                likelihood_anomalous=0.2)                    │ │      │
│              │ │                                                             │ │      │
│              │ │ Formula: P(Anomaly|Event) = P(Event|Anomaly) × P(Anomaly)  │ │      │
│              │ │                            ──────────────────────────────  │ │      │
│              │ │                                    P(Event)               │ │      │
│              │ │                                                             │ │      │
│              │ │ Confidence Levels:                                          │ │      │
│              │ │ • High (>80%): 🔴 Critical Alert                           │ │      │
│              │ │ • Medium (60-80%): 🟠 Warning                              │ │      │
│              │ │ • Low (<60%): 🟡 Informational                             │ │      │
│              │ └─────────────────────────────────────────────────────────────┘ │      │
│              └─────────────────────────────────────────────────────────────────┘      │
│                                           │                                           │
└─────────────────────────────────────────────────────────────────────────────────────────┘
                                           │
                                           ▼ Anomaly Events
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                            CORRELATION LAYER                                            │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│  🔗 ALERT CORRELATION SERVICE (Port 8002)                                              │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │ siem_architecture.py [alert_correlation]                                         │  │
│  │ ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │  │
│  │ │ Anomaly Buffer  │  │ Time Window     │  │ Pattern Match   │  │ Alert Gen    │ │  │
│  │ │ • 5min window   │─▶│ • Correlation   │─▶│ • Source IP     │─▶│ • Severity   │ │  │
│  │ │ • Event Queue   │  │ • Temporal      │  │ • Event Type    │  │ • Count      │ │  │
│  │ │ • Deduplication │  │ • Grouping      │  │ • User Pattern  │  │ • Escalation │ │  │
│  │ └─────────────────┘  └─────────────────┘  └─────────────────┘  └──────────────┘ │  │
│  │                                                                                  │  │
│  │ 📊 Correlation Rules:                                                            │  │
│  │ • Multiple anomalies from same source (≥3) → Generate Alert                     │  │
│  │ • Failed login attempts + Network scan → Brute force attack                     │  │
│  │ • High resource usage + External connections → Data exfiltration               │  │
│  │ • Error rate spike + Suspicious patterns → Injection attack                     │  │
│  └──────────────────────────────────────────────────────────────────────────────────┘  │
│                                  │                                                     │
└─────────────────────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼ HTTP POST /api/ingest_anomaly & /api/ingest_alert
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                            VISUALIZATION LAYER                                          │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│  🎨 SIEM DASHBOARD (Port 3000)                                                         │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │ dashboard.py                                                                     │  │
│  │ ┌─────────────────────────────────────────────────────────────────────────────┐  │  │
│  │ │                        🖥️ WEB INTERFACE                                     │  │  │
│  │ │ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌────────┐ │  │  │
│  │ │ │📊 Stats Grid│ │📈 Log Trends│ │🗺️ Threat Map│ │🚨 Alert Feed│ │⚙️ Health│ │  │  │
│  │ │ │• Total Logs │ │• 24hr Chart │ │• Geo Threats│ │• Critical   │ │• CPU    │ │  │  │
│  │ │ │• Anomalies  │ │• ML Trends  │ │• IP Mapping │ │• High       │ │• Memory │ │  │  │
│  │ │ │• Alerts     │ │• Categories │ │• Heatmap    │ │• Medium     │ │• Disk   │ │  │  │
│  │ │ │• Blocked IPs│ │• Predictions│ │• Risk Zones │ │• Actions    │ │• Network│ │  │  │
│  │ │ └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘ └────────┘ │  │  │
│  │ │                                                                             │  │  │
│  │ │ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │  │  │
│  │ │ │📋 Live Logs │ │🔮 Predictions│ │🛡️ Intel Feed│ │⚡ Real-time │            │  │  │
│  │ │ │• Streaming  │ │• Bayesian   │ │• Threat Data│ │• Auto-refresh│            │  │  │
│  │ │ │• Filtering  │ │• Confidence │ │• CVE Alerts │ │• 30sec cycle │            │  │  │
│  │ │ │• Search     │ │• Forecasting│ │• CISA Warns │ │• Live Updates│            │  │  │
│  │ │ └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘            │  │  │
│  │ └─────────────────────────────────────────────────────────────────────────────┐  │  │
│  │                                                                               │  │  │
│  │ 🎛️ INTERACTIVE CONTROLS:                                                      │  │  │
│  │ • Time Range Filters (1h/24h/7d/30d)                                         │  │  │
│  │ • Severity Filters (Critical/High/Medium/Low)                                 │  │  │
│  │ • Source Filters (Firewall/IDS/Endpoint/Network)                             │  │  │
│  │ • Investigation Actions (Block IP/Escalate/Export)                            │  │  │
│  │                                                                               │  │  │
│  │ 📊 VISUALIZATION TECHNOLOGIES:                                                │  │  │
│  │ • Chart.js - Interactive Charts & Graphs                                     │  │  │
│  │ • Leaflet.js - Threat Geography Maps                                         │  │  │
│  │ • Modern CSS - Responsive Design with Animations                             │  │  │
│  │ • WebSocket-like Updates - Real-time Data Refresh                            │  │  │
│  └─────────────────────────────────────────────────────────────────────────────────┘  │
│                                  │                                                     │
└─────────────────────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼ API Calls
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                            INTEGRATION LAYER                                            │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│  🔗 EXTERNAL INTEGRATIONS                                                              │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │ siem_integrations.py                                                             │  │
│  │                                                                                  │  │
│  │ 📢 NOTIFICATION SERVICES:          📡 THREAT INTELLIGENCE:                      │  │
│  │ ┌─────────────────────────────┐    ┌─────────────────────────────┐             │  │
│  │ │ Slack Integration           │    │ AbuseIPDB API               │             │  │
│  │ │ • Alert Webhooks            │    │ • IP Reputation Checks      │             │  │
│  │ │ • Rich Message Formatting   │    │ • Malicious IP Detection    │             │  │
│  │ │ • Severity-based Routing    │    │ • Geolocation Data          │             │  │
│  │ │ • Alert Correlation         │    │ • Threat Scoring            │             │  │
│  │ └─────────────────────────────┘    └─────────────────────────────┘             │  │
│  │                                                                                  │  │
│  │ 💾 DATA EXPORT SERVICES:                                                         │  │
│  │ ┌─────────────────────────────────────────────────────────────────────────────┐ │  │
│  │ │ Elasticsearch Integration                                                   │ │  │
│  │ │ • Log Indexing & Storage                                                    │ │  │
│  │ │ • Advanced Search & Analytics                                               │ │  │
│  │ │ • Long-term Data Retention                                                  │ │  │
│  │ │ • Kibana Dashboard Integration                                              │ │  │
│  │ └─────────────────────────────────────────────────────────────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                         │
└─────────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                            STORAGE & ANALYTICS LAYER                                    │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│  🗄️ ELASTICSEARCH CLUSTER (Port 9200)      📊 KIBANA ANALYTICS (Port 5601)           │
│  ┌─────────────────────────────────────┐    ┌─────────────────────────────────────┐   │
│  │ • Document Storage                  │    │ • Advanced Dashboards               │   │
│  │ • Full-text Search                  │───▶│ • Custom Visualizations            │   │
│  │ • Log Indexing                      │    │ • Query Builder                     │   │
│  │ • Aggregations                      │    │ • Report Generation                 │   │
│  │ • Scalable Architecture             │    │ • Data Exploration                  │   │
│  └─────────────────────────────────────┘    └─────────────────────────────────────┘   │
│                                                                                         │
└─────────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                            CONTAINER ORCHESTRATION                                       │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│  🐳 DOCKER COMPOSE ARCHITECTURE                                                         │
│  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
│  │                                                                                  │  │
│  │ Network: siem-net (Bridge)                                                      │  │
│  │ ┌────────────────┐ ┌────────────────┐ ┌────────────────┐ ┌──────────────────┐ │  │
│  │ │log_ingestion   │ │anomaly_detection│ │alert_correlation│ │siem_dashboard    │ │  │
│  │ │:8000 → :5000   │ │:8001 → :5001   │ │:8002 → :5002   │ │:3000 → :5000     │ │  │
│  │ └────────────────┘ └────────────────┘ └────────────────┘ └──────────────────┘ │  │
│  │ ┌────────────────┐ ┌────────────────┐ ┌────────────────┐                      │  │
│  │ │elasticsearch   │ │kibana          │ │log_collector   │                      │  │
│  │ │:9200           │ │:5601           │ │(no external)   │                      │  │
│  │ └────────────────┘ └────────────────┘ └────────────────┘                      │  │
│  │                                                                                  │  │
│  │ Volumes: es-data (Persistent Storage)                                           │  │
│  │ Health Checks: Service Monitoring & Auto-restart                               │  │
│  └──────────────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────────────┘

                    🔄 DATA FLOW SUMMARY
                    ═══════════════════════

Mac System Logs → Log Collectors → Ingestion Service → Processing Layer 
     ↓                                                        ↓
Anomaly Detection ← Rule Engine ← ML Models ← Bayesian Scoring
     ↓                                                        ↓  
Alert Correlation → Dashboard Visualization → External Integrations
     ↓                                                        ↓
Elasticsearch Storage ← Kibana Analytics ← Threat Intelligence

                    ⚡ KEY FEATURES ⚡
                    ════════════════

• Real-time log collection from actual Mac system
• Machine learning-based anomaly detection (Isolation Forest)
• Rule-based threat detection (6+ categories)
• Bayesian probability scoring for confidence levels
• Interactive web dashboard with live updates
• Threat geography mapping and visualization
• Alert correlation with time-window analysis
• External integrations (Slack, Threat Intel, Elasticsearch)
• Containerized microservices architecture
• Auto-scaling and health monitoring



On localhost:3000 dashboard looks like :

<img width="500" alt="image" src="https://github.com/Shoyaib-Hossain/AI-Siem/blob/main/Image%2029-05-2025%20at%2014.18.jpeg" />

