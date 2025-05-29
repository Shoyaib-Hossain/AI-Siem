SIEM System Architecture (Under development)

<img width="600" alt="image" src="https://github.com/Shoyaib-Hossain/AI-Siem/blob/main/Image%2029-05-2025%20at%2020.03.jpeg" />


1. Dashboard Service (dashboard.py)

A sophisticated web-based security dashboard with real-time monitoring
Beautiful UI showing logs, anomalies, alerts, threat geography, and system health
Features charts, maps, and interactive elements
Auto-refreshes every 30 seconds
Handles incoming logs and anomalies via REST APIs

2. Log Collection (real_log_collector.py & mac_host_logs.py)

Collects real system data from your Mac:

Network connections and traffic
System resources (CPU, memory, disk)
Running processes
Authentication events
Security logs


Sends this data to the dashboard for analysis

3. Anomaly Detection (anomaly_detection.py)

Uses machine learning (Isolation Forest) to detect unusual patterns
Analyzes response times, status codes, and other metrics
Classifies anomalies by severity level

4. Detection Rules Engine (detection_rules.py)

Advanced rule-based detection for:

Brute force attacks (failed login attempts)
Login velocity (too many logins too fast)
Multiple IP access patterns
Error rate spikes
Suspicious activity patterns (SQL injection, XSS, etc.)



5. Integration Layer (siem_integrations.py)

Slack notifications for alerts
Threat intelligence lookups
Elasticsearch export capabilities

Technology Stack

Backend: Python Flask
ML: scikit-learn for anomaly detection
Frontend: Modern HTML/CSS/JavaScript with charts and maps
Data Storage: In-memory with optional Elasticsearch
Containerization: Docker Compose setup
Visualization: Chart.js for graphs, Leaflet for threat maps

Key Features

Real-time monitoring of your actual Mac system
Machine learning-based anomaly detection
Rule-based threat detection
Interactive dashboard with filtering and controls
Threat geography mapping
System health monitoring
Alert correlation and escalation
Bayesian scoring for prediction confidence

How It Works

Log collectors continuously gather real data from your Mac
Detection engines analyze this data for anomalies and threats
Dashboard displays everything in real-time with visualizations
Alerts are generated for suspicious activities
Integration layer can send notifications and export data



On localhost:3000 dashboard looks like :

<img width="600" alt="image" src="https://github.com/Shoyaib-Hossain/AI-Siem/blob/main/Image%2029-05-2025%20at%2014.18.jpeg" />

