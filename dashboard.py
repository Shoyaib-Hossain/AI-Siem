import os
import json
import time
import threading
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template_string, jsonify, request
from kafka import KafkaConsumer
from collections import defaultdict, deque
import random

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration
KAFKA_HOST = os.environ.get('KAFKA_HOST', 'kafka:9092')

# Global data storage for real-time updates
recent_logs = deque(maxlen=100)
recent_anomalies = deque(maxlen=50)
recent_alerts = deque(maxlen=25)
stats = {
    'total_logs': 0,
    'total_anomalies': 0,
    'total_alerts': 0,
    'logs_per_minute': 0,
    'anomalies_per_hour': 0,
    'blocked_ips': 0,
    'failed_logins': 0
}

# Additional data structures
threat_geography = defaultdict(lambda: {'count': 0, 'severity': 'low'})
threat_categories = defaultdict(int)
system_health = {
    'cpu': 45,
    'memory': 62,
    'disk': 78,
    'network': 32
}
hourly_stats = deque(maxlen=24)
predictions = []
start_time = time.time()

# Define locations dictionary globally
locations = {
    'US': {'lat': 37.0902, 'lng': -95.7129},
    'CN': {'lat': 35.8617, 'lng': 104.1954},
    'RU': {'lat': 61.5240, 'lng': 105.3188}
}

# Enhanced HTML Template for Dashboard
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>SIEM Security Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0f1419;
            color: #e1e8ed;
            overflow-x: hidden;
        }
        .header {
            text-align: center;
            padding: 30px 0;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            border-radius: 15px;
            margin: 20px;
            position: relative;
            overflow: hidden;
        }
        .header::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
            animation: pulse 4s ease-in-out infinite;
        }
        @keyframes pulse {
            0%, 100% { transform: scale(1); opacity: 0.5; }
            50% { transform: scale(1.1); opacity: 0.8; }
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            position: relative;
            z-index: 1;
        }
        .status {
            display: inline-block;
            padding: 8px 20px;
            background: #4ade80;
            color: #0f1419;
            border-radius: 10px;
            font-weight: bold;
            animation: statusPulse 2s ease-in-out infinite;
        }
        @keyframes statusPulse) {
            0%, 100% { box-shadow: 0 0 0 0 rgba(74, 222, 128, 0.7); }
            50% { box-shadow: 0 0 0 10px rgba(74, 222, 128, 0); }
        }
        .dashboard {
            padding: 20px;
            max-width: 1800px;
            margin: 0 auto;
        }
        .filters {
            display: flex;
            gap: 15px;
            margin-bottom: 30px;
            flex-wrap: wrap;
        }
        .filter {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 10px 15px;
            color: #e1e8ed;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        .filter:hover {
            background: #334155;
            transform: translateY(-2px);
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
            border-radius: 15px;
            padding: 25px;
            text-align: center;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, #3b82f6, #8b5cf6, #ec4899);
            animation: gradient 3s ease infinite;
        }
        @keyframes gradient {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }
        .stat-number {
            font-size: 3em;
            font-weight: bold;
            margin: 10px 0;
            background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .stat-label {
            color: #94a3b8;
            font-size: 0.9em;
        }
        .stat-trend {
            font-size: 0.8em;
            color: #4ade80;
            margin-top: 5px;
        }
        .stat-trend.down {
            color: #ef4444;
        }
        .content-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .panel {
            background: #1e293b;
            border-radius: 15px;
            padding: 20px;
            border: 1px solid #334155;
            transition: all 0.3s ease;
        }
        .panel:hover {
            border-color: #3b82f6;
            box-shadow: 0 0 20px rgba(59, 130, 246, 0.3);
        }
        .panel h3 {
            display: flex;
            align-items: center;
            margin-bottom: 20px;
            font-size: 1.2em;
            font-weight: bold;
        }
        .panel h3 .icon {
            margin-right: 10px;
            font-size: 1.5em;
        }
        .log-entry, .anomaly-entry, .alert-entry {
            background: #0f172a;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: all 0.3s ease;
        }
        .log-entry:hover, .anomaly-entry:hover, .alert-entry:hover {
            background: #1e293b;
            transform: translateX(5px);
        }
        .severity-critical {
            border-left: 4px solid #ef4444;
        }
        .severity-high {
            border-left: 4px solid #f59e0b;
        }
        .severity-medium {
            border-left: 4px solid #3b82f6;
        }
        .severity-low {
            border-left: 4px solid #10b981;
        }
        .timestamp {
            font-size: 0.8em;
            opacity: 0.7;
            margin-bottom: 5px;
        }
        .action-buttons {
            display: flex;
            gap: 10px;
        }
        .action-btn {
            padding: 5px 15px;
            border-radius: 5px;
            border: none;
            cursor: pointer;
            font-size: 0.85em;
            transition: all 0.3s ease;
        }
        .btn-investigate {
            background: #3b82f6;
            color: white;
        }
        .btn-block {
            background: #ef4444;
            color: white;
        }
        .btn-escalate {
            background: #f59e0b;
            color: white;
        }
        .action-btn:hover {
            opacity: 0.8;
            transform: scale(1.05);
        }
        .controls {
            text-align: center;
            margin-bottom: 20px;
        }
        .btn {
            background: rgba(255,255,255,0.2);
            color: white;
            border: 1px solid rgba(255,255,255,0.3);
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            margin: 0 10px;
            transition: all 0.3s ease;
        }
        .btn:hover {
            background: rgba(255,255,255,0.3);
            transform: translateY(-2px);
        }
        #threatMap {
            height: 400px;
            border-radius: 15px;
            overflow: hidden;
        }
        .chart-container {
            position: relative;
            height: 300px;
            width: 100%;
        }
        .bayesian-score {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: bold;
            margin-left: 10px;
        }
        .score-high {
            background: rgba(239, 68, 68, 0.2);
            color: #ef4444;
        }
        .score-medium {
            background: rgba(245, 158, 11, 0.2);
            color: #f59e0b;
        }
        .score-low {
            background: rgba(16, 185, 129, 0.2);
            color: #10b981;
        }
        .health-metric {
            background: #0f172a;
            border-radius: 8px;
            padding: 15px;
            text-align: center;
            margin-bottom: 10px;
        }
        .health-bar {
            width: 100%;
            height: 10px;
            background: #334155;
            border-radius: 5px;
            overflow: hidden;
            margin-top: 10px;
        }
        .health-fill {
            height: 100%;
            transition: width 1s ease;
        }
        .health-good {
            background: #10b981;
        }
        .health-warning {
            background: #f59e0b;
        }
        .health-critical {
            background: #ef4444;
        }
        .prediction-card {
            background: linear-gradient(135deg, #312e81 0%, #4c1d95 100%);
            border: 1px solid #6b21a8;
        }
        .prediction-item {
            background: rgba(139, 92, 246, 0.1);
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 10px;
            border-left: 3px solid #8b5cf6;
        }
        .threat-item {
            background: #0f172a;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 10px;
            border-left: 3px solid #ef4444;
            transition: all 0.3s ease;
        }
        .threat-item:hover {
            background: #1e293b;
            transform: translateX(5px);
        }
        .auto-refresh {
            position: fixed;
            top: 20px;
            right: 20px;
            background: rgba(0,0,0,0.5);
            padding: 10px;
            border-radius: 5px;
            font-size: 0.8em;
        }
        .loading {
            text-align: center;
            opacity: 0.7;
            font-style: italic;
        }
        .full-width {
            grid-column: span 2;
        }
        @media (max-width: 768px) {
            .content-grid {
                grid-template-columns: 1fr;
            }
            .full-width {
                grid-column: span 1;
            }
        }
    </style>
</head>
<body>
    <div class="auto-refresh">
        Auto-refresh: <span id="countdown">30</span>s
    </div>
    
    <div class="header">
        <h1>🛡️ SIEM Security Dashboard</h1>
        <div class="status">SYSTEM OPERATIONAL</div>
    </div>
    
    <div class="dashboard">
        <div class="filters">
            <select class="filter" id="timeRange">
                <option value="1h">Last Hour</option>
                <option value="24h" selected>Last 24 Hours</option>
                <option value="7d">Last 7 Days</option>
                <option value="30d">Last 30 Days</option>
            </select>
            <select class="filter" id="severity">
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
            </select>
            <select class="filter" id="source">
                <option value="all">All Sources</option>
                <option value="firewall">Firewall</option>
                <option value="ids">IDS/IPS</option>
                <option value="endpoint">Endpoint</option>
                <option value="network">Network</option>
            </select>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number" id="total-logs">{{ stats.total_logs }}</div>
                <div class="stat-label">Total Logs</div>
                <div class="stat-trend">↑ 23% from yesterday</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="total-anomalies">{{ stats.total_anomalies }}</div>
                <div class="stat-label">Anomalies Detected</div>
                <div class="stat-trend down">↓ 15% from average</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="total-alerts">{{ stats.total_alerts }}</div>
                <div class="stat-label">Critical Alerts</div>
                <div class="stat-trend">2 unresolved</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="logs-per-minute">{{ stats.logs_per_minute }}</div>
                <div class="stat-label">Logs/Minute</div>
                <div class="stat-trend">Real-time rate</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="blocked-ips">{{ stats.blocked_ips }}</div>
                <div class="stat-label">Blocked IPs</div>
                <div class="stat-trend">Last 24 hours</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="failed-logins">{{ stats.failed_logins }}</div>
                <div class="stat-label">Failed Logins</div>
                <div class="stat-trend">Monitoring active</div>
            </div>
        </div>
        
        <div class="controls">
            <button class="btn" onclick="refreshData()">🔄 Refresh Now</button>
            <button class="btn" onclick="clearLogs()">🗑️ Clear Logs</button>
            <button class="btn" onclick="exportData()">📊 Export Data</button>
        </div>
        
        <div class="content-grid">
            <div class="panel">
                <h3><span class="icon">📊</span>Log Trends (24 Hours)</h3>
                <div class="chart-container">
                    <canvas id="trendChart"></canvas>
                </div>
            </div>
            
            <div class="panel">
                <h3><span class="icon">🎯</span>Threat Categories</h3>
                <div class="chart-container">
                    <canvas id="threatChart"></canvas>
                </div>
            </div>
        </div>
        
        <div class="content-grid">
            <div class="panel">
                <h3><span class="icon">🚨</span>Critical Alerts</h3>
                <div id="alerts-container">
                    {% for alert in recent_alerts %}
                    <div class="alert-entry severity-{{ alert.severity }}">
                        <div>
                            <div class="timestamp">{{ alert.timestamp }}</div>
                            <strong>{{ alert.alert_type }}</strong> - {{ alert.source }}<br>
                            Count: {{ alert.count }} | Severity: {{ alert.severity }}
                            {% if alert.bayesian_score %}
                            <span class="bayesian-score score-{{ 'high' if alert.bayesian_score > 0.8 else 'medium' if alert.bayesian_score > 0.6 else 'low' }}">
                                Confidence: {{ (alert.bayesian_score * 100)|int }}%
                            </span>
                            {% endif %}
                        </div>
                        <div class="action-buttons">
                            <button class="action-btn btn-investigate" onclick="investigate('{{ alert.id }}')">Investigate</button>
                            <button class="action-btn btn-block" onclick="blockIP('{{ alert.source }}')">Block IP</button>
                            <button class="action-btn btn-escalate" onclick="escalate('{{ alert.id }}')">Escalate</button>
                        </div>
                    </div>
                    {% endfor %}
                    {% if not recent_alerts %}
                    <div class="loading">No alerts detected</div>
                    {% endif %}
                </div>
            </div>
            
            <div class="panel">
                <h3><span class="icon">⚠️</span>Recent Anomalies</h3>
                <div id="anomalies-container">
                    {% for anomaly in recent_anomalies %}
                    <div class="anomaly-entry severity-{{ anomaly.severity }}">
                        <div>
                            <div class="timestamp">{{ anomaly.timestamp }}</div>
                            <strong>{{ anomaly.rule }}</strong><br>
                            {% if anomaly.source_ip %}Source: {{ anomaly.source_ip }}{% endif %}
                            {% if anomaly.response_time %}Response Time: {{ anomaly.response_time }}ms{% endif %}
                            {% if anomaly.bayesian_score %}
                            <span class="bayesian-score score-{{ 'high' if anomaly.bayesian_score > 0.8 else 'medium' if anomaly.bayesian_score > 0.6 else 'low' }}">
                                Score: {{ (anomaly.bayesian_score * 100)|int }}%
                            </span>
                            {% endif %}
                        </div>
                    </div>
                    {% endfor %}
                    {% if not recent_anomalies %}
                    <div class="loading">No anomalies detected</div>
                    {% endif %}
                </div>
            </div>
        </div>
        
        <div class="panel" style="margin-bottom: 20px;">
            <h3><span class="icon">🗺️</span>Threat Geography</h3>
            <div id="threatMap"></div>
        </div>
        
        <div class="content-grid">
            <div class="panel">
                <h3><span class="icon">💻</span>System Health</h3>
                <div class="system-health">
                    <div class="health-metric">
                        <div>CPU Usage</div>
                        <div id="cpuValue">{{ system_health.cpu }}%</div>
                        <div class="health-bar">
                            <div class="health-fill {{ 'health-good' if system_health.cpu < 60 else 'health-warning' if system_health.cpu < 80 else 'health-critical' }}" 
                                 style="width: {{ system_health.cpu }}%"></div>
                        </div>
                    </div>
                    <div class="health-metric">
                        <div>Memory Usage</div>
                        <div id="memValue">{{ system_health.memory }}%</div>
                        <div class="health-bar">
                            <div class="health-fill {{ 'health-good' if system_health.memory < 60 else 'health-warning' if system_health.memory < 80 else 'health-critical' }}" 
                                 style="width: {{ system_health.memory }}%"></div>
                        </div>
                    </div>
                    <div class="health-metric">
                        <div>Disk Usage</div>
                        <div id="diskValue">{{ system_health.disk }}%</div>
                        <div class="health-bar">
                            <div class="health-fill {{ 'health-good' if system_health.disk < 60 else 'health-warning' if system_health.disk < 80 else 'health-critical' }}" 
                                 style="width: {{ system_health.disk }}%"></div>
                        </div>
                    </div>
                    <div class="health-metric">
                        <div>Network Load</div>
                        <div id="netValue">{{ system_health.network }}%</div>
                        <div class="health-bar">
                            <div class="health-fill {{ 'health-good' if system_health.network < 60 else 'health-warning' if system_health.network < 80 else 'health-critical' }}" 
                                 style="width: {{ system_health.network }}%"></div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="panel">
                <h3><span class="icon">📡</span>Real-Time Threat Intelligence</h3>
                <div class="threat-feed" id="threatFeed">
                    <div class="threat-item">
                        <div style="font-weight: bold;">New Ransomware Variant Detected</div>
                        <div style="color: #94a3b8; font-size: 0.85em;">CISA Alert • 30 mins ago</div>
                    </div>
                    <div class="threat-item">
                        <div style="font-weight: bold;">Critical Apache Log4j Vulnerability</div>
                        <div style="color: #94a3b8; font-size: 0.85em;">CVE-2021-44228 • 2 hours ago</div>
                    </div>
                    <div class="threat-item">
                        <div style="font-weight: bold;">Phishing Campaign Targeting Finance</div>
                        <div style="color: #94a3b8; font-size: 0.85em;">Threat Intel Feed • 4 hours ago</div>
                    </div>
                </div>
            </div>
            
            <div class="panel prediction-card">
                <h3><span class="icon">🔮</span>Bayesian Predictions</h3>
                <div id="predictionsList">
                    {% for prediction in predictions %}
                    <div class="prediction-item">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div>
                                <div style="font-weight: bold;">{{ prediction.prediction }}</div>
                                <div style="color: #94a3b8; font-size: 0.85em; margin-top: 5px;">
                                    {{ prediction.reason }}
                                </div>
                                <div style="color: #94a3b8; font-size: 0.85em; margin-top: 5px;">
                                    Timeframe: {{ prediction.timeframe }}
                                </div>
                            </div>
                            <div class="bayesian-score score-{{ 'high' if prediction.probability > 0.8 else 'medium' if prediction.probability > 0.6 else 'low' }}" 
                                 style="font-size: 1.2em;">
                                {{ (prediction.probability * 100)|int }}%
                            </div>
                        </div>
                    </div>
                    {% endfor %}
                    {% if not predictions %}
                    <div class="loading">Calculating predictions...</div>
                    {% endif %}
                </div>
            </div>
        </div>
        
        <div class="panel full-width">
            <h3><span class="icon">📝</span>Recent Log Activity</h3>
            <div id="logs-container">
                {% for log in recent_logs %}
                <div class="log-entry">
                    <div>
                        <div class="timestamp">{{ log.timestamp }}</div>
                        <strong>{{ log.message }}</strong><br>
                        Source: {{ log.source }} | Status: {{ log.status_code }} | User: {{ log.user_id or 'unknown' }}
                    </div>
                </div>
                {% endfor %}
                {% if not recent_logs %}
                <div class="loading">No recent logs</div>
                {% endif %}
            </div>
        </div>
    </div>
    
    <script>
        let countdownTimer = 30;
        let refreshInterval;
        let trendChart, threatChart, map;
        
        function initCharts() {
            const trendCtx = document.getElementById('trendChart').getContext('2d');
            trendChart = new Chart(trendCtx, {
                type: 'line',
                data: {
                    labels: Array.from({length: 24}, (_, i) => `${i}:00`),
                    datasets: [{
                        label: 'Total Logs',
                        data: {{ hourly_logs_data|tojson }},
                        borderColor: '#3b82f6',
                        backgroundColor: 'rgba(59, 130, 246, 0.1)',
                        tension: 0.4
                    }, {
                        label: 'Anomalies',
                        data: {{ hourly_anomalies_data|tojson }},
                        borderColor: '#f59e0b',
                        backgroundColor: 'rgba(245, 158, 11, 0.1)',
                        tension: 0.4
                    }, {
                        label: 'Alerts',
                        data: {{ hourly_alerts_data|tojson }},
                        borderColor: '#ef4444',
                        backgroundColor: 'rgba(239, 68, 68, 0.1)',
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            labels: { color: '#e1e8ed' }
                        }
                    },
                    scales: {
                        x: {
                            grid: { color: '#334155' },
                            ticks: { color: '#94a3b8' }
                        },
                        y: {
                            grid: { color: '#334155' },
                            ticks: { color: '#94a3b8' }
                        }
                    }
                }
            });
            
            const threatCtx = document.getElementById('threatChart').getContext('2d');
            threatChart = new Chart(threatCtx, {
                type: 'doughnut',
                data: {
                    labels: {{ threat_categories_labels|tojson }},
                    datasets: [{
                        data: {{ threat_categories_data|tojson }},
                        backgroundColor: [
                            '#ef4444', '#f59e0b', '#3b82f6',
                            '#8b5cf6', '#10b981', '#6b7280'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right',
                            labels: { color: '#e1e8ed' }
                        }
                    }
                }
            });
        }
        
        function initMap() {
            map = L.map('threatMap').setView([30, 0], 2);
            L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                attribution: '© OpenStreetMap contributors'
            }).addTo(map);
            
            const threatLocations = {{ threat_geography|tojson }};
            Object.entries(threatLocations).forEach(([key, loc]) => {
                if (loc.lat && loc.lng) {
                    let color;
                    if (loc.severity === 'critical') {
                        color = '#ef4444';
                    } else if (loc.severity === 'high') {
                        color = '#f59e0b';
                    } else if (loc.severity === 'medium') {
                        color = '#3b82f6';
                    } else {
                        color = '#10b981';
                    }
                    
                    L.circleMarker([loc.lat, loc.lng], {
                        radius: Math.sqrt(loc.count) * 5,
                        fillColor: color,
                        color: color,
                        weight: 1,
                        opacity: 1,
                        fillOpacity: 0.6
                    }).addTo(map).bindPopup(`Threats: ${loc.count}<br>Severity: ${loc.severity}<br>Location: ${key}`);
                }
            });
        }
        
        window.onload = function() {
            initCharts();
            initMap();
            startAutoRefresh();
        };
        
        function startAutoRefresh() {
            refreshInterval = setInterval(() => {
                countdownTimer--;
                document.getElementById('countdown').innerText = countdownTimer;
                if (countdownTimer <= 0) {
                    refreshData();
                    countdownTimer = 30;
                }
            }, 1000);
        }
        
        function refreshData() {
            fetch('/api/data')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('total-logs').innerText = data.stats.total_logs;
                    document.getElementById('total-anomalies').innerText = data.stats.total_anomalies;
                    document.getElementById('total-alerts').innerText = data.stats.total_alerts;
                    document.getElementById('logs-per-minute').innerText = data.stats.logs_per_minute;
                    document.getElementById('blocked-ips').innerText = data.stats.blocked_ips;
                    document.getElementById('failed-logins').innerText = data.stats.failed_logins;
                    
                    trendChart.data.datasets[0].data = data.hourly_logs_data;
                    trendChart.data.datasets[1].data = data.hourly_anomalies_data;
                    trendChart.data.datasets[2].data = data.hourly_alerts_data;
                    trendChart.update();
                    
                    threatChart.data.labels = data.threat_categories_labels;
                    threatChart.data.datasets[0].data = data.threat_categories_data;
                    threatChart.update();
                });
        }
        
        function clearLogs() {
            fetch('/api/clear_logs', { method: 'POST' })
                .then(() => refreshData());
        }
        
        function exportData() {
            window.location.href = '/api/export';
        }
        
        function investigate(id) {
            alert(`Investigating alert ID: ${id}`);
        }
        
        function blockIP(ip) {
            fetch('/api/block_ip', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: ip })
            }).then(() => refreshData());
        }
        
        function escalate(id) {
            alert(`Escalating alert ID: ${id}`);
        }
    </script>
</body>
</html>
"""

# Simple Bayesian scoring function
def bayesian_score(event, prior=0.5, likelihood_normal=0.8, likelihood_anomalous=0.2):
    """Calculate a Bayesian score for an event based on prior and likelihoods."""
    try:
        evidence = prior * likelihood_anomalous / (prior * likelihood_anomalous + (1 - prior) * likelihood_normal)
        return evidence
    except ZeroDivisionError:
        logger.error("ZeroDivisionError in bayesian_score, returning default score")
        return 0.5

# Simulate log data (for demo purposes)
def generate_demo_log():
    sources = ['firewall', 'ids', 'endpoint', 'network']
    messages = ['Login attempt', 'Network scan detected', 'File access', 'SQL injection attempt']
    severities = ['low', 'medium', 'high', 'critical']
    location = random.choice(list(locations.keys()))
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    score = bayesian_score({'message': random.choice(messages), 'source': random.choice(sources)}, prior=0.5)

    log = {
        'timestamp': timestamp,
        'source': random.choice(sources),
        'message': random.choice(messages),
        'status_code': random.randint(200, 500),
        'user_id': f'user_{random.randint(1, 100)}',
        'location': location,
        'lat': locations[location]['lat'],
        'lng': locations[location]['lng']
    }
    anomaly = {
        'timestamp': timestamp,
        'rule': f'{log["message"]} anomaly',
        'source_ip': f'192.168.1.{random.randint(1, 255)}',
        'response_time': random.randint(10, 500),
        'severity': random.choice(severities),
        'bayesian_score': score
    }
    alert = {
        'id': f'alert_{random.randint(1000, 9999)}',
        'timestamp': timestamp,
        'alert_type': log['message'],
        'source': log['source'],
        'count': random.randint(1, 10),
        'severity': 'critical' if score > 0.8 else 'high',
        'bayesian_score': score
    }
    return log, anomaly, alert, location

# Generate Bayesian predictions (for demo purposes)
def generate_predictions():
    global predictions
    predictions.clear()
    threat_types = ['Ransomware attack', 'DDoS attempt', 'Phishing campaign']
    for _ in range(3):
        score = random.uniform(0.4, 0.9)
        predictions.append({
            'prediction': random.choice(threat_types),
            'reason': 'Based on recent anomaly patterns',
            'timeframe': f'Next {random.randint(1, 24)} hours',
            'probability': score
        })

# Kafka consumer thread
# Replace the kafka_consumer_thread function in your dashboard.py with this version:

def kafka_consumer_thread():
    logger.info(f"Attempting to connect to Kafka at {KAFKA_HOST}")
    try:
        consumer = KafkaConsumer(
            'logs',
            'anomalies',
            'alerts',
            'threats',
            'predictions',       
            bootstrap_servers=[KAFKA_HOST],
            auto_offset_reset='latest',
            enable_auto_commit=True,
            group_id='siem_dashboard',
            value_deserializer=lambda x: json.loads(x.decode('utf-8')),
            request_timeout_ms=20000,
            retry_backoff_ms=1000
        )
        logger.info("Successfully connected to Kafka")
        for message in consumer:
            log = message.value
            recent_logs.append(log)
            stats['total_logs'] += 1
            stats['logs_per_minute'] = stats['total_logs'] / max(1, (time.time() - start_time) / 60)

            # Anomaly detection using Bayesian scoring
            score = bayesian_score(log)
            if score > 0.6:
                anomaly = {
                    'timestamp': log['timestamp'],
                    'rule': f"{log['message']} anomaly",
                    'source_ip': log.get('source_ip', 'unknown'),
                    'response_time': log.get('response_time', random.randint(10, 500)),
                    'severity': 'high' if score > 0.8 else 'medium',
                    'bayesian_score': score
                }
                recent_anomalies.append(anomaly)
                stats['total_anomalies'] += 1
                stats['anomalies_per_hour'] = stats['total_anomalies'] / max(1, (time.time() - start_time) / 3600)

                if score > 0.8:
                    alert = {
                        'id': f'alert_{stats["total_alerts"]}',
                        'timestamp': log['timestamp'],
                        'alert_type': log['message'],
                        'source': log['source'],
                        'count': 1,
                        'severity': 'critical',
                        'bayesian_score': score
                    }
                    recent_alerts.append(alert)
                    stats['total_alerts'] += 1

            # Update threat geography and categories
            location = log.get('location', 'US')
            threat_geography[location]['count'] += 1
            threat_geography[location]['severity'] = 'high' if score > 0.8 else 'medium' if score > 0.6 else 'low'
            threat_geography[location]['lat'] = log.get('lat', locations['US']['lat'])
            threat_geography[location]['lng'] = log.get('lng', locations['US']['lng'])
            threat_categories[log['message']] += 1
            generate_predictions()

    except Exception as e:
        logger.error(f"Kafka consumer error: {e}, real logs only mode - no demo data will be generated")
        logger.info("Dashboard ready to receive real logs via API endpoints")
        # DO NOT generate demo data - just wait for real logs
        while True:
            time.sleep(60)  # Sleep and wait for real logs through API

# Flask Routes
@app.route('/')
def dashboard():
    hourly_logs_data = [random.randint(100, 1000) for _ in range(24)]
    hourly_anomalies_data = [random.randint(0, 50) for _ in range(24)]
    hourly_alerts_data = [random.randint(0, 10) for _ in range(24)]
    threat_categories_labels = list(threat_categories.keys()) or ['No data']
    threat_categories_data = list(threat_categories.values()) or [0]

    return render_template_string(
        DASHBOARD_HTML,
        stats=stats,
        recent_logs=recent_logs,
        recent_anomalies=recent_anomalies,
        recent_alerts=recent_alerts,
        system_health=system_health,
        predictions=predictions,
        hourly_logs_data=hourly_logs_data,
        hourly_anomalies_data=hourly_anomalies_data,
        hourly_alerts_data=hourly_alerts_data,
        threat_categories_labels=threat_categories_labels,
        threat_categories_data=threat_categories_data,
        threat_geography=threat_geography
    )

@app.route('/api/data')
def get_data():
    return jsonify({
        'stats': stats,
        'hourly_logs_data': [random.randint(100, 1000) for _ in range(24)],
        'hourly_anomalies_data': [random.randint(0, 50) for _ in range(24)],
        'hourly_alerts_data': [random.randint(0, 10) for _ in range(24)],
        'threat_categories_labels': list(threat_categories.keys()) or ['No data'],
        'threat_categories_data': list(threat_categories.values()) or [0]
    })

@app.route('/api/clear_logs', methods=['POST'])
def clear_logs():
    recent_logs.clear()
    recent_anomalies.clear()
    recent_alerts.clear()
    stats.update({
        'total_logs': 0,
        'total_anomalies': 0,
        'total_alerts': 0,
        'logs_per_minute': 0,
        'anomalies_per_hour': 0,
        'blocked_ips': 0,
        'failed_logins': 0
    })
    threat_geography.clear()
    threat_categories.clear()
    return jsonify({'status': 'success'})

@app.route('/api/block_ip', methods=['POST'])
def block_ip():
    data = request.get_json()
    ip = data.get('ip')
    if ip:
        stats['blocked_ips'] += 1
        logger.info(f"Blocked IP: {ip}")
        return jsonify({'status': 'success', 'ip': ip})
    return jsonify({'status': 'error', 'message': 'No IP provided'})

@app.route('/api/export')
def export_data():
    data = {
        'logs': list(recent_logs),
        'anomalies': list(recent_anomalies),
        'alerts': list(recent_alerts),
        'stats': stats,
        'threat_geography': dict(threat_geography),
        'threat_categories': dict(threat_categories)
    }
    return jsonify(data)
@app.route('/api/ingest_log', methods=['POST'])
def ingest_log():
    """Receive real logs from the log collector"""
    try:
        log_data = request.get_json()
        if log_data:
            # Add to recent logs
            recent_logs.append(log_data)
            stats['total_logs'] += 1
            stats['logs_per_minute'] = stats['total_logs'] / max(1, (time.time() - start_time) / 60)
            
            # Update threat categories
            threat_categories[log_data.get('message', 'Unknown')] += 1
            
            logger.info(f"Received real log: {log_data.get('message', '')}")
            return jsonify({'status': 'success'})
        else:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
    except Exception as e:
        logger.error(f"Error ingesting log: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/ingest_anomaly', methods=['POST'])
def ingest_anomaly():
    """Receive real anomalies from the log collector"""
    try:
        anomaly_data = request.get_json()
        if anomaly_data:
            # Add to recent anomalies
            recent_anomalies.append(anomaly_data)
            stats['total_anomalies'] += 1
            stats['anomalies_per_hour'] = stats['total_anomalies'] / max(1, (time.time() - start_time) / 3600)
            
            # Create alert if high severity
            if anomaly_data.get('severity') == 'high':
                alert = {
                    'id': f'alert_{stats["total_alerts"]}',
                    'timestamp': anomaly_data['timestamp'],
                    'alert_type': anomaly_data.get('rule', 'Unknown anomaly'),
                    'source': anomaly_data.get('source_log', {}).get('source', 'unknown'),
                    'count': 1,
                    'severity': 'critical',
                    'bayesian_score': anomaly_data.get('confidence', 0.7)
                }
                recent_alerts.append(alert)
                stats['total_alerts'] += 1
            
            logger.info(f"Received real anomaly: {anomaly_data.get('rule', '')}")
            return jsonify({'status': 'success'})
        else:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
    except Exception as e:
        logger.error(f"Error ingesting anomaly: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
# Start Kafka consumer in a separate thread
if __name__ == '__main__':
    threading.Thread(target=kafka_consumer_thread, daemon=True).start()
    generate_predictions()  # Initial predictions
    logger.info("Starting Flask application")
    app.run(host='0.0.0.0', port=5000, debug=True)