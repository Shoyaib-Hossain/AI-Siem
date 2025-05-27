import requests
import json
import os
from datetime import datetime

# Notification module for alerts
def send_slack_notification(webhook_url, alert_data):
    """Send alert notifications to Slack."""
    severity = alert_data.get('severity', 'medium')
    emoji = '🔴' if severity == 'high' else '🟠' if severity == 'medium' else '🟡'
    
    message = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} SIEM Alert: {alert_data.get('alert_type', 'Unknown Alert')}"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Source:*\n{alert_data.get('source', 'Unknown')}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{severity}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Time:*\n{datetime.fromtimestamp(alert_data.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S')}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Count:*\n{alert_data.get('count', 0)}"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Details:*\n```{json.dumps(alert_data, indent=2)}```"
                }
            }
        ]
    }
    
    response = requests.post(webhook_url, json=message)
    if response.status_code != 200:
        print(f"Error sending Slack notification: {response.text}")
    return response.status_code == 200

# Threat Intelligence integration
def check_threat_intelligence(ip_address, api_key):
    """Check if an IP is in threat intelligence feeds."""
    url = f"https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': 90
    }
    
    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json().get('data', {})
            return {
                'is_malicious': data.get('abuseConfidenceScore', 0) > 50,
                'score': data.get('abuseConfidenceScore', 0),
                'country': data.get('countryCode', 'Unknown'),
                'usage_type': data.get('usageType', 'Unknown'),
                'reports': data.get('totalReports', 0)
            }
    except Exception as e:
        print(f"Error checking threat intelligence: {str(e)}")
    
    return {'is_malicious': False, 'score': 0, 'country': 'Unknown', 'usage_type': 'Unknown', 'reports': 0}

# SIEM data exporter for Elasticsearch
def export_to_elasticsearch(es_host, index_name, data):
    """Export SIEM data to Elasticsearch."""
    url = f"{es_host}/{index_name}/_doc"
    headers = {'Content-Type': 'application/json'}
    
    # Add timestamp if not present
    if 'timestamp' not in data:
        data['timestamp'] = datetime.now().isoformat()
    
    try:
        response = requests.post(url, headers=headers, json=data)
        return response.status_code in [200, 201]
    except Exception as e:
        print(f"Error exporting to Elasticsearch: {str(e)}")
        return False

# Example usage in your SIEM architecture:
"""
# In your alert_correlation service:
from siem_integrations import send_slack_notification, check_threat_intelligence, export_to_elasticsearch

# When an alert is generated
if alert_detected:
    # Check if the source IP is in threat intelligence feeds
    ti_data = check_threat_intelligence(source_ip, "YOUR_ABUSEIPDB_API_KEY")
    
    # Add threat intelligence data to the alert
    alert_data['threat_intelligence'] = ti_data
    
    # Increase severity if the IP is known to be malicious
    if ti_data['is_malicious']:
        alert_data['severity'] = 'high'
    
    # Send notification for high severity alerts
    if alert_data['severity'] == 'high':
        send_slack_notification("YOUR_SLACK_WEBHOOK_URL", alert_data)
    
    # Export the alert to Elasticsearch
    export_to_elasticsearch("http://elasticsearch:9200", "siem-alerts", alert_data)
"""