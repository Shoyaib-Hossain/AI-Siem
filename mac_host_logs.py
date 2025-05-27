#!/usr/bin/env python3
"""
Enhanced Mac Host Log Collector
Collects real Mac system logs and sends to SIEM dashboard
"""

import subprocess
import json
import time
import requests
import logging
from datetime import datetime, timedelta
import re

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def send_log_to_dashboard(log_data):
    """Send log to SIEM dashboard"""
    try:
        response = requests.post(
            'http://localhost:3000/api/ingest_log',
            json=log_data,
            timeout=5
        )
        if response.status_code == 200:
            logger.info(f"✅ Sent: {log_data['message'][:50]}...")
            return True
        else:
            logger.error(f"❌ Failed: {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"❌ Error: {e}")
        return False

def get_mac_authentication_logs():
    """Get Mac authentication logs using log command"""
    logs = []
    try:
        # Get authentication events from last 10 minutes
        cmd = [
            'log', 'show',
            '--predicate', 'process == "loginwindow" OR process == "sudo" OR process == "su" OR eventMessage CONTAINS "authentication"',
            '--last', '10m',
            '--style', 'compact'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    # Parse log line
                    log_data = {
                        'timestamp': datetime.now().isoformat(),
                        'source': 'mac_auth_system',
                        'message': f"Mac Authentication Event: {line.strip()}",
                        'severity': 'medium',
                        'log_type': 'mac_authentication',
                        'raw_log': line.strip()
                    }
                    logs.append(log_data)
                    
                    # Break after 5 logs to avoid spam
                    if len(logs) >= 5:
                        break
                        
    except Exception as e:
        logger.warning(f"Could not get auth logs: {e}")
        
    return logs

def get_mac_network_logs():
    """Get Mac network connection information"""
    logs = []
    try:
        # Get network connections
        cmd = ['netstat', '-an']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        
        if result.returncode == 0:
            connections = []
            for line in result.stdout.strip().split('\n'):
                if 'ESTABLISHED' in line and ('tcp4' in line or 'tcp6' in line):
                    connections.append(line.strip())
                    if len(connections) >= 3:  # Limit to 3
                        break
            
            for conn in connections:
                log_data = {
                    'timestamp': datetime.now().isoformat(),
                    'source': 'mac_network_monitor',
                    'message': f"Mac Network Connection: {conn}",
                    'severity': 'low',
                    'log_type': 'mac_network',
                    'connection_info': conn
                }
                logs.append(log_data)
                
    except Exception as e:
        logger.warning(f"Could not get network logs: {e}")
        
    return logs

def get_mac_system_logs():
    """Get Mac system logs using log command"""
    logs = []
    try:
        # Get system events from last 5 minutes
        cmd = [
            'log', 'show',
            '--predicate', 'subsystem == "com.apple.kernel" OR process == "kernel"',
            '--last', '5m',
            '--style', 'compact'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0 and result.stdout.strip():
            lines = result.stdout.strip().split('\n')
            # Get last 3 system events
            for line in lines[-3:]:
                if line.strip():
                    log_data = {
                        'timestamp': datetime.now().isoformat(),
                        'source': 'mac_system_kernel',
                        'message': f"Mac System Event: {line.strip()}",
                        'severity': 'low',
                        'log_type': 'mac_system',
                        'raw_log': line.strip()
                    }
                    logs.append(log_data)
                    
    except Exception as e:
        logger.warning(f"Could not get system logs: {e}")
        
    return logs

def get_mac_application_logs():
    """Get Mac application logs"""
    logs = []
    try:
        # Get recent application events
        cmd = [
            'log', 'show',
            '--predicate', 'eventType == logEvent AND category == "default"',
            '--last', '5m',
            '--style', 'compact'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0 and result.stdout.strip():
            lines = result.stdout.strip().split('\n')
            # Get last 2 application events
            for line in lines[-2:]:
                if line.strip() and 'error' not in line.lower():
                    log_data = {
                        'timestamp': datetime.now().isoformat(),
                        'source': 'mac_applications',
                        'message': f"Mac App Event: {line.strip()}",
                        'severity': 'low',
                        'log_type': 'mac_application',
                        'raw_log': line.strip()
                    }
                    logs.append(log_data)
                    
    except Exception as e:
        logger.warning(f"Could not get application logs: {e}")
        
    return logs

def get_mac_security_logs():
    """Get Mac security-related logs"""
    logs = []
    try:
        # Get security events
        cmd = [
            'log', 'show',
            '--predicate', 'eventMessage CONTAINS "security" OR eventMessage CONTAINS "firewall" OR eventMessage CONTAINS "blocked"',
            '--last', '10m',
            '--style', 'compact'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().split('\n')[:3]:  # Max 3
                if line.strip():
                    log_data = {
                        'timestamp': datetime.now().isoformat(),
                        'source': 'mac_security_system',
                        'message': f"Mac Security Event: {line.strip()}",
                        'severity': 'medium',
                        'log_type': 'mac_security',
                        'raw_log': line.strip()
                    }
                    logs.append(log_data)
                    
    except Exception as e:
        logger.warning(f"Could not get security logs: {e}")
        
    return logs

def collect_all_mac_logs():
    """Collect all types of Mac host logs"""
    all_logs = []
    
    logger.info("🔍 Collecting Mac host system logs...")
    
    # Collect different types of logs
    all_logs.extend(get_mac_authentication_logs())
    all_logs.extend(get_mac_network_logs())
    all_logs.extend(get_mac_system_logs())
    all_logs.extend(get_mac_application_logs())
    all_logs.extend(get_mac_security_logs())
    
    return all_logs

def main():
    """Main loop to collect Mac host logs"""
    logger.info("🍎 Starting Mac Host Log Collector for SIEM Dashboard")
    logger.info("📡 Collecting REAL Mac system logs...")
    
    # Test dashboard connection
    try:
        response = requests.get('http://localhost:3000/api/data', timeout=5)
        if response.status_code == 200:
            logger.info("✅ Dashboard accessible")
        else:
            logger.error("❌ Dashboard not responding")
            return
    except Exception as e:
        logger.error(f"❌ Cannot connect to dashboard: {e}")
        return
    
    cycle = 0
    while True:
        try:
            cycle += 1
            logger.info(f"📊 Mac Log Collection Cycle #{cycle}")
            
            # Collect Mac host logs
            mac_logs = collect_all_mac_logs()
            
            # Send logs to dashboard
            sent_count = 0
            for log in mac_logs:
                if send_log_to_dashboard(log):
                    sent_count += 1
                time.sleep(0.5)  # Small delay between sends
            
            if sent_count > 0:
                logger.info(f"✅ Sent {sent_count} Mac host logs to dashboard")
            else:
                logger.info("ℹ️ No new Mac logs to send this cycle")
            
            # Wait 30 seconds before next collection
            logger.info("⏱️ Waiting 30 seconds before next Mac log collection...")
            time.sleep(30)
            
        except KeyboardInterrupt:
            logger.info("👋 Mac host log collector stopped")
            break
        except Exception as e:
            logger.error(f"❌ Error in collection cycle: {e}")
            time.sleep(10)

if __name__ == "__main__":
    main()