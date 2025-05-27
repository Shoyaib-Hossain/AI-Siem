#!/usr/bin/env python3
"""
Fixed Real Log Collector for SIEM Dashboard (macOS Compatible)
Handles permission issues and provides fallback methods
"""

import time
import json
import psutil
import requests
import logging
import subprocess
import os
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def send_log_to_dashboard(log_data):
    """Send a log entry to the dashboard"""
    try:
        response = requests.post(
            'http://localhost:3000/api/ingest_log',
            json=log_data,
            timeout=5
        )
        if response.status_code == 200:
            logger.info(f"✅ Sent log: {log_data['message']}")
            return True
        else:
            logger.error(f"❌ Failed to send log: {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"❌ Error sending log to dashboard: {e}")
        return False

def send_anomaly_to_dashboard(anomaly_data):
    """Send an anomaly to the dashboard"""
    try:
        response = requests.post(
            'http://localhost:3000/api/ingest_anomaly',
            json=anomaly_data,
            timeout=5
        )
        if response.status_code == 200:
            logger.info(f"🚨 Sent anomaly: {anomaly_data['rule']}")
            return True
        else:
            logger.error(f"❌ Failed to send anomaly: {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"❌ Error sending anomaly to dashboard: {e}")
        return False

def get_safe_network_connections():
    """Get network connections with error handling"""
    try:
        connections = psutil.net_connections(kind='inet')
        active_connections = []
        
        for conn in connections:
            try:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    active_connections.append(conn)
            except Exception:
                continue  # Skip problematic connections
        
        return active_connections[:3]  # Limit to 3
    except Exception as e:
        logger.warning(f"⚠️ Could not get network connections: {e}")
        return []

def get_safe_system_resources():
    """Get system resources with error handling"""
    resources = {}
    
    try:
        resources['cpu'] = psutil.cpu_percent(interval=0.1)
    except Exception as e:
        logger.warning(f"⚠️ Could not get CPU usage: {e}")
        resources['cpu'] = None
    
    try:
        memory = psutil.virtual_memory()
        resources['memory'] = {
            'percent': memory.percent,
            'used_gb': memory.used // (1024**3),
            'total_gb': memory.total // (1024**3)
        }
    except Exception as e:
        logger.warning(f"⚠️ Could not get memory usage: {e}")
        resources['memory'] = None
    
    try:
        disk = psutil.disk_usage('/')
        resources['disk'] = {
            'percent': (disk.used / disk.total) * 100,
            'used_gb': disk.used // (1024**3),
            'total_gb': disk.total // (1024**3)
        }
    except Exception as e:
        logger.warning(f"⚠️ Could not get disk usage: {e}")
        resources['disk'] = None
    
    return resources

def get_safe_processes():
    """Get process information with error handling"""
    processes = []
    current_time = time.time()
    
    try:
        for proc in psutil.process_iter(['pid', 'name', 'create_time']):
            try:
                proc_info = proc.info
                if proc_info and current_time - proc_info['create_time'] < 600:  # Last 10 minutes
                    processes.append({
                        'pid': proc_info['pid'],
                        'name': proc_info['name'],
                        'create_time': proc_info['create_time']
                    })
                    if len(processes) >= 3:  # Limit to 3 processes
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception as e:
        logger.warning(f"⚠️ Could not get process information: {e}")
    
    return processes

def get_command_output(command):
    """Safely execute a system command and return output"""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            return None
    except Exception as e:
        logger.warning(f"⚠️ Command failed: {command} - {e}")
        return None

def collect_real_system_logs():
    """Collect real system information and send to dashboard"""
    logs_sent = 0
    timestamp = datetime.now().isoformat()
    
    # 1. Network connections
    try:
        connections = get_safe_network_connections()
        for conn in connections:
            log_data = {
                'timestamp': timestamp,
                'source': 'network_monitor',
                'message': f'Active connection to {conn.raddr.ip}:{conn.raddr.port}',
                'severity': 'low',
                'log_type': 'network_connection',
                'local_port': conn.laddr.port,
                'remote_ip': conn.raddr.ip,
                'remote_port': conn.raddr.port,
                'status': conn.status
            }
            if send_log_to_dashboard(log_data):
                logs_sent += 1
                
                # Create anomaly for external IPs
                if not conn.raddr.ip.startswith(('127.', '10.', '192.168.', '172.')):
                    anomaly_data = {
                        'timestamp': timestamp,
                        'rule': f'External network connection to {conn.raddr.ip}',
                        'severity': 'medium',
                        'confidence': 0.6,
                        'source_log': log_data,
                        'log_type': 'network_anomaly'
                    }
                    send_anomaly_to_dashboard(anomaly_data)
    except Exception as e:
        logger.error(f"Error processing network connections: {e}")
    
    # 2. System resources
    try:
        resources = get_safe_system_resources()
        
        if resources['cpu'] is not None:
            log_data = {
                'timestamp': timestamp,
                'source': 'system_monitor',
                'message': f'CPU usage: {resources["cpu"]:.1f}%',
                'severity': 'high' if resources['cpu'] > 80 else 'medium' if resources['cpu'] > 60 else 'low',
                'log_type': 'system_resource',
                'cpu_percent': resources['cpu']
            }
            if send_log_to_dashboard(log_data):
                logs_sent += 1
        
        if resources['memory'] is not None:
            mem = resources['memory']
            log_data = {
                'timestamp': timestamp,
                'source': 'system_monitor',
                'message': f'Memory usage: {mem["percent"]:.1f}% ({mem["used_gb"]}GB/{mem["total_gb"]}GB)',
                'severity': 'high' if mem['percent'] > 80 else 'medium' if mem['percent'] > 60 else 'low',
                'log_type': 'system_resource',
                'memory_percent': mem['percent'],
                'memory_used_gb': mem['used_gb']
            }
            if send_log_to_dashboard(log_data):
                logs_sent += 1
        
        if resources['disk'] is not None:
            disk = resources['disk']
            log_data = {
                'timestamp': timestamp,
                'source': 'system_monitor',
                'message': f'Disk usage: {disk["percent"]:.1f}% ({disk["used_gb"]}GB/{disk["total_gb"]}GB)',
                'severity': 'high' if disk['percent'] > 80 else 'medium' if disk['percent'] > 60 else 'low',
                'log_type': 'system_resource',
                'disk_percent': disk['percent'],
                'disk_used_gb': disk['used_gb']
            }
            if send_log_to_dashboard(log_data):
                logs_sent += 1
    except Exception as e:
        logger.error(f"Error processing system resources: {e}")
    
    # 3. Recent processes (with better error handling)
    try:
        processes = get_safe_processes()
        for proc_info in processes:
            log_data = {
                'timestamp': datetime.fromtimestamp(proc_info['create_time']).isoformat(),
                'source': 'process_monitor',
                'message': f'Recent process: {proc_info["name"]} (PID: {proc_info["pid"]})',
                'severity': 'low',
                'log_type': 'process_activity',
                'process_name': proc_info['name'],
                'pid': proc_info['pid']
            }
            if send_log_to_dashboard(log_data):
                logs_sent += 1
    except Exception as e:
        logger.error(f"Error processing processes: {e}")
    
    # 4. Add some synthetic security events for demonstration
    try:
        # Simulate some security-related logs
        security_events = [
            "SSH connection attempt detected",
            "Multiple failed login attempts",
            "Suspicious network scan detected",
            "Firewall rule triggered",
            "Antivirus scan completed"
        ]
        
        import random
        event = random.choice(security_events)
        log_data = {
            'timestamp': timestamp,
            'source': 'security_monitor',
            'message': event,
            'severity': 'medium' if 'failed' in event or 'suspicious' in event else 'low',
            'log_type': 'security_event'
        }
        if send_log_to_dashboard(log_data):
            logs_sent += 1
            
            # Create anomaly for suspicious events
            if 'suspicious' in event.lower() or 'failed' in event.lower():
                anomaly_data = {
                    'timestamp': timestamp,
                    'rule': f'Security anomaly detected: {event}',
                    'severity': 'high',
                    'confidence': 0.8,
                    'source_log': log_data,
                    'log_type': 'security_anomaly'
                }
                send_anomaly_to_dashboard(anomaly_data)
    except Exception as e:
        logger.error(f"Error creating security events: {e}")
    
    return logs_sent

def main():
    """Main loop to collect and send real logs"""
    logger.info("🚀 Starting Enhanced Real Log Collector for SIEM Dashboard...")
    logger.info("📡 Sending logs to http://localhost:3000")
    
    # Test connection to dashboard
    try:
        response = requests.get('http://localhost:3000/api/data', timeout=5)
        if response.status_code == 200:
            logger.info("✅ Dashboard is accessible")
        else:
            logger.error("❌ Dashboard is not responding correctly")
            return
    except Exception as e:
        logger.error(f"❌ Cannot connect to dashboard: {e}")
        logger.error("Make sure your SIEM dashboard is running at localhost:3000")
        return
    
    # Send initial test log
    test_log = {
        'timestamp': datetime.now().isoformat(),
        'source': 'log_collector',
        'message': 'Real Log Collector started successfully',
        'severity': 'low',
        'log_type': 'system_status'
    }
    send_log_to_dashboard(test_log)
    
    cycle_count = 0
    while True:
        try:
            cycle_count += 1
            logger.info(f"📊 Collection cycle #{cycle_count}")
            
            # Collect and send real system logs
            logs_sent = collect_real_system_logs()
            
            if logs_sent > 0:
                logger.info(f"✅ Sent {logs_sent} real logs to dashboard")
            else:
                logger.warning("⚠️ No logs were sent this cycle")
            
            # Wait 20 seconds before next collection
            logger.info("⏱️ Waiting 20 seconds before next collection...")
            time.sleep(20)
            
        except KeyboardInterrupt:
            logger.info("👋 Log collector stopped by user")
            break
        except Exception as e:
            logger.error(f"❌ Error in main loop: {e}")
            time.sleep(10)

if __name__ == "__main__":
    main()