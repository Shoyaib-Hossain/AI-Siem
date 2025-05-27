import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from sklearn.ensemble import IsolationForest

class DetectionRuleEngine:
    def __init__(self):
        # Initialize counters and buffers
        self.login_attempts = defaultdict(list)  # user_id -> list of login timestamps
        self.ip_access_counts = defaultdict(Counter)  # user_id -> {ip -> count}
        self.failed_logins = defaultdict(int)  # ip -> count of failed logins
        self.response_times = []  # list of response times for baseline
        self.status_code_counts = Counter()  # status_code -> count
        
        # Initialize models
        self.response_time_model = IsolationForest(contamination=0.05)
        self.model_trained = False
        
        # Thresholds
        self.failed_login_threshold = 5  # 5 failed attempts
        self.login_velocity_threshold = 10  # 10 logins in 1 minute
        self.new_ip_threshold = 3  # user logs in from 3+ different IPs
        
    def process_log(self, log_data):
        """Process a single log entry and check for anomalies."""
        anomalies = []
        
        # Extract fields
        timestamp = log_data.get('timestamp', datetime.now().timestamp())
        source_ip = log_data.get('source_ip', log_data.get('source', 'unknown'))
        status_code = log_data.get('status_code', 200)
        user_id = log_data.get('user_id', 'anonymous')
        response_time = log_data.get('response_time', 0)
        message = log_data.get('message', '').lower()
        
        # Update counters
        dt = datetime.fromtimestamp(timestamp)
        self.status_code_counts[status_code] += 1
        self.response_times.append(response_time)
        
        # Train model if we have enough data and haven't trained yet
        if len(self.response_times) >= 100 and not self.model_trained:
            self._train_models()
        
        # Check for login-related events
        if 'login' in message:
            # Track login timestamp
            self.login_attempts[user_id].append(dt)
            
            # Track IP address usage
            self.ip_access_counts[user_id][source_ip] += 1
            
            # Check for failed logins
            if status_code in [401, 403] or 'fail' in message or 'invalid' in message:
                self.failed_logins[source_ip] += 1
                
                # Rule 1: Brute Force Detection
                if self.failed_logins[source_ip] >= self.failed_login_threshold:
                    anomalies.append({
                        'rule': 'brute_force_detection',
                        'source_ip': source_ip,
                        'count': self.failed_logins[source_ip],
                        'severity': 'high'
                    })
            
            # Rule 2: Login Velocity
            recent_logins = [t for t in self.login_attempts[user_id] 
                            if dt - t < timedelta(minutes=1)]
            if len(recent_logins) >= self.login_velocity_threshold:
                anomalies.append({
                    'rule': 'login_velocity',
                    'user_id': user_id,
                    'count': len(recent_logins),
                    'severity': 'medium'
                })
            
            # Rule 3: New IP Detection
            if len(self.ip_access_counts[user_id]) >= self.new_ip_threshold:
                anomalies.append({
                    'rule': 'multiple_ip_access',
                    'user_id': user_id,
                    'ips': list(self.ip_access_counts[user_id].keys()),
                    'severity': 'medium'
                })
        
        # Rule 4: Error Rate Spike
        error_count = sum(self.status_code_counts[code] for code in range(400, 600))
        total_count = sum(self.status_code_counts.values())
        if total_count > 50 and error_count / total_count > 0.2:  # 20% error rate
            anomalies.append({
                'rule': 'error_rate_spike',
                'error_rate': error_count / total_count,
                'severity': 'medium'
            })
        
        # Rule 5: Response Time Anomaly (ML-based)
        if self.model_trained:
            rt_array = np.array([[response_time]])
            prediction = self.response_time_model.predict(rt_array)[0]
            score = self.response_time_model.score_samples(rt_array)[0]
            
            if prediction == -1:  # Anomaly detected
                anomalies.append({
                    'rule': 'response_time_anomaly',
                    'response_time': response_time,
                    'anomaly_score': float(score),
                    'severity': 'low' if response_time < 10 else 'medium'
                })
        
        # Rule 6: Suspicious Activity Patterns
        suspicious_patterns = [
            'sql injection', 'xss', 'csrf', 
            'directory traversal', '../', 'exec(', 
            'eval(', 'command injection'
        ]
        for pattern in suspicious_patterns:
            if pattern in message:
                anomalies.append({
                    'rule': 'suspicious_pattern',
                    'pattern': pattern,
                    'message': message,
                    'severity': 'high'
                })
        
        # Clean up old data
        self._cleanup_old_data(dt)
        
        # Add original log to anomalies
        for anomaly in anomalies:
            anomaly['original_log'] = log_data
            anomaly['timestamp'] = timestamp
        
        return anomalies
    
    def _train_models(self):
        """Train ML models on collected data."""
        if len(self.response_times) < 100:
            return
        
        # Train response time anomaly model
        X = np.array(self.response_times).reshape(-1, 1)
        self.response_time_model.fit(X)
        self.model_trained = True
    
    def _cleanup_old_data(self, current_time):
        """Remove data older than 1 hour to prevent memory issues."""
        cutoff = current_time - timedelta(hours=1)
        
        # Clean up login attempts
        for user_id in list(self.login_attempts.keys()):
            self.login_attempts[user_id] = [
                t for t in self.login_attempts[user_id] 
                if t > cutoff
            ]
            if not self.login_attempts[user_id]:
                del self.login_attempts[user_id]
        
        # Limit response times history to 1000 entries
        if len(self.response_times) > 1000:
            self.response_times = self.response_times[-1000:]

# Example usage
"""
rule_engine = DetectionRuleEngine()

# Process a log
log = {
    'message': 'Failed login attempt',
    'severity': 'warning',
    'source_ip': '192.168.1.100',
    'status_code': 401,
    'response_time': 0.25,
    'user_id': 'admin',
    'timestamp': datetime.now().timestamp()
}

anomalies = rule_engine.process_log(log)
if anomalies:
    print(f"Detected {len(anomalies)} anomalies")
    for anomaly in anomalies:
        print(f"Rule: {anomaly['rule']}, Severity: {anomaly['severity']}")
"""