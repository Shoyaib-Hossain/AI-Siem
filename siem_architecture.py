import os
import json
import time
import logging
from flask import Flask, request, jsonify
from kafka import KafkaProducer, KafkaConsumer
import numpy as np
from sklearn.ensemble import IsolationForest
from collections import Counter

# Import the detection rules engine
try:
    from detection_rules import DetectionRuleEngine
    USE_ADVANCED_RULES = True
    print("Using advanced detection rules")
except ImportError:
    USE_ADVANCED_RULES = False
    print("Advanced detection rules not available, using basic detection")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Get service name from environment variables
SERVICE_NAME = os.environ.get('SERVICE_NAME', 'unknown')
logger.info(f"Starting service: {SERVICE_NAME}")

# Kafka configuration
KAFKA_BROKER = 'kafka:9092'
LOG_TOPIC = 'logs'
ANOMALY_TOPIC = 'anomalies'
ALERT_TOPIC = 'alerts'

# Initialize rule engine if available
rule_engine = DetectionRuleEngine() if USE_ADVANCED_RULES else None

# Initialize Kafka Producer
def get_kafka_producer():
    logger.info(f"Initializing Kafka producer for {KAFKA_BROKER}")
    for i in range(5):  # Retry 5 times
        try:
            producer = KafkaProducer(
                bootstrap_servers=[KAFKA_BROKER],
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                retries=5
            )
            logger.info("Kafka producer initialized successfully")
            return producer
        except Exception as e:
            logger.error(f"Failed to initialize Kafka producer (attempt {i+1}/5): {str(e)}")
            time.sleep(5)  # Wait 5 seconds before retrying
    logger.critical("Could not initialize Kafka producer after 5 attempts")
    return None

# Initialize Kafka Consumer
def get_kafka_consumer(topic):
    logger.info(f"Initializing Kafka consumer for topic {topic} on {KAFKA_BROKER}")
    for i in range(5):  # Retry 5 times
        try:
            consumer = KafkaConsumer(
                topic,
                bootstrap_servers=[KAFKA_BROKER],
                auto_offset_reset='earliest',
                enable_auto_commit=True,
                group_id=f'{topic}-group',
                value_deserializer=lambda x: json.loads(x.decode('utf-8'))
            )
            logger.info(f"Kafka consumer initialized successfully for topic {topic}")
            return consumer
        except Exception as e:
            logger.error(f"Failed to initialize Kafka consumer (attempt {i+1}/5): {str(e)}")
            time.sleep(5)  # Wait 5 seconds before retrying
    logger.critical(f"Could not initialize Kafka consumer for topic {topic} after 5 attempts")
    return None

# Log Ingestion Service
@app.route('/ingest', methods=['POST'])
def ingest_log():
    if SERVICE_NAME != 'log_ingestion':
        return jsonify({'error': 'Service not available'}), 404
    
    log_data = request.json
    logger.info(f"Received log: {log_data}")
    
    # Add timestamp if not present
    if 'timestamp' not in log_data:
        log_data['timestamp'] = time.time()
    
    # Add source information
    log_data['source'] = request.remote_addr
    
    try:
        producer = get_kafka_producer()
        if producer:
            producer.send(LOG_TOPIC, log_data)
            producer.flush()
            logger.info(f"Log sent to Kafka topic {LOG_TOPIC}")
            return jsonify({'status': 'success', 'message': 'Log ingested successfully'}), 200
        else:
            return jsonify({'status': 'error', 'message': 'Failed to connect to Kafka'}), 500
    except Exception as e:
        logger.error(f"Error sending log to Kafka: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Anomaly Detection Service
def detect_anomalies():
    if SERVICE_NAME != 'anomaly_detection':
        logger.info("Not starting anomaly detection as this is not the anomaly_detection service")
        return
    
    logger.info("Starting anomaly detection service")
    logger.info(f"Attempting to connect to Kafka broker at {KAFKA_BROKER}")
    
    consumer = get_kafka_consumer(LOG_TOPIC)
    if not consumer:
        logger.critical("Failed to initialize Kafka consumer. Exiting anomaly detection service.")
        return
    
    producer = get_kafka_producer()
    if not producer:
        logger.critical("Failed to initialize Kafka producer. Exiting anomaly detection service.")
        return
    
    # Buffer to collect logs for batch processing (only used for ML-based detection)
    log_buffer = []
    
    # Initialize the anomaly detection model
    model = IsolationForest(contamination=0.05, random_state=42)
    
    logger.info(f"Anomaly detection service started. Listening on topic: {LOG_TOPIC}")
    
    try:
        for message in consumer:
            log_data = message.value
            logger.info(f"Received message on {LOG_TOPIC}: {log_data}")
            
            # Use advanced detection rules if available
            if USE_ADVANCED_RULES:
                anomalies = rule_engine.process_log(log_data)
                if anomalies:
                    logger.info(f"Detected {len(anomalies)} anomalies with rule engine")
                    for anomaly in anomalies:
                        producer.send(ANOMALY_TOPIC, anomaly)
                        logger.info(f"Sent anomaly to Kafka: {anomaly}")
            else:
                # Fall back to basic ML-based detection
                log_buffer.append(log_data)
                
                # Process in batches of 10 logs
                if len(log_buffer) >= 10:
                    logger.info(f"Processing batch of {len(log_buffer)} logs")
                    
                    # Extract features for anomaly detection
                    features = []
                    for log in log_buffer:
                        # Example feature: response time or status code
                        response_time = log.get('response_time', 0)
                        status_code = int(log.get('status_code', 200))
                        features.append([response_time, status_code])
                    
                    # Convert to numpy array for processing
                    features = np.array(features)
                    
                    # Train and predict
                    model.fit(features)
                    predictions = model.predict(features)
                    
                    # Process anomalies
                    anomaly_count = 0
                    for i, pred in enumerate(predictions):
                        if pred == -1:  # Anomaly found
                            anomaly_count += 1
                            anomaly_data = {
                                'original_log': log_buffer[i],
                                'anomaly_score': float(model.score_samples([features[i]])[0]),
                                'timestamp': time.time()
                            }
                            producer.send(ANOMALY_TOPIC, anomaly_data)
                            logger.info(f"Anomaly detected: {anomaly_data}")
                    
                    # Log summary
                    logger.info(f"Batch processing complete. Found {anomaly_count} anomalies")
                    
                    # Clear buffer after processing
                    log_buffer = []
                    producer.flush()
    except Exception as e:
        logger.error(f"Error in anomaly detection: {str(e)}")

# Alert Correlation Service
def correlate_alerts():
    if SERVICE_NAME != 'alert_correlation':
        logger.info("Not starting alert correlation as this is not the alert_correlation service")
        return
    
    logger.info("Starting alert correlation service")
    logger.info(f"Attempting to connect to Kafka broker at {KAFKA_BROKER}")
    
    consumer = get_kafka_consumer(ANOMALY_TOPIC)
    if not consumer:
        logger.critical("Failed to initialize Kafka consumer. Exiting alert correlation service.")
        return
    
    producer = get_kafka_producer()
    if not producer:
        logger.critical("Failed to initialize Kafka producer. Exiting alert correlation service.")
        return
    
    # Time window for correlation (5 minutes)
    correlation_window = 300  # seconds
    anomaly_buffer = []
    
    logger.info(f"Alert correlation service started. Listening on topic: {ANOMALY_TOPIC}")
    
    try:
        for message in consumer:
            anomaly_data = message.value
            logger.info(f"Received anomaly on {ANOMALY_TOPIC}: {anomaly_data}")
            current_time = time.time()
            
            # Add to buffer
            anomaly_buffer.append(anomaly_data)
            
            # Remove old anomalies from buffer
            anomaly_buffer = [a for a in anomaly_buffer 
                            if current_time - a.get('timestamp', 0) <= correlation_window]
            
            # Check for correlated anomalies
            if len(anomaly_buffer) >= 3:
                logger.info(f"Checking for correlations in {len(anomaly_buffer)} anomalies")
                
                # Example correlation logic: multiple anomalies from same source
                sources = [a.get('original_log', {}).get('source') for a in anomaly_buffer]
                
                # Count occurrences of each source
                source_counts = Counter(sources)
                
                # If any source has multiple anomalies, generate an alert
                for source, count in source_counts.items():
                    if count >= 3:
                        alert_data = {
                            'alert_type': 'multiple_anomalies',
                            'source': source,
                            'count': count,
                            'anomalies': [a for a in anomaly_buffer if a.get('original_log', {}).get('source') == source],
                            'timestamp': current_time,
                            'severity': 'high'
                        }
                        producer.send(ALERT_TOPIC, alert_data)
                        logger.info(f"Alert generated for source {source} with {count} anomalies: {alert_data}")
            
            producer.flush()
    except Exception as e:
        logger.error(f"Error in alert correlation: {str(e)}")

if __name__ == '__main__':
    logger.info(f"Starting service: {SERVICE_NAME}")
    if SERVICE_NAME == 'log_ingestion':
        app.run(host='0.0.0.0', port=int(os.environ.get('FLASK_RUN_PORT', 5000)))
    elif SERVICE_NAME == 'anomaly_detection':
        detect_anomalies()
    elif SERVICE_NAME == 'alert_correlation':
        correlate_alerts()
    else:
        logger.error(f"Unknown service: {SERVICE_NAME}")