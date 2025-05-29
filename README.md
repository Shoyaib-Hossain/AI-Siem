
 AI Model: Isolation Forest for Anomaly Detection

 Overview

```ascii
Input Log -> Feature Extraction -> Isolation Forest -> Anomaly Score -> Alert
   |              |                     |                  |           |
   v              v                     v                  v           v
Raw Data    [Features Array]    Random Partitioning    0.0-1.0    Threshold Check
```

 How Isolation Forest Works

1. Basic Principle
   - Anomalies are easier to isolate than normal points
   - Requires fewer partitions to isolate anomalous data points
   - Works well with high-dimensional data

2. Feature Engineering
   ```python
   features = [
       response_time,     How long the request took
       status_code,       HTTP status code
   ]
   ```

3. Model Configuration
   ```python
   IsolationForest(
       contamination=0.05,   Expected 5% of data is anomalous
       random_state=42       For reproducibility
   )
   ```

 Processing Steps

1. Data Collection
   - Collect logs in batches of 10
   - Extract numerical features
   - Normalize data points

2. Model Training & Prediction
   ```python
   model.fit(features)            Train on batch
   predictions = model.predict(features)   -1 for anomalies, 1 for normal
   anomaly_scores = model.score_samples(features)   Anomaly scores
   ```

3. Scoring Logic
   - Lower scores indicate more anomalous behavior
   - Scores are normalized between 0 and 1
   - Threshold-based detection

 Example Scenarios

1. Response Time Anomaly
   ```
   Normal: 100-500ms
   Anomaly: >1000ms or <10ms
   ```

2. Status Code Patterns
   ```
   Normal: 200, 304
   Suspicious: 400, 401, 403
   Anomaly: 500, 503
   ```

 Integration with SIEM

1. Real-time Processing
   - Batch processing every 10 logs
   - Continuous model updates
   - Adaptive thresholds

2. Alert Generation
   ```python
   if prediction == -1:   Anomaly detected
       anomaly_data = {
           'score': anomaly_score,
           'features': features,
           'timestamp': timestamp
       }
   ```

3. Correlation with Rules
   - ML-based detection
   - Rule-based validation
   - Combined scoring

 Performance Metrics

On localhost:3000 dashboard looks like :

<img width="452" alt="image" src="https://github.com/Shoyaib-Hossain/AI-Siem/blob/main/Image%2029-05-2025%20at%2014.18.jpeg" />
