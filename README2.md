# XASSE: Real-Time XSS Attack Detection and Visualization System Using Machine Learning and Graph-Based Analysis in a Cloud Environment

This project use a combination techniques of a machine learning technique and web application firewall to detect and prevent the XSS attack and give the response in real time if possible. We introduced a process to retrain the machine learning model with a log from Neo4j to improve the accuracy of the machine learning model. We conducted the experiment and deployed our project on google cloud platform so the instruction will be written for the system to be installable on google cloud platform using VM instance.

## Prerequisite
1. Register the google account with google cloud then create the VM instance by using GUI in https://console.cloud.google.com/compute/instances or running the code below in gcloud CLI which can be installed in https://dl.google.com/dl/cloudsdk/channels/rapid/GoogleCloudSDKInstaller.exe

```
gcloud compute instances create xss-detection-vm \
  --zone=us-central1-a \
  --machine-type=e2-standard-4 \
  --image-family=ubuntu-2204-lts \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=100GB \
  --tags=http-server,https-server
```

2. configure the firewall rules to open the following ports 

```
gcloud compute firewall-rules create allow-xss-detection \
  --allow tcp:8000,tcp:8080,tcp:8081,tcp:5001,tcp:5601,tcp:9200,tcp:7474,tcp:7687 \
  --target-tags=http-server \
  --description="Allow XSS detection system ports"
```

## Installation

1.) SSH into the VM instance by using gcloud CLI or using SSH via browser and install Docker

```
# SSH into VM
gcloud compute ssh xss-detection-vm --zone=us-central1-a

# Install Docker
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
```

2.) Upload the project into the VM instances. If using the browser SSH, user can click the upload button or if user use gcloud CLI, use the code below. replace the [VM name] and [VM region] with your VM name and VM region
```
gcloud compute scp --recurse ./xss-detection-system-gcloud [VM name]:~ --zone=[VM region]
```

3.) Deploy the system
```
# On the VM
cd ~/xss-detection-system-gcloud

docker compose up -d

docker compose ps
```


After deploy
-
1.) Go to http://localhost:8000/install.php to install bWAPP databse first

2.) Every page validate the input so user can XSS attack any input in any page other than XSS related page as well.

3.) Go to http://localhost:5601/ to use Kibana, search and choose **index management** then choose blocked-requests and create view to view log.

4.) http://localhost:7474/ to use Neo4j. Log in with username **neo4j** and password **SecureGCPPassword123!**

## Testing

1.) Open `test_xss_external_payloads_combined.py` and change the DEFAULT_IP field to be the public IP of the VM instance
2.) run `test_xss_external_payloads_combined.py` 

## Neo4j
run the following commands in order
```
MATCH (d:Detection)
RETURN d.request_id, d.timestamp, d.detection_method, 
       d.payload, d.modsecurity_blocked, d.ml_detected
LIMIT 10;
```

```
// Create Attack Pattern nodes
MERGE (p1:AttackPattern {name: 'Script Injection'})
MERGE (p2:AttackPattern {name: 'Event Handler'})
MERGE (p3:AttackPattern {name: 'JavaScript Protocol'})
MERGE (p4:AttackPattern {name: 'Image Tag'})
MERGE (p5:AttackPattern {name: 'Iframe Injection'})
MERGE (p6:AttackPattern {name: 'SVG Attack'});
```

```
// Create Method nodes
MERGE (m1:Method {name: 'ModSecurity'})
MERGE (m2:Method {name: 'Machine Learning'})
MERGE (m3:Method {name: 'Dual Layer'});
```
```
// Create Severity nodes
MERGE (s1:Severity {level: 'CRITICAL'})
MERGE (s2:Severity {level: 'HIGH'})
MERGE (s3:Severity {level: 'MEDIUM'})
MERGE (s4:Severity {level: 'LOW'});
```
```
// Script Injection Pattern
MATCH (d:Detection), (p:AttackPattern {name: 'Script Injection'})
WHERE d.payload CONTAINS '<script'
MERGE (d)-[:MATCHES_PATTERN]->(p);
```
```
// Event Handler Pattern
MATCH (d:Detection), (p:AttackPattern {name: 'Event Handler'})
WHERE d.payload =~ '(?i).*on\\w+\\s*='
MERGE (d)-[:MATCHES_PATTERN]->(p);
```
```
// JavaScript Protocol Pattern
MATCH (d:Detection), (p:AttackPattern {name: 'JavaScript Protocol'})
WHERE d.payload CONTAINS 'javascript:'
MERGE (d)-[:MATCHES_PATTERN]->(p);
```
```
// Image Tag Pattern
MATCH (d:Detection), (p:AttackPattern {name: 'Image Tag'})
WHERE d.payload CONTAINS '<img'
MERGE (d)-[:MATCHES_PATTERN]->(p);
```
```
// Iframe Pattern
MATCH (d:Detection), (p:AttackPattern {name: 'Iframe Injection'})
WHERE d.payload CONTAINS '<iframe'
MERGE (d)-[:MATCHES_PATTERN]->(p);
```
```
// SVG Pattern
MATCH (d:Detection), (p:AttackPattern {name: 'SVG Attack'})
WHERE d.payload CONTAINS '<svg'
MERGE (d)-[:MATCHES_PATTERN]->(p);
```
```
// ModSecurity-only detections
MATCH (d:Detection), (m:Method {name: 'ModSecurity'})
WHERE d.modsecurity_blocked = true AND d.ml_detected = false
MERGE (d)-[:DETECTED_BY]->(m);
```
```
// ML-only detections
MATCH (d:Detection), (m:Method {name: 'Machine Learning'})
WHERE d.ml_detected = true AND d.modsecurity_blocked = false
MERGE (d)-[:DETECTED_BY]->(m);
```
```
// Dual-layer detections
MATCH (d:Detection), (m:Method {name: 'Dual Layer'})
WHERE d.modsecurity_blocked = true AND d.ml_detected = true
MERGE (d)-[:DETECTED_BY]->(m);
```
```
// Critical severity (high ML confidence)
MATCH (d:Detection), (s:Severity {level: 'CRITICAL'})
WHERE d.ml_confidence >= 0.9
MERGE (d)-[:HAS_SEVERITY]->(s);
```
```
// High severity
MATCH (d:Detection), (s:Severity {level: 'HIGH'})
WHERE (d.ml_confidence >= 0.7 AND d.ml_confidence < 0.9)
   OR (d.modsecurity_blocked = true AND d.ml_detected = false)
MERGE (d)-[:HAS_SEVERITY]->(s);
```
```
// Medium severity
MATCH (d:Detection), (s:Severity {level: 'MEDIUM'})
WHERE d.ml_confidence >= 0.5 AND d.ml_confidence < 0.7
MERGE (d)-[:HAS_SEVERITY]->(s);
```
```
MATCH (m:Method)<-[:DETECTED_BY]-(d:Detection)-[:MATCHES_PATTERN]->(p:AttackPattern)
RETURN m, d, p
LIMIT 100;
```

## Misc.










retrain command example
```
curl -X POST http://localhost:5001/retrain \
  -H "Content-Type: application/json" \
  -d '{"model_name": "demo_model", "limit": 1000}'
```

change ML model command example
```
curl -X POST http://localhost:5001/models/activate \
  -H "Content-Type: application/json" \
  -d '{"model_name": "retrained_demo_20241202_143022"}'
  ```

