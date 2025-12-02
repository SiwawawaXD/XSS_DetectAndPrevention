# Neo4j Graph Visualization Queries for XSS Detection System

## Overview
These queries create rich graph visualizations showing relationships between attacks, patterns, detection methods, and temporal connections. Perfect for presentations!

---

## 🎨 Visualization 1: Attack Pattern Groups

### Create Pattern Nodes and Relationships

First, run this query to create a rich graph structure:

```cypher
// Step 1: Create Pattern category nodes
MERGE (p1:AttackPattern {name: 'Script Injection', category: 'DOM'})
MERGE (p2:AttackPattern {name: 'Event Handler', category: 'Event-based'})
MERGE (p3:AttackPattern {name: 'JavaScript Protocol', category: 'Protocol'})
MERGE (p4:AttackPattern {name: 'Image Tag Exploit', category: 'HTML Tag'})
MERGE (p5:AttackPattern {name: 'SVG Exploit', category: 'HTML Tag'})
MERGE (p6:AttackPattern {name: 'Alert Function', category: 'Function Call'})
MERGE (p7:AttackPattern {name: 'Benign Traffic', category: 'Normal'})

// Step 2: Link detections to patterns
MATCH (d:Detection)
WHERE d.payload IS NOT NULL
WITH d,
  CASE 
    WHEN d.payload CONTAINS '<script' THEN 'Script Injection'
    WHEN d.payload =~ '(?i).*on\\w+\\s*=.*' THEN 'Event Handler'
    WHEN d.payload CONTAINS 'javascript:' THEN 'JavaScript Protocol'
    WHEN d.payload CONTAINS '<img' THEN 'Image Tag Exploit'
    WHEN d.payload CONTAINS '<svg' THEN 'SVG Exploit'
    WHEN d.payload =~ '(?i).*alert\\s*\\(' THEN 'Alert Function'
    ELSE 'Benign Traffic'
  END as pattern_name

MATCH (p:AttackPattern {name: pattern_name})
MERGE (d)-[:MATCHES_PATTERN]->(p)

RETURN count(*) as relationships_created
```

### Visualize Attack Pattern Graph

```cypher
// Show attack patterns and their connections
MATCH (d:Detection)-[:MATCHES_PATTERN]->(p:AttackPattern)
RETURN d, p
LIMIT 200
```

**What you'll see:**
- Central pattern nodes (colored by category)
- Detection nodes radiating outward
- Clear clustering by attack type
- Great for showing "attack families"

---

## 🎨 Visualization 2: Detection Method Comparison Network

### Create Method Nodes

```cypher
// Create detection method nodes
MERGE (m1:Method {name: 'ModSecurity', type: 'Signature-based'})
MERGE (m2:Method {name: 'Machine Learning', type: 'Pattern-based'})

// Link detections to methods
MATCH (d:Detection)
WHERE d.detection_method IS NOT NULL
WITH d,
  CASE 
    WHEN d.detection_method CONTAINS 'ModSecurity' THEN 'ModSecurity'
    WHEN d.detection_method = 'ML' THEN 'Machine Learning'
    ELSE 'Unknown'
  END as method_name

MATCH (m:Method {name: method_name})
MERGE (d)-[:DETECTED_BY]->(m)

RETURN count(*) as links_created
```

### Visualize Detection Overlap

```cypher
// Show which payloads were detected by both methods
MATCH (d1:Detection)-[:DETECTED_BY]->(m1:Method {name: 'ModSecurity'})
WHERE d1.is_blocked = true

MATCH (d2:Detection)-[:DETECTED_BY]->(m2:Method {name: 'Machine Learning'})
WHERE d2.is_malicious = true AND d2.payload = d1.payload

WITH d1, d2, m1, m2
MERGE (d1)-[:SAME_PAYLOAD]->(d2)

RETURN m1, d1, d2, m2
LIMIT 100
```

**What you'll see:**
- Two method nodes (ModSecurity vs ML)
- Detection nodes connected to their method
- Bridges showing payloads detected by both
- Visual comparison of coverage

---

## 🎨 Visualization 3: Temporal Attack Waves

### Create Time-based Groups

```cypher
// Group attacks by time periods
MATCH (d:Detection)
WHERE d.timestamp IS NOT NULL AND d.is_blocked = true

WITH d, 
  date(datetime(d.timestamp)) as attack_date,
  datetime(d.timestamp).hour as attack_hour

WITH attack_date, attack_hour, count(d) as attack_count, collect(d) as detections
WHERE attack_count >= 5  // Only show significant attack waves

MERGE (tw:TimeWindow {
  date: toString(attack_date),
  hour: attack_hour,
  attack_count: attack_count
})

WITH tw, detections
UNWIND detections as d
MERGE (d)-[:OCCURRED_IN]->(tw)

RETURN count(*) as time_windows_created
```

### Visualize Attack Timeline

```cypher
// Show attack waves over time
MATCH (d:Detection)-[:OCCURRED_IN]->(tw:TimeWindow)
RETURN d, tw
ORDER BY tw.date DESC, tw.hour DESC
LIMIT 150
```

**What you'll see:**
- TimeWindow nodes (sized by attack count)
- Detection nodes grouped by time
- Temporal clustering of attacks
- Shows "attack campaigns"

---

## 🎨 Visualization 4: Payload Similarity Network

### Create Similarity Relationships

```cypher
// Find similar payloads (share common attack techniques)
MATCH (d1:Detection)
WHERE d1.payload IS NOT NULL AND d1.is_blocked = true

MATCH (d2:Detection)
WHERE d2.payload IS NOT NULL 
  AND d2.is_blocked = true 
  AND id(d1) < id(d2)  // Avoid duplicates

WITH d1, d2,
  // Calculate similarity score
  CASE 
    WHEN d1.payload CONTAINS '<script' AND d2.payload CONTAINS '<script' THEN 1
    ELSE 0
  END +
  CASE 
    WHEN d1.payload =~ '(?i).*alert\\(' AND d2.payload =~ '(?i).*alert\\(' THEN 1
    ELSE 0
  END +
  CASE 
    WHEN d1.payload =~ '(?i).*on\\w+=' AND d2.payload =~ '(?i).*on\\w+=' THEN 1
    ELSE 0
  END as similarity

WHERE similarity >= 2  // At least 2 shared techniques

MERGE (d1)-[r:SIMILAR_TO {score: similarity}]->(d2)

RETURN count(r) as similarity_links
```

### Visualize Similarity Clusters

```cypher
// Show clusters of similar attacks
MATCH path = (d1:Detection)-[:SIMILAR_TO*1..2]-(d2:Detection)
WHERE d1.is_blocked = true AND d2.is_blocked = true
RETURN path
LIMIT 100
```

**What you'll see:**
- Tightly connected clusters of similar attacks
- "Attack families" based on techniques
- Isolated nodes = unique attacks
- Great for showing attack variations

---

## 🎨 Visualization 5: Source IP Attack Graph

### Create IP Nodes

```cypher
// Group attacks by source IP
MATCH (d:Detection)
WHERE d.client_ip IS NOT NULL

MERGE (ip:ClientIP {address: d.client_ip})

WITH ip, d
MERGE (d)-[:ORIGINATED_FROM]->(ip)

// Calculate threat score for each IP
WITH ip
MATCH (ip)<-[:ORIGINATED_FROM]-(d:Detection)
WITH ip, 
  count(CASE WHEN d.is_blocked = true THEN 1 END) as malicious_count,
  count(d) as total_count

SET ip.threat_score = toFloat(malicious_count) / total_count,
    ip.total_attacks = malicious_count

RETURN count(ip) as ip_nodes_created
```

### Visualize IP-based Attack Network

```cypher
// Show IPs and their attack patterns
MATCH (ip:ClientIP)<-[:ORIGINATED_FROM]-(d:Detection)-[:MATCHES_PATTERN]->(p:AttackPattern)
WHERE ip.threat_score > 0.5
RETURN ip, d, p
LIMIT 100
```

**What you'll see:**
- IP nodes (sized by threat score)
- Detection nodes from each IP
- Pattern nodes showing attack types
- Identifies persistent attackers

---

## 🎨 Visualization 6: Multi-Stage Attack Chains

### Create Attack Sequences

```cypher
// Link consecutive attacks from same IP
MATCH (d1:Detection)-[:ORIGINATED_FROM]->(ip:ClientIP)
MATCH (d2:Detection)-[:ORIGINATED_FROM]->(ip)
WHERE d1.timestamp < d2.timestamp
  AND duration.between(datetime(d1.timestamp), datetime(d2.timestamp)).seconds < 60

WITH d1, d2, ip
ORDER BY d1.timestamp, d2.timestamp
WITH d1, collect(d2)[0] as next_detection
WHERE next_detection IS NOT NULL

MERGE (d1)-[:FOLLOWED_BY]->(next_detection)

RETURN count(*) as sequences_created
```

### Visualize Attack Chains

```cypher
// Show sequential attack patterns
MATCH path = (ip:ClientIP)<-[:ORIGINATED_FROM]-(d1:Detection)-[:FOLLOWED_BY*1..5]->(d2:Detection)
WHERE ip.threat_score > 0.5
RETURN path
LIMIT 50
```

**What you'll see:**
- Attack sequences over time
- Multi-step attack attempts
- Evolution of attacker techniques
- "Attack stories"

---

## 🎨 Visualization 7: Severity Hierarchy

### Create Severity Nodes

```cypher
// Create impact level hierarchy
MERGE (s1:Severity {level: 'CRITICAL', rank: 4, color: 'red'})
MERGE (s2:Severity {level: 'HIGH', rank: 3, color: 'orange'})
MERGE (s3:Severity {level: 'MEDIUM', rank: 2, color: 'yellow'})
MERGE (s4:Severity {level: 'LOW', rank: 1, color: 'blue'})
MERGE (s5:Severity {level: 'INFO', rank: 0, color: 'green'})

// Link detections to severity
MATCH (d:Detection)
WHERE d.impact_level IS NOT NULL
MATCH (s:Severity {level: d.impact_level})
MERGE (d)-[:HAS_SEVERITY]->(s)

// Create hierarchy
MERGE (s1)-[:MORE_SEVERE_THAN]->(s2)
MERGE (s2)-[:MORE_SEVERE_THAN]->(s3)
MERGE (s3)-[:MORE_SEVERE_THAN]->(s4)
MERGE (s4)-[:MORE_SEVERE_THAN]->(s5)

RETURN count(*) as severity_links
```

### Visualize Severity Distribution

```cypher
// Show severity hierarchy with detections
MATCH (s:Severity)<-[:HAS_SEVERITY]-(d:Detection)
OPTIONAL MATCH (s)-[:MORE_SEVERE_THAN]->(s2:Severity)
RETURN s, d, s2
LIMIT 200
```

**What you'll see:**
- Pyramid of severity levels
- Detection distribution by impact
- Clear risk visualization
- Great for executive presentations

---

## 🎨 Visualization 8: Training Data Provenance

### Link Training Sources

```cypher
// Create source nodes
MERGE (src1:DataSource {name: 'ModSecurity Blocks', type: 'Real Traffic'})
MERGE (src2:DataSource {name: 'Kaggle Dataset', type: 'Synthetic'})

// Link malicious samples to ModSecurity
MATCH (d:Detection)
WHERE d.detection_method = 'ModSecurity' AND d.is_blocked = true
MERGE (src1)-[:PROVIDED_SAMPLE]->(d)

// Create model node
MERGE (m:MLModel {
  name: 'Current Active Model',
  version: 'retrained_demo'
})

// Link sources to model
MERGE (src1)-[:TRAINED]->(m)
MERGE (src2)-[:TRAINED]->(m)

RETURN count(*) as links_created
```

### Visualize Training Pipeline

```cypher
// Show where training data comes from
MATCH (src:DataSource)-[:PROVIDED_SAMPLE]->(d:Detection)
MATCH (src)-[:TRAINED]->(m:MLModel)
RETURN src, d, m
LIMIT 100
```

**What you'll see:**
- Data source nodes
- Sample detections
- Model node
- Data flow through training pipeline

---

## 🎨 Visualization 9: Complete System Overview

### Master Graph Query

```cypher
// Complete system visualization
MATCH (ip:ClientIP)<-[:ORIGINATED_FROM]-(d:Detection)
MATCH (d)-[:MATCHES_PATTERN]->(p:AttackPattern)
MATCH (d)-[:DETECTED_BY]->(m:Method)
MATCH (d)-[:HAS_SEVERITY]->(s:Severity)
WHERE d.is_blocked = true
RETURN ip, d, p, m, s
LIMIT 150
```

**What you'll see:**
- Multi-layer network
- All relationship types
- Complete attack context
- Impressive for presentations!

---

## 🎨 Visualization 10: Attack Technique Co-occurrence

### Create Technique Relationships

```cypher
// Find which techniques are used together
MATCH (d:Detection)
WHERE d.payload IS NOT NULL AND d.is_blocked = true

// Extract techniques
WITH d,
  CASE WHEN d.payload CONTAINS '<script' THEN 1 ELSE 0 END as has_script,
  CASE WHEN d.payload =~ '(?i).*on\\w+=' THEN 1 ELSE 0 END as has_event,
  CASE WHEN d.payload =~ '(?i).*alert\\(' THEN 1 ELSE 0 END as has_alert,
  CASE WHEN d.payload CONTAINS '<img' THEN 1 ELSE 0 END as has_img,
  CASE WHEN d.payload CONTAINS '<svg' THEN 1 ELSE 0 END as has_svg

// Create technique nodes
FOREACH (x IN CASE WHEN has_script = 1 THEN [1] ELSE [] END |
  MERGE (t:Technique {name: 'Script Tag'})
  MERGE (d)-[:USES_TECHNIQUE]->(t)
)
FOREACH (x IN CASE WHEN has_event = 1 THEN [1] ELSE [] END |
  MERGE (t:Technique {name: 'Event Handler'})
  MERGE (d)-[:USES_TECHNIQUE]->(t)
)
FOREACH (x IN CASE WHEN has_alert = 1 THEN [1] ELSE [] END |
  MERGE (t:Technique {name: 'Alert Function'})
  MERGE (d)-[:USES_TECHNIQUE]->(t)
)
FOREACH (x IN CASE WHEN has_img = 1 THEN [1] ELSE [] END |
  MERGE (t:Technique {name: 'Image Tag'})
  MERGE (d)-[:USES_TECHNIQUE]->(t)
)
FOREACH (x IN CASE WHEN has_svg = 1 THEN [1] ELSE [] END |
  MERGE (t:Technique {name: 'SVG Tag'})
  MERGE (d)-[:USES_TECHNIQUE]->(t)
)

RETURN count(d) as detections_processed
```

### Visualize Technique Co-occurrence

```cypher
// Show which techniques are used together
MATCH (t1:Technique)<-[:USES_TECHNIQUE]-(d:Detection)-[:USES_TECHNIQUE]->(t2:Technique)
WHERE id(t1) < id(t2)  // Avoid duplicates

WITH t1, t2, count(d) as co_occurrence
WHERE co_occurrence >= 3  // Only show significant co-occurrence

MERGE (t1)-[r:CO_OCCURS_WITH {count: co_occurrence}]->(t2)

RETURN t1, r, t2
```

**What you'll see:**
- Technique nodes
- Thick edges = frequently combined
- Attack technique combinations
- "Attack recipe" patterns

---

## 📊 Presentation Tips

### 1. **Color Coding in Neo4j Browser**

Set these in Neo4j Browser settings:

```
AttackPattern: color by category (red=malicious, green=benign)
Severity: color by level (red=CRITICAL, orange=HIGH, etc.)
Method: blue=ModSecurity, green=ML
ClientIP: size by threat_score
Detection: color by is_blocked (red=blocked, yellow=allowed)
```

### 2. **Graph Layout Tips**

- Use **Force-directed layout** for clustering visualization
- Use **Hierarchical layout** for severity/timeline views
- Adjust **physics** settings for clearer separation
- Enable **node labels** for key information

### 3. **Best Queries for Presentation**

**For Attack Diversity:**
```cypher
MATCH (d:Detection)-[:MATCHES_PATTERN]->(p:AttackPattern)
RETURN d, p LIMIT 100
```

**For Detection Comparison:**
```cypher
MATCH (m:Method)<-[:DETECTED_BY]-(d:Detection)
RETURN m, d LIMIT 100
```

**For Attack Evolution:**
```cypher
MATCH path = (d1:Detection)-[:FOLLOWED_BY*1..3]->(d2:Detection)
RETURN path LIMIT 50
```

### 4. **Interactive Demo Flow**

1. **Start simple:** Show basic Detection nodes
2. **Add patterns:** Run pattern grouping query
3. **Show methods:** Add detection method comparison
4. **Add time:** Show temporal clusters
5. **Full graph:** Show complete system overview

### 5. **Export for Presentation**

```cypher
// Export graph data for visualization tools
MATCH (d:Detection)-[r]->(target)
WHERE d.is_blocked = true
RETURN d.payload as source, 
       type(r) as relationship, 
       labels(target)[0] as target_type
LIMIT 1000
```

Can be imported into:
- Gephi (advanced graph visualization)
- Cytoscape (network analysis)
- D3.js (web visualization)

---

## 🎯 Quick Setup Script

Run this to set up all visualizations:

```cypher
// Complete setup in one query
CALL {
  // Attack Patterns
  MERGE (p1:AttackPattern {name: 'Script Injection', category: 'DOM'})
  MERGE (p2:AttackPattern {name: 'Event Handler', category: 'Event-based'})
  MERGE (p3:AttackPattern {name: 'JavaScript Protocol', category: 'Protocol'})
  MERGE (p4:AttackPattern {name: 'HTML Tag Exploit', category: 'HTML Tag'})
  
  // Methods
  MERGE (m1:Method {name: 'ModSecurity', type: 'Signature-based'})
  MERGE (m2:Method {name: 'Machine Learning', type: 'Pattern-based'})
  
  // Severity Levels
  MERGE (s1:Severity {level: 'CRITICAL', rank: 4})
  MERGE (s2:Severity {level: 'HIGH', rank: 3})
  MERGE (s3:Severity {level: 'MEDIUM', rank: 2})
  MERGE (s4:Severity {level: 'LOW', rank: 1})
  
  RETURN count(*) as setup_nodes
}

// Link everything
MATCH (d:Detection)
WHERE d.payload IS NOT NULL

// Pattern links
WITH d
OPTIONAL MATCH (p:AttackPattern)
WHERE (d.payload CONTAINS '<script' AND p.name = 'Script Injection')
   OR (d.payload =~ '(?i).*on\\w+=' AND p.name = 'Event Handler')
   OR (d.payload CONTAINS 'javascript:' AND p.name = 'JavaScript Protocol')
   OR (d.payload CONTAINS '<img' AND p.name = 'HTML Tag Exploit')

FOREACH (x IN CASE WHEN p IS NOT NULL THEN [1] ELSE [] END |
  MERGE (d)-[:MATCHES_PATTERN]->(p)
)

// Method links
WITH d
OPTIONAL MATCH (m:Method)
WHERE (d.detection_method CONTAINS 'ModSecurity' AND m.name = 'ModSecurity')
   OR (d.detection_method = 'ML' AND m.name = 'Machine Learning')

FOREACH (x IN CASE WHEN m IS NOT NULL THEN [1] ELSE [] END |
  MERGE (d)-[:DETECTED_BY]->(m)
)

// Severity links
WITH d
OPTIONAL MATCH (s:Severity {level: d.impact_level})
FOREACH (x IN CASE WHEN s IS NOT NULL THEN [1] ELSE [] END |
  MERGE (d)-[:HAS_SEVERITY]->(s)
)

// IP links
WITH d
WHERE d.client_ip IS NOT NULL
MERGE (ip:ClientIP {address: d.client_ip})
MERGE (d)-[:ORIGINATED_FROM]->(ip)

RETURN count(d) as detections_linked
```

---

## 🎬 Demo Script for Professor

```cypher
// 1. Show the raw data (boring table)
MATCH (d:Detection)
RETURN d.payload, d.detection_method, d.is_blocked
LIMIT 20

// 2. Now show it as a graph! (exciting)
MATCH (d:Detection)-[:MATCHES_PATTERN]->(p:AttackPattern)
RETURN d, p
LIMIT 50

// 3. Add detection methods
MATCH (d:Detection)-[:MATCHES_PATTERN]->(p:AttackPattern)
MATCH (d)-[:DETECTED_BY]->(m:Method)
RETURN d, p, m
LIMIT 50

// 4. Show attack clustering
MATCH (p:AttackPattern)<-[:MATCHES_PATTERN]-(d:Detection)
WITH p, count(d) as attack_count
WHERE attack_count > 5
MATCH (p)<-[:MATCHES_PATTERN]-(d:Detection)
RETURN p, d
LIMIT 100

// 5. Final: Complete system graph
MATCH (d:Detection)-[:MATCHES_PATTERN]->(p:AttackPattern)
MATCH (d)-[:DETECTED_BY]->(m:Method)
MATCH (d)-[:HAS_SEVERITY]->(s:Severity)
WHERE d.is_blocked = true
RETURN d, p, m, s
LIMIT 100
```

**Say to professor:** "Notice how the graph naturally clusters attacks by type, making it easy to identify attack families and patterns. This is much more intuitive than tables for understanding attack relationships!"

---

## 💡 Advanced: Create Custom Visualization

```cypher
// Create a "meta" view for high-level overview
MATCH (p:AttackPattern)<-[:MATCHES_PATTERN]-(d:Detection)-[:DETECTED_BY]->(m:Method)
WITH p, m, count(d) as detections
MERGE (p)-[r:DETECTED_BY_METHOD {count: detections}]->(m)
SET r.weight = detections
RETURN p, r, m
```

This creates a summary graph showing which methods are best at detecting which patterns!

---

Perfect for impressing your professor! 🎓✨
