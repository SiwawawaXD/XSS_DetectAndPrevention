#!/usr/bin/env python3
"""
Neo4j Diagnostic Script
========================

This script helps you verify what data is actually in your Neo4j database
and diagnose training issues.

Usage:
    python check_neo4j.py
"""

import os
from neo4j import GraphDatabase

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "SecureGCPPassword123!")

def check_neo4j():
    """Check what's actually in Neo4j"""
    
    print("="*60)
    print("NEO4J DIAGNOSTIC REPORT")
    print("="*60)
    
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        print(f"✓ Connected to Neo4j at {NEO4J_URI}\n")
        
        with driver.session() as session:
            
            # 1. Count total events
            print("📊 Event Counts:")
            print("-" * 60)
            result = session.run("MATCH (e) RETURN count(e) as total")
            total = result.single()["total"]
            print(f"Total nodes: {total}")
            
            # 2. Count by label
            result = session.run("""
                MATCH (e)
                UNWIND labels(e) AS label
                RETURN label, count(*) as count
                ORDER BY count DESC
            """)
            print("\nNodes by label:")
            for record in result:
                print(f"  - {record['label']}: {record['count']}")
            
            # 3. Sample AttackEvent properties
            print("\n🔍 Sample AttackEvent:")
            print("-" * 60)
            result = session.run("""
                MATCH (e)
                WHERE "AttackEvent" IN labels(e) OR "NormalRequest" IN labels(e)
                RETURN e LIMIT 1
            """)
            
            record = result.single()
            if record:
                event = dict(record["e"])
                print("Properties found:")
                for key, value in event.items():
                    if isinstance(value, str) and len(value) > 100:
                        value = value[:100] + "..."
                    print(f"  • {key}: {value}")
            else:
                print("  ⚠ No events found!")
            
            # 4. Count malicious vs benign
            print("\n📈 Attack Type Distribution:")
            print("-" * 60)
            result = session.run("""
                MATCH (e)
                WHERE "AttackEvent" IN labels(e) OR "NormalRequest" IN labels(e)
                RETURN 
                    e.attack_type as type,
                    count(*) as count
                ORDER BY count DESC
            """)
            for record in result:
                print(f"  - {record['type']}: {record['count']}")
            
            # 5. Count by labels (BlockedRequest vs NormalRequest)
            print("\n🏷️  Event Label Distribution:")
            print("-" * 60)
            result = session.run("""
                MATCH (e)
                WHERE "AttackEvent" IN labels(e) OR "NormalRequest" IN labels(e)
                WITH e,
                    CASE 
                        WHEN "BlockedRequest" IN labels(e) THEN "BlockedRequest"
                        WHEN "NormalRequest" IN labels(e) THEN "NormalRequest"
                        ELSE "Other"
                    END as category
                RETURN category, count(*) as count
                ORDER BY count DESC
            """)
            for record in result:
                print(f"  - {record['category']}: {record['count']}")
            
            # 6. Recent events with payloads
            print("\n📋 Recent Events (last 5):")
            print("-" * 60)
            result = session.run("""
                MATCH (e)
                WHERE "AttackEvent" IN labels(e) OR "NormalRequest" IN labels(e)
                RETURN 
                    e.timestamp as timestamp,
                    COALESCE(e.normalized_payload, e.payload) as payload,
                    e.attack_type as attack_type,
                    labels(e) as labels
                ORDER BY e.timestamp DESC
                LIMIT 5
            """)
            
            for i, record in enumerate(result, 1):
                payload = record["payload"]
                if payload and len(payload) > 60:
                    payload = payload[:60] + "..."
                
                print(f"\n{i}. Time: {record['timestamp']}")
                print(f"   Type: {record['attack_type']}")
                print(f"   Labels: {record['labels']}")
                print(f"   Payload: {payload}")
            
            # 7. Check for training-ready data
            print("\n✅ Training Data Check:")
            print("-" * 60)
            result = session.run("""
                MATCH (e)
                WHERE "AttackEvent" IN labels(e) OR "NormalRequest" IN labels(e)
                WITH 
                    COALESCE(e.normalized_payload, e.payload) AS payload,
                    CASE 
                        WHEN "BlockedRequest" IN labels(e) OR e.attack_type = 'xss' THEN 1
                        ELSE 0
                    END AS label
                WHERE payload IS NOT NULL
                RETURN 
                    count(*) as total,
                    sum(label) as malicious,
                    count(*) - sum(label) as benign
            """)
            
            record = result.single()
            if record and record["total"] > 0:
                print(f"✓ Training-ready samples: {record['total']}")
                print(f"  - Malicious: {record['malicious']}")
                print(f"  - Benign: {record['benign']}")
                
                if record['total'] >= 50:
                    print(f"\n✅ You have enough data to train!")
                    print(f"   Run: docker exec trainer python train_model.py --from-neo4j --version v2")
                else:
                    print(f"\n⚠ Need at least 50 samples (have {record['total']})")
                    print(f"   Generate more traffic first")
            else:
                print("⚠ No training-ready data found!")
                print("\n💡 Generate traffic:")
                print('   curl "http://localhost:8000/bwapp/xss_get.php?firstname=<script>alert(1)</script>"')
        
        driver.close()
        
    except Exception as e:
        print(f"✗ Error: {e}")
        print("\nTroubleshooting:")
        print("  1. Is Neo4j running? docker ps | grep neo4j")
        print("  2. Check credentials in docker-compose.gcp.yml")
        print("  3. Try: docker logs neo4j")
    
    print("\n" + "="*60)

if __name__ == "__main__":
    check_neo4j()
