import os
import logging
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Optional, List
from datetime import datetime
from neo4j import GraphDatabase, basic_auth

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("normalizer")


# ----------------------------------------------------
# Neo4j Client
# ----------------------------------------------------
class Neo4jLogger:
    def __init__(self, uri: str, user: str, password: str):
        logger.info("[Neo4j] Connecting...")
        self.driver = GraphDatabase.driver(uri, auth=basic_auth(user, password))
        self._init_schema_once()

    def _init_schema_once(self):
        schema_cmds = [
            "CREATE CONSTRAINT ip_unique IF NOT EXISTS FOR (i:IP) REQUIRE i.address IS UNIQUE",
            "CREATE CONSTRAINT attack_event_unique IF NOT EXISTS FOR (e:AttackEvent) REQUIRE e.event_id IS UNIQUE",
            "CREATE CONSTRAINT feature_pattern_unique IF NOT EXISTS FOR (f:FeaturePattern) REQUIRE f.name IS UNIQUE",
            "CREATE INDEX attack_event_timestamp IF NOT EXISTS FOR (e:AttackEvent) ON (e.timestamp)",
            "CREATE INDEX attack_event_type IF NOT EXISTS FOR (e:AttackEvent) ON (e.attack_type)"
        ]

        try:
            with self.driver.session() as session:
                for q in schema_cmds:
                    try:
                        session.run(q)
                        logger.info(f"[Neo4j] Schema OK → {q[:55]}...")
                    except Exception as e:
                        logger.error(f"[Neo4j] Schema error (ignored): {e}")
        except Exception as e:
            logger.error(f"[Neo4j] Schema initialization failed: {e}")

    def log_xss_event(self, record: Dict):
        query = """
        MERGE (ip:IP {address: $user_ip})

        CREATE (e {
            event_id: apoc.create.uuid(),
            timestamp: datetime($timestamp),
            attack_type: $attack_type,
            payload: $payload,
            normalized_payload: $normalized_payload,
            decoded_versions: $decoded_versions,
            confidence: $confidence,
            endpoint: $endpoint,
            method: $method
        })

        WITH e, $labels AS lbls
        CALL apoc.create.addLabels(id(e), lbls) YIELD node
        SET e = node

        MERGE (ip)-[:ORIGINATED]->(e)

        WITH e, $features AS feats
        UNWIND keys(feats) AS k
            MERGE (f:FeaturePattern {name: k})
            MERGE (e)-[:HAS_FEATURE {value: feats[k]}]->(f)

        RETURN e.event_id;
        """

        try:
            with self.driver.session() as session:
                session.run(query, **record)
        except Exception as e:
            logger.error(f"[Neo4j] Insert failed: {e}")


# Incoming Gateway Log Model
class RawLog(BaseModel):
    timestamp: Optional[str] = None
    request_id: Optional[str] = None
    method: str
    endpoint: str
    source_ip: str
    blocked: bool = False
    blocked_by: Optional[str] = None
    attack_type: str = "none"
    detected_patterns: list = []
    confidence: float = 0.0
    payload: str
    normalized_payload: Optional[str] = None
    decoded_versions: Optional[list] = []
    labels: Optional[list] = []



app = FastAPI(title="Normalizer Service")

WRITE_TO_NEO4J = os.getenv("WRITE_TO_NEO4J", "true").lower() == "true"

neo4j_client = None
if WRITE_TO_NEO4J:
    try:
        neo4j_client = Neo4jLogger(
            uri=os.getenv("NEO4J_URI", "bolt://neo4j:7687"),
            user=os.getenv("NEO4J_USER", "neo4j"),
            password=os.getenv("NEO4J_PASSWORD", "password")
        )
        logger.info("[Normalizer] Connected to Neo4j.")
    except Exception as e:
        logger.error(f"[Normalizer] Neo4j connection failed: {e}")


# ----------------------------------------------------
# Main Ingest Endpoint
# ----------------------------------------------------
@app.post("/raw")
def ingest_raw(log: RawLog):
            
    timestamp = log.timestamp or datetime.utcnow().isoformat()
    record = {
    "timestamp": timestamp,
    "attack_type": log.attack_type,
    "payload": log.payload,
    "normalized_payload": log.normalized_payload,
    "decoded_versions": log.decoded_versions,   
    "confidence": float(log.confidence),
    "user_ip": log.source_ip,
    "endpoint": log.endpoint,
    "method": log.method,
    "features": {p: 1 for p in log.detected_patterns},
    "labels": log.labels or ["LogEvent"]
    }

    logger.info(f"[Normalizer] Received event → {record['endpoint']}")

    if WRITE_TO_NEO4J and neo4j_client:
        neo4j_client.log_xss_event(record)

    return {"status": "ok", "stored": True}


@app.get("/health")
def health():
    return {"status": "normalizer running"}
