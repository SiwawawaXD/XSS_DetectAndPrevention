# normalizer/utils/neo4j_client.py

import os
import logging
import uuid
from typing import Dict
from neo4j import GraphDatabase, basic_auth

logger = logging.getLogger("neo4j_client")
logger.setLevel(logging.INFO)


class Neo4jLogger:
    def __init__(self, uri: str, user: str, password: str):
        self.driver = GraphDatabase.driver(uri, auth=basic_auth(user, password))

        # ⭐ Safe schema creation (runs every startup)
        self._initialize_schema()

    # -----------------------------------------------------------
    # ⭐ SCHEMA INITIALIZATION
    # -----------------------------------------------------------
    def _initialize_schema(self):
        """
        Create Neo4j constraints & indexes.
        Running this on startup is ALWAYS safe (Neo4j won't recreate them).
        """
        schema_queries = [

            # Unique IP node
            """
            CREATE CONSTRAINT ip_unique IF NOT EXISTS
            FOR (i:IP) REQUIRE i.address IS UNIQUE
            """,

            # Unique attack event
            """
            CREATE CONSTRAINT attack_event_unique IF NOT EXISTS
            FOR (e:AttackEvent) REQUIRE e.event_id IS UNIQUE
            """,

            # Unique feature pattern (ML feature or detected string)
            """
            CREATE CONSTRAINT feature_pattern_unique IF NOT EXISTS
            FOR (f:FeaturePattern) REQUIRE f.name IS UNIQUE
            """,

            # (Optional but recommended) faster ML export
            """
            CREATE INDEX attack_event_timestamp IF NOT EXISTS
            FOR (e:AttackEvent) ON (e.timestamp)
            """,

            """
            CREATE INDEX attack_event_type IF NOT EXISTS
            FOR (e:AttackEvent) ON (e.attack_type)
            """
        ]

        try:
            with self.driver.session() as session:
                for q in schema_queries:
                    session.run(q)
                    logger.info(f"[Neo4j] Schema OK → {q.strip().splitlines()[0]}")
        except Exception as e:
            logger.error(f"Neo4j schema initialization failed: {e}")

    # -----------------------------------------------------------
    # CLOSE DRIVER
    # -----------------------------------------------------------
    def close(self):
        try:
            self.driver.close()
        except Exception:
            pass

    # -----------------------------------------------------------
    # ⭐ STORE XSS / PAYLOAD EVENT INTO GRAPH
    # -----------------------------------------------------------
    def log_xss_event(self, record: Dict):
        """
        Expected record format from the Gateway or ML API via Sidecar:

        {
            "timestamp": "...",
            "source": "gateway",
            "attack_type": "xss" or "none",
            "payload": "<script>alert(1)</script>",
            "normalized_payload": "decoded / cleaned payload",
            "confidence": 0.82,
            "user_ip": "1.2.3.4",
            "endpoint": "/search",
            "method": "GET",
            "features": {
                "count_lt": 3,
                "count_script": 1,
                "has_onerror": 1,
                ...
            }
        }
        """

        # Generate UUID WITHOUT APOC
        event_id = str(uuid.uuid4())

        query = """
        MERGE (ip:IP {address: $user_ip})

        CREATE (e:AttackEvent {
            event_id: $event_id,
            timestamp: datetime($timestamp),
            source: $source,
            attack_type: $attack_type,
            payload: $payload,
            normalized_payload: $normalized_payload,
            decoded_versions: $decoded_versions,
            confidence: $confidence,
            endpoint: $endpoint,
            method: $method
        })

        MERGE (ip)-[:ORIGINATED]->(e)

        WITH e, $features AS feats
        UNWIND keys(feats) AS k
          MERGE (f:FeaturePattern {name: k})
            ON CREATE SET f.created = timestamp()
          MERGE (e)-[:HAS_FEATURE {value: feats[k]}]->(f)

        RETURN e.event_id AS id
        """

        params = {
            "event_id": event_id,
            "user_ip": record.get("source_ip", "unknown"),
            "timestamp": record.get("timestamp"),
            "source": record.get("source", "gateway"),
            "attack_type": record.get("attack_type", "unknown"),
            "payload": record.get("payload"),
            "normalized_payload": record.get("normalized_payload") or record.get("payload"),
            "decoded_versions": record.get("decoded_versions", []),
            "confidence": float(record.get("confidence", 0.0)),
            "endpoint": record.get("endpoint"),
            "method": record.get("method"),
            "features": {p: 1 for p in record.get("detected_patterns", [])},
            "labels": record.get("labels", ["NormalRequest"])
        }


        try:
            with self.driver.session() as session:
                session.run(query, **params)
                logger.info(f"[Neo4j] Inserted AttackEvent {event_id}")
        except Exception as e:
            logger.exception(f"[Neo4j] Write failed: {e}")
            raise
