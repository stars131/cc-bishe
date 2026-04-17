"""将CIC-IDS-2018已知攻击者IP/端口注入外部威胁情报API的SQLite DB

外部API项目位置: D:/毕设相关/api
DB路径: D:/毕设相关/api/data/threat_intel.db

注入后可通过 GET /v1/iocs/{ip} 或 GET /v1/search?q=<ip> 查询。
"""

import os
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

# 外部API的DB路径
API_DB_PATH = r"D:/毕设相关/api/data/threat_intel.db"

# 本地威胁情报JSON（作为注入数据源）
LOCAL_INTEL_JSON = "data/threat_intel/cic_ids_2018_intel.json"


def ensure_schema(conn: sqlite3.Connection):
    """确保表结构存在（与API项目 app/db.py 保持一致）"""
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS threat_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_value TEXT NOT NULL,
            normalized_value TEXT NOT NULL,
            title TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            severity TEXT NOT NULL DEFAULT '',
            tags_json TEXT NOT NULL DEFAULT '[]',
            first_seen TEXT NULL,
            last_seen TEXT NULL,
            confidence INTEGER NULL,
            reference_url TEXT NOT NULL DEFAULT '',
            raw_json TEXT NOT NULL DEFAULT '{}',
            synced_at TEXT NOT NULL,
            UNIQUE(source, entity_type, entity_value)
        );
        CREATE INDEX IF NOT EXISTS idx_threat_records_normalized_value
            ON threat_records(normalized_value);
        CREATE INDEX IF NOT EXISTS idx_threat_records_entity_type
            ON threat_records(entity_type);
        """
    )


def risk_score_to_severity(risk: float) -> str:
    if risk >= 0.9:
        return "critical"
    if risk >= 0.75:
        return "high"
    if risk >= 0.5:
        return "medium"
    return "low"


def main():
    if not os.path.exists(LOCAL_INTEL_JSON):
        print(f"错误: 未找到 {LOCAL_INTEL_JSON}")
        return

    with open(LOCAL_INTEL_JSON, "r", encoding="utf-8") as f:
        intel = json.load(f)

    # 确保DB目录存在
    Path(API_DB_PATH).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(API_DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL;")
    ensure_schema(conn)

    now = datetime.now(timezone.utc).isoformat()
    records = []

    for key, entry in intel.items():
        # 区分IP和端口
        if key.startswith("port:"):
            entity_type = "port"
            entity_value = key.split(":")[1]
        else:
            entity_type = "ipv4-addr"
            entity_value = key

        risk = float(entry.get("risk_score", 0.5))
        conf = int(float(entry.get("confidence", 0.5)) * 100)
        severity = risk_score_to_severity(risk)
        tags = entry.get("attack_types", [])
        description = entry.get("description", "")
        source_name = entry.get("source", "cic-ids-2018")

        records.append((
            "cic-ids-2018",                          # source
            entity_type,
            entity_value,
            entity_value.lower(),                     # normalized_value
            f"CIC-IDS-2018 known {entity_type}",      # title
            description,
            severity,
            json.dumps(tags),
            None,                                     # first_seen
            None,                                     # last_seen
            conf,
            "",                                       # reference_url
            json.dumps({"origin": source_name}),
            now,
        ))

    conn.executemany(
        """
        INSERT INTO threat_records (
            source, entity_type, entity_value, normalized_value,
            title, description, severity, tags_json,
            first_seen, last_seen, confidence, reference_url,
            raw_json, synced_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(source, entity_type, entity_value) DO UPDATE SET
            severity = excluded.severity,
            tags_json = excluded.tags_json,
            confidence = excluded.confidence,
            description = excluded.description,
            synced_at = excluded.synced_at;
        """,
        records,
    )
    conn.commit()

    # 统计结果
    cur = conn.execute(
        "SELECT entity_type, COUNT(*) FROM threat_records "
        "WHERE source='cic-ids-2018' GROUP BY entity_type"
    )
    print(f"已注入到 {API_DB_PATH}:")
    for et, n in cur.fetchall():
        print(f"  {et}: {n}")

    conn.close()


if __name__ == "__main__":
    main()
