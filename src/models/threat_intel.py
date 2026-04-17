"""威胁情报评分模块

支持两种查询后端：
- HTTP API（默认）: 调用外部威胁情报FastAPI服务
  (D:/毕设相关/api 提供的 /v1/iocs/{value}, /v1/search)
- local JSON: 本地JSON文件（API不可用时的fallback）
"""

import os
import json
from typing import Dict, List, Optional
from urllib.parse import quote
from urllib.request import urlopen
from urllib.error import URLError

import numpy as np


# 威胁情报API返回的severity映射到风险评分
SEVERITY_RISK_MAP = {
    "critical": 0.95,
    "high": 0.85,
    "medium": 0.6,
    "low": 0.3,
    "info": 0.1,
    "": 0.5,
}


class ThreatIntelScorer:
    """威胁情报评分器

    调用外部威胁情报API (FastAPI服务) 获取IOC风险评估，
    并将结果映射为各攻击类别的概率分布。

    API响应格式 (ThreatRecordResponse):
        {
            "local_results": [
                {
                    "source": "urlhaus" | "cisa-kev" | ...,
                    "entity_type": "url" | "cve" | "ip" | ...,
                    "entity_value": "...",
                    "severity": "critical" | "high" | "medium" | "low",
                    "confidence": 0-100,
                    "tags": ["malware", "emotet", ...],
                    "description": "...",
                    ...
                }
            ],
            "opencti_results": {...}
        }
    """

    def __init__(
        self,
        threat_intel_dir: str,
        class_names: List[str],
        api_url: Optional[str] = None,
    ):
        """
        Args:
            threat_intel_dir: 本地威胁情报JSON目录（API不可用时的fallback）
            class_names: 攻击类别名称列表（与模型输出对齐）
            api_url: 威胁情报API地址，例如 http://localhost:8000
        """
        self.threat_intel_dir = threat_intel_dir
        self.class_names = class_names
        self.num_classes = len(class_names)
        self.api_url = api_url.rstrip("/") if api_url else None
        self.intel_db: Dict = {}
        self.api_available = False

        # 加载本地fallback数据库
        self._load_local_intel()

        # 检测API可用性
        if self.api_url:
            self._check_api_health()

    def _load_local_intel(self):
        """加载所有本地威胁情报JSON文件（API不可用时使用）"""
        if not os.path.exists(self.threat_intel_dir):
            return

        loaded_entries = 0
        skipped_files = 0
        for fname in os.listdir(self.threat_intel_dir):
            if not fname.endswith(".json"):
                continue

            fpath = os.path.join(self.threat_intel_dir, fname)
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, dict):
                skipped_files += 1
                continue

            valid_entries = {
                indicator: entry
                for indicator, entry in data.items()
                if isinstance(entry, dict)
                and "attack_types" in entry
                and "risk_score" in entry
                and "confidence" in entry
            }
            if not valid_entries:
                skipped_files += 1
                continue

            self.intel_db.update(valid_entries)
            loaded_entries += len(valid_entries)

        print(
            f"加载本地威胁情报条目: {len(self.intel_db)}"
            f" (有效条目累计: {loaded_entries}, 跳过文件: {skipped_files})"
        )

    def _check_api_health(self):
        """检查API是否可用"""
        try:
            with urlopen(f"{self.api_url}/health", timeout=3) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("api") == "ok":
                    self.api_available = True
                    print(f"威胁情报API连接成功: {self.api_url}")
        except (URLError, ConnectionError, TimeoutError, json.JSONDecodeError) as e:
            print(f"威胁情报API不可用 ({e})，使用本地JSON fallback")

    def _api_query_ioc(self, value: str) -> List[Dict]:
        """通过 /v1/iocs/{value} 端点精确查询"""
        if not self.api_available:
            return []
        try:
            url = (
                f"{self.api_url}/v1/iocs/{quote(value, safe='')}"
                "?include_opencti=false"
            )
            with urlopen(url, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("local_results", []) or []
        except (URLError, ConnectionError, TimeoutError, json.JSONDecodeError):
            return []

    def _api_search(self, query: str, limit: int = 5) -> List[Dict]:
        """通过 /v1/search 端点模糊搜索"""
        if not self.api_available:
            return []
        if len(query) < 2:
            return []
        try:
            url = (
                f"{self.api_url}/v1/search?q={quote(query)}"
                f"&limit={limit}&include_opencti=false"
            )
            with urlopen(url, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("local_results", []) or []
        except (URLError, ConnectionError, TimeoutError, json.JSONDecodeError):
            return []

    def _aggregate_api_records(
        self, records: List[Dict]
    ) -> Optional[Dict]:
        """将API返回的ThreatRecord列表聚合为内部评分格式"""
        if not records:
            return None

        max_risk = 0.0
        max_conf = 0.0
        attack_types: List[str] = []

        for r in records:
            severity = (r.get("severity") or "").lower()
            risk = SEVERITY_RISK_MAP.get(severity, 0.5)
            conf = (r.get("confidence") or 50) / 100.0

            max_risk = max(max_risk, risk)
            max_conf = max(max_conf, conf)

            # 从tags和entity_type中提取攻击类型线索
            attack_types.extend(r.get("tags", []) or [])
            et = r.get("entity_type", "")
            if et:
                attack_types.append(et)

        return {
            "risk_score": max_risk,
            "attack_types": list(set(attack_types)),
            "confidence": max_conf,
            "source": "api",
            "match_count": len(records),
        }

    def _query_indicator(self, indicator: str) -> Optional[Dict]:
        """查询单个指标（优先API精确匹配 -> API搜索 -> 本地JSON）"""
        # 1. API 精确IOC匹配
        if self.api_available:
            records = self._api_query_ioc(indicator)
            if records:
                return self._aggregate_api_records(records)

            # 2. API 模糊搜索（适用于IP段、URL子串等）
            records = self._api_search(indicator, limit=5)
            if records:
                return self._aggregate_api_records(records)

        # 3. 本地JSON fallback
        if indicator in self.intel_db:
            return self.intel_db[indicator]

        return None

    def score(
        self,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        dst_port: Optional[int] = None,
    ) -> np.ndarray:
        """根据流量指标查询威胁情报，返回威胁评分向量"""
        scores = np.ones(self.num_classes) / self.num_classes

        indicators = []
        if src_ip:
            indicators.append(src_ip)
        if dst_ip:
            indicators.append(dst_ip)
        if dst_port is not None:
            indicators.append(f"port:{dst_port}")

        matched_entries = []
        for indicator in indicators:
            entry = self._query_indicator(indicator)
            if entry:
                matched_entries.append(entry)

        if not matched_entries:
            return scores

        for entry in matched_entries:
            risk_score = entry.get("risk_score", 0.5)
            confidence = entry.get("confidence", 0.5)
            attack_types = entry.get("attack_types", [])
            weight = risk_score * confidence

            for attack_type in attack_types:
                for i, cls_name in enumerate(self.class_names):
                    if self._match_attack_type(attack_type, cls_name):
                        scores[i] += weight

        total = scores.sum()
        if total > 0:
            scores = scores / total

        return scores

    def _match_attack_type(self, attack_type: str, class_name: str) -> bool:
        """模糊匹配攻击类型和类别名称"""
        at = (attack_type or "").lower().replace("_", " ").replace("-", " ")
        cn = (class_name or "").lower().replace("_", " ").replace("-", " ")
        if not at or not cn:
            return False
        return at in cn or cn in at

    def batch_score(
        self,
        src_ips: Optional[List[str]] = None,
        dst_ips: Optional[List[str]] = None,
        dst_ports: Optional[List[int]] = None,
        batch_size: int = 0,
    ) -> np.ndarray:
        """批量评分"""
        n = batch_size or len(src_ips or dst_ips or dst_ports or [])
        if n == 0:
            return np.ones((1, self.num_classes)) / self.num_classes

        results = []
        for i in range(n):
            src = src_ips[i] if src_ips and i < len(src_ips) else None
            dst = dst_ips[i] if dst_ips and i < len(dst_ips) else None
            port = dst_ports[i] if dst_ports and i < len(dst_ports) else None
            results.append(self.score(src, dst, port))

        return np.array(results)
