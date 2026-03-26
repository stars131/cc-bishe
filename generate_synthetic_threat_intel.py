"""基于训练集生成模拟威胁情报库"""

from __future__ import annotations

import argparse
import json
import math
import os
from collections import Counter, defaultdict

import torch
import yaml


def load_cache_payload(cache_dir: str) -> dict:
    cache_path = os.path.join(cache_dir, "dataset_cache.pt")
    if not os.path.exists(cache_path):
        raise FileNotFoundError(f"未找到数据缓存: {cache_path}")
    return torch.load(cache_path, map_location="cpu", weights_only=False)


def normalize_attack_names(names: list[str]) -> list[str]:
    return [name for name in names if name != "Benign"]


def build_indicator_entry(
    indicator: str,
    counts: Counter,
    min_count: int,
    min_malicious_ratio: float,
    source_name: str,
    description_prefix: str,
    top_k: int = 2,
) -> dict | None:
    total = sum(counts.values())
    benign = counts.get("Benign", 0)
    malicious = total - benign
    if total < min_count or malicious <= 0:
        return None

    malicious_ratio = malicious / total
    if malicious_ratio < min_malicious_ratio:
        return None

    malicious_counts = Counter(
        {k: v for k, v in counts.items() if k != "Benign" and v > 0}
    )
    attack_types = [name for name, _ in malicious_counts.most_common(top_k)]
    attack_types = normalize_attack_names(attack_types)
    if not attack_types:
        return None

    top_attack_count = malicious_counts[attack_types[0]]
    purity = top_attack_count / malicious if malicious > 0 else 0.0
    prevalence = min(1.0, math.log10(total + 1) / 4.0)
    risk_score = min(0.99, 0.45 + 0.5 * malicious_ratio)
    confidence = min(0.99, 0.35 + 0.35 * purity + 0.3 * prevalence)

    return {
        "risk_score": round(risk_score, 4),
        "attack_types": attack_types,
        "confidence": round(confidence, 4),
        "source": source_name,
        "description": (
            f"{description_prefix}，训练集命中{total}次，恶意比例"
            f"{malicious_ratio:.2%}"
        ),
        "stats": {
            "total_count": total,
            "malicious_count": malicious,
            "benign_count": benign,
            "malicious_ratio": round(malicious_ratio, 6),
            "top_attack_purity": round(purity, 6),
            "label_counts": dict(counts),
        },
    }


def main():
    parser = argparse.ArgumentParser(description="生成模拟威胁情报库")
    parser.add_argument(
        "--config",
        default="config.experiment_base.yaml",
        help="实验配置文件",
    )
    parser.add_argument(
        "--output-dir",
        default="/root/autodl-tmp/cc-bishe-threat-intel/synthetic_train_v1",
        help="输出目录",
    )
    parser.add_argument(
        "--max-port-entries",
        type=int,
        default=64,
        help="最多保留多少个端口情报条目",
    )
    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    payload = load_cache_payload(config["data"]["cache_dir"])
    pre_state = payload["preprocessor_state"]
    class_names = pre_state["class_names"]
    train_indices = pre_state["train_indices"]
    train_labels = pre_state["train_labels"]
    network_info = payload.get("network_info", {})

    label_lookup = {idx: class_names[int(label)] for idx, label in enumerate(train_labels)}

    src_ip_counts: dict[str, Counter] = defaultdict(Counter)
    dst_ip_counts: dict[str, Counter] = defaultdict(Counter)
    port_counts: dict[str, Counter] = defaultdict(Counter)

    src_ip_values = network_info.get("src_ip", [])
    dst_ip_values = network_info.get("dst_ip", [])
    dst_port_values = network_info.get("dst_port", [])

    for local_idx, global_idx in enumerate(train_indices):
        label_name = label_lookup[local_idx]

        if global_idx < len(src_ip_values):
            src_ip = src_ip_values[global_idx]
            if src_ip:
                src_ip_counts[src_ip][label_name] += 1

        if global_idx < len(dst_ip_values):
            dst_ip = dst_ip_values[global_idx]
            if dst_ip:
                dst_ip_counts[dst_ip][label_name] += 1

        if global_idx < len(dst_port_values):
            port = dst_port_values[global_idx]
            port_counts[f"port:{int(port)}"][label_name] += 1

    intel_db = {}

    for indicator, counts in src_ip_counts.items():
        entry = build_indicator_entry(
            indicator=indicator,
            counts=counts,
            min_count=20,
            min_malicious_ratio=0.8,
            source_name="Synthetic train-derived src_ip intel",
            description_prefix="基于训练集源IP统计构造的模拟威胁情报",
            top_k=2,
        )
        if entry:
            intel_db[indicator] = entry

    for indicator, counts in dst_ip_counts.items():
        entry = build_indicator_entry(
            indicator=indicator,
            counts=counts,
            min_count=20,
            min_malicious_ratio=0.8,
            source_name="Synthetic train-derived dst_ip intel",
            description_prefix="基于训练集目的IP统计构造的模拟威胁情报",
            top_k=2,
        )
        if entry:
            intel_db[indicator] = entry

    port_candidates = []
    for indicator, counts in port_counts.items():
        entry = build_indicator_entry(
            indicator=indicator,
            counts=counts,
            min_count=50,
            min_malicious_ratio=0.2,
            source_name="Synthetic train-derived port intel",
            description_prefix="基于训练集目的端口统计构造的模拟威胁情报",
            top_k=3,
        )
        if entry:
            port_candidates.append((indicator, entry))

    port_candidates.sort(
        key=lambda item: (
            item[1]["stats"]["malicious_count"],
            item[1]["stats"]["malicious_ratio"],
        ),
        reverse=True,
    )
    for indicator, entry in port_candidates[: args.max_port_entries]:
        intel_db[indicator] = entry

    os.makedirs(args.output_dir, exist_ok=True)
    output_path = os.path.join(args.output_dir, "synthetic_train_intel.json")
    metadata_path = os.path.join(args.output_dir, "metadata.json")

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(intel_db, f, ensure_ascii=False, indent=2)

    metadata = {
        "entry_count": len(intel_db),
        "ip_entries": sum(1 for k in intel_db if not k.startswith("port:")),
        "port_entries": sum(1 for k in intel_db if k.startswith("port:")),
        "config": os.path.abspath(args.config),
        "output_path": output_path,
        "note": (
            "该情报库由训练集指示器统计生成，仅用于模拟外部威胁情报，"
            "不代表真实生产情报源。"
        ),
    }
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, ensure_ascii=False, indent=2)

    print(f"已生成模拟威胁情报: {output_path}")
    print(f"总条目数: {len(intel_db)}")


if __name__ == "__main__":
    main()
